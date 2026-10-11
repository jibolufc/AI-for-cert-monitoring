from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .errors import ValidationError


class ProvenanceConflict(ValidationError):
    """The same source identity was observed with different raw content."""


class CollectorState:
    """Durable checkpoint, evidence, outcome, and idempotency state."""

    def __init__(self, path: Path | str):
        self.path = str(path)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS checkpoints (
                collector_id TEXT PRIMARY KEY,
                cursor TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS observations (
                collector_id TEXT NOT NULL,
                source_record_id TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                raw_payload TEXT NOT NULL,
                event_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('accepted', 'alerted', 'rejected')),
                alert_json TEXT,
                error TEXT,
                processed_at TEXT NOT NULL,
                PRIMARY KEY (collector_id, source_record_id)
            );
            CREATE TABLE IF NOT EXISTS inventory_observations (
                record_id TEXT PRIMARY KEY,
                observation_id TEXT NOT NULL UNIQUE,
                record_json TEXT NOT NULL,
                assessment_json TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            """
        )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "CollectorState":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def get_checkpoint(self, collector_id: str) -> str | None:
        row = self.connection.execute(
            "SELECT cursor FROM checkpoints WHERE collector_id = ?", (collector_id,)
        ).fetchone()
        return None if row is None else str(row["cursor"])

    def set_checkpoint(self, collector_id: str, cursor: str, updated_at: str) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO checkpoints (collector_id, cursor, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(collector_id) DO UPDATE SET
                    cursor = excluded.cursor,
                    updated_at = excluded.updated_at
                """,
                (collector_id, cursor, updated_at),
            )

    def clear_checkpoint(self, collector_id: str) -> None:
        with self.connection:
            self.connection.execute(
                "DELETE FROM checkpoints WHERE collector_id = ?", (collector_id,)
            )

    def check_duplicate(
        self, collector_id: str, source_record_id: str, payload_sha256: str
    ) -> bool:
        row = self.connection.execute(
            """
            SELECT payload_sha256 FROM observations
            WHERE collector_id = ? AND source_record_id = ?
            """,
            (collector_id, source_record_id),
        ).fetchone()
        if row is None:
            return False
        if row["payload_sha256"] != payload_sha256:
            raise ProvenanceConflict(
                "source record identity was reused with different content: "
                f"{collector_id}/{source_record_id}"
            )
        return True

    def record_outcome(
        self,
        *,
        collector_id: str,
        source_record_id: str,
        payload_sha256: str,
        raw_payload: dict[str, Any],
        event: dict[str, Any],
        status: str,
        alert: dict[str, Any] | None,
        error: str | None,
        processed_at: str,
        inventory_record: dict[str, Any] | None = None,
        pqc_assessment: dict[str, Any] | None = None,
    ) -> None:
        if status not in {"accepted", "alerted", "rejected"}:
            raise ValueError(f"unsupported observation status: {status}")
        if (inventory_record is None) != (pqc_assessment is None):
            raise ValueError("inventory_record and pqc_assessment must be supplied together")
        with self.connection:
            try:
                self.connection.execute(
                    """
                    INSERT INTO observations (
                        collector_id, source_record_id, payload_sha256,
                        raw_payload, event_json, status, alert_json, error, processed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        collector_id,
                        source_record_id,
                        payload_sha256,
                        _canonical_json(raw_payload),
                        _canonical_json(event),
                        status,
                        None if alert is None else _canonical_json(alert),
                        error,
                        processed_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if self.check_duplicate(collector_id, source_record_id, payload_sha256):
                    return
                raise ProvenanceConflict(
                    f"could not record {collector_id}/{source_record_id}"
                ) from exc
            if inventory_record is not None and pqc_assessment is not None:
                self.connection.execute(
                    """
                    INSERT INTO inventory_observations (
                        record_id, observation_id, record_json,
                        assessment_json, observed_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        inventory_record["record_id"],
                        inventory_record["observation_id"],
                        _canonical_json(inventory_record),
                        _canonical_json(pqc_assessment),
                        inventory_record["observed_at"],
                    ),
                )

    def count_observations(self, status: str | None = None) -> int:
        if status is None:
            row = self.connection.execute("SELECT COUNT(*) AS count FROM observations").fetchone()
        else:
            row = self.connection.execute(
                "SELECT COUNT(*) AS count FROM observations WHERE status = ?", (status,)
            ).fetchone()
        assert row is not None
        return int(row["count"])

    def get_observation(
        self, collector_id: str, source_record_id: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT payload_sha256, raw_payload, event_json, status,
                   alert_json, error, processed_at
            FROM observations
            WHERE collector_id = ? AND source_record_id = ?
            """,
            (collector_id, source_record_id),
        ).fetchone()
        if row is None:
            return None
        return {
            "payload_sha256": row["payload_sha256"],
            "raw_payload": json.loads(row["raw_payload"]),
            "event": json.loads(row["event_json"]),
            "status": row["status"],
            "alert": None if row["alert_json"] is None else json.loads(row["alert_json"]),
            "error": row["error"],
            "processed_at": row["processed_at"],
        }

    def count_inventory_records(self) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM inventory_observations"
        ).fetchone()
        assert row is not None
        return int(row["count"])

    def get_inventory_record(self, record_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT record_json, assessment_json, observed_at
            FROM inventory_observations WHERE record_id = ?
            """,
            (record_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "record": json.loads(row["record_json"]),
            "assessment": json.loads(row["assessment_json"]),
            "observed_at": row["observed_at"],
        }


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
