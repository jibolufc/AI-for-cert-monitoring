from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from uuid import NAMESPACE_URL, uuid5

from .errors import ValidationError
from .inventory import PqcInventoryService
from .models import CertificateEvent
from .pipeline import CertificateMonitoringPipeline
from .schema_validation import SchemaRegistry
from .state import CollectorState


MAX_FIXTURE_BYTES = 1_000_000
MAX_ENTRY_BYTES = 65_536


class CertificateTransparencySource(Protocol):
    def fetch_page(self, after_cursor: str | None) -> dict[str, Any] | None:
        """Return one decoded, bounded CT observation page or None."""


class FixtureCertificateTransparencySource:
    """Read-only decoded CT source used for deterministic tests and demos."""

    def __init__(self, directory: Path, *, maximum_file_bytes: int = MAX_FIXTURE_BYTES):
        self.directory = directory
        self.maximum_file_bytes = maximum_file_bytes
        self._pages: dict[str | None, dict[str, Any]] = {}
        for path in sorted(directory.glob("*.json")):
            if path.stat().st_size > maximum_file_bytes:
                raise ValidationError(f"CT fixture exceeds {maximum_file_bytes} bytes: {path}")
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValidationError(f"cannot read CT fixture {path}: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValidationError(f"CT fixture must be an object: {path}")
            cursor = payload.get("page_after_cursor")
            if cursor in self._pages:
                raise ValidationError(f"duplicate CT fixture cursor {cursor!r}")
            self._pages[cursor] = payload

    def fetch_page(self, after_cursor: str | None) -> dict[str, Any] | None:
        page = self._pages.get(after_cursor)
        return None if page is None else copy.deepcopy(page)


@dataclass
class CollectionResult:
    pages: int = 0
    observations: int = 0
    accepted: int = 0
    alerted: int = 0
    rejected: int = 0
    duplicates: int = 0
    alerts: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, int]:
        return {
            "pages": self.pages,
            "observations": self.observations,
            "accepted": self.accepted,
            "alerted": self.alerted,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
        }


class CertificateTransparencyCollector:
    """Converts decoded CT observations into canonical events and alerts."""

    collector_id = "ct-decoded-fixture"
    collector_version = "0.3.0"

    def __init__(
        self,
        *,
        source: CertificateTransparencySource,
        state: CollectorState,
        pipeline: CertificateMonitoringPipeline,
        schemas: SchemaRegistry,
        maximum_pages: int = 1000,
        maximum_entry_bytes: int = MAX_ENTRY_BYTES,
    ):
        self.source = source
        self.state = state
        self.pipeline = pipeline
        self.schemas = schemas
        self.maximum_pages = maximum_pages
        self.maximum_entry_bytes = maximum_entry_bytes
        self.inventory = PqcInventoryService(schemas)

    def collect(self) -> CollectionResult:
        result = CollectionResult()
        cursor = self.state.get_checkpoint(self.collector_id)
        seen_next_cursors: set[str] = set()

        while result.pages < self.maximum_pages:
            page = self.source.fetch_page(cursor)
            if page is None:
                return result
            self.schemas.validate("ct-observation-page", page)
            if page["page_after_cursor"] != cursor:
                raise ValidationError("CT page cursor does not match the requested checkpoint")
            next_cursor = page["next_cursor"]
            if next_cursor == cursor or next_cursor in seen_next_cursors:
                raise ValidationError(f"CT cursor cycle detected at {next_cursor!r}")
            seen_next_cursors.add(next_cursor)
            result.pages += 1

            for entry in page["entries"]:
                result.observations += 1
                raw_bytes = _canonical_bytes(entry)
                if len(raw_bytes) > self.maximum_entry_bytes:
                    raise ValidationError(
                        f"CT entry exceeds {self.maximum_entry_bytes} bytes"
                    )
                payload_sha256 = hashlib.sha256(raw_bytes).hexdigest()
                source_record_id = f"{page['log_id']}:{entry['index']}"
                if self.state.check_duplicate(
                    self.collector_id, source_record_id, payload_sha256
                ):
                    result.duplicates += 1
                    continue

                event = self._to_event(page, entry, source_record_id, payload_sha256)
                try:
                    alert = self.pipeline.process(event)
                    parsed_event = CertificateEvent.from_dict(event)
                    inventory = self.inventory.assess_certificate_event(parsed_event)
                    status = "alerted" if alert is not None else "accepted"
                    error = None
                except ValidationError as exc:
                    alert = None
                    inventory = None
                    status = "rejected"
                    error = str(exc)

                self.state.record_outcome(
                    collector_id=self.collector_id,
                    source_record_id=source_record_id,
                    payload_sha256=payload_sha256,
                    raw_payload=entry,
                    event=event,
                    status=status,
                    alert=alert,
                    error=error,
                    processed_at=page["collected_at"],
                    inventory_record=None if inventory is None else inventory.record,
                    pqc_assessment=None if inventory is None else inventory.assessment,
                )
                if status == "alerted":
                    result.alerted += 1
                    assert alert is not None
                    result.alerts.append(alert)
                elif status == "accepted":
                    result.accepted += 1
                else:
                    result.rejected += 1

            self.state.set_checkpoint(
                self.collector_id, next_cursor, page["collected_at"]
            )
            cursor = next_cursor

        raise ValidationError(
            f"CT collection exceeded the {self.maximum_pages}-page safety limit"
        )

    def _to_event(
        self,
        page: dict[str, Any],
        entry: dict[str, Any],
        source_record_id: str,
        payload_sha256: str,
    ) -> dict[str, Any]:
        event_id = str(
            uuid5(
                NAMESPACE_URL,
                f"crypto-control-plane:ct:{source_record_id}:{entry['certificate']['fingerprint_sha256'].lower()}",
            )
        )
        return {
            "schema_version": "1.3",
            "event_id": event_id,
            "event_type": "certificate.observed",
            "observed_at": entry["observed_at"],
            "source": {"type": "ct", "id": page["log_id"]},
            "certificate": copy.deepcopy(entry["certificate"]),
            "cryptography": copy.deepcopy(entry["cryptography"]),
            "context": {"environment": "unknown"},
            "evidence": {
                "observed_by": self.collector_id,
                "collected_at": page["collected_at"],
                "uri": entry["source_uri"],
            },
            "provenance": {
                "collector_id": self.collector_id,
                "collector_version": self.collector_version,
                "source_record_id": source_record_id,
                "payload_sha256": payload_sha256,
                "verification_state": "unverified",
                "evidence_level": "simulated",
                "cursor": str(entry["index"]),
            },
        }


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
