from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from crypto_control_plane.ct_collector import (
    CertificateTransparencyCollector,
    FixtureCertificateTransparencySource,
)
from crypto_control_plane.errors import ValidationError
from crypto_control_plane.models import MonitoringPolicy
from crypto_control_plane.pipeline import CertificateMonitoringPipeline
from crypto_control_plane.schema_validation import SchemaRegistry
from crypto_control_plane.state import CollectorState, ProvenanceConflict

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples" / "ct" / "pages"


def build_components(state: CollectorState, fixture_directory: Path = FIXTURES):
    schemas = SchemaRegistry(ROOT / "schemas")
    policy_payload = json.loads((ROOT / "examples" / "policy.json").read_text())
    schemas.validate("monitoring-policy", policy_payload)
    pipeline = CertificateMonitoringPipeline(
        MonitoringPolicy.from_dict(policy_payload), schemas
    )
    collector = CertificateTransparencyCollector(
        source=FixtureCertificateTransparencySource(fixture_directory),
        state=state,
        pipeline=pipeline,
        schemas=schemas,
    )
    return collector


class CertificateTransparencyCollectorTests(unittest.TestCase):
    def test_collects_pages_preserves_evidence_and_alerts(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite"
            with CollectorState(database) as state:
                result = build_components(state).collect()
                self.assertEqual(result.as_dict(), {
                    "pages": 2,
                    "observations": 2,
                    "accepted": 1,
                    "alerted": 1,
                    "rejected": 0,
                    "duplicates": 0,
                })
                self.assertEqual(state.get_checkpoint("ct-decoded-fixture"), "2")
                self.assertEqual(state.count_observations(), 2)
                saved = state.get_observation(
                    "ct-decoded-fixture", "example-ct-log:1"
                )
                assert saved is not None
                self.assertEqual(saved["status"], "alerted")
                self.assertEqual(
                    saved["event"]["provenance"]["payload_sha256"],
                    saved["payload_sha256"],
                )
                self.assertEqual(len(result.alerts), 1)
                self.assertEqual(result.alerts[0]["rule_id"], "CERT-001")

    def test_checkpoint_survives_process_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite"
            with CollectorState(database) as state:
                build_components(state).collect()
            with CollectorState(database) as reopened:
                self.assertEqual(reopened.get_checkpoint("ct-decoded-fixture"), "2")
                result = build_components(reopened).collect()
                self.assertEqual(result.pages, 0)
                self.assertEqual(result.observations, 0)

    def test_replay_is_idempotent_and_emits_no_second_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            with CollectorState(Path(directory) / "state.sqlite") as state:
                first = build_components(state).collect()
                state.clear_checkpoint("ct-decoded-fixture")
                second = build_components(state).collect()
                self.assertEqual(first.alerted, 1)
                self.assertEqual(second.duplicates, 2)
                self.assertEqual(second.alerted, 0)
                self.assertEqual(second.alerts, [])
                self.assertEqual(state.count_observations(), 2)

    def test_source_identity_reuse_with_changed_content_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            copied = temporary / "pages"
            shutil.copytree(FIXTURES, copied)
            with CollectorState(temporary / "state.sqlite") as state:
                build_components(state, copied).collect()
                state.clear_checkpoint("ct-decoded-fixture")
                first_page = copied / "001-known-domain.json"
                payload = json.loads(first_page.read_text())
                payload["entries"][0]["certificate"]["subject"] = "CN=changed.example.com"
                first_page.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(ProvenanceConflict):
                    build_components(state, copied).collect()

    def test_malformed_page_fails_before_state_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            pages = temporary / "pages"
            pages.mkdir()
            (pages / "bad.json").write_text(
                json.dumps({
                    "schema_version": "1.0",
                    "page_after_cursor": None,
                    "next_cursor": "1",
                    "collected_at": "2026-10-11T10:00:00Z",
                    "entries": [{}],
                }),
                encoding="utf-8",
            )
            with CollectorState(temporary / "state.sqlite") as state:
                with self.assertRaises(ValidationError):
                    build_components(state, pages).collect()
                self.assertEqual(state.count_observations(), 0)
                self.assertIsNone(state.get_checkpoint("ct-decoded-fixture"))

    def test_fixture_size_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_text(" " * 101, encoding="utf-8")
            with self.assertRaises(ValidationError):
                FixtureCertificateTransparencySource(
                    Path(directory), maximum_file_bytes=100
                )

    def test_entry_size_limit_fails_before_state_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            with CollectorState(Path(directory) / "state.sqlite") as state:
                collector = build_components(state)
                collector.maximum_entry_bytes = 100
                with self.assertRaises(ValidationError):
                    collector.collect()
                self.assertEqual(state.count_observations(), 0)
                self.assertIsNone(state.get_checkpoint("ct-decoded-fixture"))

    def test_domain_invalid_entry_is_preserved_as_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            pages = temporary / "pages"
            shutil.copytree(FIXTURES, pages)
            first_page = pages / "001-known-domain.json"
            payload = json.loads(first_page.read_text())
            payload["entries"][0]["certificate"]["not_after"] = "2025-01-01T00:00:00Z"
            first_page.write_text(json.dumps(payload), encoding="utf-8")
            with CollectorState(temporary / "state.sqlite") as state:
                result = build_components(state, pages).collect()
                self.assertEqual(result.rejected, 1)
                self.assertEqual(result.alerted, 1)
                rejected = state.get_observation(
                    "ct-decoded-fixture", "example-ct-log:0"
                )
                assert rejected is not None
                self.assertEqual(rejected["status"], "rejected")
                self.assertIn("not_after", rejected["error"])


if __name__ == "__main__":
    unittest.main()
