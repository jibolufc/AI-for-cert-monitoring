from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from crypto_control_plane.errors import ValidationError
from crypto_control_plane.models import MonitoringPolicy
from crypto_control_plane.pipeline import CertificateMonitoringPipeline
from crypto_control_plane.schema_validation import SchemaRegistry
from crypto_control_plane.sinks import JsonlAlertSink

ROOT = Path(__file__).resolve().parents[1]


def fixture(name: str):
    return json.loads((ROOT / "examples" / "events" / name).read_text(encoding="utf-8"))


def policy():
    payload = json.loads((ROOT / "examples" / "policy.json").read_text(encoding="utf-8"))
    SchemaRegistry(ROOT / "schemas").validate("monitoring-policy", payload)
    return MonitoringPolicy.from_dict(payload)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.schemas = SchemaRegistry(ROOT / "schemas")
        self.pipeline = CertificateMonitoringPipeline(policy(), self.schemas)

    def test_unknown_domain_produces_high_severity_alert(self):
        alert = self.pipeline.process(fixture("unknown-domain-issued.json"))
        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert["rule_id"], "CERT-001")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["risk_score"], 80)
        self.assertEqual(alert["policy"]["policy_version"], 1)
        self.assertEqual(alert["explanation_authority"], "advisory-only")
        self.assertEqual(alert["evidence"]["unmatched_dns_names"], ["login.lookalike-example.net"])

    def test_known_suffix_and_wildcard_do_not_alert(self):
        self.assertIsNone(self.pipeline.process(fixture("known-domain-issued.json")))

    def test_suffix_matching_requires_dns_label_boundary(self):
        event = fixture("known-domain-issued.json")
        event["certificate"]["san_dns_names"] = ["api.badexample.com"]
        alert = self.pipeline.process(event)
        self.assertIsNotNone(alert)

    def test_dns_normalization_handles_case_trailing_dot_and_idn(self):
        event = fixture("known-domain-issued.json")
        event["certificate"]["san_dns_names"] = [
            "API.Example.COM.",
            "bücher.example.com",
        ]
        self.assertIsNone(self.pipeline.process(event))

    def test_invalid_wildcard_position_fails_closed(self):
        event = fixture("known-domain-issued.json")
        event["certificate"]["san_dns_names"] = ["api.*.example.com"]
        with self.assertRaises(ValidationError):
            self.pipeline.process(event)

    def test_alert_identifier_is_deterministic(self):
        event = fixture("unknown-domain-issued.json")
        first = self.pipeline.process(event)
        second = self.pipeline.process(copy.deepcopy(event))
        assert first is not None and second is not None
        self.assertEqual(first["alert_id"], second["alert_id"])

    def test_invalid_fingerprint_fails_closed(self):
        event = fixture("unknown-domain-issued.json")
        event["certificate"]["fingerprint_sha256"] = "not-a-fingerprint"
        with self.assertRaises(ValidationError):
            self.pipeline.process(event)

    def test_naive_timestamp_fails_closed(self):
        event = fixture("unknown-domain-issued.json")
        event["observed_at"] = "2026-10-11T09:00:00"
        with self.assertRaises(ValidationError):
            self.pipeline.process(event)

    def test_unexpected_field_fails_closed(self):
        event = fixture("unknown-domain-issued.json")
        event["certificate"]["private_key"] = "should-never-be-here"
        with self.assertRaises(ValidationError):
            self.pipeline.process(event)

    def test_empty_subject_is_valid_x509_telemetry(self):
        event = fixture("known-domain-issued.json")
        event["certificate"]["subject"] = ""
        self.assertIsNone(self.pipeline.process(event))

    def test_jsonl_sink_writes_one_parseable_record(self):
        alert = self.pipeline.process(fixture("unknown-domain-issued.json"))
        assert alert is not None
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "alerts.jsonl"
            JsonlAlertSink(path).write(alert)
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["alert_id"], alert["alert_id"])


if __name__ == "__main__":
    unittest.main()
