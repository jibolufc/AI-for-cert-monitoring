from __future__ import annotations

import json
import unittest
from pathlib import Path

from crypto_control_plane.errors import ValidationError
from crypto_control_plane.schema_validation import SchemaRegistry

ROOT = Path(__file__).resolve().parents[1]


class SchemaValidationTests(unittest.TestCase):
    def setUp(self):
        self.schemas = SchemaRegistry(ROOT / "schemas")

    def test_published_examples_conform_to_full_schemas(self):
        policy = json.loads((ROOT / "examples" / "policy.json").read_text())
        self.schemas.validate("monitoring-policy", policy)
        for path in (ROOT / "examples" / "events").glob("*.json"):
            self.schemas.validate("certificate-event", json.loads(path.read_text()))
        for path in (ROOT / "examples" / "ct" / "pages").glob("*.json"):
            self.schemas.validate("ct-observation-page", json.loads(path.read_text()))
        catalog = json.loads(
            (ROOT / "examples" / "migration" / "fictional-enterprise.json").read_text()
        )
        self.schemas.validate("enterprise-catalog", catalog)

    def test_format_checker_rejects_invalid_uri(self):
        page = json.loads(
            (ROOT / "examples" / "ct" / "pages" / "001-known-domain.json").read_text()
        )
        page["entries"][0]["source_uri"] = "not a uri"
        with self.assertRaises(ValidationError):
            self.schemas.validate("ct-observation-page", page)

    def test_policy_schema_rejects_boolean_version(self):
        policy = json.loads((ROOT / "examples" / "policy.json").read_text())
        policy["policy_version"] = True
        with self.assertRaises(ValidationError):
            self.schemas.validate("monitoring-policy", policy)

    def test_legacy_certificate_contract_requires_explicit_upgrade(self):
        event = json.loads(
            (ROOT / "examples" / "events" / "known-domain-issued.json").read_text()
        )
        event["schema_version"] = "1.2"
        with self.assertRaises(ValidationError):
            self.schemas.validate("certificate-event", event)

    def test_evidence_level_is_required(self):
        event = json.loads(
            (ROOT / "examples" / "events" / "known-domain-issued.json").read_text()
        )
        del event["provenance"]["evidence_level"]
        with self.assertRaises(ValidationError):
            self.schemas.validate("certificate-event", event)


if __name__ == "__main__":
    unittest.main()
