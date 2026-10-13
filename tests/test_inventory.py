from __future__ import annotations

import copy
from contextlib import redirect_stdout
from io import StringIO
import json
import tempfile
import unittest
from pathlib import Path

from crypto_control_plane.errors import ValidationError
from crypto_control_plane.inventory import PqcInventoryService
from crypto_control_plane.inventory_cli import main as inventory_main
from crypto_control_plane.models import CertificateEvent
from crypto_control_plane.schema_validation import SchemaRegistry

ROOT = Path(__file__).resolve().parents[1]


def event_payload() -> dict:
    return json.loads(
        (ROOT / "examples" / "events" / "known-domain-issued.json").read_text()
    )


class PqcInventoryTests(unittest.TestCase):
    def setUp(self):
        self.schemas = SchemaRegistry(ROOT / "schemas")
        self.service = PqcInventoryService(self.schemas)

    def assess(self, payload: dict):
        self.schemas.validate("certificate-event", payload)
        return self.service.assess_certificate_event(CertificateEvent.from_dict(payload))

    def test_classical_certificate_is_quantum_vulnerable_and_high_priority(self):
        result = self.assess(event_payload())
        assessment = result.assessment
        self.assertEqual(assessment["exposure_status"], "quantum-vulnerable")
        self.assertEqual(assessment["migration_priority"], "high")
        self.assertEqual(
            {item["rule_id"] for item in assessment["findings"]},
            {"PQC-001", "PQC-002", "PQC-004"},
        )
        self.assertEqual(result.record["coverage"]["scope"], "certificate-only")
        self.assertIn(
            "cryptographic_use.implementation.product",
            assessment["missing_context"],
        )

    def test_unknown_algorithm_never_becomes_quantum_safe(self):
        payload = event_payload()
        payload["cryptography"]["public_key"] = {
            "family": "unknown", "name": "unknown", "oid": "unknown"
        }
        payload["cryptography"]["certificate_signature"] = {
            "family": "unknown", "name": "unknown", "oid": "unknown"
        }
        result = self.assess(payload)
        self.assertEqual(result.assessment["exposure_status"], "unknown")
        self.assertEqual(result.assessment["migration_priority"], "needs-evidence")
        self.assertIn("PQC-003", {item["rule_id"] for item in result.assessment["findings"]})

    def test_pqc_algorithms_are_candidates_not_declared_safe(self):
        payload = event_payload()
        payload["cryptography"]["public_key"] = {
            "family": "ml-dsa", "name": "ML-DSA-65", "oid": "2.16.840.1.101.3.4.3.18"
        }
        payload["cryptography"]["certificate_signature"] = {
            "family": "ml-dsa", "name": "ML-DSA-65", "oid": "2.16.840.1.101.3.4.3.18"
        }
        result = self.assess(payload)
        self.assertEqual(
            result.assessment["exposure_status"], "candidate-quantum-resistant"
        )
        self.assertEqual(result.assessment["migration_priority"], "verify")
        self.assertIn("PQC-005", {item["rule_id"] for item in result.assessment["findings"]})

    def test_known_classical_exposure_is_not_masked_by_unknown_signature(self):
        payload = event_payload()
        payload["cryptography"]["certificate_signature"] = {
            "family": "unknown", "name": "unknown", "oid": "unknown"
        }
        result = self.assess(payload)
        self.assertEqual(result.assessment["exposure_status"], "quantum-vulnerable")
        self.assertIn("PQC-001", {item["rule_id"] for item in result.assessment["findings"]})

    def test_hybrid_label_requires_protocol_verification(self):
        payload = event_payload()
        payload["cryptography"]["public_key"] = {
            "family": "hybrid", "name": "example-hybrid", "oid": "1.3.6.1.4.1.99999.1"
        }
        payload["cryptography"]["certificate_signature"] = {
            "family": "hybrid", "name": "example-hybrid-signature", "oid": "1.3.6.1.4.1.99999.2"
        }
        result = self.assess(payload)
        self.assertEqual(result.assessment["exposure_status"], "hybrid-unverified")
        self.assertIn("PQC-006", {item["rule_id"] for item in result.assessment["findings"]})

    def test_missing_business_context_blocks_prioritisation(self):
        payload = event_payload()
        payload["context"] = {"environment": "unknown"}
        result = self.assess(payload)
        self.assertEqual(result.assessment["migration_priority"], "needs-context")
        self.assertIn("asset.owner", result.assessment["missing_context"])

    def test_assessment_is_deterministic(self):
        payload = event_payload()
        first = self.assess(payload)
        second = self.assess(copy.deepcopy(payload))
        self.assertEqual(first.record, second.record)
        self.assertEqual(first.assessment, second.assessment)

    def test_inventory_cli_writes_valid_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "inventory.json"
            with redirect_stdout(StringIO()):
                result = inventory_main([
                    "--event", str(ROOT / "examples" / "events" / "known-domain-issued.json"),
                    "--output", str(output),
                ])
            self.assertEqual(result, 0)
            bundle = json.loads(output.read_text())
            self.schemas.validate("cryptographic-inventory-record", bundle["record"])
            self.schemas.validate("pqc-assessment", bundle["assessment"])

    def test_unexpected_algorithm_field_fails_closed(self):
        payload = event_payload()
        payload["cryptography"]["public_key"]["claimed_quantum_safe"] = True
        with self.assertRaises(ValidationError):
            self.schemas.validate("certificate-event", payload)

    def test_kem_cannot_be_claimed_as_certificate_signature(self):
        payload = event_payload()
        payload["cryptography"]["certificate_signature"] = {
            "family": "ml-kem", "name": "ML-KEM-768", "oid": "2.16.840.1.101.3.4.4.2"
        }
        with self.assertRaises(ValidationError):
            self.schemas.validate("certificate-event", payload)


if __name__ == "__main__":
    unittest.main()
