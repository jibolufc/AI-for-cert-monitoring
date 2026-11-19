from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from crypto_control_plane.g4_readiness import G4ReadinessGate
from crypto_control_plane.schema_validation import SchemaRegistry


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "examples/g4/synthetic-production-preparation-plan.json"
EVIDENCE_PATH = ROOT / "evidence/g4/2026-11-19-foundation-preparation.json"
NOW = "2026-11-19T15:30:00Z"

FOUNDATION = {
    "service_ownership": ROOT / "docs/operations/G4-C01-service-ownership.md",
    "service_level_objectives": ROOT / "docs/operations/G4-C02-service-level-objectives.md",
    "data_protection_retention": ROOT / "docs/operations/G4-C09-data-protection-retention.md",
    "operational_runbooks_support": ROOT / "docs/operations/G4-C10-operating-runbooks.md",
}


class G4FoundationArtifactTests(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))

    def test_foundation_artifacts_are_referenced_but_not_claimed_demonstrated(self):
        for control, path in FOUNDATION.items():
            with self.subTest(control=control):
                self.assertTrue(path.is_file())
                declaration = self.plan["controls"][control]
                self.assertEqual(declaration["status"], "planned")
                self.assertEqual(declaration["evidence_refs"], [str(path.relative_to(ROOT))])

    def test_prepared_documents_do_not_make_g4_ready(self):
        report = G4ReadinessGate(SchemaRegistry(ROOT / "schemas")).assess(
            self.plan,
            as_of=NOW,
        )
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(
            report["control_summary"],
            {"required": 10, "demonstrated": 0, "remaining": 10},
        )
        self.assertFalse(report["g4_gate_passed"])
        self.assertEqual(report["production_operating_authority"], "none")
        self.assertEqual(report["migration_execution_authority"], "none")

    def test_ownership_keeps_accountability_unassigned_until_accepted(self):
        text = FOUNDATION["service_ownership"].read_text(encoding="utf-8")
        normalised = " ".join(text.split())
        for role in ("Service owner", "Security owner", "Data owner", "Operations owner", "Change approver"):
            self.assertIn(role, text)
        self.assertGreaterEqual(text.count("UNASSIGNED"), 5)
        self.assertIn("requester and approver must remain different", normalised)
        self.assertIn("Cryptographic change execution | Prohibited", text)

    def test_slo_targets_are_candidates_and_have_no_false_measurement_claim(self):
        text = FOUNDATION["service_level_objectives"].read_text(encoding="utf-8")
        for target in (
            "at least 99.5%",
            "at least 99.0%",
            "p95 at most 5 minutes",
            "p95 at most 2 minutes",
            "at most 4 hours",
            "at most 24 hours",
        ):
            self.assertIn(target, text)
        self.assertIn("No production service or measurement history exists", text)
        self.assertNotIn("SLO achieved", text)

    def test_data_policy_matches_current_retention_and_forbids_secrets(self):
        text = FOUNDATION["data_protection_retention"].read_text(encoding="utf-8")
        for expected in ("Synthetic S3 evidence | 30 days", "Synthetic Lambda logs | 30 days", "Reviewed staging templates | 7 days"):
            self.assertIn(expected, text)
        self.assertIn("Passwords, tokens, private keys or client secrets | No", text)
        self.assertIn("Real or production data | Not authorised", text)
        self.assertIn("Git history is not an appropriate store", text)

    def test_runbooks_cover_stop_deploy_rollback_access_recovery_and_incident(self):
        text = FOUNDATION["operational_runbooks_support"].read_text(encoding="utf-8")
        for heading in (
            "## Universal stop conditions",
            "## Deployment runbook",
            "## Rollback runbook",
            "## Access runbook",
            "## Backup and recovery runbook",
            "## Security incident runbook",
            "## Support and escalation runbook",
        ):
            self.assertIn(heading, text)
        self.assertIn("do not use root for routine work", text)
        self.assertIn("No response-time promise exists", text)

    def test_no_foundation_document_claims_production_authority(self):
        for path in FOUNDATION.values():
            text = path.read_text(encoding="utf-8").lower()
            with self.subTest(path=path.name):
                self.assertNotIn("g4_gate_passed: true", text)
                self.assertNotIn("production_operating_authority: granted", text)
                self.assertNotIn("migration_execution_authority: granted", text)

    def test_foundation_evidence_manifest_matches_files_and_preserves_no_authority(self):
        record = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        for artifact in record["artifact_hashes"]:
            path = ROOT / artifact["path"]
            with self.subTest(path=artifact["path"]):
                self.assertTrue(path.is_file())
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    artifact["sha256"],
                )
        self.assertEqual(record["validation"]["demonstrated_controls"], 0)
        self.assertEqual(record["validation"]["remaining_controls"], 10)
        self.assertFalse(record["authority"]["g4_gate_passed"])
        self.assertEqual(record["authority"]["production_operating_authority"], "none")
        self.assertEqual(record["authority"]["migration_execution_authority"], "none")


if __name__ == "__main__":
    unittest.main()
