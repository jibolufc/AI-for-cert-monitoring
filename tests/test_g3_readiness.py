from __future__ import annotations

import copy
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from crypto_control_plane.g3_readiness import G3ReadinessGate
from crypto_control_plane.g3_readiness_cli import main as g3_main
from crypto_control_plane.schema_validation import SchemaRegistry


ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-10-18T12:00:00Z"


class G3ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.schemas = SchemaRegistry(ROOT / "schemas")
        self.plan = json.loads((ROOT / "examples/g3/synthetic-readiness-plan.json").read_text())
        self.gate = G3ReadinessGate(self.schemas)

    def demonstrated_plan(self):
        plan = copy.deepcopy(self.plan)
        for name, control in plan["controls"].items():
            control.update({"status": "demonstrated", "evidence_refs": [f"test-evidence:{name}"]})
        return plan

    def test_synthetic_plan_is_ready_but_never_passes_g3(self):
        report = self.gate.assess(self.demonstrated_plan(), as_of=NOW)
        self.assertEqual(report["status"], "synthetic-staging-ready")
        self.assertFalse(report["g3_gate_passed"])
        self.assertEqual(report["collection_execution_authority"], "none")
        self.assertEqual(report["control_summary"], {"required": 8, "demonstrated": 8, "remaining": 0})

    def test_missing_control_evidence_blocks_readiness(self):
        plan = self.demonstrated_plan()
        plan["controls"]["backup_restore"] = {"status": "planned", "evidence_refs": []}
        report = self.gate.assess(plan, as_of=NOW)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("control is not evidenced as demonstrated: backup_restore", report["unmet_requirements"])

    def test_synthetic_plan_rejects_real_data_and_claim_inflation(self):
        plan = self.demonstrated_plan()
        plan["real_data_enabled"] = True
        plan["evidence_level"] = "authenticated-production"
        plan["authenticated_source"] = True
        report = self.gate.assess(plan, as_of=NOW)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("synthetic staging must keep real-data collection disabled", report["unmet_requirements"])
        self.assertIn("synthetic staging cannot claim an authenticated production source", report["unmet_requirements"])

    def test_incomplete_real_pilot_is_blocked(self):
        plan = self.demonstrated_plan()
        plan.update({
            "environment": "authorised-pilot",
            "real_data_enabled": True,
            "data_classification": "confidential",
            "privacy_review": "pending",
            "security_review": "pending",
            "authorisation_reference": None,
        })
        report = self.gate.assess(plan, as_of=NOW)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("written pilot authorisation reference is missing", report["unmet_requirements"])
        self.assertIn("privacy review is not approved", report["unmet_requirements"])

    def test_complete_declarations_require_external_g3_decision(self):
        plan = self.demonstrated_plan()
        plan.update({
            "environment": "authorised-pilot",
            "real_data_enabled": True,
            "authenticated_source": True,
            "evidence_level": "authenticated-production",
            "data_classification": "confidential",
            "privacy_review": "approved",
            "security_review": "approved",
            "authorisation_reference": "APPROVAL-EXTERNAL-001",
        })
        report = self.gate.assess(plan, as_of=NOW)
        self.assertEqual(report["status"], "g3-decision-required")
        self.assertFalse(report["g3_gate_passed"])
        self.assertEqual(report["collection_execution_authority"], "none")

    def test_self_approval_expiry_and_missing_prohibitions_block(self):
        plan = self.demonstrated_plan()
        plan["approved_by"] = plan["requested_by"]
        plan["prohibited_operations"].remove("revoke")
        report = self.gate.assess(plan, as_of="2027-01-01T00:00:00Z")
        self.assertEqual(report["status"], "blocked")
        self.assertIn("independent approval is required; requester and approver must differ", report["unmet_requirements"])
        self.assertIn("the plan is outside its approved validity window", report["unmet_requirements"])
        self.assertIn("prohibited operations are incomplete: revoke", report["unmet_requirements"])

    def test_cli_writes_deterministic_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with redirect_stdout(StringIO()):
                result = g3_main(["--plan", str(ROOT / "examples/g3/synthetic-readiness-plan.json"), "--output", str(output), "--as-of", NOW])
            self.assertEqual(result, 3)
            report = json.loads(output.read_text())
            self.schemas.validate("g3-readiness-report", report)
            self.assertEqual(report["status"], "blocked")
            self.assertEqual(report["control_summary"]["remaining"], 8)

    def test_schemas_load(self):
        self.schemas._load("g3-readiness-plan")
        self.schemas._load("g3-readiness-report")


if __name__ == "__main__":
    unittest.main()
