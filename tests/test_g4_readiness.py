from __future__ import annotations

import copy
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from crypto_control_plane.errors import ValidationError
from crypto_control_plane.g4_readiness import G4ReadinessGate
from crypto_control_plane.g4_readiness_cli import main as g4_main
from crypto_control_plane.schema_validation import SchemaRegistry


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "examples/g4/synthetic-production-preparation-plan.json"
NOW = "2026-11-19T14:00:00Z"


class G4ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.schemas = SchemaRegistry(ROOT / "schemas")
        self.plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
        self.gate = G4ReadinessGate(self.schemas)

    def demonstrated_plan(self):
        plan = copy.deepcopy(self.plan)
        for name, control in plan["controls"].items():
            control.update({"status": "demonstrated", "evidence_refs": [f"test-evidence:{name}"]})
        return plan

    def test_example_is_blocked_with_all_controls_visible(self):
        report = self.gate.assess(self.plan, as_of=NOW)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["control_summary"], {"required": 10, "demonstrated": 0, "remaining": 10})
        self.assertFalse(report["g4_gate_passed"])
        self.assertEqual(report["production_operating_authority"], "none")
        self.assertEqual(report["migration_execution_authority"], "none")

    def test_complete_preparation_never_grants_production_authority(self):
        report = self.gate.assess(self.demonstrated_plan(), as_of=NOW)
        self.assertEqual(report["status"], "g4-preparation-ready")
        self.assertFalse(report["g4_gate_passed"])
        self.assertEqual(report["production_operating_authority"], "none")
        self.assertEqual(report["migration_execution_authority"], "none")

    def test_missing_control_evidence_blocks_preparation(self):
        plan = self.demonstrated_plan()
        plan["controls"]["independent_security_testing"] = {"status": "planned", "evidence_refs": []}
        report = self.gate.assess(plan, as_of=NOW)
        self.assertEqual(report["status"], "blocked")
        self.assertIn(
            "control is not evidenced as demonstrated: independent_security_testing",
            report["unmet_requirements"],
        )

    def test_self_approval_and_expiry_block_preparation(self):
        plan = self.demonstrated_plan()
        plan["approved_by"] = plan["requested_by"]
        report = self.gate.assess(plan, as_of="2027-03-01T00:00:00Z")
        self.assertEqual(report["status"], "blocked")
        self.assertIn("independent approval is required; requester and approver must differ", report["unmet_requirements"])
        self.assertIn("the production-preparation plan is outside its validity window", report["unmet_requirements"])

    def test_schema_forbids_activation_flags(self):
        for field in ("real_data_enabled", "public_endpoint_enabled", "production_traffic_enabled"):
            plan = copy.deepcopy(self.plan)
            plan[field] = True
            with self.subTest(field=field), self.assertRaises(ValidationError):
                self.gate.assess(plan, as_of=NOW)

        plan = copy.deepcopy(self.plan)
        plan["execution_authority"] = "migration"
        with self.assertRaises(ValidationError):
            self.gate.assess(plan, as_of=NOW)

    def test_cli_writes_deterministic_blocked_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with redirect_stdout(StringIO()):
                result = g4_main(["--plan", str(PLAN_PATH), "--output", str(output), "--as-of", NOW])
            self.assertEqual(result, 3)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.schemas.validate("g4-readiness-report", report)
            self.assertEqual(report["status"], "blocked")
            self.assertEqual(report["control_summary"]["remaining"], 10)

    def test_schemas_load(self):
        self.schemas._load("g4-readiness-plan")
        self.schemas._load("g4-readiness-report")


if __name__ == "__main__":
    unittest.main()
