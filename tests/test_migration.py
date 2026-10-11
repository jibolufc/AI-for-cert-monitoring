from __future__ import annotations

import copy
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from crypto_control_plane.errors import ValidationError
from crypto_control_plane.migration import MigrationPlanner, MigrationWorkflow
from crypto_control_plane.migration_cli import main as migration_main
from crypto_control_plane.schema_validation import SchemaRegistry


ROOT = Path(__file__).resolve().parents[1]


def catalog_payload() -> dict:
    return json.loads(
        (ROOT / "examples" / "migration" / "fictional-enterprise.json").read_text()
    )


class MigrationPlanningTests(unittest.TestCase):
    def setUp(self):
        self.schemas = SchemaRegistry(ROOT / "schemas")
        self.planner = MigrationPlanner(self.schemas)
        self.workflow = MigrationWorkflow(self.schemas)

    def plan(self, catalog: dict | None = None):
        return self.planner.plan(catalog or catalog_payload())

    def item(self, service_id: str):
        return next(
            item for item in self.plan().work_items if item["service_id"] == service_id
        )

    def approval(self, work_item: dict, *, actor_id: str = "approver-crypto") -> dict:
        return {
            "schema_version": "1.0",
            "decision_id": "f3c7f9f5-d7ed-46b6-9901-9da04ddabec5",
            "work_item_id": work_item["work_item_id"],
            "work_item_version": work_item["object_version"],
            "decision_type": "approve",
            "actor": {"actor_id": actor_id, "role": "cryptography-authority"},
            "decided_at": "2026-10-11T13:00:00Z",
            "rationale": "Target and verification plan reviewed for the controlled scenario.",
            "evidence_refs": ["review:architecture-board-001"],
            "conditions": [],
            "expires_at": None,
        }

    def test_fictional_catalogue_produces_dependency_aware_work(self):
        result = self.plan()
        self.assertEqual(len(result.work_items), 6)
        by_service = {item["service_id"]: item for item in result.work_items}
        self.assertEqual(by_service["svc-identity"]["wave"], "wave-1")
        self.assertEqual(by_service["svc-api"]["wave"], "wave-2")
        self.assertEqual(by_service["svc-api"]["dependencies"], ["svc-identity"])
        self.assertEqual(by_service["svc-payments"]["status"], "blocked")
        self.assertIn("target-not-ready", by_service["svc-payments"]["blockers"])
        self.assertIn("unsupported-target", by_service["svc-legacy"]["blockers"])
        self.assertIn("blocked-dependency", by_service["svc-reporting"]["blockers"])

    def test_coverage_and_migration_progress_are_separate(self):
        report = self.plan().coverage_report
        self.assertEqual(report["discovery_coverage"]["coverage_percent"], 83.33)
        self.assertEqual(report["discovery_coverage"]["unknown_assets"], 1)
        self.assertEqual(report["migration_progress"]["verified_percent"], 0.0)
        self.assertEqual(report["migration_progress"]["approval_required"], 3)
        self.assertEqual(report["migration_progress"]["blocked"], 3)
        self.assertEqual(report["migration_progress"]["rejected"], 0)
        self.assertNotIn("overall_percent", report)

    def test_plan_is_deterministic_and_all_outputs_validate(self):
        first = self.plan()
        second = self.plan(copy.deepcopy(catalog_payload()))
        self.assertEqual(first, second)
        for item in first.work_items:
            self.schemas.validate("migration-work-item", item)
        self.schemas.validate("migration-coverage-report", first.coverage_report)

    def test_dependency_cycle_fails_closed(self):
        catalog = catalog_payload()
        identity = next(item for item in catalog["services"] if item["service_id"] == "svc-identity")
        identity["dependencies"] = [{"service_id": "svc-reporting", "type": "hard"}]
        with self.assertRaisesRegex(ValidationError, "cycle"):
            self.plan(catalog)

    def test_unknown_dependency_fails_closed(self):
        catalog = catalog_payload()
        catalog["services"][0]["dependencies"] = [
            {"service_id": "svc-does-not-exist", "type": "hard"}
        ]
        with self.assertRaisesRegex(ValidationError, "unknown dependencies"):
            self.plan(catalog)

    def test_conflicting_owner_record_fails_closed(self):
        catalog = catalog_payload()
        catalog["owners"].append({
            "owner_id": "owner-identity",
            "display_name": "Conflicting identity owner",
            "role": "service-owner",
        })
        with self.assertRaisesRegex(ValidationError, "conflicting owner"):
            self.plan(catalog)

    def test_conflicting_asset_ownership_fails_closed(self):
        catalog = catalog_payload()
        duplicate = copy.deepcopy(catalog["services"][0])
        duplicate["service_id"] = "svc-identity-shadow"
        duplicate["owner_id"] = "owner-digital"
        duplicate["cryptographic_uses"][0]["use_id"] = "use-identity-shadow"
        catalog["services"].append(duplicate)
        with self.assertRaisesRegex(ValidationError, "conflicting ownership"):
            self.plan(catalog)

    def test_use_cannot_claim_stronger_evidence_than_catalogue(self):
        catalog = catalog_payload()
        catalog["services"][0]["cryptographic_uses"][0]["evidence_level"] = "generated"
        with self.assertRaisesRegex(ValidationError, "stronger evidence"):
            self.plan(catalog)

    def test_functionally_invalid_supported_target_is_blocked(self):
        catalog = catalog_payload()
        api = next(item for item in catalog["services"] if item["service_id"] == "svc-api")
        api["cryptographic_uses"][0]["target_state"] = {
            "algorithm_family": "ml-dsa",
            "algorithm_name": "ML-DSA-65",
            "standard": "FIPS 204",
            "readiness": "supported",
        }
        item = next(
            work for work in self.plan(catalog).work_items if work["service_id"] == "svc-api"
        )
        self.assertEqual(item["status"], "blocked")
        self.assertIn("unsupported-target", item["blockers"])

    def test_high_assurance_catalogue_claim_is_rejected(self):
        catalog = catalog_payload()
        catalog["evidence_level"] = "authenticated-production"
        with self.assertRaisesRegex(ValidationError, "authenticated source registry"):
            self.plan(catalog)

    def test_stale_decision_and_self_approval_are_rejected(self):
        work = self.item("svc-identity")
        stale = self.approval(work)
        stale["work_item_version"] = 999
        with self.assertRaisesRegex(ValidationError, "stale"):
            self.workflow.apply_decision(work, stale)
        self_approval = self.approval(work, actor_id=work["requested_by"])
        with self.assertRaisesRegex(ValidationError, "own migration"):
            self.workflow.apply_decision(work, self_approval)

    def test_expired_exception_is_rejected(self):
        work = self.item("svc-payments")
        exception = {
            "schema_version": "1.0",
            "exception_id": "1ce51f24-ce2d-42f1-94bb-7bc141767d2e",
            "work_item_id": work["work_item_id"],
            "work_item_version": work["object_version"],
            "status": "active",
            "risk_owner_id": "risk-owner-1",
            "approved_by": "risk-approver-1",
            "approved_at": "2026-09-01T09:00:00Z",
            "expires_at": "2026-10-01T09:00:00Z",
            "rationale": "Temporary supplier-readiness exception.",
            "compensating_controls": ["Restrict exposure and monitor every use."],
            "review_cadence_days": 14,
        }
        with self.assertRaisesRegex(ValidationError, "expired"):
            self.workflow.apply_exception(work, exception, as_of="2026-10-11T12:00:00Z")

    def test_active_exception_is_time_bounded_and_separately_validated(self):
        work = self.item("svc-payments")
        exception = {
            "schema_version": "1.0",
            "exception_id": "2b1435a8-9b1e-4759-bf9b-9592fc41a0e8",
            "work_item_id": work["work_item_id"],
            "work_item_version": work["object_version"],
            "status": "active",
            "risk_owner_id": "risk-owner-1",
            "approved_by": "risk-approver-1",
            "approved_at": "2026-10-11T09:00:00Z",
            "expires_at": "2026-11-11T09:00:00Z",
            "rationale": "Supplier target is planned but not yet available.",
            "compensating_controls": ["Restrict exposure and review every seven days."],
            "review_cadence_days": 7,
        }
        excepted = self.workflow.apply_exception(
            work, exception, as_of="2026-10-11T12:00:00Z"
        )
        self.assertEqual(excepted["status"], "excepted")
        self.assertIn(f"exception:{exception['exception_id']}", excepted["evidence_refs"])

    def test_verified_state_requires_independent_complete_post_change_evidence(self):
        work = self.item("svc-identity")
        approved = self.workflow.apply_decision(work, self.approval(work))
        verification_required = self.workflow.advance_to_verification(
            approved, implementation_evidence_ref="change:CHG-1001"
        )
        verification = {
            "schema_version": "1.0",
            "verification_id": "e48a153b-b6b3-4c16-a4a6-0a478e5d7214",
            "work_item_id": verification_required["work_item_id"],
            "work_item_version": verification_required["object_version"],
            "verified_at": "2026-10-12T14:00:00Z",
            "verifier": {"actor_id": "independent-verifier-1", "independence": "internal-independent"},
            "target_state": copy.deepcopy(verification_required["target_state"]),
            "pre_change_evidence_refs": ["inventory:before-001"],
            "post_change_evidence_refs": ["inventory:after-001"],
            "checks": [
                {"name": criterion, "result": "pass", "evidence_ref": f"test:{index}"}
                for index, criterion in enumerate(verification_required["verification_criteria"], 1)
            ],
            "residual_findings": [],
            "conclusion": "verified",
        }
        incomplete = copy.deepcopy(verification)
        incomplete["checks"] = incomplete["checks"][:-1]
        with self.assertRaisesRegex(ValidationError, "every approved criterion"):
            self.workflow.apply_verification(verification_required, incomplete)
        verified = self.workflow.apply_verification(verification_required, verification)
        self.assertEqual(verified["status"], "verified")
        self.assertIn("inventory:after-001", verified["evidence_refs"])
        items = list(self.plan().work_items)
        items[items.index(work)] = verified
        report = self.planner.report(catalog_payload(), items)
        self.assertEqual(report["migration_progress"]["verified"], 1)
        self.assertEqual(report["migration_progress"]["verified_percent"], 16.67)
        self.assertEqual(report["discovery_coverage"]["coverage_percent"], 83.33)

    def test_migration_cli_writes_valid_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "migration-plan.json"
            with redirect_stdout(StringIO()):
                result = migration_main([
                    "--catalog", str(ROOT / "examples/migration/fictional-enterprise.json"),
                    "--output", str(output),
                ])
            self.assertEqual(result, 0)
            bundle = json.loads(output.read_text())
            self.schemas.validate("enterprise-catalog", bundle["catalog"])
            for item in bundle["work_items"]:
                self.schemas.validate("migration-work-item", item)
            self.schemas.validate("migration-coverage-report", bundle["coverage_report"])


if __name__ == "__main__":
    unittest.main()
