from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4
from contextlib import redirect_stdout
from io import StringIO

from crypto_control_plane.errors import ValidationError
from crypto_control_plane.inventory import PqcInventoryService
from crypto_control_plane.models import CertificateEvent
from crypto_control_plane.roadmap import (
    ControlPlaneStore,
    EvidenceReconciler,
    IntegrationProposalService,
    OfflineEvidenceBundle,
    PilotGate,
    cbom_export,
    dependency_graph,
    sanitise,
)
from crypto_control_plane.schema_validation import SchemaRegistry
from crypto_control_plane.roadmap_cli import main as roadmap_main


ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-10-11T15:00:00Z"


class RemainingMilestoneTests(unittest.TestCase):
    def setUp(self):
        self.schemas = SchemaRegistry(ROOT / "schemas")
        payload = json.loads((ROOT / "examples/events/known-domain-issued.json").read_text())
        self.record = PqcInventoryService(self.schemas).assess_certificate_event(
            CertificateEvent.from_dict(payload)
        ).record

    def conflict_record(self):
        item = copy.deepcopy(self.record)
        item["record_id"] = str(uuid4())
        item["observation_id"] = str(uuid4())
        item["observed_at"] = "2026-10-11T14:00:00Z"
        item["cryptographic_use"]["algorithm"] = {
            "family": "ml-dsa", "name": "ML-DSA-65", "oid": "2.16.840.1.101.3.4.3.18"
        }
        return item

    def authorisation(self):
        return {
            "schema_version": "1.0", "authorisation_id": str(uuid4()),
            "requested_by": "pilot-owner", "approved_by": "security-authority",
            "source_id": "simulated-source", "mode": "read-only",
            "asset_ids": [self.record["asset"]["asset_id"]],
            "valid_from": "2026-10-01T00:00:00Z", "expires_at": "2026-11-01T00:00:00Z",
            "authenticated_source": False, "evidence_level": "simulated",
            "stop_conditions": ["Any out-of-scope record immediately stops collection."],
        }

    def test_reconciliation_preserves_conflicting_lineage(self):
        result = EvidenceReconciler(self.schemas).reconcile(
            [self.record, self.conflict_record()], as_of=NOW
        )
        self.assertEqual(result.report["conflicted_identities"], 1)
        self.assertEqual(result.records[0]["status"], "conflicted")
        self.assertEqual(len(result.records[0]["observation_record_ids"]), 2)
        self.assertEqual(len(result.records[0]["conflicts"]), 2)

    def test_reconciliation_is_deterministic_and_rejects_duplicate_ids(self):
        reconciler = EvidenceReconciler(self.schemas)
        self.assertEqual(
            reconciler.reconcile([self.record], as_of=NOW),
            reconciler.reconcile([copy.deepcopy(self.record)], as_of=NOW),
        )
        with self.assertRaisesRegex(ValidationError, "duplicate"):
            reconciler.reconcile([self.record, self.record], as_of=NOW)

    def test_signed_bundle_round_trip_and_trust_boundary(self):
        service = OfflineEvidenceBundle(self.schemas)
        bundle = service.create({"inventory": [self.record]}, created_at=NOW)
        result = service.verify(bundle)
        self.assertTrue(result["integrity_verified"])
        self.assertFalse(result["signer_trusted"])
        self.assertEqual(result["evidence_level"], "simulated")
        trusted = service.verify(bundle, trusted_public_keys={bundle["public_key"]})
        self.assertTrue(trusted["signer_trusted"])
        self.assertEqual(trusted["evidence_level"], "simulated")

    def test_bundle_tampering_fails_closed(self):
        service = OfflineEvidenceBundle(self.schemas)
        bundle = service.create({"inventory": [self.record]}, created_at=NOW)
        bundle["artifacts"]["inventory"][0]["asset"]["service_id"] = "tampered"
        with self.assertRaisesRegex(ValidationError, "digest mismatch"):
            service.verify(bundle)

    def test_offline_builder_cannot_originate_high_assurance_claim(self):
        record = copy.deepcopy(self.record)
        record["evidence_level"] = "authenticated-production"
        with self.assertRaisesRegex(ValidationError, "cannot originate"):
            OfflineEvidenceBundle(self.schemas).create({"inventory": [record]}, created_at=NOW)

    def test_sanitiser_redacts_identity_but_preserves_algorithm(self):
        cleaned = sanitise(self.record)
        self.assertTrue(cleaned["asset"]["owner"].startswith("redacted:"))
        self.assertTrue(cleaned["certificate"]["subject"].startswith("redacted:"))
        self.assertEqual(
            cleaned["cryptographic_use"]["algorithm"],
            self.record["cryptographic_use"]["algorithm"],
        )

    def test_cbom_and_dependency_exports_retain_conflict_status(self):
        reconciled = EvidenceReconciler(self.schemas).reconcile([self.record], as_of=NOW)
        cbom = cbom_export([self.record], list(reconciled.records))
        graph = dependency_graph([self.record])
        self.assertEqual(cbom["components"][0]["reconciliation_status"], "consistent")
        self.assertIn(self.record["asset"]["asset_id"], graph["nodes"])

    def test_pilot_requires_valid_independent_read_only_authorisation(self):
        gate = PilotGate(self.schemas)
        report = gate.assess(self.authorisation(), [self.record], as_of=NOW)
        self.assertEqual(report["coverage_percent"], 100.0)
        self.assertEqual(report["gate_status"], "measured-reference-only")
        invalid = self.authorisation(); invalid["approved_by"] = invalid["requested_by"]
        with self.assertRaisesRegex(ValidationError, "self-authorise"):
            gate.assess(invalid, [self.record], as_of=NOW)

    def test_pilot_scope_and_expiry_fail_closed(self):
        auth = self.authorisation(); auth["asset_ids"] = ["different-asset"]
        with self.assertRaisesRegex(ValidationError, "outside authorised"):
            PilotGate(self.schemas).assess(auth, [self.record], as_of=NOW)
        with self.assertRaisesRegex(ValidationError, "not currently valid"):
            PilotGate(self.schemas).assess(self.authorisation(), [], as_of="2027-01-01T00:00:00Z")

    def test_control_plane_transaction_writes_audit_and_outbox(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlPlaneStore(Path(directory) / "control.sqlite")
            store.create_request(tenant_id="tenant-a", request_id="req-1", requester="alice", payload={"change": "reference"}, at=NOW)
            store.approve(tenant_id="tenant-a", request_id="req-1", actor="bob", roles={"change-authority"}, expected_version=1, at=NOW)
            self.assertEqual(store.snapshot("tenant-a", "req-1")["status"], "approved")
            self.assertEqual(store.counts("tenant-a"), {"audit": 2, "outbox": 2})
            self.assertIsNone(store.snapshot("tenant-b", "req-1"))
            store.close()

    def test_control_plane_enforces_role_separation_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ControlPlaneStore(Path(directory) / "control.sqlite")
            store.create_request(tenant_id="tenant-a", request_id="req-1", requester="alice", payload={}, at=NOW)
            with self.assertRaisesRegex(ValidationError, "own request"):
                store.approve(tenant_id="tenant-a", request_id="req-1", actor="alice", roles={"change-authority"}, expected_version=1, at=NOW)
            with self.assertRaisesRegex(ValidationError, "role"):
                store.approve(tenant_id="tenant-a", request_id="req-1", actor="bob", roles={"viewer"}, expected_version=1, at=NOW)
            with self.assertRaisesRegex(ValidationError, "stale"):
                store.approve(tenant_id="tenant-a", request_id="req-1", actor="bob", roles={"change-authority"}, expected_version=9, at=NOW)
            store.close()

    def test_integration_is_proposal_only(self):
        service = IntegrationProposalService(self.schemas)
        proposal = service.propose(adapter="ticketing", operation="create-change-request", target_ref="CHG-draft", requested_by="alice", evidence_refs=["work:item-1"], as_of=NOW)
        self.assertEqual(proposal["execution_authority"], "none")
        self.assertEqual(proposal["status"], "approval-required")
        with self.assertRaisesRegex(ValidationError, "outside this release"):
            service.propose(adapter="pki", operation="revoke", target_ref="cert-1", requested_by="alice", evidence_refs=["alert:1"], as_of=NOW)

    def test_published_new_schemas_load(self):
        for contract in ("reconciled-evidence", "offline-evidence-bundle", "pilot-authorisation", "integration-proposal"):
            self.schemas._load(contract)

    def test_reference_release_cli_builds_non_production_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            with redirect_stdout(StringIO()):
                result = roadmap_main([
                    "--event", str(ROOT / "examples/events/known-domain-issued.json"),
                    "--output-dir", directory,
                ])
            self.assertEqual(result, 0)
            summary = json.loads((Path(directory) / "summary.json").read_text())
            self.assertTrue(summary["bundle_integrity_verified"])
            self.assertFalse(summary["bundle_signer_trusted"])
            self.assertFalse(summary["production_gates_passed"])
            self.assertEqual(summary["integration_execution_authority"], "none")
            with redirect_stdout(StringIO()):
                rerun = roadmap_main([
                    "--event", str(ROOT / "examples/events/known-domain-issued.json"),
                    "--output-dir", directory,
                ])
            self.assertEqual(rerun, 0)


if __name__ == "__main__":
    unittest.main()
