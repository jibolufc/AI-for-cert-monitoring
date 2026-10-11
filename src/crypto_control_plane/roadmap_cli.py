from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from .cli import load_json
from .errors import ValidationError
from .inventory import PqcInventoryService
from .models import CertificateEvent
from .roadmap import (
    ControlPlaneStore,
    EvidenceReconciler,
    IntegrationProposalService,
    OfflineEvidenceBundle,
    PilotGate,
    cbom_export,
    dependency_graph,
)
from .schema_validation import SchemaRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the safe Milestones 6-9 reference evidence set")
    parser.add_argument("--event", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--as-of", default="2026-10-11T15:00:00Z")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        schemas = SchemaRegistry()
        inventory = PqcInventoryService(schemas)
        records = [
            inventory.assess_certificate_event(CertificateEvent.from_dict(load_json(path))).record
            for path in args.event
        ]
        reconciliation = EvidenceReconciler(schemas).reconcile(records, as_of=args.as_of)
        cbom = cbom_export(records, list(reconciliation.records))
        graph = dependency_graph(records)
        bundle_service = OfflineEvidenceBundle(schemas)
        bundle = bundle_service.create(
            {"inventory": records, "reconciliation": list(reconciliation.records), "cbom": cbom, "dependency_graph": graph},
            created_at=args.as_of,
        )
        verification = bundle_service.verify(bundle)
        asset_ids = sorted({item["asset"]["asset_id"] for item in records if item["asset"]["asset_id"]})
        if not asset_ids:
            raise ValidationError("reference pilot requires at least one identified asset")
        authorisation = {
            "schema_version": "1.0",
            "authorisation_id": str(uuid5(NAMESPACE_URL, f"simulated-pilot:{args.as_of}")),
            "requested_by": "reference-pilot-owner", "approved_by": "reference-security-authority",
            "source_id": "local-fixtures", "mode": "read-only", "asset_ids": asset_ids,
            "valid_from": "2026-10-01T00:00:00Z", "expires_at": "2026-12-31T23:59:59Z",
            "authenticated_source": False, "evidence_level": "simulated",
            "stop_conditions": ["Stop on any out-of-scope record or attempted mutation."],
        }
        pilot_records = [item for item in records if item["asset"]["asset_id"] in set(asset_ids)]
        pilot = PilotGate(schemas).assess(authorisation, pilot_records, as_of=args.as_of)
        proposal = IntegrationProposalService(schemas).propose(
            adapter="ticketing", operation="create-change-request", target_ref="reference-only",
            requested_by="reference-pilot-owner", evidence_refs=[f"bundle:{bundle['manifest']['bundle_id']}"], as_of=args.as_of,
        )
        args.output_dir.mkdir(parents=True, exist_ok=True)
        store = ControlPlaneStore(args.output_dir / "control-plane.sqlite")
        if store.snapshot("reference-tenant", "reference-request") is None:
            store.create_request(tenant_id="reference-tenant", request_id="reference-request", requester="reference-pilot-owner", payload={"proposal_id": proposal["proposal_id"]}, at=args.as_of)
        control_plane = {"request": store.snapshot("reference-tenant", "reference-request"), "counts": store.counts("reference-tenant")}
        store.close()
        outputs = {
            "reconciliation.json": {"records": list(reconciliation.records), "report": reconciliation.report},
            "cbom.json": cbom, "dependency-graph.json": graph, "offline-bundle.json": bundle,
            "bundle-verification.json": verification, "pilot-report.json": pilot,
            "integration-proposal.json": proposal, "control-plane-reference.json": control_plane,
        }
        for name, payload in outputs.items():
            (args.output_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary = {
            "version": "0.9.0", "records": len(records), "reconciled_identities": reconciliation.report["identities"],
            "bundle_integrity_verified": verification["integrity_verified"], "bundle_signer_trusted": verification["signer_trusted"],
            "pilot_gate_status": pilot["gate_status"], "integration_execution_authority": proposal["execution_authority"],
            "production_gates_passed": False,
        }
        (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except (OSError, json.JSONDecodeError, sqlite3.Error, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
