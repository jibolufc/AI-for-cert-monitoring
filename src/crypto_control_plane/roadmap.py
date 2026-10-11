from __future__ import annotations

import base64
import copy
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import ValidationError
from .schema_validation import SchemaRegistry


SENSITIVE_KEYS = {
    "owner", "subject", "issuer", "uri", "peer_host", "supplier",
    "asset_id", "service_id", "observed_by", "collector_id",
    "source_record_id", "account", "region", "fingerprint_sha256",
    "payload_sha256",
}
HIGH_ASSURANCE = {"authenticated-production", "independently-verified"}
PROPOSAL_ONLY_ADAPTERS = {"ticketing", "cmdb", "pki", "kms-hsm", "deployment-evidence"}
MUTATING_OPERATIONS = {"issue", "revoke", "rotate", "delete", "deploy", "change-trust", "execute"}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class ReconciliationResult:
    records: tuple[dict[str, Any], ...]
    report: dict[str, Any]


class EvidenceReconciler:
    """Reconcile observations without discarding conflicts or provenance."""

    def __init__(self, schemas: SchemaRegistry):
        self.schemas = schemas

    def reconcile(self, records: list[dict[str, Any]], *, as_of: str) -> ReconciliationResult:
        _timestamp(as_of)
        groups: dict[str, list[dict[str, Any]]] = {}
        seen_ids: set[str] = set()
        for record in records:
            self.schemas.validate("cryptographic-inventory-record", record)
            if record["record_id"] in seen_ids:
                raise ValidationError("duplicate inventory record id")
            seen_ids.add(record["record_id"])
            asset = record["asset"]["asset_id"] or f"unknown:{record['record_id']}"
            use = record["cryptographic_use"]
            key = f"{asset}|{use['function']}|{use['protocol']}"
            groups.setdefault(key, []).append(record)

        reconciled = []
        conflict_count = 0
        for key in sorted(groups):
            observations = sorted(groups[key], key=lambda item: (item["observed_at"], item["record_id"]))
            states: dict[str, list[str]] = {}
            for observation in observations:
                algorithm = observation["cryptographic_use"]["algorithm"]
                state = f"{algorithm['family']}:{algorithm['name']}"
                states.setdefault(state, []).append(observation["record_id"])
            conflicts = [
                {"state": state, "record_ids": ids}
                for state, ids in sorted(states.items())
            ] if len(states) > 1 else []
            if conflicts:
                conflict_count += 1
            canonical = observations[-1]
            item = {
                "schema_version": "1.0",
                "reconciliation_id": str(uuid5(NAMESPACE_URL, f"reconcile:{key}:{as_of}")),
                "identity_key": key,
                "as_of": as_of,
                "canonical_record_id": canonical["record_id"],
                "observation_record_ids": [item["record_id"] for item in observations],
                "status": "conflicted" if conflicts else "consistent",
                "conflicts": conflicts,
                "evidence_level": _weakest_level(observations),
                "decision_authority": "deterministic-advisory",
            }
            self.schemas.validate("reconciled-evidence", item)
            reconciled.append(item)

        report = {
            "as_of": as_of,
            "input_records": len(records),
            "identities": len(groups),
            "consistent_identities": len(groups) - conflict_count,
            "conflicted_identities": conflict_count,
            "unknown_asset_records": sum(item["asset"]["asset_id"] is None for item in records),
            "limitations": [
                "Latest-observation selection is deterministic and does not resolve a conflict as truth.",
                "Reconciliation does not prove asset ownership or production coverage.",
            ],
        }
        return ReconciliationResult(tuple(reconciled), report)


class OfflineEvidenceBundle:
    """Create and verify a self-contained integrity-protected offline bundle."""

    def __init__(self, schemas: SchemaRegistry):
        self.schemas = schemas

    def create(
        self,
        artifacts: dict[str, Any],
        *,
        created_at: str,
        sanitised: bool = True,
        private_key: Ed25519PrivateKey | None = None,
    ) -> dict[str, Any]:
        _timestamp(created_at)
        if not artifacts:
            raise ValidationError("offline bundle requires at least one artifact")
        key = private_key or Ed25519PrivateKey.generate()
        content = sanitise(artifacts) if sanitised else copy.deepcopy(artifacts)
        evidence_claim, evidence_levels = _artifact_evidence_level(artifacts)
        if evidence_levels & HIGH_ASSURANCE:
            raise ValidationError("offline builder cannot originate a high-assurance evidence claim")
        entries = [
            {"name": name, "sha256": sha256(value), "size_bytes": len(canonical_json(value))}
            for name, value in sorted(content.items())
        ]
        manifest = {
            "schema_version": "1.0",
            "bundle_id": str(uuid5(NAMESPACE_URL, f"offline-bundle:{created_at}:{sha256(content)}")),
            "created_at": created_at,
            "sanitised": sanitised,
            "entries": entries,
            "evidence_claim": evidence_claim,
            "signer_trust": "self-signed-local-integrity-only",
        }
        signature = key.sign(canonical_json(manifest))
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        bundle = {
            "schema_version": "1.0",
            "manifest": manifest,
            "artifacts": content,
            "signature": base64.b64encode(signature).decode(),
            "public_key": base64.b64encode(public).decode(),
        }
        self.schemas.validate("offline-evidence-bundle", bundle)
        return bundle

    def verify(
        self, bundle: dict[str, Any], *, trusted_public_keys: set[str] | None = None
    ) -> dict[str, Any]:
        self.schemas.validate("offline-evidence-bundle", bundle)
        manifest = bundle["manifest"]
        expected_names = set(bundle["artifacts"])
        entry_names = {item["name"] for item in manifest["entries"]}
        if expected_names != entry_names:
            raise ValidationError("bundle manifest and artifact names do not match")
        for entry in manifest["entries"]:
            value = bundle["artifacts"][entry["name"]]
            if sha256(value) != entry["sha256"] or len(canonical_json(value)) != entry["size_bytes"]:
                raise ValidationError(f"bundle artifact digest mismatch: {entry['name']}")
        derived_claim, derived_levels = _artifact_evidence_level(bundle["artifacts"])
        if derived_levels & HIGH_ASSURANCE:
            raise ValidationError(
                "offline import cannot establish a high-assurance evidence claim"
            )
        if manifest["evidence_claim"] != derived_claim:
            raise ValidationError(
                "bundle evidence claim does not match the weakest artifact evidence"
            )
        try:
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(bundle["public_key"], validate=True))
            public.verify(base64.b64decode(bundle["signature"], validate=True), canonical_json(manifest))
        except (ValueError, InvalidSignature) as exc:
            raise ValidationError("bundle signature verification failed") from exc
        trusted = trusted_public_keys is not None and bundle["public_key"] in trusted_public_keys
        return {
            "integrity_verified": True,
            "signer_trusted": trusted,
            "evidence_level": manifest["evidence_claim"],
            "warning": None if trusted else "Self-signed bundle proves integrity, not source identity.",
        }


def sanitise(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in SENSITIVE_KEYS and item is not None:
                result[key] = f"redacted:{hashlib.sha256(str(item).encode()).hexdigest()[:12]}"
            else:
                result[key] = sanitise(item)
        return result
    if isinstance(value, list):
        return [sanitise(item) for item in value]
    return value


class PilotGate:
    def __init__(self, schemas: SchemaRegistry):
        self.schemas = schemas

    def assess(self, authorisation: dict[str, Any], records: list[dict[str, Any]], *, as_of: str) -> dict[str, Any]:
        self.schemas.validate("pilot-authorisation", authorisation)
        now = _timestamp(as_of)
        if not (_timestamp(authorisation["valid_from"]) <= now < _timestamp(authorisation["expires_at"])):
            raise ValidationError("pilot authorisation is not currently valid")
        if authorisation["mode"] != "read-only":
            raise ValidationError("pilot must be read-only")
        if authorisation["approved_by"] == authorisation["requested_by"]:
            raise ValidationError("pilot requester cannot self-authorise")
        allowed_assets = set(authorisation["asset_ids"])
        observed = set()
        for record in records:
            self.schemas.validate("cryptographic-inventory-record", record)
            asset_id = record["asset"]["asset_id"]
            if asset_id not in allowed_assets:
                raise ValidationError(f"record is outside authorised pilot scope: {asset_id}")
            if record["evidence_level"] in HIGH_ASSURANCE and not authorisation["authenticated_source"]:
                raise ValidationError("high-assurance evidence requires an authenticated pilot source")
            observed.add(asset_id)
        denominator = len(allowed_assets)
        return {
            "authorisation_id": authorisation["authorisation_id"],
            "as_of": as_of,
            "authoritative_assets": denominator,
            "observed_assets": len(observed),
            "unknown_assets": len(allowed_assets - observed),
            "coverage_percent": round(100 * len(observed) / denominator, 2),
            "gate_status": "measured-reference-only" if authorisation["evidence_level"] == "simulated" else "pilot-measured",
        }


class ControlPlaneStore:
    """Tenant-scoped workflow, audit, and outbox reference transaction."""

    def __init__(self, path: Path | str):
        self.connection = sqlite3.connect(str(path))
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript("""
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS requests(tenant_id TEXT, request_id TEXT, requester TEXT, payload TEXT, status TEXT, version INTEGER, PRIMARY KEY(tenant_id, request_id));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, actor TEXT, action TEXT, object_id TEXT, at TEXT, details TEXT);
        CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, event_type TEXT, payload TEXT, delivered INTEGER DEFAULT 0);
        """)

    def close(self) -> None:
        self.connection.close()

    def create_request(self, *, tenant_id: str, request_id: str, requester: str, payload: dict[str, Any], at: str) -> None:
        _required_text(tenant_id, "tenant_id"); _required_text(request_id, "request_id"); _timestamp(at)
        with self.connection:
            self.connection.execute("INSERT INTO requests VALUES(?,?,?,?,?,?)", (tenant_id, request_id, requester, json.dumps(payload, sort_keys=True), "approval-required", 1))
            self._audit(tenant_id, requester, "request.created", request_id, at, {"version": 1})
            self._outbox(tenant_id, "request.created", {"request_id": request_id, "version": 1})

    def approve(self, *, tenant_id: str, request_id: str, actor: str, roles: set[str], expected_version: int, at: str) -> None:
        _timestamp(at)
        if not roles & {"cryptography-authority", "change-authority"}:
            raise ValidationError("approval role is required")
        with self.connection:
            row = self.connection.execute("SELECT * FROM requests WHERE tenant_id=? AND request_id=?", (tenant_id, request_id)).fetchone()
            if row is None:
                raise ValidationError("request not found in tenant")
            if row["requester"] == actor:
                raise ValidationError("requester cannot approve their own request")
            updated = self.connection.execute(
                "UPDATE requests SET status='approved', version=version+1 WHERE tenant_id=? AND request_id=? AND version=? AND status='approval-required'",
                (tenant_id, request_id, expected_version),
            )
            if updated.rowcount != 1:
                raise ValidationError("stale or invalid workflow transition")
            self._audit(tenant_id, actor, "request.approved", request_id, at, {"version": expected_version + 1})
            self._outbox(tenant_id, "request.approved", {"request_id": request_id, "version": expected_version + 1})

    def snapshot(self, tenant_id: str, request_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM requests WHERE tenant_id=? AND request_id=?", (tenant_id, request_id)).fetchone()
        return None if row is None else dict(row)

    def counts(self, tenant_id: str) -> dict[str, int]:
        audit = self.connection.execute("SELECT COUNT(*) FROM audit WHERE tenant_id=?", (tenant_id,)).fetchone()[0]
        outbox = self.connection.execute("SELECT COUNT(*) FROM outbox WHERE tenant_id=?", (tenant_id,)).fetchone()[0]
        return {"audit": audit, "outbox": outbox}

    def _audit(self, tenant: str, actor: str, action: str, object_id: str, at: str, details: dict[str, Any]) -> None:
        self.connection.execute("INSERT INTO audit(tenant_id,actor,action,object_id,at,details) VALUES(?,?,?,?,?,?)", (tenant, actor, action, object_id, at, json.dumps(details, sort_keys=True)))

    def _outbox(self, tenant: str, event_type: str, payload: dict[str, Any]) -> None:
        self.connection.execute("INSERT INTO outbox(tenant_id,event_type,payload) VALUES(?,?,?)", (tenant, event_type, json.dumps(payload, sort_keys=True)))


class IntegrationProposalService:
    def __init__(self, schemas: SchemaRegistry):
        self.schemas = schemas

    def propose(self, *, adapter: str, operation: str, target_ref: str, requested_by: str, evidence_refs: list[str], as_of: str) -> dict[str, Any]:
        if adapter not in PROPOSAL_ONLY_ADAPTERS:
            raise ValidationError("unsupported integration adapter")
        if operation in MUTATING_OPERATIONS:
            raise ValidationError("cryptographic or deployment mutations are outside this release")
        if not evidence_refs:
            raise ValidationError("integration proposal requires evidence")
        _timestamp(as_of); _required_text(target_ref, "target_ref")
        proposal = {
            "schema_version": "1.0",
            "proposal_id": str(uuid5(NAMESPACE_URL, f"proposal:{adapter}:{operation}:{target_ref}:{as_of}")),
            "adapter": adapter,
            "operation": operation,
            "target_ref": target_ref,
            "requested_by": requested_by,
            "created_at": as_of,
            "evidence_refs": sorted(set(evidence_refs)),
            "status": "approval-required",
            "execution_authority": "none",
        }
        self.schemas.validate("integration-proposal", proposal)
        return proposal


def cbom_export(records: list[dict[str, Any]], reconciled: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {item["record_id"]: item for item in records}
    components = []
    for item in reconciled:
        record = by_id[item["canonical_record_id"]]
        components.append({
            "identity_key": item["identity_key"],
            "asset_id": record["asset"]["asset_id"],
            "service_id": record["asset"]["service_id"],
            "function": record["cryptographic_use"]["function"],
            "algorithm": record["cryptographic_use"]["algorithm"],
            "dependencies": record["dependencies"],
            "reconciliation_status": item["status"],
            "evidence_level": item["evidence_level"],
        })
    return {"format": "cbom-style-reference-1.0", "components": components, "limitations": ["Reference export; not asserted to conform to an external CBOM standard."]}


def dependency_graph(records: list[dict[str, Any]]) -> dict[str, Any]:
    nodes = sorted({item["asset"]["asset_id"] for item in records if item["asset"]["asset_id"]})
    edges = sorted({(item["asset"]["asset_id"], dependency) for item in records if item["asset"]["asset_id"] for dependency in item["dependencies"]})
    return {"nodes": nodes, "edges": [{"from": source, "to": target} for source, target in edges]}


def _weakest_level(records: list[dict[str, Any]]) -> str:
    order = ["simulated", "generated", "public-observation", "sanitised-capture", "authenticated-production", "independently-verified"]
    return min((item["evidence_level"] for item in records), key=order.index)


def _artifact_evidence_level(value: Any) -> tuple[str, set[str]]:
    order = ["simulated", "generated", "public-observation", "sanitised-capture", "authenticated-production", "independently-verified"]
    found: list[str] = []
    def walk(item: Any) -> None:
        if isinstance(item, dict):
            level = item.get("evidence_level")
            if level in order:
                found.append(level)
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)
    walk(value)
    return (min(found, key=order.index) if found else "simulated", set(found))


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValidationError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError("timestamp must include timezone")
    return parsed


def _required_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{label} is required")
