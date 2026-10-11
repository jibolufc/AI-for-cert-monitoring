from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from .errors import ValidationError
from .schema_validation import SchemaRegistry


SIGNATURE_TARGETS = {"ml-dsa", "slh-dsa", "hybrid"}
KEY_ESTABLISHMENT_TARGETS = {"ml-kem", "hybrid"}
HIGH_ASSURANCE_LEVELS = {"authenticated-production", "independently-verified"}
EVIDENCE_RANK = {
    "simulated": 0,
    "generated": 1,
    "public-observation": 1,
    "sanitised-capture": 2,
    "authenticated-production": 3,
    "independently-verified": 4,
}


@dataclass(frozen=True)
class MigrationPlan:
    work_items: tuple[dict[str, Any], ...]
    coverage_report: dict[str, Any]


class MigrationPlanner:
    """Build deterministic migration work without granting change authority."""

    method_version = "migration-planner-v1"

    def __init__(self, schemas: SchemaRegistry):
        self.schemas = schemas

    def plan(self, catalog: dict[str, Any]) -> MigrationPlan:
        self.schemas.validate("enterprise-catalog", catalog)
        self._validate_catalog(catalog)

        services = {service["service_id"]: service for service in catalog["services"]}
        ordered_ids = _topological_order(services)
        service_blocked: dict[str, bool] = {}
        items: list[dict[str, Any]] = []

        for service_id in ordered_ids:
            service = services[service_id]
            service_items = []
            hard_dependencies = sorted(
                dependency["service_id"]
                for dependency in service["dependencies"]
                if dependency["type"] == "hard"
            )
            all_dependencies = sorted(
                dependency["service_id"] for dependency in service["dependencies"]
            )
            blocked_dependency = any(service_blocked.get(item, False) for item in hard_dependencies)
            for use in sorted(service["cryptographic_uses"], key=lambda item: item["use_id"]):
                blockers = self._blockers(service, use)
                if blocked_dependency:
                    blockers.add("blocked-dependency")
                priority = _priority(service, use)
                work_item = self._work_item(
                    catalog, service, use, priority, sorted(blockers), all_dependencies
                )
                self.schemas.validate("migration-work-item", work_item)
                service_items.append(work_item)
                items.append(work_item)
            service_blocked[service_id] = any(item["status"] == "blocked" for item in service_items)

        coverage = self._coverage_report(catalog, items)
        self.schemas.validate("migration-coverage-report", coverage)
        return MigrationPlan(work_items=tuple(items), coverage_report=coverage)

    def report(
        self, catalog: dict[str, Any], work_items: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Recalculate separate coverage and progress measures after workflow updates."""
        self.schemas.validate("enterprise-catalog", catalog)
        self._validate_catalog(catalog)
        for item in work_items:
            self.schemas.validate("migration-work-item", item)
            if (
                item["catalog_id"] != catalog["catalog_id"]
                or item["catalog_version"] != catalog["catalog_version"]
            ):
                raise ValidationError("work item does not belong to the catalogue version")
        report = self._coverage_report(catalog, work_items)
        self.schemas.validate("migration-coverage-report", report)
        return report

    def _validate_catalog(self, catalog: dict[str, Any]) -> None:
        if catalog["evidence_level"] in HIGH_ASSURANCE_LEVELS:
            raise ValidationError(
                "high-assurance catalogue evidence is reserved until an authenticated source registry exists"
            )

        owners = _unique_by_id(catalog["owners"], "owner_id", "owner")
        services = _unique_by_id(catalog["services"], "service_id", "service")
        known = set(catalog["scope"]["known_asset_ids"])
        in_scope = set(catalog["scope"]["in_scope_asset_ids"])
        out_scope = set(catalog["scope"]["out_of_scope_asset_ids"])
        if not in_scope <= known or not out_scope <= known:
            raise ValidationError("in-scope and out-of-scope assets must be present in known assets")
        if in_scope & out_scope:
            raise ValidationError("an asset cannot be both in scope and out of scope")

        all_use_ids: set[str] = set()
        asset_owners: dict[str, str] = {}
        for service in catalog["services"]:
            if service["owner_id"] not in owners:
                raise ValidationError(
                    f"service {service['service_id']!r} references unknown owner {service['owner_id']!r}"
                )
            if service["asset_id"] not in in_scope:
                raise ValidationError(
                    f"service {service['service_id']!r} asset must be explicitly in scope"
                )
            existing_owner = asset_owners.get(service["asset_id"])
            if existing_owner is not None and existing_owner != service["owner_id"]:
                raise ValidationError(
                    f"conflicting ownership for asset {service['asset_id']!r}: "
                    f"{existing_owner!r} and {service['owner_id']!r}"
                )
            asset_owners[service["asset_id"]] = service["owner_id"]
            dependency_ids = [item["service_id"] for item in service["dependencies"]]
            if len(dependency_ids) != len(set(dependency_ids)):
                raise ValidationError(f"service {service['service_id']!r} repeats a dependency")
            if service["service_id"] in dependency_ids:
                raise ValidationError(f"service {service['service_id']!r} cannot depend on itself")
            unknown = sorted(set(dependency_ids) - set(services))
            if unknown:
                raise ValidationError(
                    f"service {service['service_id']!r} has unknown dependencies: {unknown}"
                )
            for use in service["cryptographic_uses"]:
                if use["use_id"] in all_use_ids:
                    raise ValidationError(f"duplicate cryptographic use id: {use['use_id']!r}")
                all_use_ids.add(use["use_id"])
                if EVIDENCE_RANK[use["evidence_level"]] > EVIDENCE_RANK[catalog["evidence_level"]]:
                    raise ValidationError(
                        f"cryptographic use {use['use_id']!r} claims stronger evidence than its catalogue"
                    )

        _topological_order(services)

    def _blockers(self, service: dict[str, Any], use: dict[str, Any]) -> set[str]:
        blockers: set[str] = set()
        if (
            service["business_criticality"] == "unknown"
            or service["data_classification"] == "unknown"
            or service["protection_lifetime_months"] is None
        ):
            blockers.add("missing-context")
        if (
            use["evidence_status"] == "missing"
            or use["inventory_record_id"] is None
            or use["exposure_status"] == "unknown"
        ):
            blockers.add("missing-evidence")
        elif use["evidence_status"] == "stale":
            blockers.add("stale-evidence")

        target = use["target_state"]
        if target["readiness"] in {"planned", "unknown"}:
            blockers.add("target-not-ready")
        elif target["readiness"] == "unsupported":
            blockers.add("unsupported-target")

        allowed = (
            KEY_ESTABLISHMENT_TARGETS
            if use["function"] == "key-establishment"
            else SIGNATURE_TARGETS
        )
        if target["algorithm_family"] not in allowed:
            blockers.add("unsupported-target")
        return blockers

    def _work_item(
        self,
        catalog: dict[str, Any],
        service: dict[str, Any],
        use: dict[str, Any],
        priority: str,
        blockers: list[str],
        dependencies: list[str],
    ) -> dict[str, Any]:
        work_id = str(uuid5(
            NAMESPACE_URL,
            f"crypto-control-plane:migration:{catalog['catalog_id']}:{catalog['catalog_version']}:{service['service_id']}:{use['use_id']}:{self.method_version}",
        ))
        evidence_refs = []
        if use["inventory_record_id"] is not None:
            evidence_refs.append(f"inventory:{use['inventory_record_id']}")
        return {
            "schema_version": "1.0",
            "work_item_id": work_id,
            "object_version": 1,
            "catalog_id": catalog["catalog_id"],
            "catalog_version": catalog["catalog_version"],
            "service_id": service["service_id"],
            "asset_id": service["asset_id"],
            "use_id": use["use_id"],
            "owner_id": service["owner_id"],
            "requested_by": service["requested_by"],
            "environment": service["environment"],
            "current_state": {
                "function": use["function"],
                "protocol": use["protocol"],
                "algorithm_family": use["current_algorithm_family"],
                "exposure_status": use["exposure_status"],
                "evidence_status": use["evidence_status"],
                "evidence_level": use["evidence_level"],
            },
            "target_state": copy.deepcopy(use["target_state"]),
            "priority": priority,
            "wave": _wave(priority),
            "status": "blocked" if blockers else "approval-required",
            "blockers": blockers,
            "dependencies": dependencies,
            "verification_criteria": _verification_criteria(use),
            "approval_actor_id": None,
            "evidence_refs": evidence_refs,
            "decision_authority": "deterministic-advisory-human-approval-required",
        }

    def _coverage_report(
        self, catalog: dict[str, Any], work_items: list[dict[str, Any]]
    ) -> dict[str, Any]:
        in_scope = set(catalog["scope"]["in_scope_asset_ids"])
        observed = {
            service["asset_id"]
            for service in catalog["services"]
            if any(
                use["inventory_record_id"] is not None
                and use["evidence_status"] in {"current", "stale"}
                for use in service["cryptographic_uses"]
            )
        }
        counts = {
            status: sum(item["status"] == status for item in work_items)
            for status in (
                "blocked", "approval-required", "approved",
                "rejected", "verification-required", "verified", "excepted", "regressed",
            )
        }
        total = len(work_items)
        report_id = str(uuid5(
            NAMESPACE_URL,
            f"crypto-control-plane:coverage:{catalog['catalog_id']}:{catalog['catalog_version']}:{catalog['as_of']}",
        ))
        return {
            "schema_version": "1.0",
            "report_id": report_id,
            "catalog_id": catalog["catalog_id"],
            "catalog_version": catalog["catalog_version"],
            "as_of": catalog["as_of"],
            "evidence_level": catalog["evidence_level"],
            "discovery_coverage": {
                "known_assets": len(catalog["scope"]["known_asset_ids"]),
                "in_scope_assets": len(in_scope),
                "observed_assets": len(observed & in_scope),
                "unknown_assets": len(in_scope - observed),
                "out_of_scope_assets": len(catalog["scope"]["out_of_scope_asset_ids"]),
                "coverage_percent": _percentage(len(observed & in_scope), len(in_scope)),
            },
            "migration_progress": {
                "total_uses": total,
                "blocked": counts["blocked"],
                "approval_required": counts["approval-required"],
                "approved": counts["approved"],
                "rejected": counts["rejected"],
                "verification_required": counts["verification-required"],
                "verified": counts["verified"],
                "excepted": counts["excepted"],
                "regressed": counts["regressed"],
                "verified_percent": _percentage(counts["verified"], total),
            },
            "limitations": [
                "The catalogue is simulated and does not establish production discovery coverage.",
                "Coverage and migration completion are separate measures and must not be combined.",
                "A supported target records planning readiness, not interoperability or deployment proof.",
            ],
        }


class MigrationWorkflow:
    """Apply human decisions and verification records with safety gates."""

    def __init__(self, schemas: SchemaRegistry):
        self.schemas = schemas

    def apply_decision(
        self, work_item: dict[str, Any], decision: dict[str, Any]
    ) -> dict[str, Any]:
        self.schemas.validate("migration-work-item", work_item)
        self.schemas.validate("migration-decision", decision)
        _match_versioned_record(work_item, decision)
        actor = decision["actor"]
        if decision["decision_type"] == "approve":
            if actor["actor_id"] == work_item["requested_by"]:
                raise ValidationError("requester cannot approve their own migration work")
        if decision["decision_type"] == "approve":
            if work_item["status"] != "approval-required":
                raise ValidationError("only approval-required work can be approved")
            if actor["role"] not in {"cryptography-authority", "change-authority"}:
                raise ValidationError("approval requires cryptography or change authority")
            status = "approved"
        elif decision["decision_type"] == "reject":
            if work_item["status"] != "approval-required":
                raise ValidationError("only approval-required work can be rejected")
            status = "rejected"
        elif decision["decision_type"] == "defer":
            if work_item["status"] != "approval-required":
                raise ValidationError("only approval-required work can be deferred")
            if decision["expires_at"] is None:
                raise ValidationError("a deferral must have an expiry")
            if _timestamp(decision["expires_at"]) <= _timestamp(decision["decided_at"]):
                raise ValidationError("a deferral expiry must be after the decision")
            status = "blocked"
        if decision["decision_type"] in {"approve", "reject"} and decision["expires_at"] is not None:
            raise ValidationError("approval and rejection decisions must not carry an expiry")
        updated = copy.deepcopy(work_item)
        updated["object_version"] += 1
        updated["status"] = status
        updated["approval_actor_id"] = actor["actor_id"]
        updated["evidence_refs"] = sorted(set(updated["evidence_refs"] + decision["evidence_refs"]))
        self.schemas.validate("migration-work-item", updated)
        return updated

    def apply_exception(
        self,
        work_item: dict[str, Any],
        exception: dict[str, Any],
        *,
        as_of: str,
    ) -> dict[str, Any]:
        self.schemas.validate("migration-work-item", work_item)
        self.schemas.validate("migration-exception", exception)
        _match_versioned_record(work_item, exception)
        if exception["approved_by"] == work_item["requested_by"]:
            raise ValidationError("requester cannot approve their own exception")
        approved = _timestamp(exception["approved_at"])
        expiry = _timestamp(exception["expires_at"])
        effective = _timestamp(as_of)
        if expiry <= approved:
            raise ValidationError("exception expiry must be after approval")
        if effective < approved:
            raise ValidationError("exception cannot be applied before its approval time")
        if exception["status"] != "active" or expiry <= effective:
            raise ValidationError("expired, revoked, or inactive exception cannot be applied")
        if work_item["status"] != "blocked":
            raise ValidationError("an exception may only be applied to blocked work")
        updated = copy.deepcopy(work_item)
        updated["object_version"] += 1
        updated["status"] = "excepted"
        updated["approval_actor_id"] = exception["approved_by"]
        updated["evidence_refs"] = sorted(
            set(updated["evidence_refs"] + [f"exception:{exception['exception_id']}"])
        )
        self.schemas.validate("migration-work-item", updated)
        return updated

    def advance_to_verification(
        self, work_item: dict[str, Any], *, implementation_evidence_ref: str
    ) -> dict[str, Any]:
        self.schemas.validate("migration-work-item", work_item)
        if work_item["status"] != "approved":
            raise ValidationError("only approved work can advance to verification")
        if not implementation_evidence_ref.strip():
            raise ValidationError("implementation evidence reference is required")
        updated = copy.deepcopy(work_item)
        updated["object_version"] += 1
        updated["status"] = "verification-required"
        updated["evidence_refs"] = sorted(
            set(updated["evidence_refs"] + [implementation_evidence_ref])
        )
        self.schemas.validate("migration-work-item", updated)
        return updated

    def apply_verification(
        self, work_item: dict[str, Any], verification: dict[str, Any]
    ) -> dict[str, Any]:
        self.schemas.validate("migration-work-item", work_item)
        self.schemas.validate("migration-verification", verification)
        _match_versioned_record(work_item, verification)
        if work_item["status"] != "verification-required":
            raise ValidationError("work must be verification-required before verification")
        verifier_id = verification["verifier"]["actor_id"]
        if verifier_id in {work_item["requested_by"], work_item["approval_actor_id"]}:
            raise ValidationError("verification must be independent of requester and approver")
        if verification["target_state"] != work_item["target_state"]:
            raise ValidationError("verification target does not match the approved target")
        required = set(work_item["verification_criteria"])
        supplied = {check["name"] for check in verification["checks"]}
        if not required <= supplied:
            raise ValidationError("verification does not cover every approved criterion")
        all_pass = all(check["result"] == "pass" for check in verification["checks"])
        conclusion = verification["conclusion"]
        if conclusion == "verified" and not all_pass:
            raise ValidationError("verified conclusion requires every check to pass")
        updated = copy.deepcopy(work_item)
        updated["object_version"] += 1
        if conclusion == "verified":
            updated["status"] = "verified"
        elif conclusion == "failed":
            updated["status"] = "regressed"
        else:
            updated["status"] = "verification-required"
        updated["evidence_refs"] = sorted(set(
            updated["evidence_refs"]
            + verification["pre_change_evidence_refs"]
            + verification["post_change_evidence_refs"]
            + [f"verification:{verification['verification_id']}"]
        ))
        self.schemas.validate("migration-work-item", updated)
        return updated


def _unique_by_id(items: list[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        identity = item[key]
        if identity in result:
            if result[identity] != item:
                raise ValidationError(f"conflicting {label} records for {identity!r}")
            raise ValidationError(f"duplicate {label} record for {identity!r}")
        result[identity] = item
    return result


def _topological_order(services: dict[str, dict[str, Any]]) -> list[str]:
    incoming = {
        service_id: {
            dependency["service_id"] for dependency in service["dependencies"]
        }
        for service_id, service in services.items()
    }
    ordered: list[str] = []
    ready = sorted(service_id for service_id, dependencies in incoming.items() if not dependencies)
    while ready:
        service_id = ready.pop(0)
        ordered.append(service_id)
        for candidate in sorted(incoming):
            if service_id in incoming[candidate]:
                incoming[candidate].remove(service_id)
                if not incoming[candidate] and candidate not in ordered and candidate not in ready:
                    ready.append(candidate)
                    ready.sort()
    if len(ordered) != len(services):
        cyclic = sorted(service_id for service_id in services if service_id not in ordered)
        raise ValidationError(f"dependency graph contains a cycle involving: {cyclic}")
    return ordered


def _priority(service: dict[str, Any], use: dict[str, Any]) -> str:
    if (
        use["evidence_status"] == "missing"
        or use["inventory_record_id"] is None
        or use["exposure_status"] == "unknown"
    ):
        return "needs-evidence"
    if (
        service["business_criticality"] == "unknown"
        or service["data_classification"] == "unknown"
        or service["protection_lifetime_months"] is None
    ):
        return "needs-context"
    lifetime = service["protection_lifetime_months"]
    if service["business_criticality"] == "critical" or (
        service["data_classification"] in {"confidential", "restricted"}
        and lifetime >= 60
    ):
        return "urgent"
    if service["business_criticality"] == "high" or lifetime >= 36:
        return "high"
    if service["business_criticality"] == "medium":
        return "medium"
    return "low"


def _wave(priority: str) -> str:
    return {
        "urgent": "wave-1",
        "high": "wave-2",
        "medium": "wave-3",
        "low": "wave-3",
        "needs-context": "unassigned",
        "needs-evidence": "unassigned",
    }[priority]


def _verification_criteria(use: dict[str, Any]) -> list[str]:
    common = [
        "Post-change discovery matches the approved target state",
        "Classical fallback and downgrade behavior are tested",
        "No unresolved critical regression is present",
    ]
    if use["function"] == "key-establishment":
        return common + ["Negotiated key establishment is directly evidenced"]
    return common + ["Signature, trust-chain, and relying-party interoperability pass"]


def _percentage(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else round(100.0 * numerator / denominator, 2)


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"invalid timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValidationError("timestamp must include timezone information")
    return parsed


def _match_versioned_record(work_item: dict[str, Any], record: dict[str, Any]) -> None:
    if record["work_item_id"] != work_item["work_item_id"]:
        raise ValidationError("record references a different work item")
    if record["work_item_version"] != work_item["object_version"]:
        raise ValidationError("record is stale for the current work-item version")
