from __future__ import annotations

from typing import Any

from .roadmap import MUTATING_OPERATIONS, _timestamp
from .schema_validation import SchemaRegistry


REQUIRED_STAGING_CONTROLS = (
    "workload_identity",
    "least_privilege_rbac",
    "private_networking",
    "encryption",
    "secret_management",
    "central_logging",
    "deployment_controls",
    "backup_restore",
)


class G3ReadinessGate:
    """Assess G3 evidence without granting collection or production authority."""

    def __init__(self, schemas: SchemaRegistry):
        self.schemas = schemas

    def assess(self, plan: dict[str, Any], *, as_of: str) -> dict[str, Any]:
        self.schemas.validate("g3-readiness-plan", plan)
        now = _timestamp(as_of)
        unmet: list[str] = []

        if plan["requested_by"] == plan["approved_by"]:
            unmet.append("independent approval is required; requester and approver must differ")
        if not (_timestamp(plan["valid_from"]) <= now < _timestamp(plan["expires_at"])):
            unmet.append("the plan is outside its approved validity window")

        missing_prohibitions = sorted(MUTATING_OPERATIONS - set(plan["prohibited_operations"]))
        if missing_prohibitions:
            unmet.append("prohibited operations are incomplete: " + ", ".join(missing_prohibitions))

        demonstrated = 0
        for control_name in REQUIRED_STAGING_CONTROLS:
            control = plan["controls"][control_name]
            if control["status"] == "demonstrated" and control["evidence_refs"]:
                demonstrated += 1
            else:
                unmet.append(f"control is not evidenced as demonstrated: {control_name}")

        if plan["environment"] == "synthetic-staging":
            self._assess_synthetic(plan, unmet)
        else:
            self._assess_real_pilot(plan, unmet)

        if unmet:
            status = "blocked"
        elif plan["environment"] == "synthetic-staging":
            status = "synthetic-staging-ready"
        else:
            status = "g3-decision-required"

        report = {
            "schema_version": "1.0",
            "plan_id": plan["plan_id"],
            "assessed_at": as_of,
            "status": status,
            "g3_gate_passed": False,
            "collection_execution_authority": "none",
            "control_summary": {
                "required": len(REQUIRED_STAGING_CONTROLS),
                "demonstrated": demonstrated,
                "remaining": len(REQUIRED_STAGING_CONTROLS) - demonstrated,
            },
            "unmet_requirements": sorted(set(unmet)),
            "limitations": [
                "This assessment validates declared evidence references; it does not independently verify the referenced artifacts.",
                "Synthetic staging evidence cannot establish enterprise discovery coverage or production readiness.",
                "A real-data pilot requires a recorded accountable G3 decision outside this tool.",
            ],
        }
        self.schemas.validate("g3-readiness-report", report)
        return report

    @staticmethod
    def _assess_synthetic(plan: dict[str, Any], unmet: list[str]) -> None:
        if plan["real_data_enabled"]:
            unmet.append("synthetic staging must keep real-data collection disabled")
        if plan["evidence_level"] != "simulated":
            unmet.append("synthetic staging must use simulated evidence")
        if plan["data_classification"] != "synthetic":
            unmet.append("synthetic staging must classify its data as synthetic")
        if plan["authenticated_source"]:
            unmet.append("synthetic staging cannot claim an authenticated production source")
        if plan["authorisation_reference"] is not None:
            unmet.append("synthetic staging must not imply a real-pilot authorisation")
        if plan["privacy_review"] != "not-required-synthetic":
            unmet.append("synthetic staging must use the explicit synthetic privacy-review disposition")
        if plan["security_review"] != "approved":
            unmet.append("synthetic staging security review is not approved")

    @staticmethod
    def _assess_real_pilot(plan: dict[str, Any], unmet: list[str]) -> None:
        if not plan["real_data_enabled"]:
            unmet.append("authorised-pilot plan does not request real-data collection")
        if plan["evidence_level"] != "authenticated-production":
            unmet.append("real pilot must use authenticated-production evidence")
        if not plan["authenticated_source"]:
            unmet.append("real pilot source authentication is not approved")
        if not plan["authorisation_reference"]:
            unmet.append("written pilot authorisation reference is missing")
        if plan["data_classification"] == "synthetic":
            unmet.append("real pilot data classification is not declared")
        if plan["privacy_review"] != "approved":
            unmet.append("privacy review is not approved")
        if plan["security_review"] != "approved":
            unmet.append("security review is not approved")
