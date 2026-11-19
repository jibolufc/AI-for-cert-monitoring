from __future__ import annotations

from typing import Any

from .roadmap import _timestamp
from .schema_validation import SchemaRegistry


REQUIRED_G4_CONTROLS = (
    "service_ownership",
    "service_level_objectives",
    "production_identity_access",
    "monitoring_alerting",
    "incident_response",
    "backup_failover_recovery",
    "secure_delivery_supply_chain",
    "independent_security_testing",
    "data_protection_retention",
    "operational_runbooks_support",
)


class G4ReadinessGate:
    """Assess production preparation without granting production authority."""

    def __init__(self, schemas: SchemaRegistry):
        self.schemas = schemas

    def assess(self, plan: dict[str, Any], *, as_of: str) -> dict[str, Any]:
        self.schemas.validate("g4-readiness-plan", plan)
        now = _timestamp(as_of)
        unmet: list[str] = []

        if plan["requested_by"] == plan["approved_by"]:
            unmet.append("independent approval is required; requester and approver must differ")
        if not (_timestamp(plan["valid_from"]) <= now < _timestamp(plan["expires_at"])):
            unmet.append("the production-preparation plan is outside its validity window")

        demonstrated = 0
        for control_name in REQUIRED_G4_CONTROLS:
            control = plan["controls"][control_name]
            if control["status"] == "demonstrated" and control["evidence_refs"]:
                demonstrated += 1
            else:
                unmet.append(f"control is not evidenced as demonstrated: {control_name}")

        if plan["real_data_enabled"]:
            unmet.append("production preparation must not enable real data")
        if plan["public_endpoint_enabled"]:
            unmet.append("production preparation must not enable a public endpoint")
        if plan["production_traffic_enabled"]:
            unmet.append("production preparation must not enable production traffic")
        if plan["execution_authority"] != "none":
            unmet.append("production preparation cannot grant execution authority")
        if plan["evidence_level"] != "simulated":
            unmet.append("production preparation must retain simulated evidence level")
        if plan["data_classification"] != "synthetic":
            unmet.append("production preparation must remain synthetic")

        status = "blocked" if unmet else "g4-preparation-ready"
        report = {
            "schema_version": "1.0",
            "plan_id": plan["plan_id"],
            "assessed_at": as_of,
            "status": status,
            "g4_gate_passed": False,
            "production_operating_authority": "none",
            "migration_execution_authority": "none",
            "control_summary": {
                "required": len(REQUIRED_G4_CONTROLS),
                "demonstrated": demonstrated,
                "remaining": len(REQUIRED_G4_CONTROLS) - demonstrated,
            },
            "unmet_requirements": sorted(set(unmet)),
            "limitations": [
                "This assessor validates declarations and evidence references; it does not independently verify artifacts.",
                "Preparation evidence cannot establish production availability, operational ownership, or security assurance.",
                "Only an accountable external governance decision may authorise production operation.",
                "Gate G5 migration execution remains separately prohibited even after a future G4 decision.",
            ],
        }
        self.schemas.validate("g4-readiness-report", report)
        return report
