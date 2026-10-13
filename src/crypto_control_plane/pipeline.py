from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from .models import CertificateEvent, MonitoringPolicy
from .normalization import matches_policy, normalize_dns_name
from .schema_validation import SchemaRegistry


@dataclass(frozen=True)
class Enrichment:
    all_dns_names: tuple[str, ...]
    unmatched_dns_names: tuple[str, ...]


class DeterministicExplainer:
    """Advisory wording only; it has no alert or severity authority."""

    authority = "advisory-only"

    def explain(self, event: CertificateEvent, enrichment: Enrichment, severity: str) -> str:
        names = ", ".join(enrichment.unmatched_dns_names)
        return (
            f"{severity.upper()} CERT-001: certificate event {event.event_id} from "
            f"{event.source_type}/{event.source_id} contains DNS name(s) outside the "
            f"configured namespace policy: {names}. This is an advisory explanation, "
            "not proof of malicious issuance; verify source evidence and authoritative "
            "domain ownership before taking action."
        )


class CertificateMonitoringPipeline:
    def __init__(
        self,
        policy: MonitoringPolicy,
        schemas: SchemaRegistry,
        explainer: DeterministicExplainer | None = None,
    ):
        self.policy = policy
        self.schemas = schemas
        self.explainer = explainer or DeterministicExplainer()

    def process(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        self.schemas.validate("certificate-event", payload)
        event = CertificateEvent.from_dict(payload)
        enrichment = self._enrich(event)
        if not enrichment.unmatched_dns_names:
            return None
        severity = "high" if event.environment == "production" else "medium"
        risk_score = min(100, (80 if severity == "high" else 55) + min(10, 2 * (len(enrichment.unmatched_dns_names) - 1)))
        alert_id = str(
            uuid5(
                NAMESPACE_URL,
                f"crypto-control-plane:{event.event_id}:CERT-001:{self.policy.policy_id}:{self.policy.policy_version}",
            )
        )
        alert = {
            "schema_version": "1.2",
            "alert_id": alert_id,
            "rule_id": "CERT-001",
            "event_id": event.event_id,
            "created_at": event.observed_at,
            "severity": severity,
            "risk_score": risk_score,
            "title": "Certificate contains a DNS name outside approved namespaces",
            "evidence": {
                "fingerprint_sha256": event.fingerprint_sha256,
                "source_type": event.source_type,
                "source_id": event.source_id,
                "issuer": event.issuer,
                "subject": event.subject,
                "all_dns_names": list(enrichment.all_dns_names),
                "unmatched_dns_names": list(enrichment.unmatched_dns_names),
                "environment": event.environment,
                "source_evidence": event.evidence,
                "event_provenance": event.provenance,
            },
            "policy": {
                "policy_id": self.policy.policy_id,
                "policy_version": self.policy.policy_version,
            },
            "explanation": self.explainer.explain(event, enrichment, severity),
            "explanation_authority": self.explainer.authority,
            "playbook": "docs/soc-playbooks/CERT-001-unknown-domain.md",
        }
        self.schemas.validate("detection-alert", alert)
        return alert

    def _enrich(self, event: CertificateEvent) -> Enrichment:
        normalized = tuple(normalize_dns_name(name) for name in event.san_dns_names)
        unmatched = tuple(
            name
            for name in normalized
            if not matches_policy(name, self.policy.allowed_dns_names, self.policy.allowed_dns_suffixes)
        )
        return Enrichment(all_dns_names=normalized, unmatched_dns_names=unmatched)
