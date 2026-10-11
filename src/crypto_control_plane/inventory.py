from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from .models import CertificateEvent
from .schema_validation import SchemaRegistry


QUANTUM_VULNERABLE = {"rsa", "elliptic-curve", "finite-field-dh"}
PQC_FAMILIES = {"ml-kem", "ml-dsa", "slh-dsa"}


@dataclass(frozen=True)
class InventoryAssessment:
    record: dict[str, Any]
    assessment: dict[str, Any]


class PqcInventoryService:
    """Builds evidence records and deterministic, non-authoritative PQC assessments."""

    method_version = "pqc-exposure-v1"

    def __init__(self, schemas: SchemaRegistry):
        self.schemas = schemas

    def assess_certificate_event(self, event: CertificateEvent) -> InventoryAssessment:
        record = self._record(event)
        self.schemas.validate("cryptographic-inventory-record", record)
        assessment = self._assessment(record)
        self.schemas.validate("pqc-assessment", assessment)
        return InventoryAssessment(record=record, assessment=assessment)

    def _record(self, event: CertificateEvent) -> dict[str, Any]:
        function = _certificate_function(event.key_usage)
        record_id = str(uuid5(NAMESPACE_URL, f"crypto-control-plane:inventory:{event.event_id}:x509-public-key"))
        context = event.context
        return {
            "schema_version": "1.0",
            "record_id": record_id,
            "observation_id": event.event_id,
            "observed_at": event.observed_at,
            "asset": {
                "asset_id": context.get("asset_id"),
                "service_id": context.get("service_id"),
                "owner": context.get("owner"),
                "environment": event.environment,
                "business_criticality": context.get("business_criticality"),
                "data_classification": context.get("data_classification"),
                "protection_lifetime_months": context.get("protection_lifetime_months"),
            },
            "cryptographic_use": {
                "function": function,
                "protocol": "x509",
                "implementation": {
                    "product": None,
                    "provider": None,
                    "version": None,
                },
                "algorithm": event.public_key,
            },
            "certificate": {
                "fingerprint_sha256": event.fingerprint_sha256,
                "subject": event.subject,
                "issuer": event.issuer,
                "key_usage": list(event.key_usage),
                "extended_key_usage": list(event.extended_key_usage),
                "signature_algorithm": event.certificate_signature,
            },
            "dependencies": [],
            "supplier": None,
            "evidence_confidence": event.provenance["verification_state"],
            "source_evidence": event.evidence,
            "event_provenance": event.provenance,
            "coverage": {
                "scope": "certificate-only",
                "limitations": [
                    "Certificate evidence does not prove the negotiated key-establishment mechanism.",
                    "Trust-chain and relying-party support are not established by this observation.",
                    "No application, library, private-key, or non-certificate cryptography was inspected.",
                ],
            },
        }

    def _assessment(self, record: dict[str, Any]) -> dict[str, Any]:
        public_family = record["cryptographic_use"]["algorithm"]["family"]
        signature_family = record["certificate"]["signature_algorithm"]["family"]
        families = {public_family, signature_family}
        findings: list[dict[str, Any]] = []

        if public_family in QUANTUM_VULNERABLE:
            findings.append(_finding(
                "PQC-001", "action-required",
                "Quantum-vulnerable certificate public-key algorithm",
                f"The observed X.509 public key uses the {public_family} family.",
                ["cryptographic_use.algorithm.family"],
            ))
        if signature_family in QUANTUM_VULNERABLE:
            findings.append(_finding(
                "PQC-002", "action-required",
                "Quantum-vulnerable certificate signature algorithm",
                f"The observed certificate signature uses the {signature_family} family.",
                ["certificate.signature_algorithm.family"],
            ))

        if families & QUANTUM_VULNERABLE:
            exposure = "quantum-vulnerable"
        elif "unknown" in families or "other" in families:
            exposure = "unknown"
            findings.append(_finding(
                "PQC-003", "evidence-required",
                "Algorithm evidence is incomplete",
                "At least one relevant algorithm family is unknown or unclassified.",
                ["cryptographic_use.algorithm.family", "certificate.signature_algorithm.family"],
            ))
        elif "hybrid" in families:
            exposure = "hybrid-unverified"
            findings.append(_finding(
                "PQC-006", "verification-required",
                "Hybrid algorithm evidence requires protocol verification",
                "A hybrid label does not establish that a standards-based hybrid mechanism was negotiated or validated by every dependency.",
                ["cryptographic_use.algorithm", "certificate.signature_algorithm"],
            ))
        elif families <= PQC_FAMILIES:
            exposure = "candidate-quantum-resistant"
            findings.append(_finding(
                "PQC-005", "verification-required",
                "PQC algorithm evidence requires deployment verification",
                "Algorithm names alone do not establish trust-chain, protocol, implementation, or relying-party readiness.",
                ["cryptographic_use.algorithm", "certificate.signature_algorithm"],
            ))
        else:
            exposure = "unknown"

        missing = [
            field
            for field in (
                "asset.asset_id", "asset.service_id", "asset.owner",
                "asset.business_criticality", "asset.data_classification",
                "asset.protection_lifetime_months",
                "cryptographic_use.implementation.product",
                "cryptographic_use.implementation.version",
            )
            if _get(record, field) is None
        ]
        if missing:
            findings.append(_finding(
                "PQC-004", "context-required",
                "Migration prioritisation context is incomplete",
                "Required business or implementation context is missing; the listed fields must be resolved before a complete migration decision.",
                missing,
            ))

        priority = _priority(exposure, record, missing)
        assessment_id = str(uuid5(NAMESPACE_URL, f"crypto-control-plane:assessment:{record['record_id']}:{self.method_version}"))
        return {
            "schema_version": "1.0",
            "assessment_id": assessment_id,
            "record_id": record["record_id"],
            "assessed_at": record["observed_at"],
            "method_version": self.method_version,
            "exposure_status": exposure,
            "migration_priority": priority,
            "findings": findings,
            "missing_context": missing,
            "limitations": list(record["coverage"]["limitations"]),
            "decision_authority": "deterministic-advisory",
        }


def _certificate_function(key_usage: tuple[str, ...]) -> str:
    if "key-agreement" in key_usage or "key-encipherment" in key_usage:
        # A certificate extension expresses permitted use; it does not prove
        # which protocol mechanism was negotiated at runtime.
        return "authentication-and-key-establishment-capable"
    if {"digital-signature", "key-cert-sign"} & set(key_usage):
        return "digital-signature"
    return "unknown"


def _finding(rule_id: str, status: str, title: str, rationale: str, evidence_fields: list[str]) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "status": status,
        "title": title,
        "rationale": rationale,
        "evidence_fields": evidence_fields,
    }


def _get(payload: dict[str, Any], dotted_path: str) -> Any:
    value: Any = payload
    for part in dotted_path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _priority(exposure: str, record: dict[str, Any], missing: list[str]) -> str:
    if exposure == "unknown":
        return "needs-evidence"
    if exposure in {"candidate-quantum-resistant", "hybrid-unverified"}:
        return "verify"
    if any(field.startswith("asset.") for field in missing):
        return "needs-context"
    criticality = record["asset"]["business_criticality"]
    lifetime = record["asset"]["protection_lifetime_months"]
    if criticality in {"high", "critical"} or (lifetime is not None and lifetime >= 60):
        return "high"
    return "medium"
