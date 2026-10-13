from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .errors import ValidationError
from .validation import (
    require_exact_keys,
    require_mapping,
    require_string,
    require_string_list,
    require_timestamp,
    require_uuid,
)

EVENT_TYPES = {"certificate.issued", "certificate.observed"}
SOURCE_TYPES = {
    "fixture", "file", "ct", "acme", "tls", "aws-acm", "azure-key-vault",
    "gcp-certificate-manager", "cert-manager", "vault", "adcs",
}
ENVIRONMENTS = {"production", "staging", "development", "unknown"}
EVIDENCE_LEVELS = {
    "simulated", "generated", "public-observation", "sanitised-capture",
    "authenticated-production", "independently-verified",
}
ALGORITHM_FAMILIES = {
    "rsa", "elliptic-curve", "finite-field-dh", "dsa", "ml-kem", "ml-dsa",
    "slh-dsa", "hybrid", "other", "unknown",
}
SIGNATURE_FAMILIES = {
    "rsa", "elliptic-curve", "dsa", "ml-dsa", "slh-dsa", "hybrid", "other", "unknown",
}
KEY_USAGES = {
    "digital-signature", "content-commitment", "key-encipherment",
    "data-encipherment", "key-agreement", "key-cert-sign", "crl-sign",
    "encipher-only", "decipher-only", "unknown",
}


@dataclass(frozen=True)
class CertificateEvent:
    raw: dict[str, Any]
    schema_version: str
    event_id: str
    event_type: str
    observed_at: str
    source_type: str
    source_id: str
    fingerprint_sha256: str
    serial_number: str
    subject: str
    issuer: str
    san_dns_names: tuple[str, ...]
    not_before: str
    not_after: str
    public_key: dict[str, Any]
    certificate_signature: dict[str, Any]
    key_usage: tuple[str, ...]
    extended_key_usage: tuple[str, ...]
    environment: str
    context: dict[str, Any]
    evidence: dict[str, Any]
    provenance: dict[str, Any]
    transport: dict[str, Any] | None

    @classmethod
    def from_dict(cls, payload: Any) -> "CertificateEvent":
        root = require_mapping(payload, "event")
        require_exact_keys(
            root,
            {"schema_version", "event_id", "event_type", "observed_at", "source", "certificate", "cryptography", "context", "evidence", "provenance"},
            {"transport"},
            "event",
        )
        if root["schema_version"] != "1.3":
            raise ValidationError("event.schema_version must be '1.3'")
        event_type = require_string(root["event_type"], "event.event_type", maximum=64)
        if event_type not in EVENT_TYPES:
            raise ValidationError("event.event_type is unsupported")

        source = require_mapping(root["source"], "event.source")
        require_exact_keys(source, {"type", "id"}, set(), "event.source")
        source_type = require_string(source["type"], "event.source.type", maximum=64)
        if source_type not in SOURCE_TYPES:
            raise ValidationError("event.source.type is unsupported")

        certificate = require_mapping(root["certificate"], "event.certificate")
        require_exact_keys(
            certificate,
            {"fingerprint_sha256", "serial_number", "subject", "issuer", "san_dns_names", "not_before", "not_after"},
            set(),
            "event.certificate",
        )
        fingerprint = require_string(certificate["fingerprint_sha256"], "event.certificate.fingerprint_sha256", maximum=64)
        if len(fingerprint) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in fingerprint):
            raise ValidationError("event.certificate.fingerprint_sha256 must contain 64 hexadecimal characters")
        not_before = require_timestamp(certificate["not_before"], "event.certificate.not_before")
        not_after = require_timestamp(certificate["not_after"], "event.certificate.not_after")
        if _timestamp_value(not_after) <= _timestamp_value(not_before):
            raise ValidationError("event.certificate.not_after must be after not_before")

        cryptography = require_mapping(root["cryptography"], "event.cryptography")
        require_exact_keys(
            cryptography,
            {"public_key", "certificate_signature", "key_usage", "extended_key_usage"},
            set(),
            "event.cryptography",
        )
        public_key = _algorithm(cryptography["public_key"], "event.cryptography.public_key")
        certificate_signature = _algorithm(
            cryptography["certificate_signature"],
            "event.cryptography.certificate_signature",
            allow_parameters=False,
            allowed_families=SIGNATURE_FAMILIES,
        )
        key_usage = require_string_list(
            cryptography["key_usage"], "event.cryptography.key_usage"
        )
        if any(item not in KEY_USAGES for item in key_usage):
            raise ValidationError("event.cryptography.key_usage contains an unsupported value")
        extended_key_usage = require_string_list(
            cryptography["extended_key_usage"],
            "event.cryptography.extended_key_usage",
        )

        context = require_mapping(root["context"], "event.context")
        require_exact_keys(
            context,
            {"environment"},
            {
                "account", "region", "asset_id", "service_id", "owner",
                "business_criticality", "data_classification",
                "protection_lifetime_months",
            },
            "event.context",
        )
        environment = require_string(context["environment"], "event.context.environment", maximum=32)
        if environment not in ENVIRONMENTS:
            raise ValidationError("event.context.environment is unsupported")
        for optional_key in ("account", "region"):
            if optional_key in context:
                require_string(context[optional_key], f"event.context.{optional_key}", maximum=256)
        for optional_key in ("asset_id", "service_id", "owner"):
            if optional_key in context:
                require_string(context[optional_key], f"event.context.{optional_key}", maximum=256)
        if "business_criticality" in context and context["business_criticality"] not in {
            "low", "medium", "high", "critical", "unknown"
        }:
            raise ValidationError("event.context.business_criticality is unsupported")
        if "data_classification" in context and context["data_classification"] not in {
            "public", "internal", "confidential", "restricted", "unknown"
        }:
            raise ValidationError("event.context.data_classification is unsupported")
        if "protection_lifetime_months" in context:
            lifetime = context["protection_lifetime_months"]
            if (
                not isinstance(lifetime, int)
                or isinstance(lifetime, bool)
                or not 0 <= lifetime <= 1200
            ):
                raise ValidationError(
                    "event.context.protection_lifetime_months must be an integer from 0 to 1200"
                )

        evidence = require_mapping(root["evidence"], "event.evidence")
        require_exact_keys(evidence, {"observed_by", "collected_at"}, {"uri"}, "event.evidence")
        require_string(evidence["observed_by"], "event.evidence.observed_by", maximum=256)
        require_timestamp(evidence["collected_at"], "event.evidence.collected_at")
        if "uri" in evidence:
            require_string(evidence["uri"], "event.evidence.uri", maximum=2048)

        provenance = require_mapping(root["provenance"], "event.provenance")
        require_exact_keys(
            provenance,
            {"collector_id", "collector_version", "source_record_id", "payload_sha256", "verification_state", "evidence_level", "cursor"},
            set(),
            "event.provenance",
        )
        require_string(provenance["collector_id"], "event.provenance.collector_id", maximum=128)
        require_string(provenance["collector_version"], "event.provenance.collector_version", maximum=32)
        require_string(provenance["source_record_id"], "event.provenance.source_record_id", maximum=512)
        payload_sha256 = require_string(provenance["payload_sha256"], "event.provenance.payload_sha256", maximum=64)
        if len(payload_sha256) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in payload_sha256):
            raise ValidationError("event.provenance.payload_sha256 must contain 64 hexadecimal characters")
        if provenance["verification_state"] not in {"verified", "unverified", "failed"}:
            raise ValidationError("event.provenance.verification_state is unsupported")
        if provenance["evidence_level"] not in EVIDENCE_LEVELS:
            raise ValidationError("event.provenance.evidence_level is unsupported")
        require_string(provenance["cursor"], "event.provenance.cursor", maximum=256)
        _validate_evidence_claim(
            source_type=source_type,
            collector_id=provenance["collector_id"],
            evidence_level=provenance["evidence_level"],
        )

        transport = None
        if "transport" in root:
            transport = require_mapping(root["transport"], "event.transport")
            require_exact_keys(
                transport,
                {
                    "protocol", "tls_version", "cipher_suite", "peer_host",
                    "peer_port", "peer_verification", "negotiated_key_establishment",
                },
                set(),
                "event.transport",
            )
            if transport["protocol"] != "tls":
                raise ValidationError("event.transport.protocol must be 'tls'")
            for key in ("tls_version", "cipher_suite", "peer_host", "peer_verification"):
                require_string(transport[key], f"event.transport.{key}", maximum=256)
            peer_port = transport["peer_port"]
            if not isinstance(peer_port, int) or isinstance(peer_port, bool) or not 1 <= peer_port <= 65535:
                raise ValidationError("event.transport.peer_port must be an integer from 1 to 65535")
            negotiated = transport["negotiated_key_establishment"]
            if negotiated is not None:
                require_string(
                    negotiated,
                    "event.transport.negotiated_key_establishment",
                    maximum=256,
                )

        return cls(
            raw=dict(root),
            schema_version="1.3",
            event_id=require_uuid(root["event_id"], "event.event_id"),
            event_type=event_type,
            observed_at=require_timestamp(root["observed_at"], "event.observed_at"),
            source_type=source_type,
            source_id=require_string(source["id"], "event.source.id", maximum=256),
            fingerprint_sha256=fingerprint.lower(),
            serial_number=require_string(certificate["serial_number"], "event.certificate.serial_number", maximum=128),
            # RFC 5280 permits an empty subject when identity is carried in a
            # critical subjectAltName extension, so empty is valid telemetry.
            subject=require_string(certificate["subject"], "event.certificate.subject", minimum=0),
            issuer=require_string(certificate["issuer"], "event.certificate.issuer"),
            san_dns_names=tuple(require_string_list(certificate["san_dns_names"], "event.certificate.san_dns_names")),
            not_before=not_before,
            not_after=not_after,
            public_key=public_key,
            certificate_signature=certificate_signature,
            key_usage=tuple(key_usage),
            extended_key_usage=tuple(extended_key_usage),
            environment=environment,
            context=dict(context),
            evidence=dict(evidence),
            provenance=dict(provenance),
            transport=None if transport is None else dict(transport),
        )


def _validate_evidence_claim(
    *, source_type: str, collector_id: str, evidence_level: str
) -> None:
    collector_levels = {
        "fixture-generator": {"simulated"},
        "ct-decoded-fixture": {"simulated"},
        "x509-file-parser": {"generated", "sanitised-capture"},
        "tls-loopback-lab": {"generated"},
    }
    if source_type == "fixture" and evidence_level != "simulated":
        raise ValidationError("fixture sources may only claim simulated evidence")
    allowed = collector_levels.get(collector_id)
    if allowed is not None and evidence_level not in allowed:
        raise ValidationError(
            f"collector {collector_id!r} may not claim {evidence_level!r} evidence"
        )
    if evidence_level in {"authenticated-production", "independently-verified"}:
        raise ValidationError(
            f"{evidence_level} evidence is reserved until an authenticated collector trust registry exists"
        )


def _algorithm(
    payload: Any,
    path: str,
    *,
    allow_parameters: bool = True,
    allowed_families: set[str] = ALGORITHM_FAMILIES,
) -> dict[str, Any]:
    algorithm = require_mapping(payload, path)
    optional = {"key_size_bits", "curve"} if allow_parameters else {"hash_algorithm"}
    require_exact_keys(
        algorithm,
        {"family", "name", "oid"},
        optional,
        path,
    )
    family = require_string(algorithm["family"], f"{path}.family", maximum=64)
    if family not in allowed_families:
        raise ValidationError(f"{path}.family is unsupported")
    require_string(algorithm["name"], f"{path}.name", maximum=128)
    oid = require_string(algorithm["oid"], f"{path}.oid", maximum=128)
    if oid != "unknown" and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", oid) is None:
        raise ValidationError(f"{path}.oid must be a dotted-decimal OID or 'unknown'")
    if "key_size_bits" in algorithm:
        size = algorithm["key_size_bits"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise ValidationError(f"{path}.key_size_bits must be a positive integer")
    for key in ("curve", "hash_algorithm"):
        if key in algorithm:
            require_string(algorithm[key], f"{path}.{key}", maximum=128)
    return dict(algorithm)


def _timestamp_value(text: str):
    from datetime import datetime

    return datetime.fromisoformat(text.replace("Z", "+00:00"))


@dataclass(frozen=True)
class MonitoringPolicy:
    schema_version: str
    policy_id: str
    policy_version: int
    allowed_dns_names: tuple[str, ...]
    allowed_dns_suffixes: tuple[str, ...]

    @classmethod
    def from_dict(cls, payload: Any) -> "MonitoringPolicy":
        root = require_mapping(payload, "policy")
        require_exact_keys(
            root,
            {"schema_version", "policy_id", "policy_version", "allowed_dns_names", "allowed_dns_suffixes"},
            set(),
            "policy",
        )
        if root["schema_version"] != "1.1":
            raise ValidationError("policy.schema_version must be '1.1'")
        policy_id = require_string(root["policy_id"], "policy.policy_id", maximum=128)
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]*", policy_id) is None:
            raise ValidationError("policy.policy_id has an invalid format")
        if not isinstance(root["policy_version"], int) or isinstance(root["policy_version"], bool) or root["policy_version"] < 1:
            raise ValidationError("policy.policy_version must be a positive integer")
        names = require_string_list(root["allowed_dns_names"], "policy.allowed_dns_names")
        suffixes = require_string_list(root["allowed_dns_suffixes"], "policy.allowed_dns_suffixes")
        if not names and not suffixes:
            raise ValidationError("policy must allow at least one DNS name or suffix")
        from .normalization import normalize_dns_name

        return cls(
            schema_version="1.1",
            policy_id=policy_id,
            policy_version=root["policy_version"],
            allowed_dns_names=tuple(normalize_dns_name(item, allow_wildcard=False) for item in names),
            allowed_dns_suffixes=tuple(normalize_dns_name(item, allow_wildcard=False) for item in suffixes),
        )
