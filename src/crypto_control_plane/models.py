from __future__ import annotations

from dataclasses import dataclass
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
    "fixture", "ct", "acme", "tls", "aws-acm", "azure-key-vault",
    "gcp-certificate-manager", "cert-manager", "vault", "adcs",
}
ENVIRONMENTS = {"production", "staging", "development", "unknown"}


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
    environment: str
    evidence: dict[str, Any]

    @classmethod
    def from_dict(cls, payload: Any) -> "CertificateEvent":
        root = require_mapping(payload, "event")
        require_exact_keys(
            root,
            {"schema_version", "event_id", "event_type", "observed_at", "source", "certificate", "context", "evidence"},
            set(),
            "event",
        )
        if root["schema_version"] != "1.0":
            raise ValidationError("event.schema_version must be '1.0'")
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

        context = require_mapping(root["context"], "event.context")
        require_exact_keys(context, {"environment"}, {"account", "region"}, "event.context")
        environment = require_string(context["environment"], "event.context.environment", maximum=32)
        if environment not in ENVIRONMENTS:
            raise ValidationError("event.context.environment is unsupported")
        for optional_key in ("account", "region"):
            if optional_key in context:
                require_string(context[optional_key], f"event.context.{optional_key}", maximum=256)

        evidence = require_mapping(root["evidence"], "event.evidence")
        require_exact_keys(evidence, {"observed_by", "collected_at"}, {"uri"}, "event.evidence")
        require_string(evidence["observed_by"], "event.evidence.observed_by", maximum=256)
        require_timestamp(evidence["collected_at"], "event.evidence.collected_at")
        if "uri" in evidence:
            require_string(evidence["uri"], "event.evidence.uri", maximum=2048)

        return cls(
            raw=dict(root),
            schema_version="1.0",
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
            san_dns_names=tuple(require_string_list(certificate["san_dns_names"], "event.certificate.san_dns_names", minimum=1)),
            not_before=not_before,
            not_after=not_after,
            environment=environment,
            evidence=dict(evidence),
        )


def _timestamp_value(text: str):
    from datetime import datetime

    return datetime.fromisoformat(text.replace("Z", "+00:00"))


@dataclass(frozen=True)
class MonitoringPolicy:
    schema_version: str
    allowed_dns_names: tuple[str, ...]
    allowed_dns_suffixes: tuple[str, ...]

    @classmethod
    def from_dict(cls, payload: Any) -> "MonitoringPolicy":
        root = require_mapping(payload, "policy")
        require_exact_keys(root, {"schema_version", "allowed_dns_names", "allowed_dns_suffixes"}, set(), "policy")
        if root["schema_version"] != "1.0":
            raise ValidationError("policy.schema_version must be '1.0'")
        names = require_string_list(root["allowed_dns_names"], "policy.allowed_dns_names")
        suffixes = require_string_list(root["allowed_dns_suffixes"], "policy.allowed_dns_suffixes")
        if not names and not suffixes:
            raise ValidationError("policy must allow at least one DNS name or suffix")
        from .normalization import normalize_dns_name

        return cls(
            schema_version="1.0",
            allowed_dns_names=tuple(normalize_dns_name(item, allow_wildcard=False) for item in names),
            allowed_dns_suffixes=tuple(normalize_dns_name(item, allow_wildcard=False) for item in suffixes),
        )
