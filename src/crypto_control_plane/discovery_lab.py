from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
from pathlib import Path
import socket
import ssl
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .errors import ValidationError
from .schema_validation import SchemaRegistry


MAX_CERTIFICATE_BYTES = 1_000_000


@dataclass(frozen=True)
class GeneratedCertificate:
    scenario: str
    certificate_pem: bytes
    private_key_pem: bytes


class SyntheticCertificateFactory:
    """Creates non-production X.509 artifacts for the controlled lab only."""

    def generate(
        self,
        *,
        scenario: str,
        key_family: str,
        rsa_key_size: int = 2048,
        ec_curve: str = "P-256",
        dns_names: tuple[str, ...] = ("localhost",),
        validity: str = "valid",
        is_ca: bool = False,
        now: datetime | None = None,
    ) -> GeneratedCertificate:
        basis = now or datetime.now(timezone.utc)
        if basis.tzinfo is None:
            raise ValueError("now must include a timezone")
        if key_family == "rsa":
            if rsa_key_size not in {2048, 3072, 4096}:
                raise ValueError("rsa_key_size must be 2048, 3072, or 4096")
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=rsa_key_size
            )
        elif key_family == "elliptic-curve":
            curves = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1}
            try:
                curve_type = curves[ec_curve]
            except KeyError as exc:
                raise ValueError("ec_curve must be 'P-256' or 'P-384'") from exc
            private_key = ec.generate_private_key(curve_type())
        else:
            raise ValueError("key_family must be 'rsa' or 'elliptic-curve'")

        if validity == "valid":
            not_before, not_after = basis - timedelta(minutes=5), basis + timedelta(days=30)
        elif validity == "expired":
            not_before, not_after = basis - timedelta(days=60), basis - timedelta(days=30)
        elif validity == "not-yet-valid":
            not_before, not_after = basis + timedelta(days=1), basis + timedelta(days=31)
        else:
            raise ValueError("validity must be valid, expired, or not-yet-valid")

        common_name = dns_names[0] if dns_names else f"{scenario}.invalid"
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        )
        if dns_names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
                critical=False,
            )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=key_family == "rsa" and not is_ca,
                data_encipherment=False,
                key_agreement=key_family == "elliptic-curve" and not is_ca,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        if not is_ca:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
        certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
        return GeneratedCertificate(
            scenario=scenario,
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
            private_key_pem=private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ),
        )


class X509CertificateDiscovery:
    collector_id = "x509-file-parser"
    collector_version = "0.4.0"

    def __init__(self, schemas: SchemaRegistry):
        self.schemas = schemas

    def parse_file(
        self,
        path: Path,
        *,
        evidence_level: str,
        observed_at: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if evidence_level not in {"generated", "sanitised-capture"}:
            raise ValidationError(
                "the local X.509 file parser only accepts generated or sanitised-capture evidence"
            )
        try:
            size = path.stat().st_size
            if size > MAX_CERTIFICATE_BYTES:
                raise ValidationError(
                    f"certificate exceeds {MAX_CERTIFICATE_BYTES} bytes: {path}"
                )
            raw = path.read_bytes()
        except OSError as exc:
            raise ValidationError(f"cannot read certificate {path}: {exc}") from exc
        return self._parse(
            raw,
            source_type="file",
            source_id=path.name,
            collector_id=self.collector_id,
            evidence_level=evidence_level,
            observed_at=observed_at,
            # Do not leak an absolute workstation path into portable evidence.
            evidence_uri=None,
            context=context,
            transport=None,
        )

    def parse_bytes_for_lab(
        self,
        raw: bytes,
        *,
        source_id: str,
        observed_at: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._parse(
            raw,
            source_type="file",
            source_id=source_id,
            collector_id=self.collector_id,
            evidence_level="generated",
            observed_at=observed_at,
            evidence_uri=None,
            context=context,
            transport=None,
        )

    def _parse(
        self,
        raw: bytes,
        *,
        source_type: str,
        source_id: str,
        collector_id: str,
        evidence_level: str,
        observed_at: str,
        evidence_uri: str | None,
        context: dict[str, Any] | None,
        transport: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if not raw or len(raw) > MAX_CERTIFICATE_BYTES:
            raise ValidationError("certificate input is empty or exceeds the size limit")
        if context is not None and not isinstance(context, dict):
            raise ValidationError("discovery context must be a JSON object")
        try:
            certificate = (
                x509.load_pem_x509_certificate(raw)
                if raw.lstrip().startswith(b"-----BEGIN CERTIFICATE-----")
                else x509.load_der_x509_certificate(raw)
            )
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise ValidationError(f"cannot parse X.509 certificate: {exc}") from exc

        try:
            der = certificate.public_bytes(serialization.Encoding.DER)
            fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
            public_key = _public_key(certificate.public_key())
            signature = _signature_algorithm(certificate)
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise ValidationError(f"unsupported X.509 certificate algorithm: {exc}") from exc
        key_usage = _key_usage(certificate)
        extended_key_usage = _extended_key_usage(certificate)
        san_dns_names = _san_dns_names(certificate)
        payload_sha256 = hashlib.sha256(der).hexdigest()
        source_record_id = f"{source_id}:{fingerprint}"
        event_id = str(
            uuid5(
                NAMESPACE_URL,
                f"crypto-control-plane:x509:{collector_id}:{source_record_id}",
            )
        )
        evidence: dict[str, Any] = {
            "observed_by": collector_id,
            "collected_at": observed_at,
        }
        if evidence_uri is not None:
            evidence["uri"] = evidence_uri
        event: dict[str, Any] = {
            "schema_version": "1.3",
            "event_id": event_id,
            "event_type": "certificate.observed",
            "observed_at": observed_at,
            "source": {"type": source_type, "id": source_id},
            "certificate": {
                "fingerprint_sha256": fingerprint,
                "serial_number": format(certificate.serial_number, "X"),
                "subject": certificate.subject.rfc4514_string(),
                "issuer": certificate.issuer.rfc4514_string(),
                "san_dns_names": san_dns_names,
                "not_before": _timestamp(certificate.not_valid_before_utc),
                "not_after": _timestamp(certificate.not_valid_after_utc),
            },
            "cryptography": {
                "public_key": public_key,
                "certificate_signature": signature,
                "key_usage": key_usage,
                "extended_key_usage": extended_key_usage,
            },
            "context": {"environment": "unknown", **(context or {})},
            "evidence": evidence,
            "provenance": {
                "collector_id": collector_id,
                "collector_version": self.collector_version,
                "source_record_id": source_record_id,
                "payload_sha256": payload_sha256,
                "verification_state": "unverified",
                "evidence_level": evidence_level,
                "cursor": fingerprint,
            },
        }
        if transport is not None:
            event["transport"] = transport
        self.schemas.validate("certificate-event", event)
        return event


class LoopbackTlsProbe:
    """Bounded TLS discovery for the local lab; non-loopback targets are rejected."""

    collector_id = "tls-loopback-lab"

    def __init__(self, schemas: SchemaRegistry, *, timeout_seconds: float = 2.0):
        if not 0 < timeout_seconds <= 10:
            raise ValueError("timeout_seconds must be greater than zero and at most 10")
        self.schemas = schemas
        self.timeout_seconds = timeout_seconds
        self.parser = X509CertificateDiscovery(schemas)

    def probe(
        self,
        host: str,
        port: int,
        *,
        observed_at: str,
        server_hostname: str = "localhost",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValidationError("loopback TLS probe requires an IP address literal") from exc
        if not address.is_loopback:
            raise ValidationError("loopback TLS probe refuses non-loopback targets")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValidationError("TLS port must be an integer from 1 to 65535")
        if not isinstance(server_hostname, str) or not 1 <= len(server_hostname) <= 253:
            raise ValidationError("server_hostname must contain 1 to 253 characters")

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection(
                (host, port), timeout=self.timeout_seconds
            ) as connection:
                with ssl_context.wrap_socket(
                    connection, server_hostname=server_hostname
                ) as tls_connection:
                    certificate_der = tls_connection.getpeercert(binary_form=True)
                    cipher = tls_connection.cipher()
                    tls_version = tls_connection.version()
        except (OSError, ssl.SSLError) as exc:
            raise ValidationError(f"loopback TLS probe failed: {exc}") from exc
        if certificate_der is None or cipher is None or tls_version is None:
            raise ValidationError("loopback TLS probe returned incomplete handshake evidence")

        transport = {
            "protocol": "tls",
            "tls_version": tls_version,
            "cipher_suite": cipher[0],
            "peer_host": host,
            "peer_port": port,
            "peer_verification": "unverified",
            "negotiated_key_establishment": None,
        }
        return self.parser._parse(
            certificate_der,
            source_type="tls",
            source_id=f"{host}:{port}",
            collector_id=self.collector_id,
            evidence_level="generated",
            observed_at=observed_at,
            evidence_uri=f"tls://{host}:{port}",
            context=context,
            transport=transport,
        )


def _public_key(public_key: Any) -> dict[str, Any]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return {
            "family": "rsa",
            "name": "RSA",
            "oid": "1.2.840.113549.1.1.1",
            "key_size_bits": public_key.key_size,
        }
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return {
            "family": "elliptic-curve",
            "name": "id-ecPublicKey",
            "oid": "1.2.840.10045.2.1",
            "curve": public_key.curve.name,
        }
    class_name = type(public_key).__name__.lower()
    family = "unknown"
    if "mlkem" in class_name:
        family = "ml-kem"
    elif "mldsa" in class_name:
        family = "ml-dsa"
    elif "slhdsa" in class_name:
        family = "slh-dsa"
    return {"family": family, "name": type(public_key).__name__, "oid": "unknown"}


def _signature_algorithm(certificate: x509.Certificate) -> dict[str, Any]:
    oid = certificate.signature_algorithm_oid.dotted_string
    if oid.startswith("1.2.840.113549.1.1."):
        family = "rsa"
    elif oid.startswith("1.2.840.10045.4."):
        family = "elliptic-curve"
    elif oid in {f"2.16.840.1.101.3.4.3.{number}" for number in range(17, 20)}:
        family = "ml-dsa"
    elif oid in {f"2.16.840.1.101.3.4.3.{number}" for number in range(20, 32)}:
        family = "slh-dsa"
    else:
        family = "unknown"
    names = {
        "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
        "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    }
    result = {
        "family": family,
        "name": names.get(oid, oid),
        "oid": oid,
    }
    try:
        signature_hash = certificate.signature_hash_algorithm
    except UnsupportedAlgorithm:
        signature_hash = None
    if signature_hash is not None:
        result["hash_algorithm"] = signature_hash.name.upper()
    return result


def _key_usage(certificate: x509.Certificate) -> list[str]:
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return []
    values = {
        "digital-signature": usage.digital_signature,
        "content-commitment": usage.content_commitment,
        "key-encipherment": usage.key_encipherment,
        "data-encipherment": usage.data_encipherment,
        "key-agreement": usage.key_agreement,
        "key-cert-sign": usage.key_cert_sign,
        "crl-sign": usage.crl_sign,
        "encipher-only": usage.encipher_only if usage.key_agreement else False,
        "decipher-only": usage.decipher_only if usage.key_agreement else False,
    }
    return [name for name, enabled in values.items() if enabled]


def _extended_key_usage(certificate: x509.Certificate) -> list[str]:
    try:
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return []
    names = {
        ExtendedKeyUsageOID.SERVER_AUTH: "server-authentication",
        ExtendedKeyUsageOID.CLIENT_AUTH: "client-authentication",
        ExtendedKeyUsageOID.CODE_SIGNING: "code-signing",
        ExtendedKeyUsageOID.EMAIL_PROTECTION: "email-protection",
        ExtendedKeyUsageOID.TIME_STAMPING: "time-stamping",
        ExtendedKeyUsageOID.OCSP_SIGNING: "ocsp-signing",
    }
    return [names.get(oid, oid.dotted_string) for oid in usage]


def _san_dns_names(certificate: x509.Certificate) -> list[str]:
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return list(san.get_values_for_type(x509.DNSName))


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
