from __future__ import annotations

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ed448, ed25519
from cryptography.x509.oid import NameOID

from crypto_control_plane.discovery_lab import (
    LoopbackTlsProbe,
    MAX_CERTIFICATE_BYTES,
    SyntheticCertificateFactory,
    X509CertificateDiscovery,
)
from crypto_control_plane.discovery_lab_cli import main as discovery_lab_main
from crypto_control_plane.errors import ValidationError
from crypto_control_plane.inventory import PqcInventoryService
from crypto_control_plane.models import CertificateEvent
from crypto_control_plane.schema_validation import SchemaRegistry

ROOT = Path(__file__).resolve().parents[1]
OBSERVED_AT = "2026-10-11T12:00:00Z"
BASIS = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)


class DiscoveryLabTests(unittest.TestCase):
    def setUp(self):
        self.schemas = SchemaRegistry(ROOT / "schemas")
        self.factory = SyntheticCertificateFactory()
        self.discovery = X509CertificateDiscovery(self.schemas)
        self.inventory = PqcInventoryService(self.schemas)

    def test_golden_generated_corpus(self):
        manifest = json.loads(
            (ROOT / "examples" / "lab" / "scenarios.json").read_text()
        )
        self.assertEqual(manifest["evidence_level"], "generated")
        for scenario in manifest["scenarios"]:
            with self.subTest(scenario=scenario["name"]):
                generated = self.factory.generate(
                    scenario=scenario["name"],
                    key_family=scenario["key_family"],
                    rsa_key_size=scenario.get("rsa_key_size", 2048),
                    ec_curve=scenario.get("ec_curve", "P-256"),
                    dns_names=tuple(scenario["dns_names"]),
                    validity=scenario["validity"],
                    is_ca=scenario["is_ca"],
                    now=BASIS,
                )
                event = self.discovery.parse_bytes_for_lab(
                    generated.certificate_pem,
                    source_id=scenario["name"],
                    observed_at=OBSERVED_AT,
                )
                parsed = CertificateEvent.from_dict(event)
                result = self.inventory.assess_certificate_event(parsed)
                self.assertEqual(
                    parsed.public_key["family"],
                    scenario["expected_public_key_family"],
                )
                if "expected_key_size_bits" in scenario:
                    self.assertEqual(
                        parsed.public_key["key_size_bits"],
                        scenario["expected_key_size_bits"],
                    )
                if "expected_curve" in scenario:
                    self.assertEqual(
                        parsed.public_key["curve"], scenario["expected_curve"]
                    )
                self.assertEqual(
                    result.assessment["exposure_status"],
                    scenario["expected_exposure"],
                )
                self.assertEqual(result.record["evidence_level"], "generated")
                self.assertEqual(result.record["coverage"]["scope"], "certificate-only")

    def test_rsa_and_ecdsa_parameters_are_derived_from_certificate(self):
        rsa_certificate = self.factory.generate(
            scenario="rsa", key_family="rsa", now=BASIS
        )
        rsa_event = self.discovery.parse_bytes_for_lab(
            rsa_certificate.certificate_pem,
            source_id="rsa",
            observed_at=OBSERVED_AT,
        )
        self.assertEqual(rsa_event["cryptography"]["public_key"]["key_size_bits"], 2048)
        self.assertEqual(rsa_event["cryptography"]["certificate_signature"]["family"], "rsa")

        ec_certificate = self.factory.generate(
            scenario="ec", key_family="elliptic-curve", now=BASIS
        )
        ec_event = self.discovery.parse_bytes_for_lab(
            ec_certificate.certificate_pem,
            source_id="ec",
            observed_at=OBSERVED_AT,
        )
        self.assertEqual(ec_event["cryptography"]["public_key"]["curve"], "secp256r1")
        self.assertEqual(
            ec_event["cryptography"]["certificate_signature"]["family"],
            "elliptic-curve",
        )

    def test_eddsa_and_dsa_certificates_are_classified_as_classical(self):
        cases = (
            ("ed25519", ed25519.Ed25519PrivateKey.generate(), None, "elliptic-curve"),
            ("ed448", ed448.Ed448PrivateKey.generate(), None, "elliptic-curve"),
            ("dsa", dsa.generate_private_key(key_size=2048), hashes.SHA256(), "dsa"),
        )
        for name, private_key, signing_hash, expected_family in cases:
            with self.subTest(algorithm=name):
                subject = issuer = x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, f"{name}.invalid")]
                )
                certificate = (
                    x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(issuer)
                    .public_key(private_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(BASIS - timedelta(minutes=5))
                    .not_valid_after(BASIS + timedelta(days=30))
                    .add_extension(
                        x509.KeyUsage(
                            digital_signature=True,
                            content_commitment=False,
                            key_encipherment=False,
                            data_encipherment=False,
                            key_agreement=False,
                            key_cert_sign=False,
                            crl_sign=False,
                            encipher_only=False,
                            decipher_only=False,
                        ),
                        critical=True,
                    )
                    .sign(private_key, signing_hash)
                )
                event = self.discovery.parse_bytes_for_lab(
                    certificate.public_bytes(serialization.Encoding.PEM),
                    source_id=name,
                    observed_at=OBSERVED_AT,
                )
                self.assertEqual(
                    event["cryptography"]["public_key"]["family"], expected_family
                )
                self.assertEqual(
                    event["cryptography"]["certificate_signature"]["family"],
                    expected_family,
                )
                assessment = self.inventory.assess_certificate_event(
                    CertificateEvent.from_dict(event)
                )
                self.assertEqual(
                    assessment.assessment["exposure_status"], "quantum-vulnerable"
                )

    def test_ca_without_san_is_valid_discovery_evidence(self):
        generated = self.factory.generate(
            scenario="ca", key_family="rsa", dns_names=(), is_ca=True, now=BASIS
        )
        event = self.discovery.parse_bytes_for_lab(
            generated.certificate_pem,
            source_id="ca",
            observed_at=OBSERVED_AT,
        )
        self.assertEqual(event["certificate"]["san_dns_names"], [])
        self.assertIn("key-cert-sign", event["cryptography"]["key_usage"])

    def test_malformed_certificate_fails_closed(self):
        with self.assertRaises(ValidationError):
            self.discovery.parse_bytes_for_lab(
                b"not a certificate",
                source_id="malformed",
                observed_at=OBSERVED_AT,
            )

    def test_file_parser_rejects_unsupported_evidence_claim(self):
        generated = self.factory.generate(
            scenario="claim", key_family="rsa", now=BASIS
        )
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "certificate.pem"
            certificate.write_bytes(generated.certificate_pem)
            with self.assertRaises(ValidationError):
                self.discovery.parse_file(
                    certificate,
                    evidence_level="authenticated-production",
                    observed_at=OBSERVED_AT,
                )

    def test_sanitised_capture_level_is_preserved(self):
        generated = self.factory.generate(
            scenario="sanitised", key_family="rsa", now=BASIS
        )
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "certificate.pem"
            certificate.write_bytes(generated.certificate_pem)
            event = self.discovery.parse_file(
                certificate,
                evidence_level="sanitised-capture",
                observed_at=OBSERVED_AT,
            )
        parsed = CertificateEvent.from_dict(event)
        assessed = self.inventory.assess_certificate_event(parsed)
        self.assertEqual(assessed.record["evidence_level"], "sanitised-capture")
        self.assertNotIn("uri", event["evidence"])

    def test_oversized_certificate_fails_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "oversized.pem"
            certificate.write_bytes(b" " * (MAX_CERTIFICATE_BYTES + 1))
            with self.assertRaises(ValidationError):
                self.discovery.parse_file(
                    certificate,
                    evidence_level="generated",
                    observed_at=OBSERVED_AT,
                )

    def test_fixture_cannot_be_upgraded_to_production_evidence(self):
        payload = json.loads(
            (ROOT / "examples" / "events" / "known-domain-issued.json").read_text()
        )
        payload["provenance"]["evidence_level"] = "authenticated-production"
        payload["provenance"]["verification_state"] = "verified"
        self.schemas.validate("certificate-event", payload)
        with self.assertRaises(ValidationError):
            CertificateEvent.from_dict(payload)

    def test_unknown_collector_cannot_claim_production_evidence(self):
        payload = json.loads(
            (ROOT / "examples" / "events" / "known-domain-issued.json").read_text()
        )
        payload["source"] = {"type": "tls", "id": "unknown-source"}
        payload["provenance"]["collector_id"] = "unregistered-collector"
        payload["provenance"]["evidence_level"] = "authenticated-production"
        payload["provenance"]["verification_state"] = "verified"
        self.schemas.validate("certificate-event", payload)
        with self.assertRaises(ValidationError):
            CertificateEvent.from_dict(payload)

    def test_loopback_probe_records_tls_without_inventing_key_establishment(self):
        generated = self.factory.generate(
            scenario="tls", key_family="rsa", dns_names=("localhost",), now=BASIS
        )
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            certificate_path = temporary / "certificate.pem"
            key_path = temporary / "private-key.pem"
            certificate_path.write_bytes(generated.certificate_pem)
            key_path.write_bytes(generated.private_key_pem)
            key_path.chmod(0o600)

            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(certificate_path, key_path)
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                server.bind(("127.0.0.1", 0))
            except PermissionError:
                server.close()
                self.skipTest("sandbox does not permit loopback socket binding")
            server.listen(1)
            port = server.getsockname()[1]
            errors: list[BaseException] = []

            def serve_once() -> None:
                try:
                    connection, _ = server.accept()
                    with connection:
                        with server_context.wrap_socket(
                            connection, server_side=True
                        ):
                            pass
                except BaseException as exc:  # surfaced in the test thread
                    errors.append(exc)
                finally:
                    server.close()

            thread = threading.Thread(target=serve_once, daemon=True)
            thread.start()
            event = LoopbackTlsProbe(self.schemas).probe(
                "127.0.0.1", port, observed_at=OBSERVED_AT
            )
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(event["transport"]["protocol"], "tls")
            self.assertEqual(event["transport"]["peer_verification"], "unverified")
            self.assertIsNone(event["transport"]["negotiated_key_establishment"])
            assessed = self.inventory.assess_certificate_event(
                CertificateEvent.from_dict(event)
            )
            self.assertEqual(
                assessed.record["transport_observation"]["tls_version"],
                event["transport"]["tls_version"],
            )

    def test_loopback_probe_refuses_external_target(self):
        with self.assertRaises(ValidationError):
            LoopbackTlsProbe(self.schemas).probe(
                "192.0.2.10", 443, observed_at=OBSERVED_AT
            )

    def test_x509_lab_cli_emits_valid_bundle(self):
        generated = self.factory.generate(
            scenario="cli", key_family="rsa", now=BASIS
        )
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "certificate.pem"
            output = Path(directory) / "output" / "bundle.json"
            certificate.write_bytes(generated.certificate_pem)
            with redirect_stdout(StringIO()):
                status = discovery_lab_main([
                    "--certificate", str(certificate),
                    "--evidence-level", "generated",
                    "--observed-at", OBSERVED_AT,
                    "--output", str(output),
                ])
            self.assertEqual(status, 0)
            bundle = json.loads(output.read_text())
            self.schemas.validate("certificate-event", bundle["event"])
            self.schemas.validate("cryptographic-inventory-record", bundle["record"])
            self.schemas.validate("pqc-assessment", bundle["assessment"])


if __name__ == "__main__":
    unittest.main()
