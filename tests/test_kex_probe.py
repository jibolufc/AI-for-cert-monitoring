"""Adapter tests for the Rust kex-probe collector.

These tests replace the binary with a scripted stand-in so they run without a
Rust toolchain and never skip. The real binary is exercised end to end by
`cargo test` in kex-probe/ and by tools/kex_probe_smoke.py in CI.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from crypto_control_plane.discovery_lab import RustKexProbe, SyntheticCertificateFactory
from crypto_control_plane.errors import ValidationError
from crypto_control_plane.inventory import PqcInventoryService
from crypto_control_plane.models import CertificateEvent
from crypto_control_plane.schema_validation import SchemaRegistry


OBSERVED_AT = "2026-10-16T12:00:00Z"
BASIS = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
PORT = 44321


class FakeProbe:
    """Writes a stand-in executable that records its argv and prints a response."""

    def __init__(self, directory: Path, stdout: str, exit_code: int = 0, stderr: str = ""):
        self.argv_file = directory / "argv.json"
        script = directory / "kex-probe"
        script.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\n"
            f"open({str(self.argv_file)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
            f"sys.stdout.write({stdout!r})\n"
            f"sys.stderr.write({stderr!r})\n"
            f"sys.exit({exit_code})\n",
            encoding="utf-8",
        )
        script.chmod(0o700)
        self.path = script

    @property
    def ran(self) -> bool:
        return self.argv_file.exists()

    def argv(self) -> list[str]:
        return json.loads(self.argv_file.read_text(encoding="utf-8"))


class RustKexProbeAdapterTest(unittest.TestCase):
    def setUp(self):
        self.schemas = SchemaRegistry()
        generated = SyntheticCertificateFactory().generate(
            scenario="kex", key_family="elliptic-curve", dns_names=("localhost",), now=BASIS
        )
        der = x509.load_pem_x509_certificate(generated.certificate_pem).public_bytes(
            serialization.Encoding.DER
        )
        self.certificate_b64 = base64.b64encode(der).decode()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tmp = Path(self.directory.name)

    def envelope(self, group: str = "X25519MLKEM768", family: str = "hybrid", **transport) -> dict:
        body = {
            "schema_version": "1.0",
            "collector_id": "kex-probe",
            "collector_version": "0.1.0",
            "transport": {
                "protocol": "tls",
                "tls_version": "TLSv1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "peer_host": "127.0.0.1",
                "peer_port": PORT,
                "peer_verification": "unverified",
                "negotiated_key_establishment": group,
            },
            "key_establishment": {
                "group": group,
                "group_id": 4588 if group == "X25519MLKEM768" else 29,
                "family": family,
                "offered_groups": ["X25519MLKEM768", "x25519"],
            },
            "peer_certificate_der_base64": self.certificate_b64,
        }
        body["transport"].update(transport)
        return body

    def run_probe(self, stdout: str, exit_code: int = 0, host: str = "127.0.0.1"):
        fake = FakeProbe(self.tmp, stdout, exit_code, stderr='{"error":"failed: handshake"}')
        probe = RustKexProbe(self.schemas, fake.path)
        return fake, probe.probe(host, PORT, observed_at=OBSERVED_AT)

    def test_hybrid_group_reaches_certificate_event_and_inventory_record(self):
        fake, event = self.run_probe(json.dumps(self.envelope()))
        self.assertEqual(event["transport"]["negotiated_key_establishment"], "X25519MLKEM768")
        self.assertEqual(event["provenance"]["collector_id"], "kex-probe-rust")
        self.assertEqual(event["provenance"]["evidence_level"], "generated")
        self.assertEqual(
            fake.argv(),
            ["probe", "--host", "127.0.0.1", "--port", str(PORT),
             "--server-name", "localhost", "--timeout-ms", "5000"],
        )
        assessed = PqcInventoryService(self.schemas).assess_certificate_event(
            CertificateEvent.from_dict(event)
        )
        self.assertEqual(
            assessed.record["transport_observation"]["negotiated_key_establishment"],
            "X25519MLKEM768",
        )
        self.assertEqual(assessed.assessment["schema_version"], "1.2")
        self.assertEqual(assessed.assessment["method_version"], "pqc-exposure-v2")
        self.assertEqual(assessed.assessment["exposure_status"], "quantum-vulnerable")
        self.assertIn("PQC-001", {f["rule_id"] for f in assessed.assessment["findings"]})
        self.assertIn("PQC-002", {f["rule_id"] for f in assessed.assessment["findings"]})
        self.assertEqual(assessed.assessment["evidence_level"], "generated")
        self.assertEqual(assessed.assessment["transport_key_exchange"], {
            "status": "hybrid-observed",
            "reason": "recognized-hybrid-group",
            "reported_group": "X25519MLKEM768",
            "tls_version": "TLSv1.3",
            "scope": "single-tls-observation",
        })

    def test_classical_group_is_recorded_as_observed(self):
        _, event = self.run_probe(json.dumps(self.envelope("x25519", "elliptic-curve")))
        self.assertEqual(event["transport"]["negotiated_key_establishment"], "x25519")
        result = PqcInventoryService(self.schemas).assess_certificate_event(
            CertificateEvent.from_dict(event)
        )
        self.assertEqual(result.assessment["transport_key_exchange"]["status"], "classical-observed")

    def test_uncertain_transport_never_becomes_hybrid(self):
        _, event = self.run_probe(json.dumps(self.envelope()))
        service = PqcInventoryService(self.schemas)
        for group, version, verification, reason in (
            (None, "TLSv1.3", "unverified", "not-observed"),
            ("unrecognised", "TLSv1.3", "unverified", "unsupported-group-for-version"),
            ("X25519MLKEM768", "TLSv1.2", "unverified", "unsupported-group-for-version"),
            ("X25519MLKEM768", "unknown", "unverified", "unsupported-tls-version"),
            ("X25519MLKEM768", "TLSv1.3", "failed", "failed-evidence"),
        ):
            with self.subTest(group=group, version=version, verification=verification):
                event["transport"]["negotiated_key_establishment"] = group
                event["transport"]["tls_version"] = version
                event["provenance"]["verification_state"] = verification
                assessment = service.assess_certificate_event(CertificateEvent.from_dict(event)).assessment
                observed = assessment["transport_key_exchange"]
                self.assertEqual((observed["status"], observed["reason"]), ("unknown", reason))
                self.assertEqual(observed["reported_group"], group)
                self.assertEqual(assessment["exposure_status"], "quantum-vulnerable")

    def test_non_loopback_target_is_rejected_before_the_binary_runs(self):
        fake = FakeProbe(self.tmp, json.dumps(self.envelope()))
        for host in ("192.0.2.10", "localhost"):
            with self.assertRaises(ValidationError):
                RustKexProbe(self.schemas, fake.path).probe(host, 443, observed_at=OBSERVED_AT)
        self.assertFalse(fake.ran)

    def test_failed_handshake_fails_closed(self):
        with self.assertRaisesRegex(ValidationError, "exit 1"):
            self.run_probe("", exit_code=1)

    def test_reported_peer_must_match_request(self):
        with self.assertRaisesRegex(ValidationError, "different peer"):
            self.run_probe(json.dumps(self.envelope(peer_port=PORT + 1)))

    def test_transport_and_key_establishment_must_agree(self):
        envelope = self.envelope()
        envelope["key_establishment"]["group"] = "x25519"
        with self.assertRaisesRegex(ValidationError, "disagree"):
            self.run_probe(json.dumps(envelope))

    def test_group_name_and_numeric_code_point_must_agree(self):
        envelope = self.envelope()
        envelope["key_establishment"]["group_id"] = 29
        with self.assertRaisesRegex(ValidationError, "IANA code point disagree"):
            self.run_probe(json.dumps(envelope))

    def test_unexpected_fields_and_groups_are_rejected_by_schema(self):
        extra = self.envelope()
        extra["transport"]["note"] = "trust me"
        verified = self.envelope(peer_verification="verified")
        unknown_group = self.envelope("mlkem1024")
        for envelope in (extra, verified, unknown_group):
            with self.assertRaises(ValidationError):
                self.run_probe(json.dumps(envelope))

    def test_malformed_output_is_rejected(self):
        for stdout in ("not json", "[]"):
            with self.assertRaises(ValidationError):
                self.run_probe(stdout)
        bad_certificate = self.envelope()
        bad_certificate["peer_certificate_der_base64"] = base64.b64encode(b"junk").decode()
        with self.assertRaisesRegex(ValidationError, "X.509"):
            self.run_probe(json.dumps(bad_certificate))


if __name__ == "__main__":
    unittest.main()
