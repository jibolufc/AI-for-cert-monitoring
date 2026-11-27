"""End-to-end check: real kex-probe binary -> Python adapter -> inventory record.

Usage: python tools/kex_probe_smoke.py <path-to-kex-probe-binary>

Starts the binary's loopback lab server twice (hybrid-capable and classical-only),
probes each through RustKexProbe, and fails unless the expected group is recorded.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from crypto_control_plane.discovery_lab import RustKexProbe
from crypto_control_plane.inventory import PqcInventoryService
from crypto_control_plane.models import CertificateEvent
from crypto_control_plane.schema_validation import SchemaRegistry

CASES = [
    ("x25519mlkem768,x25519", "X25519MLKEM768", "hybrid-observed"),
    ("x25519", "x25519", "classical-observed"),
]


def main(binary: Path) -> int:
    schemas = SchemaRegistry()
    for server_groups, expected, expected_status in CASES:
        server = subprocess.Popen(
            [str(binary), "serve", "--groups", server_groups, "--connections", "1"],
            stdout=subprocess.PIPE, text=True,
        )
        try:
            port = json.loads(server.stdout.readline())["port"]
            event = RustKexProbe(schemas, binary).probe(
                "127.0.0.1", port, observed_at="2026-10-16T12:00:00Z"
            )
            result = PqcInventoryService(schemas).assess_certificate_event(
                CertificateEvent.from_dict(event)
            )
            observed = result.record["transport_observation"]["negotiated_key_establishment"]
            assessment = result.assessment
            status = assessment["transport_key_exchange"]["status"]
            print(f"server offers {server_groups:<22} -> {observed}: {status}")
            if (observed != expected or status != expected_status
                    or assessment["exposure_status"] != "quantum-vulnerable"):
                print(f"FAIL: expected {expected}, {expected_status}, and classical X.509 exposure",
                      file=sys.stderr)
                return 1
            server.wait(timeout=5)
        finally:
            if server.poll() is None:
                server.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1])))
