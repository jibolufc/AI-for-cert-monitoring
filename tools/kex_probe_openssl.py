"""Cross-check Rust TLS observations against an independent OpenSSL server.

Run from the repository root with an OpenSSL 3.5+ CLI built with tracing.
All three cases use an ephemeral P-256 certificate and bind to loopback only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

from crypto_control_plane.schema_validation import SchemaRegistry


LOOPBACK = "127.0.0.1"
CASES = (
    ("X25519MLKEM768", "X25519MLKEM768", 4588),
    ("X25519", "x25519", 29),
    ("P-384", None, None),
)


def run_case(
    openssl: str, binary: Path, tmp: Path, groups: str,
    expected_group: str | None, expected_id: int | None,
) -> None:
    trace = tmp / f"{groups}.trace"
    log = tmp / f"{groups}.log"
    with log.open("wb") as log_file, subprocess.Popen(
        [
            openssl, "s_server", "-accept", f"{LOOPBACK}:0", "-tls1_3",
            "-groups", groups, "-cert", str(tmp / "cert.pem"),
            "-key", str(tmp / "key.pem"), "-trace", "-msgfile", str(trace),
            "-naccept", "1",
        ],
        stdin=subprocess.PIPE, stdout=log_file, stderr=subprocess.STDOUT,
    ) as server:
        try:
            deadline = time.monotonic() + 5
            while True:
                output = log.read_text(encoding="utf-8", errors="replace")
                ready = re.search(r"^ACCEPT 127\.0\.0\.1:(\d+)$", output, re.MULTILINE)
                if ready:
                    break
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"OpenSSL server failed to bind: {output}")
                time.sleep(0.02)

            probe = subprocess.run(
                [
                    str(binary), "probe", "--host", LOOPBACK,
                    "--port", ready[1], "--groups", "x25519mlkem768,x25519",
                ],
                capture_output=True, text=True, timeout=8,
            )
            if server.wait(timeout=5) != 0:
                raise RuntimeError(f"OpenSSL server failed: {log.read_text()}")
        finally:
            if server.poll() is None:
                server.kill()

    server_trace = trace.read_text(encoding="utf-8")
    server_hellos = re.findall(
        r"^    ServerHello, Length=\d+\n((?:[^\n]+\n)*)",
        server_trace, re.MULTILINE,
    )
    if expected_group is None:
        if (probe.returncode != 1 or probe.stdout or server_hellos
                or "handshake failure(40)" not in server_trace
                or "HandshakeFailure" not in probe.stderr):
            raise RuntimeError("No-common-group did not fail closed on both peers")
        print(f"{groups}: no common group; OpenSSL fatal alert 40; Rust exit 1, no observation")
        return

    if probe.returncode != 0:
        raise RuntimeError(f"Probe failed ({groups}): {probe.stderr}")
    observation = json.loads(probe.stdout)
    SchemaRegistry().validate("kex-probe-observation", observation)
    selected = [
        match
        for hello in server_hellos
        for match in re.findall(
            r"extension_type=key_share\(51\),[^\n]+\n\s+NamedGroup: ([^ ]+) \((\d+)\)",
            hello,
        )
    ]
    group = observation["key_establishment"]
    transport = observation["transport"]
    if (len(selected) != 1 or int(selected[0][1]) != expected_id
            or group["group_id"] != expected_id or group["group"] != expected_group
            or transport["negotiated_key_establishment"] != expected_group
            or transport["tls_version"] != "TLSv1.3"):
        raise RuntimeError(f"TLS selection mismatch: OpenSSL {selected}, Rust {group}")
    print(f"{groups}: OpenSSL ServerHello {selected[0][0]} ({selected[0][1]}); "
          f"Rust {group['group']} ({group['group_id']})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--expect-version", help="Require this exact OpenSSL release, e.g. 3.5.9")
    args = parser.parse_args()
    version = subprocess.check_output([args.openssl, "version"], text=True, timeout=5).strip()
    match = re.match(r"^OpenSSL (\d+)\.(\d+)\.(\d+)\s", version)
    if not match or tuple(map(int, match.groups())) < (3, 5, 0):
        parser.error(f"OpenSSL 3.5+ is required, found {version}")
    if args.expect_version and ".".join(match.groups()) != args.expect_version:
        parser.error(f"Expected OpenSSL {args.expect_version}, found {version}")
    print(version)
    with tempfile.TemporaryDirectory(prefix="ccp-openssl-") as directory:
        tmp = Path(directory)
        subprocess.run(
            [
                args.openssl, "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc", "-subj",
                "/CN=localhost", "-days", "1", "-out", str(tmp / "cert.pem"),
                "-keyout", str(tmp / "key.pem"),
            ],
            check=True, capture_output=True, timeout=5,
        )
        for case in CASES:
            run_case(args.openssl, args.binary.resolve(), tmp, *case)


if __name__ == "__main__":
    main()
