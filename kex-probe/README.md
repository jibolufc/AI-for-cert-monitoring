# kex-probe

Loopback-only TLS lab collector that records the **negotiated key-exchange
group** of one handshake. Python's `ssl` module cannot report the group, so the
Python `LoopbackTlsProbe` leaves `negotiated_key_establishment` as `null`. This
binary uses rustls with the aws-lc-rs provider, which reports the group and
supports the hybrid `X25519MLKEM768` group.

## Boundaries

- Targets must be IP literals on a loopback address. Hostnames and other
  addresses are rejected before any socket opens (exit code 2).
- The peer certificate is not checked against a trust store. The handshake
  signature is still verified against the presented certificate, so the peer
  must hold the private key. Output says `peer_verification: "unverified"`.
- A failed handshake exits 1 and prints nothing to stdout. The probe never
  reports a group it did not observe.
- Output is lab evidence. The Python adapter labels it `generated`.

## Use

```sh
cargo build --release
./target/release/kex-probe serve --groups x25519mlkem768,x25519   # prints {"listening":"127.0.0.1:PORT",...}
./target/release/kex-probe probe --host 127.0.0.1 --port PORT
```

Default client offer is `X25519MLKEM768,x25519`, matching a current
PQC-capable client. Use `--groups` to change it.

## Output

One JSON object, validated by `schemas/kex-probe-observation.schema.json`:

| Field | Meaning |
|---|---|
| `transport` | Exactly the `certificate-event` transport contract |
| `key_establishment.group` | IANA TLS Supported Groups name, for example `X25519MLKEM768` or `x25519` |
| `key_establishment.group_id` | IANA code point (`4588` for X25519MLKEM768) |
| `key_establishment.family` | `hybrid`, `elliptic-curve`, `finite-field-dh` or `unknown` |
| `key_establishment.offered_groups` | What the probe offered |
| `peer_certificate_der_base64` | Leaf certificate, parsed by the Python X.509 path |

From Python:

```python
from crypto_control_plane.discovery_lab import RustKexProbe
event = RustKexProbe(SchemaRegistry(), "kex-probe/target/release/kex-probe").probe(
    "127.0.0.1", port, observed_at="2026-10-16T12:00:00Z")
```

## Tests

- `cargo test`: 7 tests against the built-in lab server (hybrid, classical
  fallback, TLS 1.2 ECDHE, no common group, schema shape, target rejection).
- `tests/test_kex_probe.py`: 8 adapter tests with a scripted stand-in binary.
- `tools/kex_probe_smoke.py`: real binary through the adapter into an
  inventory record. CI runs all three.

Cross-checked manually against OpenSSL 3.0 `s_server` for x25519 and
secp384r1. The hybrid group has only been checked against rustls itself;
checking it against an independent OpenSSL 3.5 server is still to do.
