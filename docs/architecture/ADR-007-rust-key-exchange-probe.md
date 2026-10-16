# ADR-007: Rust key-exchange probe for negotiated key establishment

- Status: Accepted (lab scope)
- Date: 16 October 2026

## Context

Harvest-now-decrypt-later exposure depends on the key-establishment mechanism a
TLS session actually negotiated, not on the certificate. The Milestone 4
loopback probe uses Python's `ssl` module, which exposes protocol version and
cipher suite but not the key-exchange group, so `negotiated_key_establishment`
has always been `null`.

## Decision

Add a separate Rust binary, `kex-probe`, built on rustls with the aws-lc-rs
provider. It completes one loopback handshake and emits a JSON envelope whose
`transport` object is the existing certificate-event contract. A Python adapter,
`RustKexProbe`, runs the binary as an untrusted collector: it re-checks the
target, bounds output size, validates `kex-probe-observation` schema, requires
the reported peer to equal the requested peer, and routes the leaf certificate
through the existing X.509 parser.

The rest of the control plane stays in Python. The JSON schemas are the
contract between the two languages.

## Consequences

- Positive: negotiated groups, including `X25519MLKEM768`, become evidence
  instead of `null`.
- Positive: loopback-only and fail-closed rules are enforced twice, in the
  binary and in the adapter.
- Negative: CI needs a Rust toolchain and aws-lc-rs needs a C compiler; the
  `kex-probe` CI job adds a few minutes.
- Negative: the PQC assessment does not yet use the group. The inventory record
  stores it in `transport_observation`, but exposure rules and the static
  "certificate evidence does not prove key establishment" limitation are
  unchanged. Classifying key establishment is a follow-up.
- Boundary unchanged: lab evidence only (`generated`); no non-loopback
  scanning.
