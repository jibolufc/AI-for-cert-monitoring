# ADR-010: Scanner-neutral CycloneDX interoperability boundary

- **Status:** proposed (feature track item 1 of 8)
- **Date:** 2026-11-20

## Context

The control plane exports a project format, `cbom-style-reference-1.0`
(`roadmap.cbom_export`), and imports no external inventory. Buyers already hold
CycloneDX for SBOMs, and cryptographic scanners already emit CycloneDX CBOMs.
Two examples:

| Tool | Input it scans | CycloneDX it emits | Notes |
|---|---|---|---|
| CBOMkit (PQCA, formerly IBM): sonar-cryptography, cbomkit-theia | Source code; container images and file systems | 1.6 | Static discovery of cryptographic API use and artefacts |
| pqaudit 0.2 (Rust, Apache-2.0) | Live TLS endpoints | 1.5 | Reports what a server **supports**, not what a session **negotiated** |

CycloneDX 1.7 (released 21 October 2025) adds a standard list of
cryptographic algorithm families and a list of elliptic curves. The project's
hand-maintained family mapping caused review finding D2 (EdDSA and DSA
unclassified).

This ADR's predecessor numbering has a duplicate: two records are numbered
ADR-007 (`external-review-remediation` and `rust-key-exchange-probe`). Both are
kept; this record takes the next free number.

## Decision

The control plane is **not a scanner**. It consumes CycloneDX CBOMs produced
by any scanner as untrusted collector input, assesses them with its own rules,
and exports CycloneDX plus an assurance sidecar for what CycloneDX cannot
express.

### Versions

- **Import:** CycloneDX JSON 1.5, 1.6 and 1.7. XML and SPDX are out of scope.
- **Export:** 1.6 by default (widest tool support); 1.7 when requested.
- Validate every document against the official CycloneDX JSON schema for its
  declared `specVersion`, vendored in the repository with a recorded SHA-256.
  A document that fails validation is rejected, not partially imported.
- Conformance to CycloneDX is claimed only for outputs that pass that
  validation in CI.

### Import trust boundary

1. An imported BOM is collector evidence from an unauthenticated source. Its
   `metadata.tools`, `serialNumber`, `version`, every `bom-ref` and the SHA-256
   of the original bytes are recorded as provenance.
2. Evidence level comes from the **import manifest**, not the BOM, and is
   capped: `simulated`, `generated` or `public-observation` only.
   `sanitised-capture` needs a sanitisation record. The two high-assurance
   levels stay runtime-disabled, as for every other collector.
3. Importing a BOM that describes real enterprise systems is real-data intake
   and is blocked until a G3 pilot authorisation exists.
4. The control plane **recomputes** exposure from the algorithm family. A
   scanner's `nistQuantumSecurityLevel`, PQC label or safety verdict is kept as
   an asserted value, never used as the classification. Unknown remains never
   safe.
5. Fields the mapping does not understand are preserved verbatim in the
   sidecar, so an import followed by an export loses nothing (a round-trip test
   enforces this).
6. Size and depth limits apply before parsing (number of components, nesting
   depth, document size), as for the existing CT and kex-probe collectors.

### Canonical mapping (item 4 fills the table)

| CycloneDX `cryptoProperties.assetType` | Control-plane target |
|---|---|
| `certificate` | X.509 certificate record; signature and subject-key algorithm references resolved by `bom-ref` |
| `algorithm` | Cryptographic use: family, primitive, parameter set, function |
| `protocol` | Transport observation; cipher suites and groups resolved by reference |
| `related-crypto-material` | Key or secret **metadata only**; any key value in the input is a rejection, not an import |

Algorithm families normalise through the CycloneDX 1.7 family list, pinned by
hash. A family absent from that list maps to `unknown`.

### Export

- One CycloneDX document per export, with `cryptoProperties` for each asset and
  `dependencies` from the control-plane dependency graph.
- One sidecar JSON per export, `ccp-assurance-1.0`, keyed by `bom-ref` and bound
  to the exported BOM by its SHA-256. It carries evidence level, provenance,
  exposure status, verification state, migration priority and wave, and
  preserved unmapped fields.
- The sidecar is authoritative for assurance fields. They are not duplicated
  into CycloneDX `properties`, to avoid two copies drifting. Whether CycloneDX
  1.7 citations can carry provenance natively is evaluated in item 5, not
  assumed here.

### Comparison harness (items 6 and 7)

- Third-party tools run **outside CI**, by a person, at pinned versions,
  against project-owned inputs only: generated certificates, a fixture source
  tree, and the kex-probe loopback lab server. Never against external hosts.
- Their outputs are committed as fixtures with SHA-256 hashes and the exact
  command line. CI compares against fixtures and never runs the tools.
- The gap report states only measured differences per fixture: assets found,
  classifications, evidence carried, and supported versus negotiated key
  exchange. It contains no rankings or market claims.

## Consequences

- Positive: the control plane works with any CycloneDX-emitting scanner and
  competes on assessment, evidence and governance rather than discovery.
- Positive: scanner verdicts cannot raise a classification or an evidence level.
- Positive: the 1.7 family list replaces part of the hand-maintained mapping.
- Negative: three schema versions to validate and keep fixtures for.
- Negative: the sidecar is a project format. Consumers that read only the BOM
  see no evidence levels.
- Negative: harness fixtures go stale as tools change and must be re-recorded
  with each tool upgrade.
- Unchanged: no scanning of real systems, no real-data import before G3, no
  execution authority.

## Alternatives considered

- **Keep the project format only:** rejected; it adds integration cost for every
  consumer and was the subject of an external review finding.
- **Put assurance fields in CycloneDX `properties`:** rejected as the primary
  store; untyped strings, easily dropped by tools, and duplication with the
  sidecar would drift. May be added later as a read-only summary.
- **Become a scanner:** rejected; CBOMkit and pqaudit already cover discovery
  for source, containers and endpoints, and kex-probe covers negotiated key
  exchange in the lab.
- **Run scanners inside CI:** rejected; needs Java, Go and Rust toolchains and
  network access on every run, and makes results depend on tool releases.

## Feature track

1. This ADR.
2. CycloneDX 1.7 schema validation and import fixtures.
3. 1.6 and 1.5 compatibility tests.
4. Canonical mapping and provenance preservation (completes the table above).
5. CycloneDX export plus `ccp-assurance-1.0` sidecar.
6. CBOMkit and pqaudit comparison harness (fixture-based).
7. Hash-backed gap report.
8. Website and deck wording, only after items 2 to 7 have runtime evidence.

## References

- CycloneDX v1.7 release announcement: https://cyclonedx.org/news/cyclonedx-v1.7-released
- OWASP CycloneDX guide to CBOM: https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-CBOM-en.pdf
- CBOMkit: https://github.com/cbomkit
- pqaudit 0.2.0: https://docs.rs/crate/pqaudit/0.2.0
