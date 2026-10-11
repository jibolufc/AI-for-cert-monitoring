# LLM Council architecture review

Date: 2026-10-11
Decision scope: foundation and first executable vertical slice

## Recommendation

Build an event-contract-first, deterministic certificate monitoring slice
before adding live collectors, statistical models, generative AI, cloud
infrastructure, or certificate lifecycle orchestration. Keep evidence,
detection, scoring, explanation, transport, and response procedures as
separate components.

## Independent perspectives

### Evidence analyst

The repository was empty, so there were no compatibility constraints or
existing controls to preserve. RFC 5280 provides the Internet X.509 certificate
profile, while Certificate Transparency provides auditable observations rather
than prevention of misissuance. JSON Schema Draft 2020-12 is an appropriate
versioned wire-contract format. NIST AI risk guidance supports governance,
testing, provenance, documentation, and human oversight for generative AI.

The supplied concept is a target architecture, not evidence that every proposed
collector, detection, or orchestration workflow is feasible. Vendor event
formats, enterprise ownership data, event volumes, latency objectives, and SIEM
requirements remain unknown.

### Sceptic / red team

The leading failure mode is granting credibility or operational authority to a
model-generated explanation. Other material risks are forged telemetry,
allowlist poisoning, wildcard/IDN normalization errors, sensitive certificate
metadata leakage, duplicate/replayed events, alert flooding, and later privilege
creep into CA/HSM operations.

The response is to make alert creation deterministic, preserve evidence, label
the explanation as advisory, avoid credentials and network access, and document
future trust gates explicitly.

### Alternative strategist

Three credible starting points were considered:

1. Start with a live Certificate Transparency collector. This demonstrates real
   data quickly but couples the design to external feeds before the internal
   contract and ownership policy are stable.
2. Start with a broad cryptographic asset inventory. This is strategically
   valuable but too large to validate the detection-to-response flow early.
3. Start with a narrow event-to-alert slice using fixtures. This provides the
   smallest reversible test of contracts, policy, explanation boundaries, SIEM
   output, and SOC usability.

Option 3 is selected. The other options become later adapters and capabilities.

### Practical implementation reviewer

A Python standard-library implementation minimizes setup friction and supply
chain surface while keeping the contracts language-neutral. The first rule is
small enough to test exhaustively. JSONL is adequate for local verification,
but explicitly not a production queue or SIEM integration.

### Risk and future reviewer

Stable versioned event and alert contracts reduce future collector and platform
lock-in. The architecture should evolve toward signed provenance, idempotent
processing, dependency-aware inventory, pluggable policy, and controlled
workflow. PQC readiness belongs in later inventory and risk layers; it should
not be forced into the first certificate-domain rule.

## Cross-examination

### Agreement

- Establish the canonical event contract before vendor integrations.
- Keep detection and severity deterministic.
- Give no model direct CA, HSM, KMS, revocation, or deployment authority.
- Preserve source evidence and create a testable analyst response path.
- Build one complete slice before expanding to eleven rules.

### Disagreement

The strongest disagreement was whether to begin with live CT ingestion. It was
rejected for Milestone 1 because public CT coverage is not equivalent to an
enterprise certificate inventory, and a live feed would add network, parsing,
replay, and operational concerns before the core contracts are proven.

### Weak assumptions and missing evidence

- The example DNS allowlist is only a stand-in for authoritative ownership data.
- Event throughput, latency, retention, and multi-tenancy requirements are not
  yet known.
- A future severity model needs enterprise asset criticality and business
  context; environment alone is insufficient.
- Vendor collectors and SIEM mappings require validated sample payloads.

### Failure conditions

This recommendation becomes wrong if the immediate objective is a production CT
monitor with fixed vendor contracts and SLOs, or if the organization already has
a canonical event bus/schema that this repository must adopt.

## Council challenge

The strongest counterargument is that a fixture-driven vertical slice can look
complete while avoiding the hardest problem: trustworthy discovery and
ownership correlation. That criticism is valid. This milestone is accepted only
as a contract and control-boundary proof, not as production monitoring.

## Chair synthesis

Proceed with the narrow deterministic slice and make its limitations prominent.
Defer live integrations and model calls until the event contract, provenance,
policy ownership, replay semantics, evaluation corpus, and operational controls
are defined.

Confidence: **MODERATE**. The security boundary and incremental sequence are
well supported, but enterprise data sources and operational requirements have
not yet been supplied.

The recommendation would change if authoritative event schemas, existing
platform constraints, required SLOs, or a mandated deployment target show that a
different contract or implementation language is necessary.
