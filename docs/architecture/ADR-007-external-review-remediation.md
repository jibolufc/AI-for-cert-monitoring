# ADR-007: External review remediation and assurance-preserving controls

- Status: accepted
- Date: 2026-10-11
- Amends: ADR-003, ADR-005, ADR-006

## Context

An external reassessment identified four reproducible weaknesses in the local
reference implementation: a current PQC candidate could be prioritised as an
urgent migration, EdDSA and DSA certificates could be left unclassified, a
self-signed offline bundle could carry a re-signed but inflated evidence claim,
and an exception could be approved by an actor other than its named risk owner.

The remediation must preserve the product's central rule: algorithm names and
signatures are evidence, not proof of safe deployment or production identity.

## Decision

1. A current `candidate-quantum-resistant` or `hybrid-unverified` use whose
   algorithm family already matches its target enters a `verification-required`
   lane with priority `verify` and wave `verification`. It is not marked
   complete. A different target family remains governed migration work.
2. Ed25519 and Ed448 are classified as classical elliptic-curve signatures.
   DSA is represented as a separate classical, quantum-vulnerable family.
3. Offline bundle import recomputes the weakest evidence level from the
   enclosed artifacts. A manifest mismatch or an enclosed high-assurance claim
   is rejected even when the attacker can produce a valid self-signature.
4. An active exception must be approved by the actor named as its risk owner.
   Delegated risk authority is not inferred; it requires a future explicit,
   independently validated delegation contract.

## Consequences

- Current PQC-labelled observations receive verification work without a false
  urgent migration signal.
- Classical EdDSA and DSA exposure is visible to inventory and assessment.
- Bundle signatures continue to prove integrity only; they cannot raise source
  assurance through a self-authored manifest.
- Exception accountability is bound to an explicit actor in the current
  contract.
- Adding a second portfolio priority model and implementing an externally
  governed standards-update process remain separate roadmap items.

## Verification

The automated suite covers the matching-target verification lane, a differing
PQC target, Ed25519, Ed448, DSA, evidence-claim inflation with a valid
self-signature, and mismatched risk-owner approval.
