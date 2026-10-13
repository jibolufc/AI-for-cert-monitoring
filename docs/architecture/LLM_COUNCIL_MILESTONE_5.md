# LLM Council review: Milestone 5 migration management

- Date: 2026-10-11
- Scope: fictional enterprise catalogue, dependency-aware planning, governed
  decisions, exceptions, verification, and metrics
- Decision: proceed as a deterministic non-executing reference workflow

## Recommendation

Build the migration-management domain now using simulated enterprise data and
explicitly keep execution outside the control plane. Treat the work-item state
machine and evidence gates as the product core; defer user interface, live
integration, and production orchestration.

## Evidence analyst

Milestones 1-4 provide versioned evidence and assessment inputs. They do not
provide authoritative ownership, dependencies, supplier support, or real
migration outcomes. The new catalogue must therefore be labelled simulated and
must not raise its component evidence above the catalogue's maturity.

## Sceptic / red team

The main failure mode is producing an attractive migration dashboard that
mistakes hand-authored relationships and target labels for enterprise truth.
Controls should reject evidence escalation, surface stale/missing observations,
block unsupported targets, and prohibit one combined readiness score.

Workflow threats include self-approval, stale-object decisions, permanent
exceptions, non-independent verification, and verification without post-change
evidence. Each needs a negative test.

## Alternative strategist

An alternative is to wait for real customer data. That would postpone the most
reusable elements: contracts, dependency rules, state transitions, decision
binding, exception expiry, and verification semantics. A simulated portfolio is
the better learning vehicle if its limits remain machine-readable.

Another alternative is to adopt an external ticketing platform as the workflow
system immediately. That would add vendor-specific identity and lifecycle
assumptions before the domain model is stable. Portable contracts should come
first.

## Practical implementation reviewer

A small catalogue plus deterministic Python service fits the existing
repository architecture. JSON Schema preserves language-neutral interfaces;
UUIDv5 provides repeatable work identities; file-oriented CLI output keeps the
milestone demonstrable without adding hosting or credentials.

## Risk and future reviewer

Function-specific targets must remain revisable as protocol profiles, products,
standards, and implementation evidence evolve. The system should preserve the
catalogue version, object version, evidence references, and decision history so
later policy changes cannot silently rewrite prior rationale.

## Cross-examination

Agreement:

- build workflow semantics before execution;
- keep coverage and completion separate;
- require explicit post-change verification;
- treat unsupported targets and missing evidence as blockers;
- use deterministic policy for priority and state gates.

Material uncertainty:

- no organisation-approved risk appetite or target dates exist;
- no authoritative dependency or ownership source exists;
- fictional supplier readiness cannot predict actual interoperability.

## Devil's advocate

If this milestone fails, the most likely reason is that the fictional catalogue
looks more authoritative than it is. The design therefore carries simulated
evidence into reports, rejects high-assurance claims at runtime, states coverage
limitations, and requires a later reconciliation milestone before any pilot.

## Council chair

Proceed. The approach is reversible, testable, and moves the project toward its
stated migration-control-plane goal without broadening authority. Confidence is
high for reference workflow semantics and deliberately low for production
coverage or migration readiness.
