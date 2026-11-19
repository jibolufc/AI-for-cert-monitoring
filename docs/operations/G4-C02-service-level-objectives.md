# G4-C02 Candidate Service-Level Objectives

## Control state

**Prepared, not demonstrated.** These are candidate objectives for design and
measurement planning. No production service or measurement history exists, and
no owner has approved the targets.

## Measurement principles

- Measure only traffic and evidence within an authorised service boundary.
- Separate failures caused by the service from unavailable or unauthorised sources.
- Never hide missing coverage behind availability percentages.
- Report numerator, denominator, exclusions and measurement source together.
- An SLO is not demonstrated until its telemetry has been exercised and reviewed.

## Candidate objectives

| Indicator | Candidate objective | Window | Planned measurement source | Current evidence |
|---|---:|---|---|---|
| Service availability | at least 99.5% | calendar month | synthetic health checks and service metrics | none |
| Authorised ingestion success | at least 99.0% | rolling 24 hours | per-source accepted/failed outcome counters | none |
| Evidence processing latency | p95 at most 5 minutes after authorised receipt | rolling 24 hours | correlated intake and persisted-evidence timestamps | none |
| High-severity alert delivery | p95 at most 2 minutes after deterministic detection | rolling 24 hours | detection and sink acknowledgement timestamps | none |
| Inventory freshness | at least 95% within the source-specific approved interval | calendar day | coverage denominator and last-observed timestamps | none |
| Evidence integrity | 100% of exported bundles validate | every release | manifest and signature verification | local reference tests only |
| Recovery time objective | at most 4 hours | per qualifying incident | recovery exercise timeline | not exercised |
| Recovery point objective | at most 24 hours | per qualifying incident | backup and restored checkpoint comparison | not exercised |

Targets are deliberately modest until workload, source, tenancy and recovery
characteristics are measured. They must not be presented as contractual
commitments.

## Error-budget policy candidate

- Availability error budget for 99.5% is approximately 3 hours 39 minutes in a
  30-day month.
- Exhaustion pauses non-security production change and triggers service review.
- Security containment, evidence preservation and emergency rollback take
  priority over availability objectives.
- Source-denied or out-of-authority collection is never reclassified as a
  harmless availability failure.

## Demonstration criteria

G4-C02 remains `planned` until:

1. the service and operations owners approve the indicators, objectives, windows and exclusions;
2. each indicator has a named telemetry source and accountable reviewer;
3. synthetic tests prove the calculations, missing-data behaviour and alert thresholds;
4. at least one review cycle records actual results and error-budget treatment; and
5. the evidence is independently checked for denominator or exclusion manipulation.

