# Reliability and availability targets

The open-source project does not operate an uptime SLA. Local availability depends
on the operator's host. The following are **proposed targets for future shared
deployments**, subject to measured capacity, staffing and an operator's acceptance.

## Availability objectives

| Deployment stage | Proposed target | Equivalent unavailable time in 30 days |
|---|---|---|
| Controlled pilot | 99% | 7 hours 12 minutes |
| General shared service | 99.9% | 43 minutes 12 seconds |
| Later resilient deployment | 99.95% | 21 minutes 36 seconds |

The time figures are arithmetic illustrations for a time-based SLI. A request-based
budget counts failed requests and cannot be converted to downtime without a traffic
model. A contract, exclusions or compensation terms would need a separate SLA.

## Measurement contract to implement

Use a rolling 30-day window. Define each SLI before the pilot:

| User experience | Proposed indicator and initial target |
|---|---|
| Read project/task state | Successful authorized reads / eligible reads; stage availability target |
| Submit task | Valid in-quota submissions durably acknowledged / eligible submissions; stage target |
| API latency | p95 ≤ 500 ms and p99 ≤ 2 s for ordinary metadata requests, excluding model execution |
| Event freshness | 99% of authorized events visible within 5 s under the agreed load |
| Job progress | Queue age and completion percentiles by job class and model, with class-specific deadlines |
| Data integrity | No lost acknowledged task transition or duplicate committed approval effect in tests |

Latency and freshness numbers are proposed acceptance thresholds, not measurements.
Measure frontend synthetic journeys and server events; a responding health endpoint
alone does not prove login, submission or evidence retrieval works.

Exclude genuinely invalid credentials/input and correctly enforced contractual
quotas from eligible requests, but track them independently. Count internal errors,
capacity rejection of in-quota work, timeouts and lost acknowledgements as failures.
Provider failures remain visible in task-execution SLIs even if task-status reads
succeed. Track cancelled, policy-blocked and failed tasks separately. Publish
exclusion rules and avoid retroactively redefining the denominator to hide outages.

The SLI/error-budget method follows
[Google's SLO guidance](https://sre.google/workbook/implementing-slos/);
the numerical targets and scope above are this project's proposals.

## Error budget and alerting

Budget is `eligible events × (1 − target)`. Alert on fast and sustained burn,
including low-traffic synthetic checks. If budget is exhausted, prioritize recovery
and reliability fixes over risky releases. Security containment can deliberately
reduce availability; record its impact rather than weakening a control to keep green.

Collect request rate/errors/latency, queue age, worker occupancy, lease renewal,
provider failures, spend, database saturation and audit-write failures. Use bounded
cardinality and sanitized traces; never log secrets or unrestricted source.
Provide operator-owned dashboards, escalation routes and documented incident roles.

## Recovery design

| Data/service | Proposed RPO | Proposed RTO | Proof required |
|---|---|---|---|
| Durable task/approval metadata within a region | Zero acknowledged writes lost for a tolerated node/zone failure | 15 minutes | Failover with consistency and replay checks |
| Regional disaster recovery | At most 15 minutes, where replication is permitted | 60 minutes | Authorized regional failover with residency checks |
| Recoverable artifacts/backups | At most 24 hours unless policy demands tighter | 4 hours | Restore, hash checks and access-policy reconstruction |

RPO means tolerated data loss; RTO means recovery time. These are future design
objectives. Disaster RTO may exceed the normal monthly availability budget: that
would be an SLO miss and must be reported. Reconcile commitments before launch.

Encrypt backups, separate backup credentials, verify restoration into an empty
environment, and rehearse recovery at least quarterly and before major storage
changes. Include identity, key recovery, audit anchors and configuration, not just
database files. Current built-in backups are integrity-checked but not encrypted.

## Releases and incidents

Use immutable artifacts, reversible migrations, staged rollout and measured rollback
criteria. Test lost workers, stale leases, queue redelivery, database failover,
provider timeout, audit failure and revoked identity. Never fail over to an
unauthorized model or region.

During incidents: contain, preserve evidence, restore the approved service path,
communicate known user impact, and review causes with actionable follow-up tests.
An operator must establish staffed coverage before promising continuous response.
See the [operations runbook](OPERATIONS_RUNBOOK.md).
