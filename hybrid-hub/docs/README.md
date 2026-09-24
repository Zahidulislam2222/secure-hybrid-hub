# Public documentation

This documentation covers an open-source local broker and its proposed future
self-hosted web and distributed deployments. **Current** means code exists;
**verified** requires test evidence; **planned** means implementation or
validation remains. A design target is not a measured service result.

## Reading paths

- Users: [overview](../../README.md), [status](STATUS.md), [setup](../README.md),
  [guided tasks](GUIDED_ORCHESTRATION.md).
- Contributors: [architecture](ARCHITECTURE.md), [security](SECURITY_DESIGN.md),
  [contributing](../../CONTRIBUTING.md), [release process](RELEASE_PROCESS.md).
- Platform reviewers: [frontend/API](FRONTEND_API.md), [scalability](SCALABILITY.md),
  [reliability](RELIABILITY.md), [roadmap](ROADMAP.md).
- Operators: [runbook](OPERATIONS_RUNBOOK.md), [routing](MODEL_ROUTING_OPERATIONS.md),
  [opt-in](OPT_IN_PROJECTS.md), [profiles](PROJECT_MODIFIERS.md).
- Privacy reviewers: [legal/privacy](LEGAL_PRIVACY.md),
  [security policy](../../SECURITY.md), [verification](VERIFICATION.md).

## Terms

| Term | Meaning |
|---|---|
| System | Explicitly registered repositories and components |
| Broker | Deterministic authority for policy, task state, artifacts and gates |
| Supervisor | Selected planning/review role; cannot override broker policy |
| Worker | Scoped implementation process with bounded access |
| Task | Audited unit of authorized work, distinct from a chat or browser session |
| Lease | Time-bounded resource ownership, not a durable identity |
| Egress | Data leaving its approved local or tenant boundary |
| SLI / SLO / SLA | Measured indicator / operational target / contractual agreement |
| Concurrent user | Connected user in a specified workload, not necessarily an AI job |
| Cell | Proposed bounded set of tenants/services with an isolated failure domain |

## Maintenance

Update claims when behavior changes. Record tested commits, environments,
limitations and source dates; remove obsolete entry-point counts. Keep public
docs self-contained. Private dossiers, credentials, client incidents, runtime
state and local exports do not belong in Git. External standards guide the
design; citing them does not establish certification or compliance.
