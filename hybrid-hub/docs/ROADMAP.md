# Open-source roadmap

This roadmap is ordered by evidence and dependencies, not promised dates. All
stages remain open until their exit criteria have current proof. Historical phase
numbers are preserved as evidence, not reused as completion labels here.

| Stage | Deliverables | Exit criteria |
|---|---|---|
| A. Foundation closure | Complete task/approval enforcement, executable identity, recovery, safe diagnostics and configuration audit | Real CLI flows and adversarial tests cover every entry point; independent review resolves privacy-critical findings |
| B. Reproducible local release | Supported-host matrix, corrected build-backend minimum, packaging, setup, sample config, scanner availability and recovery docs | Clean-checkout tests/build/scans pass; restore and uninstall behavior demonstrated |
| C. Optional web interface | Accessible frontend, versioned API, identity and event streaming | Synthetic user journeys, object authorization, revocation and accessibility checks pass |
| D. Controlled real-client pilot | Approved secret/provider backend, contracts, data scope and operational ownership | All applicable privacy/security gates pass before real data; monitored pilot and recovery evidence accepted |
| E. Team and shared deployment | Tenant boundaries, durable queue, worker scheduling, quotas and transactional state | 100 → 1,000 → 10,000-user workload tests, tenant isolation and failure recovery meet declared targets |
| F. Regional cells | Partitioning, locality, bounded failure domains and migration tooling | 100,000-user representative load with failed cell/zone and no authorization/data-integrity loss |
| G. Million-user validation | Distributed load harness, capacity/cost model and sustained observability | 1M+ simultaneous-user mixed workload passes soak, burst and failure tests with published evidence |
| H. Mature operations | Repeatable releases, maintenance, incident learning, reliability reviews and community governance | Observed SLO windows, recovery drills and ongoing security review support operator commitments |

## Release-critical versus optional work

No stage may defer a control whose failure can disclose secrets, client source,
regulated records or privileged material. A small release may omit a browser UI,
provider plugin or scale feature. It may not omit authorization, safe diagnostics,
tenant isolation or recovery controls required by its declared deployment scope.

The million-user target depends on [scalability assumptions](SCALABILITY.md) and
[reliability measurement](RELIABILITY.md). A local single-user release need not
deploy distributed infrastructure to be useful. Keep local operation supported.

## Contributor workstreams

- Correctness: bounded task lifecycle, cancellation, idempotency and concurrency.
- Security: boundary tests, executable identity, secret backends and disclosure controls.
- Developer experience: reliable setup, configuration validation and useful error recovery.
- Frontend: implement the [proposed journeys](FRONTEND_API.md) after API/security contracts.
- Operations: reproducible benchmarks, recovery drills and cost reporting.
- Documentation: tested examples, translations, diagrams and updated status evidence.

Open an issue with scope, acceptance tests and deployment impact before large work.
Maintainers review design changes, dependencies and license compatibility. An
issue, feature request or roadmap entry is not permission for paid API usage,
cloud resources, access to real data, or a security-policy exception.

## Definition of release readiness

Record the exact source/artifact digest; show criteria coverage, tests, type/lint
results where configured, security scans, packaging, real CLI/UI behavior and an
independent review verdict. Missing or failing gates stay visible. Validate public
docs against that source. Any later escaped defect needs a regression and a record
of the gate that should have caught it. Follow the [release process](RELEASE_PROCESS.md).
