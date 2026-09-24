# Current status and capability boundaries

Reviewed for the September 2026 documentation publication. The package declares
version `0.11.0` and the changelog contains unreleased work. Identify behavior by
commit or release tag, not the package version alone.

| Area | Current public implementation | Remaining gate |
|---|---|---|
| Interface | Python CLI, agent skills and VS Code tasks | Browser frontend and authenticated web API |
| Broker | Policy composition, SQLite, artifacts and audit chain | Complete crash, concurrency and adversarial acceptance |
| Project scope | Registered roots, topology, workspaces and leases | Real-client isolation validation |
| Workers | Local, subscription CLI and metered HTTP adapters | Explicit route/model/account/data authorization on every execution path |
| Approvals | Task-selection store and approval-authority modules | Complete entry-point enforcement and organizational authentication |
| Verification | Synthetic unit, integration and adversarial tests | Exact-commit release checks and deployment-specific evidence |
| Secrets/egress | Capability/scanning interfaces and synthetic tests | Real secret backend and behavioral disclosure tests |
| Deployment | Staging/canary/rollback interfaces and simulations | Real transport and separately authorized pilot |
| Operations | Backup, restore checks, retention, SBOM and audit tools | Encrypted storage, live monitoring and recovery drills |
| Scale | Single-host local broker | Distributed cells and measured 1M+ capacity |
| Legal readiness | Apache-2.0 source license and guidance | Operator-specific contracts and jurisdiction review |

## Known limitations

- Packaging currently declares a setuptools minimum older than its SPDX license
  metadata requires. Use a current build backend; see [build evidence](VERIFICATION.md).

- Historical phase 0–11 reports describe synthetic milestones, not completion of
  all later hardening or production prerequisites.
- Partially generated candidates are not released changes. Only integrated
  source with matching verification belongs in a release.
- CLI approver labels do not authenticate people. Approval primitives alone do
  not prove enforcement across every worker, router, CLI and deployment path.
- Executable version/digest assertions need code enforcement. Current worker
  path checks do not establish enforcement of every executable pin.
- Kernel isolation, filesystem permissions and socket support vary by host.
  Unit tests do not prove process containment on an untested operating system.
- Sharing SQLite/runtime directories between web replicas is not a distributed
  architecture. The shared-service design requires different persistence and
  concurrency contracts.
- No browser application, customer web API, production shared service,
  million-user benchmark or observed uptime history ships in this tree.

A successful test run covers the collected tests on one source snapshot and
host. It does not cover every provider, malicious input or legal obligation.
[Current checks](VERIFICATION.md) and [roadmap gates](ROADMAP.md) govern new claims.
