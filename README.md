# Secure Hybrid AI Development Hub

An open-source local policy broker for AI-assisted software development. Humans
choose the supervisor and coding worker; the broker coordinates scoped
repositories, isolated workspaces, model adapters, verification, and audit evidence.

**Status: experimental, pre-production.** The repository contains a Python
backend/CLI and editor/agent integrations. A browser frontend and distributed,
multi-tenant deployment are future work. Synthetic tests establish specific
behaviors, not production readiness or an uptime guarantee.

## What it does

- Registers explicit roots for single-repo, monorepo and polyrepo systems.
- Applies policy to task scope, model routing, egress and controlled operations.
- Creates isolated Git workspaces with writer leases and recoverable task state.
- Supports local workers and explicitly authorized subscription/API adapters.
- Records quality results, sanitized audit events and dossier checkpoints.
- Provides deployment and operations interfaces; live transports and production
  use need additional implementation, verification and separate authorization.

Models propose changes. Their output is not approval, policy or verification.
See the [capability and gap matrix](hybrid-hub/docs/STATUS.md).

## Open source and self-hosting

The source is licensed under [Apache-2.0](LICENSE). Run the broker on your own
machine; no project-operated SaaS subscription is required. Model weights,
provider accounts and infrastructure have separate licenses, terms and costs.
Offline synthetic tests do not require a model-provider account.

Future scale plans include self-managed and organization-operated deployments.
They do not require a commercial hosted edition or authorize paid resources.
Contributions are welcome through the [contribution guide](CONTRIBUTING.md).

## Start locally

Requirements: Python 3.11+, Git and a POSIX environment. Linux/WSL2 is the
reference environment for Linux sandbox controls. Native Windows is unsupported;
macOS lacks Linux-specific isolation and requires separate validation.
There are no third-party Python runtime dependencies. Test/build tools and model
services are separate dependencies.

```bash
git clone https://github.com/Zahidulislam2222/secure-hybrid-hub.git
cd secure-hybrid-hub/hybrid-hub
python3 hub.py --help
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Tests use synthetic fixtures and mocked external services. Some require local
sockets or OS sandbox facilities; a restricted container may block those tests.
Follow the [backend guide](hybrid-hub/README.md) for runtime setup. Keep runtime
state on an owner-protected filesystem outside the public checkout. Invoking a
real model may consume subscription allowance or incur API charges.

## Public documentation

| Topic | Guide |
|---|---|
| Navigation and terminology | [Documentation index](hybrid-hub/docs/README.md) |
| Implemented behavior and limitations | [Status](hybrid-hub/docs/STATUS.md) |
| Backend components and trust boundaries | [Architecture](hybrid-hub/docs/ARCHITECTURE.md) |
| Planned browser experience and API | [Frontend and API](hybrid-hub/docs/FRONTEND_API.md) |
| Installation and configuration | [Backend README](hybrid-hub/README.md) |
| Task execution and model selection | [Guided orchestration](hybrid-hub/docs/GUIDED_ORCHESTRATION.md), [model routing](hybrid-hub/docs/MODEL_ROUTING_OPERATIONS.md) |
| Project isolation and profiles | [Project opt-in](hybrid-hub/docs/OPT_IN_PROJECTS.md), [modifiers](hybrid-hub/docs/PROJECT_MODIFIERS.md) |
| Path toward 1M+ simultaneous users | [Scalability](hybrid-hub/docs/SCALABILITY.md) |
| Uptime, monitoring and recovery | [Reliability](hybrid-hub/docs/RELIABILITY.md), [operations](hybrid-hub/docs/OPERATIONS_RUNBOOK.md) |
| Threats and security requirements | [Security design](hybrid-hub/docs/SECURITY_DESIGN.md), [reporting](SECURITY.md) |
| Licensing, privacy and legal readiness | [Legal and privacy](hybrid-hub/docs/LEGAL_PRIVACY.md) |
| Delivery stages and release gates | [Roadmap](hybrid-hub/docs/ROADMAP.md), [release process](hybrid-hub/docs/RELEASE_PROCESS.md) |
| Publication checks | [Verification record](hybrid-hub/docs/VERIFICATION.md) |
| Contributions and changes | [Contributing](CONTRIBUTING.md), [changelog](CHANGELOG.md) |

## Future scale and availability

The proposed distributed design targets **1M+ simultaneous connected users**
through regional cells and separately scaled connection, API and worker tiers.
Active AI jobs have separate capacity and cost limits. The scale guide defines
workload assumptions, sample calculations, load tests and acceptance gates.
No million-user benchmark has been demonstrated.

Proposed availability stages are **99% for a controlled pilot**, **99.9% for a
general shared deployment**, and **99.95% for a later resilient deployment**.
They require measurement and operational evidence. These are optional operator
objectives, not an SLA supplied by the open-source project.

## Verification and historical evidence

Run the suite for the exact commit and environment you intend to use. Historical
phase reports are in [verification](hybrid-hub/verification/) and
[checkpoints](hybrid-hub/dossier/checkpoints/). Their labels do not establish
completion of the current roadmap, real-client readiness or live deployment.

## License and maintainer

[Apache-2.0](LICENSE). Third-party services, models and dependencies have their own
terms. Maintained by [Zahidul Islam](https://github.com/Zahidulislam2222).
