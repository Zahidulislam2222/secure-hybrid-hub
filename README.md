# Secure Hybrid AI Development Hub

A fail-closed, standard-library-only local policy broker for hybrid AI
development workflows:

- cloud models perform planning and carefully scoped review;
- local Ollama models perform high-volume implementation;
- a deterministic local broker mediates every cloud/local handoff;
- internet research is isolated from private code and credentials;
- credentials are used by controlled tools, never placed in model context.

The design is not based on one unrestricted agent. An agent that can
simultaneously read secrets, browse arbitrary pages, and execute commands is
an exfiltration risk even when the model runs locally. Here, models propose
work; deterministic code controls project scope, policy, task state,
artifacts, local worker access, and verification evidence.

## Requirements

- Linux, WSL2, or macOS (native Windows is not supported: the sandbox and
  quality runners use the Unix-only `resource` and `fcntl` modules, and some
  isolation features — Landlock, namespaces — are Linux-only). On Windows,
  run the hub inside WSL2.
- Python 3.11 or newer. SQLite 3.38+ (standard in every 2022+ distribution).
- No third-party dependencies — the hub is Python standard library only.

## Quick verification

```bash
cd hybrid-hub
PYTHONPATH=src python3 -m unittest discover -s tests -v
# or: pytest -q
```

The 135-test suite is synthetic and offline: no network, no credentials, no
installed services. See [CONTRIBUTING.md](CONTRIBUTING.md) for details and
[hybrid-hub/README.md](hybrid-hub/README.md) for usage — registering a
system, guided orchestration, per-project modifiers, and the operational
boundary.

## Status

Phases 0–11 of the build plan are implemented and verified with synthetic
data and mocked network boundaries: broker core, topology registry, project
dossier, quality gates with sandbox isolation, isolated research, local
adapter identities, guided orchestration, verified model routing, cloud and
deployment surfaces (disabled by default, fail closed), and operational
hardening (backup/restore, SBOM, retention, access review).

Live research routes, real secret backends, real cloud transmission,
production adapters, and regulated production use remain disabled by default
and require explicit, separate authorization. CLI approval labels are not
cryptographic identities. See
[hybrid-hub/docs/OPERATIONS_RUNBOOK.md](hybrid-hub/docs/OPERATIONS_RUNBOOK.md)
for the exact remaining risks.

## Documentation

- [Implemented hub](hybrid-hub/README.md)
- [Guided orchestration](hybrid-hub/docs/GUIDED_ORCHESTRATION.md)
- [Model routing operations](hybrid-hub/docs/MODEL_ROUTING_OPERATIONS.md)
- [Per-project modifiers](hybrid-hub/docs/PROJECT_MODIFIERS.md)
- [Explicit project opt-in](hybrid-hub/docs/OPT_IN_PROJECTS.md)
- [Operations runbook](hybrid-hub/docs/OPERATIONS_RUNBOOK.md)

### Verification evidence

Phase-by-phase machine-readable evidence lives in
[hybrid-hub/verification/](hybrid-hub/verification/):
[0–3](hybrid-hub/verification/phase-0-3.json),
[4](hybrid-hub/verification/phase-4.json),
[5](hybrid-hub/verification/phase-5.json),
[6](hybrid-hub/verification/phase-6.json),
[7](hybrid-hub/verification/phase-7.json),
[8](hybrid-hub/verification/phase-8.json),
[9](hybrid-hub/verification/phase-9.json),
[10](hybrid-hub/verification/phase-10.json),
[11](hybrid-hub/verification/phase-11.json),
[guided orchestration](hybrid-hub/verification/guided-orchestration.json),
[gemma3 guided evaluation](hybrid-hub/verification/gemma3-guided-evaluation.json),
[gemma3 complex evaluation](hybrid-hub/verification/gemma3-complex-evaluation.json).
Immutable dossier checkpoints are under
[hybrid-hub/dossier/checkpoints/](hybrid-hub/dossier/checkpoints/).

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy.

## License

[Apache-2.0](LICENSE)
