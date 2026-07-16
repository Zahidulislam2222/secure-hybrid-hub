# Secure Hybrid AI Development Hub

This directory contains the implementation defined by
`../docs/FINAL_BUILD_PLAN.md`: Phases 0–6. It uses Python's standard library
and synthetic fixtures. Phase 4 adds a deterministic quality engine with
approved argv-only commands, disposable snapshots, Landlock/namespace
isolation, targeted/full gates, and hashed sanitized evidence. Cloud egress,
live external research, real secret backends, cloud transmission, production
access, deployments, and model downloads remain disabled by default.

Run without installing:

```bash
cd hybrid-hub
PYTHONPATH=src python3 -m hybrid_hub --help
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Runtime state defaults to a temporary or explicitly selected directory. Never
place real credentials in this source tree or in a hub dossier.

Quality commands beyond the broker's built-in Python gates require a proposed
and explicitly approved command set:

```bash
python3 hub.py quality propose SYSTEM --commands commands.json --proposer OWNER
python3 hub.py quality approve COMMAND_SET_ID --approver OWNER
python3 hub.py test TASK_ID --scope targeted
python3 hub.py test TASK_ID --scope full
```

Quality execution currently requires Linux/WSL support for unprivileged user,
PID, IPC, UTS, and network namespaces plus Landlock. It fails closed when those
controls are unavailable and refuses Windows executables.

Phase 5 adds an isolated official-source research worker, a system-separated
local cache/index, and an optional localhost SearXNG discovery interface. Live
networking is a separate policy approval and is not enabled by this repository.
The SearXNG file under `config/research/` is only a template; no service or
container was installed or started.

Phase 6 adds synthetic-only named secret capabilities and sealed offline egress
bundles. The CLI deliberately cannot accept secret values, and approved bundles
cannot be transmitted. A real backend/provider requires separate authorization.
