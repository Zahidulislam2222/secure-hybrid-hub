# Secure Hybrid AI Development Hub

This workspace contains the research, authoritative build plan, and the verified
local-only Phase 0–3 implementation slice for a privacy-tiered development system:

- cloud models perform planning and carefully scoped review;
- local Ollama models perform high-volume implementation;
- a deterministic local broker mediates every cloud/local handoff;
- internet research is isolated from private code and credentials;
- credentials are used by controlled tools, never placed in model context.

The design is not based on one unrestricted agent. An agent that can simultaneously read secrets, browse arbitrary pages, and execute commands is an exfiltration risk even when the model runs locally.

Start here:

- [Final build plan](docs/FINAL_BUILD_PLAN.md) — authoritative implementation specification
- [Research and architecture](docs/RESEARCH_AND_ARCHITECTURE.md)
- [Regulated-client security profile](docs/REGULATED_CLIENT_PROFILE.md)
- [Automation and local-search design](docs/AUTOMATION_AND_LOCAL_SEARCH.md)
- [Implementation roadmap](docs/IMPLEMENTATION_ROADMAP.md)
- [Decision log](docs/DECISION_LOG.md)
- [Implemented hub](hybrid-hub/README.md)
- [Phase 0–3 verification evidence](hybrid-hub/verification/phase-0-3.json)
- [Explicit project opt-in](hybrid-hub/docs/OPT_IN_PROJECTS.md)

Status: Phases 0–3 are implemented and verified with synthetic data. Later
quality, network research, DLP/secret runner, cloud, deployment, and regulated
pilot phases remain disabled pending their specific authorization. No service,
container, dependency, or model was installed; no cloud egress was enabled.

Quick local verification:

```bash
cd hybrid-hub
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
