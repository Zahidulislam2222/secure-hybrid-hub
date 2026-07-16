# Secure Hybrid AI Development Hub

This directory contains the local-only implementation slice defined by
`../docs/FINAL_BUILD_PLAN.md`: Phases 0–3. It uses Python's standard library
and synthetic fixtures. Cloud egress, external research, secret backends,
production access, deployments, and model downloads are disabled.

Run without installing:

```bash
cd hybrid-hub
PYTHONPATH=src python3 -m hybrid_hub --help
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Runtime state defaults to a temporary or explicitly selected directory. Never
place real credentials in this source tree or in a hub dossier.
