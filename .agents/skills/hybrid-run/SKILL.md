---
name: hybrid-run
description: Submit and follow a software task through the Secure Hybrid AI Development Hub. Use when the user asks to build, modify, debug, or verify a registered project through the broker-controlled local workflow.
---

# Hybrid Run

Locate the project-local `.hybrid-hub.json` marker and invoke its exact `hub.py`
and runtime with `run`, the user's exact task, registered system ID,
`--through verified`, an explicitly selected installed local model, and either
`codex-local` or `claude-local`. If the marker is absent, stop and direct the
user to explicitly register/install this project; never fall back to a global
Hub configuration. Render the final verification report and exact broker state;
do not implement a parallel workflow or edit the worktree outside the broker.

Do not add credentials, raw logs, regulated records, or new permissions to the
request. Never translate a pause or blocked status into success. Ask only for
the specific input or authorization named by the broker, then use
`$hybrid-resume`.
