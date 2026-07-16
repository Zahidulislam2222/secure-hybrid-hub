---
name: hybrid-run
description: Submit and follow a software task through the Secure Hybrid AI Development Hub. Use when the user asks to build, modify, debug, or verify a registered project through the broker-controlled local workflow.
---

# Hybrid Run

Locate the project-local `.hybrid-hub.json` marker. Act as the high-level
supervisor first: inspect only policy-permitted code, dossier, and topology;
produce a small ordered plan matching `docs/GUIDED_ORCHESTRATION.md` beside the
Hub entry named by the marker; and use
generic technology questions plus exact official-documentation URLs for
research, never private project details. Save the temporary plan outside the
target repository or under the broker runtime.

Invoke the marker's exact `hub.py` and runtime with `run`, the user's exact
task, registered system ID, `--through verified`, `--guided-plan`,
`--supervisor-source codex-interactive`, an explicitly selected installed local
model, and either `codex-local` or `claude-local`. The broker isolates internet
research, injects bounded evidence into component-sized local coding packets,
runs deterministic tests after every packet, and preserves checkpoints. Never
send one whole-project implementation prompt to the local model.

If the marker is absent, stop and direct the user to explicitly
register/install this project; never fall back to a global Hub configuration.
Render the final verification report and exact broker state; do not implement a
parallel workflow or edit the worktree outside the broker.

Do not add credentials, raw logs, regulated records, or new permissions to the
request. Never translate a pause or blocked status into success. Ask only for
the specific input or authorization named by the broker, then use
`$hybrid-resume`.
