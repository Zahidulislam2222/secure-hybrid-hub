# Explicit project opt-in

The hub is not a global replacement for Codex or Claude Code.

- Only canonical repository roots registered with `hub system init` are visible.
- Discovery and human dossier approval are required before tasks can start.
- Project-local Codex/Claude/VS Code integrations are copied only into projects
  the user explicitly selects; nothing is installed in user-global folders.
- `hub system disable SYSTEM --actor NAME` blocks new and progressing work while
  leaving status, audit, evidence, and cancellation available.
- Unregistered projects continue to use ordinary Codex or Claude Code with no
  hub interception.
- A registration never grants access to siblings, parents, a whole drive, or a
  different client. Overlapping client roots are rejected.
- Project integrations are installed only by the explicit `hub integrations
  install --system SYSTEM --project EXACT_ROOT` command after system approval.
- Installation adds project-local skills, a marker, and merged VS Code tasks;
  it never creates extra `AGENTS.md`/`CLAUDE.md` files or modifies global user
  configuration.
- Project modifiers are separately proposed/approved and bound immutably per
  task. They can specialize or restrict behavior but never add authority.
