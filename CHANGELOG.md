# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] - 2026-07-20

### Added

- Metered vendor HTTP API coding workers: guided packets can be implemented
  over an Anthropic-native (`anthropic-api`) or OpenAI-compatible
  (`openai-compatible-api`; OpenAI/MiniMax/GLM/Kimi) HTTPS API. Fail-closed
  twice over: live egress requires an approved `vendor-api` provider profile
  with `--enable-live`, and every run requires explicit token prices plus a
  hard per-task spend cap. Token usage is metered and audited per call
  (`worker.tokens-metered`); reaching the cap blocks and asks the human.
  API keys are read from a private `chmod 600` key file at call time —
  never from environment variables — never stored in state or audit, and
  redacted from error text.
- The model catalog gained an `anthropic-api` platform, and both API
  platforms are now selectable through `model select`, which stores the
  metered transport (base URL, key file, prices, cap) for flagless runs.
- Per-project coding-model selection (`model select`): the developer
  chooses the coding platform and model at project start — interactively
  or via flags — from a data-driven catalog
  (`config/model-catalog.example.json`). Selection runs a real one-packet
  synthetic probe against the chosen model, records the probe result as
  the model's evaluation, and pins the project routing policy to the
  choice with no automatic escalation or fallback.
- Subscription-CLI coding workers: guided packets can be implemented by a
  logged-in Claude Code (`claude -p`, tools disallowed) or Codex
  (`codex exec`, read-only sandbox) subscription CLI, running in an empty
  scratch directory with an environment allowlist that never inherits
  provider API keys. Every outbound prompt is audit-logged with its
  SHA-256 and byte count before the call. Vendor HTTP API platforms remain
  fail-closed.
- Flagless guided runs: `run --through verified` without `--model` uses
  the project's pinned selection and stored transport, audited as
  `model.selection-used`.

### Fixed

- Local file workers now strip an unclosed leading markdown fence when the
  model emits the stop marker before closing its code fence (observed with
  qwen2.5-coder), instead of failing the parse gate on every retry.

## [0.9.0] - 2026-07-19

First public release of the Secure Hybrid AI Development Hub: a fail-closed,
standard-library-only local policy broker for hybrid AI development
workflows (Phases 0–11 of the build plan, verified with synthetic fixtures).

### Fixed

- Sandbox now grants read+execute on the running interpreter's installation
  prefix, so Python installs outside `/usr` (GitHub hostedtoolcache, pyenv,
  conda) work under Landlock.
- Test suite is hermetic for public checkouts: no dependency on the private
  gitignored master dossier, and pytest no longer collects the intentionally
  failing fixture project.
- CI enables unprivileged user namespaces on Ubuntu 24.04 runners so the
  sandbox's `unshare` isolation works.

### Added

- Deterministic policy broker with typed artifacts, SQLite transactional
  state, hash-chained sanitized audit events, and strictest-wins policy
  profiles.
- Explicit system/repository/component registry with monorepo and polyrepo
  topology support, safe path authorization, and Windows/WSL path
  normalization.
- Hierarchical project dossier with versions, proposals, approvals, and
  immutable checkpoints.
- Git task worktrees, cross-repository workspaces, and one-writer leases.
- `codex-local` and `claude-local` adapter identities restricted to local
  Ollama; bounded loopback HTTP transport with output-token caps.
- Deterministic quality gate runner with disposable snapshots, Landlock and
  namespace isolation, secret/DLP scanning, and evidence hashing.
- Isolated research workers (internet, no repository), provenance labeling,
  and prompt-injection labeling.
- Disabled-by-default cloud-review, deployment, staging/canary/rollback, and
  operations (backup/restore, SBOM, retention, access review) surfaces that
  fail closed without explicit approval.
- Per-project modifiers, guided orchestration, and verified model routing
  with CLI entry points.
- 108-test synthetic offline test suite.

### Fixed

- `OperationsManager.sbom()` no longer walks broker runtime state, VCS
  internals, or dependency caches; SBOM generation and the release-phase
  test complete quickly on a used installation.
- Native Windows now fails at startup with a clear "requires Linux, WSL2, or
  macOS" message instead of a raw `ModuleNotFoundError` traceback.

[0.10.0]: https://github.com/Zahidulislam2222/secure-hybrid-hub/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/Zahidulislam2222/secure-hybrid-hub/releases/tag/v0.9.0
