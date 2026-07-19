# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/OWNER/secure-hybrid-hub/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/OWNER/secure-hybrid-hub/releases/tag/v0.9.0
