# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0] - 2026-07-20

### Added

- External audit anchor: `audit anchor` emits a small `{head_hash, count,
  anchored_at}` object to store outside the runtime (e.g. a git commit), and
  `audit verify --anchor <file>` checks the live chain head against it. This
  detects a whole-chain rewrite that internal hash-chain verification alone
  cannot, because a consistently rebuilt chain still re-derives valid hashes.
- HTTP API preflight now surfaces `key_age_days` (from the key file mtime) so a
  stale credential is visible; no rotation threshold is hardcoded.

### Changed

- The per-task HTTP API spend cap is now a strict pre-egress ceiling: before
  each call the worker refuses if the call's worst-case cost (prompt bytes plus
  a framing-token allowance as an upper bound on input tokens, plus
  `max_output_tokens` of output) could breach the cap. Previously the cap was
  checked after the call, permitting one bounded overshoot. The post-call check
  is retained as a backstop for a vendor that bills more than the bound
  predicted.

### Fixed

- Real-money metering gap: every billed (2xx) response is now metered against
  the spend cap before its content is judged. Previously a truncated
  (`stop_reason=="max_tokens"`), oversized, malformed, or usage-less success
  raised before the spend record was written, so the vendor billed for a call
  the hub recorded as $0 — and because the orchestrator retries adapter
  failures, a model repeatedly hitting the output limit could bill on every
  attempt while the cap never filled. Response bodies are now read by a
  non-raising interpreter, and any unforeseen exception from a body shape is
  converted into a failure raised only after the call has been metered.
- A response whose body could not be read, or whose connection failed to close,
  is no longer treated as a request that never happened. The vendor bills at
  generation, not at delivery, so once a status is in hand the call is metered:
  an unreadable body (including a mid-read `IncompleteRead`, which is not an
  `OSError` and previously escaped the worker and the orchestrator both) at the
  worst case, and a complete body whose connection merely failed to close at its
  reported usage.
- A request that times out with the prompt already fully sent is now charged at
  the worst case. A non-streaming vendor returns headers only once generation
  finishes, so that timeout is the shape of a call that was generated and
  billed; leaving it unmetered let the orchestrator re-drive the same slow
  request on every repair attempt, billing each time against a ledger that read
  $0. Metering it makes those retries self-limiting. The two timeout phases are
  distinguished: a connect, TLS, or send-phase timeout never reached the vendor
  and is not charged, because charging it would let a passing network fault
  exhaust a real budget on $0 of actual spend. That case, and any other transport
  failure without a status, is audited as `worker.egress-unaccounted` rather
  than passing silently.
- Policy refusals raised from inside the HTTP opener — the forbidden-redirect
  control among them — keep their own meaning instead of being reported as
  transport failures, so a deliberate refusal blocks the task rather than being
  retried.
- A billed call whose spend record cannot be written now blocks the task instead
  of raising a retryable adapter error, since retrying with metering known to be
  broken is how unbounded billing happens.
- Vendor-reported token counts are now bounded before they are used. JSON
  integers are unbounded, and an absurd count either overflowed the cost
  arithmetic (escaping before the spend record was written, on a call the vendor
  had already billed) or persisted a spend total that permanently exhausted the
  task. Counts above a sanity ceiling are refused and charged at the worst case.
- The whole metering step, not only response parsing, is now guarded: any
  failure between a billed response and its spend record blocks the task rather
  than escaping, and the message names the recovery.
- A response reporting usage that cannot be true — zero input tokens, or zero
  output tokens alongside returned text — is no longer taken at face value. Such
  a report would hold the spend total at $0 and disable the cap; it is now
  charged at the worst-case bound and the run fails.
- The worst-case input bound used by the spend ceiling now adds a framing-token
  allowance, because vendors bill request framing (role markers, message
  envelope) on top of the prompt text; the prompt's byte length alone was not a
  true upper bound. The allowance is configurable per adapter
  (`--framing-token-overhead` on `run` and `model select`, stored with the model
  selection; default 64).
- A guided run whose worker cannot authorize (missing/not-live-enabled provider
  profile) no longer strands the task silently in `LOCAL_IMPLEMENTING` holding
  its workspace lease. `AuthorizationRequired` is caught mid-orchestration and
  the task blocks cleanly, which auto-releases the lease.
- A lease conflict error now names the owning task, so the operator knows which
  task to cancel or resume.

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

[0.11.0]: https://github.com/Zahidulislam2222/secure-hybrid-hub/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/Zahidulislam2222/secure-hybrid-hub/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/Zahidulislam2222/secure-hybrid-hub/releases/tag/v0.9.0
