# Secure Hybrid AI Development Hub

This is the project-local, opt-in Secure Hybrid AI Development Hub
implementation. It coordinates registered Git repositories,
local Ollama coding, deterministic quality gates, isolated research, bounded
cloud-review bundles, controlled CI/CD adapters, operational evidence, and a
versioned project dossier.

No global Codex, Claude, MCP, or VS Code configuration is installed. No live
cloud provider, real credential backend, SearXNG service, production adapter,
or network research route is enabled by the repository.

## Verify the Hub

```bash
cd hybrid-hub
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The suite uses synthetic single-repository, monorepo, polyrepo-microservice,
and hybrid-system projects. It includes complete Codex-local and Claude-local
CLI flows, fail-then-repair behavior, DLP/adversarial tests, staging/canary
rollback simulations, backup/restore drills, and per-project modifiers.

## Register one selected project

```bash
python3 hub.py --runtime /protected/hub-runtime system init \
  --id my-system --client my-client --name "My System" \
  --root /exact/registered/repository --profile standard \
  --purpose "Approved project purpose"

python3 hub.py --runtime /protected/hub-runtime system approve \
  my-system --approver OWNER
```

Registration and initial dossier approval are explicit. Other projects remain
untouched. Install the unprivileged UI wrappers only into a registered root:

```bash
python3 hub.py --runtime /protected/hub-runtime integrations install \
  --system my-system --project /exact/registered/repository
```

This adds project-local skills, merges Hub tasks into `.vscode/tasks.json`, and
creates `.hybrid-hub.json`. It does not create `AGENTS.md` or `CLAUDE.md` and
does not modify user-global settings.

## Choose the coding model at project start

The coding worker is chosen per project — platform first, then the exact
model on it. The catalog is data, not code: copy
`config/model-catalog.example.json` and edit it to the models actually
installed or subscribed on the machine. Run interactively (omit
`--platform`/`--model` to get a menu):

```bash
python3 hub.py --runtime /protected/hub-runtime model select my-system \
  --catalog config/model-catalog.example.json --actor OWNER \
  --http-bridge-executable /mnt/c/Windows/System32/curl.exe
```

Selection runs a real one-packet synthetic probe against the chosen model in
a throwaway runtime and records that result — never catalog claims — as the
model's evaluation. A passing probe approves the model and pins the
project's routing policy to exactly that choice with `max_attempts` 1: no
automatic escalation and no automatic fallback; a defeated or unreachable
model blocks cleanly and waits for a human decision.
Re-run `model select` at any time to change the choice. After selection,
guided runs need no per-invocation flags: `run` without `--model` uses the
project's pinned choice and stored transport automatically (audited as
`model.selection-used`).

### Subscription-CLI coding workers

Guided runs can use a logged-in Claude Code or Codex subscription CLI as
the coding worker instead of local Ollama:

```bash
python3 hub.py --runtime /protected/hub-runtime run "..." \
  --system my-system --through verified --guided-plan .../plan.json \
  --supervisor-source claude-interactive \
  --adapter claude-subscription-cli --model haiku \
  --cli-executable /absolute/path/to/claude
```

(`codex-subscription-cli` with `--model default` uses the model the Codex
subscription is configured with.) The worker is text-only generation:
headless `claude -p` with tools disallowed, or `codex exec` in a read-only
sandbox, running in an empty scratch directory with a scrubbed environment
that never inherits provider API keys — so usage stays on the subscription,
never metered API billing. Unlike local workers this transport sends the
bounded packet context to the vendor; every outbound prompt is
audit-logged with its SHA-256 and byte count before the call, and
subscription adapters accept guided plans only. A Claude-CLI worker shares
the Claude subscription usage window with an interactive Claude Code
supervisor session; Codex does not.

### Metered HTTP API coding workers

Guided runs can also use a vendor HTTP API — Anthropic-native
(`--adapter anthropic-api`) or any OpenAI-compatible endpoint such as
OpenAI, MiniMax, GLM, or Kimi (`--adapter openai-compatible-api`). This
transport costs real money per token, so it is fail-closed twice over:

1. The system needs an approved `vendor-api` provider profile with live
   egress explicitly enabled (`provider propose` → `provider approve
   --enable-live`), whose endpoint origin must match the base URL.
2. Every run requires explicit economics: `--input-cost-per-mtok`,
   `--output-cost-per-mtok`, and a hard `--max-task-cost-usd` spend cap.
   Token usage from each response is metered and audited
   (`worker.tokens-metered`); when the accumulated task spend reaches the
   cap the hub blocks and asks the human — it never switches providers.
   The cap is enforced before egress against the call's worst-case cost, so
   no call that could breach it is made. That bound adds an allowance for
   the tokens a vendor bills for request framing; if a vendor's observed
   input billing exceeds the prompt's own byte count by more than the
   default, raise `--framing-token-overhead` (also accepted by
   `model select`, which stores it with the selection).

The API key is read from a private single-line key file
(`--api-key-file`, must be `chmod 600`) at call time. Keys are never read
from environment variables, never stored in hub state or audit, and are
redacted from any error text. As with subscription workers, prompts are
audit-logged with their SHA-256 before egress, secret-like material is
refused in both directions, and only guided plans are accepted.

```bash
python3 hub.py --runtime /protected/hub-runtime run "..." \
  --system my-system --through verified --guided-plan .../plan.json \
  --supervisor-source claude-interactive \
  --adapter anthropic-api --model claude-haiku-4-5-20251001 \
  --api-base-url https://api.anthropic.com \
  --api-key-file /home/me/.hub-secrets/anthropic.key \
  --input-cost-per-mtok 1.00 --output-cost-per-mtok 5.00 \
  --max-task-cost-usd 0.25
```

For OpenAI-compatible vendors the base URL carries the vendor's path
prefix (for example `https://api.openai.com/v1`); the adapter appends
`/chat/completions`. Verify current token prices at the vendor console —
the hub meters against the prices you pass; it cannot know the vendor's
real prices.

## One-command guided local implementation

The recommended path is high-model decomposition plus isolated research and
one broker-selected file at a time. Create a plan using
`docs/GUIDED_ORCHESTRATION.md`, then run:

```bash
python3 hub.py --runtime /protected/hub-runtime run \
  "Implement the requested change and fully verify it" \
  --system my-system --through verified \
  --guided-plan /protected/hub-runtime/inbox/plan.json \
  --supervisor-source codex-interactive \
  --adapter codex-local --model INSTALLED_MODEL
```

For a Windows Ollama installation visible from WSL, use the explicit local
loopback bridge `--http-bridge-executable
/mnt/c/Windows/System32/curl.exe`. It sends requests only to the validated
Ollama loopback endpoint, keeps prompts off the command line, and enforces an
output-token cap and stop sequence. The older `--executable ollama.exe`
transport remains suitable for short structured probes but guided file
generation rejects it because it cannot enforce those bounds.

The broker preflights the model before creating a task worktree. The high model
chooses exact deliverables; the local model returns one raw file body and never
chooses a path or runs a command. Isolated research workers have internet but
no repository. Local workers have repository context but no internet and see
only high-model research guidance plus official source hashes. Deterministic
per-packet, targeted, and full gates—not model confidence—decide whether the
task reaches `VERIFIED`.

## Per-project modifiers

Modifiers specialize each registered system without weakening global rules.
Examples are under `config/modifiers/`; see `docs/PROJECT_MODIFIERS.md`.

```bash
python3 hub.py --runtime /protected/hub-runtime modifier propose my-system \
  --file config/modifiers/standard-local.example.json --proposer OWNER
python3 hub.py --runtime /protected/hub-runtime modifier approve MODIFIER_ID \
  --approver OWNER
```

Select it with `run --modifier MODIFIER_ID`. The immutable task snapshot records
the modifier hash.

## Operational boundary

Cloud and deployment adapter interfaces are active but fail closed until a
project-local provider/CI identity is separately approved. CLI approval labels
are not cryptographic identities. Regulated production use still requires a
dedicated OS account/runtime, approved credential/provider backends, actual
client contracts and jurisdiction review, authenticated human approvals, and
an authorized low-risk pilot. See `docs/OPERATIONS_RUNBOOK.md` and the project
dossier for the exact remaining risks.
