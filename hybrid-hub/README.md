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
model blocks cleanly and waits for a human decision. Platforms whose
adapter is not implemented yet (subscription CLIs, vendor HTTP APIs) are
listed for the roadmap but fail closed when selected. Re-run `model select`
at any time to change the choice.

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
