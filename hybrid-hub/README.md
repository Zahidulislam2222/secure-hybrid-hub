# Secure Hybrid AI Development Hub

This is the project-local, opt-in implementation of
`../docs/FINAL_BUILD_PLAN.md`. It coordinates registered Git repositories,
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

## One-command local implementation

```bash
python3 hub.py --runtime /protected/hub-runtime run \
  "Implement the requested change and fully verify it" \
  --system my-system --through verified \
  --adapter codex-local --model INSTALLED_MODEL
```

For a Windows Ollama installation visible from WSL, add the explicit absolute
`--executable` path. The broker preflights the model before creating a task
worktree. Models return typed file operations; they never receive arbitrary
shell authority. Deterministic targeted and full gates—not model confidence—
decide whether the task reaches `VERIFIED`.

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
