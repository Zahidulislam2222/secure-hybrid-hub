# Hub backend and CLI

This is the Python implementation of the open-source Secure Hybrid AI Development
Hub. It coordinates registered repositories, workspaces, model workers, policy,
verification and evidence. It is experimental and pre-production. There is no
browser frontend or general web API in this directory; see the proposed
[frontend/API design](docs/FRONTEND_API.md) and [current status](docs/STATUS.md).

## Requirements and verification

Use Python 3.11+, Git and a POSIX host. Linux/WSL2 is the reference environment for
Linux sandbox controls. Native Windows is unsupported. macOS needs separate
isolation validation. The Python runtime has no third-party dependencies; model
services and test/build tooling are installed separately when required.

From this directory:

```bash
python3 hub.py --help
PYTHONPATH=src python3 -m unittest discover -s tests -v
# Optional, if pytest is installed:
pytest -q
```

The suite uses synthetic repositories and mocked external providers. It includes
path/policy refusal, task recovery, adapter, topology and operational simulations.
Some tests require local sockets or host isolation primitives. Record environment
failures explicitly. Neither these commands nor installing the package requires
an account with a project-operated hosted service.

## Disposable local runtime

For a synthetic local demonstration on a POSIX filesystem:

```bash
HUB_RUNTIME="$(mktemp -d)"
python3 hub.py --runtime "$HUB_RUNTIME" init-runtime
python3 hub.py --runtime "$HUB_RUNTIME" audit verify
```

The temporary path is an example for a disposable trial. For continuing work,
choose a persistent owner-only runtime on an OS-protected filesystem and pass
that same path on every invocation. Keep it outside the public repository and
back it up. Do not put sensitive runtime state on a filesystem that cannot enforce
required ownership/modes. A missing runtime is not permission to reuse another one.

## Register one exact project

Set `PROJECT_ROOT` to the authorized repository. For an initial trial use only a
synthetic test repository. Then register and review it:

```bash
python3 hub.py --runtime "$HUB_RUNTIME" system init   --id example-system --client example-owner --name "Synthetic example"   --root "$PROJECT_ROOT" --profile standard --purpose "Synthetic validation"
python3 hub.py --runtime "$HUB_RUNTIME" system show example-system
python3 hub.py --runtime "$HUB_RUNTIME" dossier show example-system --include-draft
python3 hub.py --runtime "$HUB_RUNTIME" system approve example-system --approver OWNER
```

`OWNER` is an illustrative actor label, not proof of an authenticated identity.
Registration is exact opt-in; it does not grant access to sibling projects.
Review [approval gaps](docs/STATUS.md) before real use.

Optional project-local integration:

```bash
python3 hub.py --runtime "$HUB_RUNTIME" integrations install   --system example-system --project "$PROJECT_ROOT"
```

This creates a local marker/skills and merges VS Code tasks. It does not install
global agent configuration. Review generated changes before keeping them.

## Configuration map

| Configuration | Owner and example |
|---|---|
| Runtime and roots | Explicit CLI arguments and registered system; private local state |
| Policy defaults | [policy example](config/policy.example.toml) |
| Adapter settings | [local adapter example](config/adapters/local.example.toml) |
| Model catalog | [catalog example](config/model-catalog.example.json); verify actual availability |
| Project restrictions | [modifier examples](config/modifiers/), proposed/approved per system |
| Research service | [research example](config/research/searxng.example.yml); installation is separate |
| Task scope | Guided plan with exact context/deliverable paths and acceptance criteria |
| HTTP credentials | Private owner-only key file referenced at execution; never committed |
| Provider economics | Explicit current token prices, timeout/output limits and task spend ceiling |

Examples are not production configurations or live provider authorization. The
current project uses files, registry state and CLI settings; it does not provide
an all-in-one `.env` contract. See `python3 hub.py --help` and each subcommand's
`--help` for the implemented interface. A central-settings audit remains planned.

## Model selection and costs

The registry supports local workers, subscription CLI workers and metered HTTP
API workers. See [model routing](docs/MODEL_ROUTING_OPERATIONS.md). Catalog entries
are examples; validate the installed model/account and explicit task choices.
A stored selection or a successful connectivity probe is not authorization to
expand data scope, fallback, spending or production access.

`model select` can execute a real synthetic model probe. It is not an offline
listing command. Confirm the provider, data boundary and any cost before invoking
it. Local inference uses your hardware; subscription execution may consume
allowance or paid extras depending on account settings; HTTP APIs charge under
provider terms. Never infer billing behavior solely from an adapter name.

The HTTP adapter accepts `--api-base-url`, `--api-key-file`, explicit input/output
prices and `--max-task-cost-usd`. Read its help before use. Prices and model IDs
must come from current configuration. Spending estimates are not provider invoices.
No paid command is needed for the offline setup and tests above.

## Guided execution

Write a bounded plan using [guided orchestration](docs/GUIDED_ORCHESTRATION.md).
After explicit model and scope authorization, a local-worker command has this form:

```bash
python3 hub.py --runtime "$HUB_RUNTIME" run "Authorized synthetic task"   --system example-system --through verified --guided-plan "$GUIDED_PLAN"   --supervisor-source codex-interactive   --adapter codex-local --model "$APPROVED_LOCAL_MODEL"
```

`GUIDED_PLAN` and `APPROVED_LOCAL_MODEL` must be supplied by the operator; there is
no implied model download or fallback. Connectivity, code quality and complete
workflow enforcement are distinct gates. Never treat generated output as a release.

## Status, recovery and operations

```bash
python3 hub.py --runtime "$HUB_RUNTIME" status TASK_ID
python3 hub.py --runtime "$HUB_RUNTIME" audit verify
python3 hub.py --runtime "$HUB_RUNTIME" dossier show example-system
```

Preserve blocked/interrupted workspaces. Resume only from a supported state with
its exact missing input; do not repeat an already-consumed approval or provider
call. Follow the [operations runbook](docs/OPERATIONS_RUNBOOK.md) for cancellation,
backup, restore and incident response.

## Troubleshooting

| Symptom | Safe next step |
|---|---|
| Runtime permission refusal | Use an owner-protected POSIX runtime; do not weaken permission checks |
| Socket/sandbox test failure | Record host restriction and rerun in a supported isolated environment |
| Resource already leased | Inspect owning task; use broker recovery/cancellation, not database edits |
| No eligible model | Check explicit selection, evaluation, policy and account authorization |
| Provider failure or budget block | Preserve evidence; do not switch provider or increase spend automatically |
| Quality failure on synthetic fixtures | Inspect approved exact fixture evidence; never disable the scanner |
| Native Windows import/platform error | Run inside WSL2; direct Windows execution is unsupported |

See the [public documentation index](docs/README.md), [roadmap](docs/ROADMAP.md)
and [license](../LICENSE). Self-hosting transfers operational responsibility to
the operator; production/client use still needs the applicable release gates.
