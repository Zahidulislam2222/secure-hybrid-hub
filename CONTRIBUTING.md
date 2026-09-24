# Contributing

Thanks for your interest in the Secure Hybrid AI Development Hub.

## Requirements

- Linux, WSL2, or macOS (native Windows is not supported — the sandbox and
  quality runners use the Unix-only `resource` and `fcntl` modules; some
  isolation features are Linux-only, e.g. Landlock and namespaces).
- Python 3.11 or newer.
- Git.
- No third-party runtime dependencies: the hub is standard-library only, and
  contributions must keep it that way unless a maintainer agrees otherwise
  first.

## Running the tests

From `hybrid-hub/`:

```bash
# stdlib unittest (no extra installs needed)
PYTHONPATH=src python3 -m unittest discover -s tests

# or pytest (configuration lives in pyproject.toml)
pytest -q

# a single module
PYTHONPATH=src:tests python3 -m unittest test_release_phases
```

The full suite is synthetic and offline: it must pass with no network access,
no credentials, and no external provider services. Some tests require local
sockets and Linux isolation facilities; report host restrictions explicitly.
A test that reaches the real external network, reads state outside its temp directory, or depends on a previously
used runtime will be rejected.

## Making changes

1. Open an issue first for anything beyond a small fix, so scope can be
   agreed before you build it.
2. One feature or fix per branch/PR.
3. Add or update tests for every behavior change. The broker is fail-closed:
   when in doubt, the correct behavior is to refuse and raise a typed error
   from `hybrid_hub.errors`.
4. Do not weaken path, network, provider, credential, state, dossier, or
   approval controls to make a feature easier. PRs that bypass a control are
   closed.
5. No hardcoded environment-specific values (URLs, model IDs, paths,
   timeouts) in business logic; configuration flows in through constructors
   and the registry.
6. Never commit secrets. `.env*` files, keys, and local runtime state are
   gitignored; keep it that way. CI runs gitleaks, bandit and semgrep on
   configured default-branch pushes and pull requests; inspect actual checks.

## Commit and PR expectations

- A PR description states what changed, why, and how it was verified
  (test output, not assertions of confidence).
- CI (test matrix + security scans) must be green.
- New files need the project's plain-prose style: explain constraints, not
  restated code.

## Open-source scope and documentation

Contributions are under the existing [Apache-2.0 license](LICENSE). Submit only
material you have the right to share. Discuss dependency/license changes before
adding them; provider/model terms are separate from the repository license.
Keep discussion respectful, actionable and free of private client information.

Use the [roadmap](hybrid-hub/docs/ROADMAP.md) for open workstreams and the
[release process](hybrid-hub/docs/RELEASE_PROCESS.md) for evidence requirements.
Update both entry-point READMEs when usage/status changes. Planned designs must
state assumptions and exit gates. Public documentation belongs under
`hybrid-hub/docs/`; private operator records must remain excluded.

For frontend work, first agree the [API and accessibility contract](hybrid-hub/docs/FRONTEND_API.md).
For scale work, publish reproducible workload and capacity evidence. Preserve
local self-hosting and do not require a commercial service to run synthetic tests.
