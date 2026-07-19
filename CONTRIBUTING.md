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
PYTHONPATH=src:tests python3 -m unittest tests.test_release_phases
```

The full suite is synthetic and offline: it must pass with no network access,
no credentials, and no installed services. A test that reaches the real
network, reads state outside its temp directory, or depends on a previously
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
   gitignored; keep it that way. CI runs gitleaks, bandit, and semgrep on
   every push and PR.

## Commit and PR expectations

- A PR description states what changed, why, and how it was verified
  (test output, not assertions of confidence).
- CI (test matrix + security scans) must be green.
- New files need the project's plain-prose style: explain constraints, not
  restated code.
