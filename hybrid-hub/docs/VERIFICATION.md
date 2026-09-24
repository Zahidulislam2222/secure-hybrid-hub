# Documentation publication verification

Date: 2026-09-24. Backend source baseline: `945ee2271ef37ec1597e7a1d5671ba6d0ef1dd77`.
The documentation publication changes public Markdown and ignore rules; it does
not integrate unfinished worker output, modify Python behavior or release a new
package version. Git history identifies the publication commit containing this file.

## Checks performed

| Check | Result and scope |
|---|---|
| Synthetic suite | Python 3.12: **257 passed, 1 skipped** using `python3 -m pytest -q` in a clean public snapshot |
| Skip | Private master dossier is intentionally absent from public checkouts |
| Initial restricted run | `unittest` collected 258; one loopback-server test hit sandbox socket denial, one skipped; rerun with local sockets allowed passed |
| CLI behavior | Runtime init, synthetic registration, inspection, draft dossier, approval, approved dossier, audit, backup, verification and restore passed |
| Secret scan | Gitleaks 8.30.1: zero findings in the public snapshot and its reachable Git history |
| Python security | Bandit 1.9.4 at the repository CI medium/high threshold: zero findings |
| Semgrep | Repository CI security-audit configuration: zero findings/errors; existing HTTPS-connection rule exclusion retained unchanged |
| Build | Source distribution and wheel built with setuptools 84.0.0 and build 1.6.1 |
| Install smoke | Wheel installed to a temporary directory; module help, runtime initialization and synthetic registration passed |
| Documentation | Public relative-link, code-fence and private-reference checks; all README entry points refreshed |
| Private artifacts | Credentials, private dossier, memory, local marker, exports and ordinary environment files excluded; checked private paths absent from reachable publication history |
| Type/lint | No configured standalone type checker or general Python linter was run; Python source is unchanged in this documentation update |
| Review | Documentation content and exact publication scope reviewed by the author; no independent code-review claim is made for this documentation update |

## Build compatibility finding

An initial build using the host's older setuptools failed to parse the SPDX
`project.license` string. Building with setuptools 84.0.0 succeeded. The declared
minimum remains `setuptools>=68`, which is too permissive for this metadata form;
SPDX license-expression support arrived in setuptools 77. Treat tightening the
build requirement as an outstanding packaging task, not a completed fix.
Source: [setuptools license migration](https://setuptools.pypa.io/en/stable/userguide/license_migration.html).

## Interpretation and reproducibility

Tests used synthetic data, local disposable runtimes and mocked model providers.
No real model invocation, cloud deployment or paid infrastructure was used for
these checks. Security scans are evidence for their configured scope, not proof
that no vulnerability exists. No million-user test or live uptime measurement ran.

Reproduce using the [setup commands](../README.md) and the
[release process](RELEASE_PROCESS.md). Check GitHub workflow results for the exact
PR/commit: a successful push alone does not establish CI success. Build tools were
installed in temporary validation storage, not added as runtime dependencies.

The public docs describe the remaining [status gaps](STATUS.md),
[scale gates](SCALABILITY.md) and [roadmap](ROADMAP.md). This publication establishes
documentation coverage and the checks above, not production release readiness.
