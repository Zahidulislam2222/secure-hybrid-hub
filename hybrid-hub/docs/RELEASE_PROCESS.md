# Contribution, verification and publication process

This process applies to the open-source repository. Publishing documentation is
not deploying the software or announcing a production-ready release.

## Prepare a bounded change

1. Record acceptance criteria and the baseline commit before implementation.
2. Work on one branch per coherent change. Preserve unrelated local work.
3. Update behavior, tests and public docs together; separate current behavior
   from proposed designs. Use safe configuration examples.
4. Review exact changes and dependency licenses. Never bypass security hooks or
   weaken tests/scanners to obtain a passing result.

## Validation evidence

| Gate | Evidence to record |
|---|---|
| Tests | Exact command, interpreter/OS, collected count, skips/failures and exit code |
| Behavioral | Actual CLI/UI journey and both allowed/refused cases |
| Types and lint | Configured tool/rules and result; explicitly record if unconfigured |
| Security | Secret scan of candidate and history, code scan, redacted findings and disposition |
| Packaging | Clean wheel/source build, install/import/entry-point check and artifact hashes |
| Documentation | Relative links in published tree, accurate CLI examples, private-path exclusion |
| Review | Reviewer independent of implementation, criteria coverage and unresolved findings |

The current workflows run tests on Python 3.11–3.13 for `main` pushes and pull
requests. Security runs on `main`/`master` pushes and pull requests. A push to
another branch does not itself prove CI ran. Inspect the actual workflow/check
results before merging; do not infer green checks from a successful Git push.

Documentation-only changes need link/content/security validation and appropriately
scoped regression checks. They do not justify silently refactoring the backend.
Baseline failures must be disclosed and tracked separately. A full release still
needs its own green gates; publishing a truthful limitation is not fixing it.

## Safe Git publication

Inspect staged paths and content, not just the working-tree status. Explicitly
stage intended public paths. Check private records, environment values, keys,
runtime databases, generated exports and local agent memory are ignored and absent
from the candidate. Inspect reachable history for accidental sensitive publication.

Push a named branch without force. Review its comparison against the base, open a
pull request when appropriate, and respect branch protection and required checks.
Never use administrator bypass to merge a failing change. Verify the remote ref
equals the local commit after push. A branch publication and a default-branch merge
are separate events and must be reported separately.

Keep the [Apache license](../../LICENSE) intact. Publish a changelog, artifact
digests and a source-tag relationship for versioned releases. Do not tag a new
version or manufacture a release artifact solely for a documentation refresh.

## Community practice

Use public issues for reproducible non-sensitive bugs and design discussions.
Use [private reporting](../../SECURITY.md) for vulnerabilities. Maintain respectful,
specific technical discussion, credit contributors and explain rejected proposals.
Do not post client data or raw private runtime evidence into issues/PRs.

GitHub's [repository guidance](https://docs.github.com/en/repositories/creating-and-managing-repositories/best-practices-for-repositories)
supports clear entry-point documentation, security reporting and reviewed branch
workflows. Repository settings should be verified, not assumed from these docs.
