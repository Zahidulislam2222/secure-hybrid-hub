# Security design and release requirements

The project is an experimental local broker. This document describes existing
boundaries and the requirements for expanding them. Consult [status](STATUS.md)
for gaps and [SECURITY.md](../../SECURITY.md) for private reporting.

## Threat model

| Threat | Intended boundary | Required adversarial evidence |
|---|---|---|
| Prompt injection from files/pages | Untrusted content cannot grant permissions | Malicious instructions cannot widen roots, egress or command scope |
| Secret disclosure through output | Approved secret-use tools and minimized diagnostics | Exact/encoded canaries absent from model context, artifacts and logs |
| Traversal/symlink/race attacks | Canonical roots and safe filesystem operations | Escape, replacement and race cases refused |
| Cross-project or tenant leakage | Separate identity, storage and authorization | Object substitution, cache and event-stream isolation tests |
| Approval forgery/replay | Authenticated action/artifact-bound authority | Expired, consumed, wrong-identity and changed-artifact refusals |
| Worker escape or network misuse | OS isolation and controlled outbound paths | Filesystem/process/network denial on supported kernels |
| SSRF and malicious research | Constrained research process without private repository access | Private-address, redirect, DNS and oversized-response tests |
| Double execution/stale writers | Transactions, idempotency and lease fencing | Crash/retry/reordering/concurrency tests |
| Audit tampering | Hash chain plus separately stored trusted anchor | Changed, truncated and consistently rebuilt-chain detection |
| Resource/billing exhaustion | Work limits, quotas and approved spend bounds | Oversized input, loop, timeout and ambiguous-billing tests |
| Compromised dependencies | Pinned/reviewed dependencies, scans and provenance | SBOM, reproducible artifact checks and update review |

Hash chaining alone cannot detect an attacker rebuilding the entire chain with
access to its storage. Store audit anchors separately with appropriate authority.
OS isolation depends on a trustworthy host/kernel and enforced filesystem permissions.
The current design does not defend against a fully compromised administrator host.

## Current controls versus required closure

The code contains path/policy checks, bounded workers, scanning, leases, audit and
approval primitives. Complete end-to-end task authority, authenticated production
approvals, enforced executable identity, real secret backends, scanner availability
and live network isolation remain release gates. Do not convert a written policy
into a claimed implemented control.

Fail closed when classification, authorization, scanner availability or audit
durability is uncertain. Model selection never permits otherwise-forbidden data
disclosure. Local models also must not receive raw secrets. Third-party provider
policies and account settings must be assessed before any permitted transmission.

## Proposed web/distributed requirements

Enforce tenant/object authorization on every API, artifact, approval and event.
Use reviewed authentication with revocation and step-up for privileged actions.
Separate worker identities from control-plane identities. Encrypt transport and
protected storage; define key ownership, rotation and recovery. Use egress
allowlists, per-tenant limits, safe rendering and explicit upload limits.

Map implementation tests to a chosen version of
[OWASP ASVS](https://owasp.github.io/www-project-application-security-verification-standard/).
ASVS is a verification framework, not a claim that this project has passed an audit.
Adopt risk-appropriate controls and publish the assessed scope and unresolved findings.

## Open-source supply chain and publication

- Review exact diffs; preserve genuine negative security tests and scanner rules.
- Scan candidate files and Git history with redacted output. Classify findings
  using evidence; rotate real exposed credentials, do not simply delete a line.
- Pin release inputs, inventory dependencies and inspect licenses. Keep build-time
  tools separate from the broker's standard-library runtime contract.
- Protect release authority, require checks/review and publish artifact digests.
- Keep private dossiers, local runtime, exports, keys and environment values out
  of commits. Public synthetic fixtures must be clearly identifiable as synthetic.
- Never enable paid automated model review or grant broader CI permissions as a
  side effect of updating documentation.

See [release process](RELEASE_PROCESS.md) for validation and failure handling.
