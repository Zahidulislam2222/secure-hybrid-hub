# Security Policy

The Secure Hybrid AI Development Hub is a fail-closed local policy broker.
Reports that show a way to bypass its path, network, provider, credential,
state, dossier-checkpoint, sandbox, or approval controls are treated as
security vulnerabilities, not ordinary bugs.

## Supported versions

| Version | Supported |
|---|---|
| Current development branch / 0.11.0 package line | Reports accepted; experimental, no production support guarantee |
| Older tags | Reproduce on current code where safe; no promised backport schedule |

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability.

Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on this repository.

Include the affected version or commit, a reproduction (a failing test or
exact CLI sequence is ideal), and the impact — which control is bypassed and
what an attacker gains.

The project aims to acknowledge reports within 7 days; volunteer availability
is not a support SLA. Coordinate disclosure timing with the maintainer, with
90 days as a starting discussion window rather than a guaranteed fix deadline.

## Scope notes

- The hub deliberately refuses to run on native Windows (POSIX-only sandbox
  primitives). Windows-specific crashes outside WSL2 are not vulnerabilities.
- The threat model assumes models are untrusted proposal generators. A model
  producing bad *proposals* is expected; the broker *accepting* an unsafe
  proposal it should have rejected is a vulnerability.

## Reporting channel and readiness

Use [GitHub private vulnerability reporting](https://github.com/Zahidulislam2222/secure-hybrid-hub/security/advisories/new).
Include a minimal synthetic reproduction and redact credentials, client source
and personal data. Do not upload a private runtime or raw production logs.
If private reporting is unavailable, request a private contact route without
posting exploit details publicly.

See the [threat model](hybrid-hub/docs/SECURITY_DESIGN.md),
[current gaps](hybrid-hub/docs/STATUS.md) and
[legal/privacy responsibilities](hybrid-hub/docs/LEGAL_PRIVACY.md).
The open-source license does not provide a security certification or hosted SLA.
