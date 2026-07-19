# Security Policy

The Secure Hybrid AI Development Hub is a fail-closed local policy broker.
Reports that show a way to bypass its path, network, provider, credential,
state, dossier-checkpoint, sandbox, or approval controls are treated as
security vulnerabilities, not ordinary bugs.

## Supported versions

| Version | Supported |
|---|---|
| 0.9.x | Yes |
| < 0.9 | No |

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability.

Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on this repository.

Include the affected version or commit, a reproduction (a failing test or
exact CLI sequence is ideal), and the impact — which control is bypassed and
what an attacker gains.

You can expect an acknowledgement within 7 days. Please allow up to 90 days
for a fix before public disclosure; coordinated earlier disclosure is fine
once a fixed release exists.

## Scope notes

- The hub deliberately refuses to run on native Windows (POSIX-only sandbox
  primitives). Windows-specific crashes outside WSL2 are not vulnerabilities.
- The threat model assumes models are untrusted proposal generators. A model
  producing bad *proposals* is expected; the broker *accepting* an unsafe
  proposal it should have rejected is a vulnerability.
