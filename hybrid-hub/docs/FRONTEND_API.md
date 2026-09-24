# Planned frontend and web API

**Design proposal.** No browser application or public HTTP API is implemented
in this tree. The current UI is the [CLI and editor integration](../README.md).
This specification is intended for open-source contributors and self-hosting
operators; selecting a frontend framework is a separate implementation decision.

## User journeys

| Journey | Proposed behavior and acceptance evidence |
|---|---|
| Register a project | Show exact roots, topology and data classification; approval precedes access |
| Start a task | Show supervisor, worker, model, account mode, effort, egress, limits and fallback together |
| Understand eligibility | Explain unavailable, unevaluated or policy-prohibited models without silently substituting one |
| Monitor work | Show state, bounded progress events, last update and verified gate results |
| Resolve a block | Identify the exact missing input; preserve context and resume without replaying completed actions |
| Approve an action | Show artifact/action scope and expiry; changed scope invalidates approval |
| Review a result | Present sanitized diff, test evidence and limitations; separate verification from deployment |
| Cancel/recover | Confirm cancellation state and preserved evidence; explain any already-started external action |
| Deploy | Require a separate deployment approval with environment, release and rollback plan |

Do not display raw secrets, unrestricted logs or confidential source to users
without the required authorization. Download/export flows need the same checks.
Do not expose implementation diagnostics when an actionable explanation suffices.

## Frontend requirements

- Responsive layouts and keyboard-operable navigation, dialogs and task controls.
- Visible focus, text alternatives, labelled inputs and errors, sufficient
  contrast, reduced-motion support, and screen-reader announcements for state.
- Target WCAG 2.2 AA, verified by automated checks plus manual keyboard and
  assistive-technology testing. This is an accessibility target, not certification.
  Source: [W3C WCAG 2.2](https://www.w3.org/TR/WCAG22/).
- Virtualized or paginated task lists; bounded event buffers; resumable streams;
  display stale/disconnected state instead of silently showing old data as live.
- Render untrusted Markdown/diffs with a safe renderer. Disable arbitrary HTML,
  executable links and scriptable attachments; apply a restrictive CSP.
- Serve versioned static assets with caching. Never put tokens or private
  project data into public caches, analytics events, URLs or browser persistence.

## API contract to implement

The following resource families are proposed, not available endpoints:

| Family | Operations | Required boundary |
|---|---|---|
| Projects | Register, inspect, disable | Tenant membership and exact scope |
| Tasks | Submit, read, cancel, resume | Object authorization and idempotency |
| Selections | List eligible models, confirm task envelope | Policy-filtered inventory and explicit choice |
| Approvals | Issue challenge, decide, consume | Authenticated identity, expiry, anti-replay and atomic consume |
| Evidence | List gate results, inspect allowed artifacts | Redaction, content type/size and scoped download |
| Events | Subscribe, reconnect from cursor | Per-task authority, bounded buffers and cursor validation |
| Releases | Inspect verified manifest, request promotion | Immutable artifact and separate deployment authority |

Before implementation, publish a versioned OpenAPI contract with request limits,
pagination, structured errors and compatibility rules. An opaque error reference
may point to protected diagnostics. Never put a raw stack trace in an API response.
Cancellation and retries need explicit state-transition semantics.

## Identity and safety

Support operator-selected identity providers; verify sessions on the server.
Use secure, HTTP-only cookies with CSRF protection for a browser session design,
or an equally reviewed token design. Restrict CORS to configured origins. Apply
object-level authorization on every API/event request, MFA or step-up for
privileged actions, and revocation propagation to existing streams.

Suggested roles are reader, contributor, approver and operator; define a precise
permission matrix before coding. A client-supplied tenant ID never grants access.
Apply bounded body sizes, rate limits and per-tenant quotas. An unavailable
authorization service fails closed even if read-only status remains available.

## Release tests

Exercise registration → selection → task → quality evidence → approval → result
with synthetic repositories. Include cross-tenant ID substitution, replay,
expired approval, revoked access during streaming, reconnect storms, duplicate
submission, stale tabs, network loss and malicious rendered content. Browser tests
must prove users cannot bypass broker policy by calling the API directly.
