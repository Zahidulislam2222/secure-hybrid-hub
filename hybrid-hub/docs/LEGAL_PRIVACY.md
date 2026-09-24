# Open-source licensing, privacy and legal readiness

This is a deployment-planning guide, not a contract or a declaration of universal
compliance. Legal obligations depend on the operator, jurisdiction, people served,
data, providers and intended use. Review them before processing real client data.

## Open-source license

The source repository uses [Apache License 2.0](../../LICENSE). Redistribution
requires the applicable license and notices, retention of relevant attribution,
and notices of modified files. Preserve applicable NOTICE material when present.
The license includes a patent grant with conditions and does not grant general
trademark rights. Review the authoritative
[Apache license text](https://www.apache.org/licenses/LICENSE-2.0).

Open-source availability does not grant rights to client repositories, personal
data, model weights, provider services or third-party dependencies. Review each
license/contract separately. Contributors must have rights to their submitted
work; do not submit confidential employer/client material. Proposed model output
still needs provenance, license and security review before redistribution.

## Responsibility boundaries

| Actor | Responsibility |
|---|---|
| Project maintainers | Source/license clarity, vulnerability handling and accurate release claims |
| Self-hosting operator | Lawful processing, deployment security, notices, contracts and incident procedures |
| Organization/customer | Authority over supplied projects/data and allowed processing purposes |
| Model/infrastructure provider | Obligations under its actual service terms and signed agreements |

Installing the software does not sign a DPA, BAA, SLA or support agreement with
its maintainers. A future operator offering a hosted service must publish its own
privacy notice, terms, contact details, subprocessors and service commitments
before collecting user data. This repository does not invent those details.

## Applicability assessment

| Area | Questions and evidence needed before use |
|---|---|
| General privacy | What data is processed, for what purpose, under whose authority, in which locations? |
| EU/EEA GDPR | Does territorial/material scope apply? Identify controller/processor roles, legal bases, rights and transfer arrangements |
| US HIPAA | Is the use by/for a covered entity or business associate, and does it involve PHI? Determine required agreements and safeguards |
| Other jurisdictions | Assess national/state privacy, breach, employment, consumer and cross-border rules for the actual market |
| Legal/confidential work | Assess client consent, professional secrecy, privilege and contractual disclosure limits |
| Finance or critical services | Assess applicable sector rules, records, resilience and outsourcing requirements |
| AI-specific regulation | Classify actual use and organizational role under applicable AI law before market deployment |
| Children, payments and biometrics | Treat as distinct scope requiring specialist review; do not assume ordinary account-data controls suffice |

GDPR applicability and the distinction between anonymous and re-identifiable data
are described by the [European Commission](https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/application-gdpr_en).
HIPAA applies to defined covered entities and business associates; see
[HHS applicability guidance](https://www.hhs.gov/hipaa/for-professionals/covered-entities/index.html).
A profile named `healthcare`, `legal` or `gdpr` is a policy selection, not legal
certification. SOC 2 and ISO 27001 are separate assurance frameworks, not substitutes
for determining applicable law; no certification is claimed here.

## Data inventory and lifecycle

| Data category | Proposed default handling |
|---|---|
| Source and task instructions | Minimum authorized scope; local-only when classification requires |
| Identity/membership | Minimum operator-required identity; access-controlled and revocable |
| Credentials | Approved secret backend or protected capability; never model context |
| Model prompts/results | Minimized, scanned and provider-authorized before egress |
| Diagnostics/evidence | Structured, bounded and redacted; avoid raw transcripts and production records |
| Audit/approval records | Tamper-evident metadata with defined legal retention and access |
| Backups | Encrypted, bounded retention, documented restore and deletion behavior |
| Browser analytics | No private source/tokens; optional telemetry needs transparent operator policy |

Before rollout, document collection, purpose, legal basis where applicable,
recipients, storage locations, retention, deletion and restore behavior for every
category. Avoid a universal retention duration: contracts, legal holds and statutory
requirements may conflict. Define how deletion requests interact with audit records,
backups, provider retention and mandatory preservation, and test the workflow.

The current retention command preserves audit/dossier history and referenced
evidence. It is not a complete personal-data erasure mechanism. Operators must
resolve data minimization and retention requirements before real-data admission.

## Provider and launch review

Check actual account terms for training use, retention, regional processing,
subprocessors, support access and incident notification. A subscription label,
local adapter name or pricing tier does not establish confidentiality guarantees.
Record the review date and exact agreement/account scope without publishing secrets.

Before real-client launch require: a data-flow map, threat assessment, applicable
contracts and notices, approved vendors, retention/deletion tests, access reviews,
incident contacts, jurisdiction-specific notification procedure and a controlled
pilot. See [roadmap](ROADMAP.md) and [security design](SECURITY_DESIGN.md).
