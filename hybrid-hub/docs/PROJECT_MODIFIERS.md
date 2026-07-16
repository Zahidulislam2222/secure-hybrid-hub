# Project modifiers

A modifier is a versioned, human-approved specialization for one registered
system. It exists because a medical service, a legal matter system, a public
library, and a normal internal application should not use identical model,
research, review, quality, and deployment settings.

Modifiers can:

- set a classification floor;
- prefer `codex-local` or `claude-local`;
- allow only explicitly named installed models;
- reduce context and repair limits;
- add mandatory quality gates;
- select cache-only or separately approved official-source research;
- disable, optionally request, or require approved cloud review;
- disable deployment, permit staging, or permit controlled production;
- deny cloud review, live research, secret capabilities, staging, or production;
- scope intended component IDs and path prefixes for dossier/task planning.

They cannot enable a provider, add filesystem roots, insert credentials, remove
quality gates, raise managed repair/context limits, grant production authority,
or override a higher-level deny. Unknown fields fail validation.

Lifecycle:

```bash
hub modifier propose SYSTEM --file modifier.json --proposer OWNER
hub modifier approve MODIFIER_ID --approver OWNER
hub modifier show MODIFIER_ID
hub modifier list SYSTEM
hub run "TASK" --system SYSTEM --modifier MODIFIER_ID --through verified \
  --adapter codex-local --model ALLOWED_INSTALLED_MODEL
```

Approval creates a protected dossier change and an immutable checkpoint. A task
binding cannot be changed after creation. Superseding a modifier affects only
future tasks; in-flight tasks retain the approved hash they started with.

The example healthcare/legal modifiers intentionally require specialized gates.
They remain blocked until those gate commands are proposed and approved for the
actual project. This prevents a template name from being mistaken for legal or
technical compliance.
