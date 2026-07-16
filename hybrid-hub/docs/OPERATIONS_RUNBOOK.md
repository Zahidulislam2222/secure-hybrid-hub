# Operations and regulated-use runbook

## Before any real project

1. Run the broker under a dedicated OS account on an OS-protected Linux/WSL
   filesystem; do not store sensitive runtime state on broadly readable NTFS.
2. Register only exact project roots and verify discovery/dossier contents.
3. Select the real client profiles, jurisdictions, retention, contracts, data
   classes, and a separately approved project modifier.
4. Approve deterministic build/test/scan commands. Specialized healthcare,
   legal, GDPR, financial, and production gates must have real implementations.
5. Configure an organizational secret backend and workload identity outside
   model context. The repository ships only a synthetic backend.
6. Configure cloud and CI/CD provider identities only after contract, account,
   endpoint, BAA/DPA/transfer, and authorization review.
7. Replace string approver labels with an authenticated organizational approval
   service before regulated production operations.

## Routine evidence

```bash
hub audit verify
hub operations access-review
hub operations security-evaluation
hub operations sbom --source /path/to/hub-or-project
hub operations retention --days DAYS
```

Retention defaults to preview. `--execute` is explicit and never deletes audit
or dossier history or evidence referenced by quality/research records.

## Backup and restore drill

```bash
hub operations backup
hub operations verify-backup BACKUP_ID
hub operations restore-backup BACKUP_ID --destination /empty/restore/drill
```

Built-in backups are integrity-protected but not encrypted. Store them only on
an approved encrypted/OS-protected volume. Restore refuses a non-empty target.

## Incident response

1. Activate `hub emergency-stop` to prevent new worker/provider actions.
2. Preserve runtime, worktrees, audit chain, and hashed evidence; do not paste
   raw logs or records into a model.
3. Rotate/revoke credentials through the real secret/provider owner when
   exposure is suspected.
4. Create a sanitized diagnostic bundle or synthetic reproduction.
5. Verify audit integrity, review provider/capability access, and record the
   incident through the responsible organization's process.
6. Restore from a verified backup into an empty location and test before reuse.
7. Clear emergency stop only after an authorized human approves recovery.

## Production progression

Only an approved CI/CD transport receives artifact IDs and parameters. Models
never receive production credentials or shells. The enforced sequence is:

```text
VERIFIED -> STAGING_DEPLOYED -> STAGING_VERIFIED
 -> single-use PRODUCTION_APPROVAL -> PRODUCTION_CANARY
 -> PRODUCTION_VERIFIED -> HUMAN_ACCEPTED
```

A failed canary invokes the approved rollback action and records non-secret
evidence. Destructive data/IAM/network changes require separate authorization
outside a general “finish” request.
