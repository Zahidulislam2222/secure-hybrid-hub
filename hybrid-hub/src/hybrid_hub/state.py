from __future__ import annotations

import json
import uuid
from typing import Any

from .audit import AuditLog
from .dossier import DossierStore
from .errors import ConflictError, PolicyDenied, ValidationError
from .storage import Database
from .util import bounded_text, require_id, utc_now

TRANSITIONS = {
    "NEW": {"REGISTERED_CONTEXT", "CANCELLED"},
    "REGISTERED_CONTEXT": {"CLASSIFIED", "CANCELLED"},
    "CLASSIFIED": {"SCOPED", "BLOCKED_POLICY", "CANCELLED"},
    "SCOPED": {"PLAN_BUNDLE_READY", "PLANNED", "WORKSPACES_READY", "CANCELLED"},
    "PLAN_BUNDLE_READY": {"PLANNED", "PAUSED_APPROVAL", "BLOCKED_POLICY", "CANCELLED"},
    "PLANNED": {"WORKSPACES_READY", "CANCELLED"},
    "WORKSPACES_READY": {"LOCAL_IMPLEMENTING", "PAUSED_INPUT", "PAUSED_AUTH", "PAUSED_APPROVAL", "FAILED_INFRA", "CANCELLED"},
    "LOCAL_IMPLEMENTING": {"TARGETED_TESTING", "LOCAL_REPAIRING", "PAUSED_INPUT", "PAUSED_AUTH", "PAUSED_APPROVAL", "BLOCKED_QUALITY", "BLOCKED_POLICY", "FAILED_INFRA", "CANCELLED"},
    "TARGETED_TESTING": {"LOCAL_REPAIRING", "FULL_QUALITY_GATES", "PAUSED_INPUT", "BLOCKED_QUALITY", "FAILED_INFRA", "CANCELLED"},
    "LOCAL_REPAIRING": {"TARGETED_TESTING", "PAUSED_INPUT", "BLOCKED_QUALITY", "BLOCKED_POLICY", "FAILED_INFRA", "CANCELLED"},
    "FULL_QUALITY_GATES": {"LOCAL_REPAIRING", "REVIEW_BUNDLE_READY", "RELEASE_EVIDENCE_READY", "BLOCKED_QUALITY", "FAILED_INFRA", "CANCELLED"},
    "REVIEW_BUNDLE_READY": {"CLOUD_REVIEWED", "PAUSED_APPROVAL", "BLOCKED_POLICY", "CANCELLED"},
    "CLOUD_REVIEWED": {"LOCAL_FIXING", "RELEASE_EVIDENCE_READY", "BLOCKED_QUALITY", "CANCELLED"},
    "LOCAL_FIXING": {"FULL_QUALITY_GATES", "BLOCKED_QUALITY", "CANCELLED"},
    "RELEASE_EVIDENCE_READY": {"VERIFIED", "BLOCKED_QUALITY", "CANCELLED"},
    "PAUSED_INPUT": set(), "PAUSED_AUTH": set(), "PAUSED_APPROVAL": set(),
    "BLOCKED_QUALITY": set(), "BLOCKED_POLICY": set(), "FAILED_INFRA": set(),
    "VERIFIED": {"STAGING_DEPLOYED", "CANCELLED"},
    "STAGING_DEPLOYED": {"STAGING_VERIFIED", "FAILED_INFRA", "CANCELLED"},
    "STAGING_VERIFIED": {"PRODUCTION_APPROVAL", "CANCELLED"},
    "PRODUCTION_APPROVAL": {"PRODUCTION_CANARY", "PAUSED_APPROVAL", "CANCELLED"},
    "PRODUCTION_CANARY": {"PRODUCTION_VERIFIED", "FAILED_INFRA", "CANCELLED"},
    "PRODUCTION_VERIFIED": {"HUMAN_ACCEPTED", "CANCELLED"},
    "HUMAN_ACCEPTED": set(), "CANCELLED": set(),
}

RESUME_TARGETS = {
    "PAUSED_INPUT": {"WORKSPACES_READY", "LOCAL_IMPLEMENTING", "LOCAL_REPAIRING"},
    "PAUSED_AUTH": {"WORKSPACES_READY", "REVIEW_BUNDLE_READY"},
    "PAUSED_APPROVAL": {"PLAN_BUNDLE_READY", "WORKSPACES_READY", "REVIEW_BUNDLE_READY"},
    "FAILED_INFRA": {"WORKSPACES_READY", "TARGETED_TESTING", "FULL_QUALITY_GATES"},
}


class TaskManager:
    def __init__(self, database: Database, audit: AuditLog, dossier: DossierStore):
        self.database = database
        self.audit = audit
        self.dossier = dossier

    def create(self, system_id: str, request: str, classification: str, policy_hash: str, task_id: str | None = None) -> dict[str, Any]:
        task_id = task_id or f"task-{uuid.uuid4().hex[:12]}"
        require_id(task_id, "task ID")
        bounded_text(request, 16_384, "task request")
        if classification not in {"R0", "R1", "R2", "R3", "R4"}:
            raise ValidationError("invalid task classification")
        now = utc_now()
        with self.database.transaction() as connection:
            system = connection.execute("SELECT approved FROM systems WHERE system_id=?", (system_id,)).fetchone()
            if not system or not system["approved"]:
                raise PolicyDenied("system and initial dossier must be approved")
            connection.execute("INSERT INTO tasks VALUES(?,?,?,?,?,?,NULL,0,?,?)", (task_id, system_id, request, "NEW", classification, policy_hash, now, now))
            self.dossier.checkpoint(system_id, "task-created", "NEW", {"actor": "broker", "policy_hash": policy_hash, "classification": classification, "evidence": []}, task_id=task_id, connection=connection)
            self.audit.append("task.created", {"classification": classification, "policy_hash": policy_hash}, system_id=system_id, task_id=task_id, connection=connection)
        return self.get(task_id)

    def transition(self, task_id: str, target: str, *, evidence: list[str] | None = None, reason: str | None = None, fail_checkpoint: bool = False) -> dict[str, Any]:
        if target not in TRANSITIONS:
            raise ValidationError("unknown target state")
        with self.database.transaction() as connection:
            row = connection.execute("SELECT tasks.*, systems.approved AS system_approved FROM tasks JOIN systems USING(system_id) WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                raise ValidationError("unknown task")
            current = row["state"]
            if not row["system_approved"] and target != "CANCELLED":
                raise PolicyDenied("system is disabled; only status and cancellation remain available")
            if target == current:
                return self._row(row)
            if target not in TRANSITIONS.get(current, set()):
                raise ConflictError(f"invalid transition {current} -> {target}")
            if fail_checkpoint:
                raise OSError("simulated checkpoint failure")
            payload = {"actor": "broker", "from": current, "to": target, "policy_hash": row["policy_hash"], "classification": row["classification"], "evidence": evidence or [], "unresolved_risks": [reason] if reason else []}
            occurrence = connection.execute("SELECT COUNT(*) FROM checkpoints WHERE task_id=? AND state=?", (task_id, target)).fetchone()[0]
            phase = target.lower() if occurrence == 0 else f"{target.lower()}-{occurrence + 1}"
            self.dossier.checkpoint(row["system_id"], phase, target, payload, task_id=task_id, connection=connection)
            now = utc_now()
            connection.execute("UPDATE tasks SET state=?,reason=?,cancelled=?,updated_at=? WHERE task_id=?", (target, reason, int(target == "CANCELLED"), now, task_id))
            self.audit.append("task.transition", {"from": current, "to": target, "reason": reason, "evidence": evidence or []}, system_id=row["system_id"], task_id=task_id, connection=connection)
        return self.get(task_id)

    def resume(self, task_id: str, target: str) -> dict[str, Any]:
        with self.database.transaction() as connection:
            row = connection.execute("SELECT tasks.*, systems.approved AS system_approved FROM tasks JOIN systems USING(system_id) WHERE task_id=?", (task_id,)).fetchone()
            if not row or row["state"] not in {"PAUSED_INPUT", "PAUSED_AUTH", "PAUSED_APPROVAL", "FAILED_INFRA"}:
                raise ConflictError("task is not resumable")
            if not row["system_approved"]:
                raise PolicyDenied("system is disabled")
            if target not in RESUME_TARGETS[row["state"]]:
                raise PolicyDenied("resume target is not allowed from this paused state")
            payload = {"actor": "broker", "from": row["state"], "to": target, "policy_hash": row["policy_hash"], "classification": row["classification"], "evidence": []}
            occurrence = connection.execute("SELECT COUNT(*) FROM checkpoints WHERE task_id=? AND phase LIKE ?", (task_id, f"resume-{target.lower()}%")).fetchone()[0]
            phase = f"resume-{target.lower()}" if occurrence == 0 else f"resume-{target.lower()}-{occurrence + 1}"
            self.dossier.checkpoint(row["system_id"], phase, target, payload, task_id=task_id, connection=connection)
            connection.execute("UPDATE tasks SET state=?,reason=NULL,updated_at=? WHERE task_id=?", (target, utc_now(), task_id))
            self.audit.append("task.resumed", {"from": row["state"], "to": target}, system_id=row["system_id"], task_id=task_id, connection=connection)
        return self.get(task_id)

    def cancel(self, task_id: str) -> dict[str, Any]:
        row = self.get(task_id)
        if row["state"] == "CANCELLED":
            return row
        return self.transition(task_id, "CANCELLED", reason="cancelled by user")

    def get(self, task_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if not row:
            raise ValidationError("unknown task")
        return self._row(row)

    @staticmethod
    def _row(row) -> dict[str, Any]:
        result = dict(row)
        result.pop("system_approved", None)
        result["cancelled"] = bool(result["cancelled"])
        return result
