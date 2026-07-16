from __future__ import annotations

import json
import re
import uuid
from typing import Any

from .audit import AuditLog
from .dossier import DossierStore
from .errors import ConflictError, PolicyDenied, ValidationError
from .policy import RANK
from .storage import Database
from .util import require_id, sha256_json, utc_now


GATE = re.compile(r"^[a-z][a-z0-9._-]{1,63}$")
DENIABLE = {"cloud-review", "live-research", "secret-capability", "staging", "production"}


class ModifierStore:
    """Approved per-system workflow specialization that can never expand authority."""

    def __init__(self, database: Database, audit: AuditLog, dossier: DossierStore):
        self.database = database
        self.audit = audit
        self.dossier = dossier

    def propose(self, system_id: str, value: dict[str, Any], proposer: str) -> dict[str, Any]:
        require_id(proposer, "proposer")
        clean = self._validate(value)
        modifier_id = f"mod-{uuid.uuid4().hex[:16]}"
        digest = sha256_json(clean)
        with self.database.transaction() as connection:
            system = connection.execute("SELECT 1 FROM systems WHERE system_id=?", (system_id,)).fetchone()
            if not system:
                raise ValidationError("unknown system")
            duplicate = connection.execute("SELECT 1 FROM project_modifiers WHERE system_id=? AND name=? AND status='pending'", (system_id, clean["name"])).fetchone()
            if duplicate:
                raise ConflictError("a pending modifier with this name already exists")
            connection.execute("INSERT INTO project_modifiers VALUES(?,?,?,?,?,?,?,?,?,NULL)", (modifier_id, system_id, clean["name"], "pending", self.database.json(clean), digest, proposer, None, utc_now()))
            self.audit.append("modifier.proposed", {"modifier_id": modifier_id, "name": clean["name"], "modifier_hash": digest}, system_id=system_id, connection=connection)
        return self.get(modifier_id)

    def approve(self, modifier_id: str, approver: str) -> dict[str, Any]:
        require_id(approver, "approver")
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM project_modifiers WHERE modifier_id=?", (modifier_id,)).fetchone()
        if not row or row["status"] != "pending":
            raise ConflictError("pending modifier unavailable")
        modifier = json.loads(row["modifier_json"])
        proposal = self.dossier.propose(row["system_id"], {"security": {"active_modifier_name": modifier["name"], "modifier_hash": row["modifier_hash"], "authority_effect": "restrict-or-specialize-only"}})
        self.dossier.decide(proposal["proposal_id"], approver, True)
        with self.database.transaction() as connection:
            current = connection.execute("SELECT * FROM project_modifiers WHERE modifier_id=?", (modifier_id,)).fetchone()
            if not current or current["status"] != "pending":
                raise ConflictError("pending modifier unavailable")
            connection.execute("UPDATE project_modifiers SET status='superseded' WHERE system_id=? AND name=? AND status='approved'", (current["system_id"], current["name"]))
            connection.execute("UPDATE project_modifiers SET status='approved',approved_by=?,approved_at=? WHERE modifier_id=?", (approver, utc_now(), modifier_id))
            checkpoint = self.dossier.checkpoint(current["system_id"], f"modifier-{modifier_id}", "MODIFIER_APPROVED", {"actor": approver, "policy_hash": current["modifier_hash"], "classification": modifier["classification_floor"], "evidence": [current["modifier_hash"]], "unresolved_risks": []}, connection=connection)
            self.audit.append("modifier.approved", {"modifier_id": modifier_id, "modifier_hash": current["modifier_hash"], "approver": approver, "checkpoint_hash": checkpoint}, system_id=current["system_id"], connection=connection)
        return self.get(modifier_id)

    def get(self, modifier_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM project_modifiers WHERE modifier_id=?", (modifier_id,)).fetchone()
        if not row:
            raise ValidationError("unknown project modifier")
        result = dict(row)
        result["modifier"] = json.loads(result.pop("modifier_json"))
        if sha256_json(result["modifier"]) != result["modifier_hash"]:
            raise PolicyDenied("project modifier integrity check failed")
        return result

    def bind(self, task_id: str, modifier_id: str) -> dict[str, Any]:
        modifier = self.get(modifier_id)
        if modifier["status"] != "approved":
            raise PolicyDenied("task modifier must be approved")
        with self.database.transaction() as connection:
            task = connection.execute("SELECT system_id,classification FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not task or task["system_id"] != modifier["system_id"]:
                raise PolicyDenied("modifier cannot cross its registered system boundary")
            if RANK[task["classification"]] < RANK[modifier["modifier"]["classification_floor"]]:
                raise PolicyDenied("task classification is below the modifier floor; create a correctly classified task")
            existing = connection.execute("SELECT * FROM task_modifier_bindings WHERE task_id=?", (task_id,)).fetchone()
            if existing:
                if existing["modifier_id"] == modifier_id and existing["modifier_hash"] == modifier["modifier_hash"]:
                    return {"task_id": task_id, "modifier_id": modifier_id, "modifier_hash": modifier["modifier_hash"]}
                raise ConflictError("task modifier is immutable after binding")
            connection.execute("INSERT INTO task_modifier_bindings VALUES(?,?,?,?)", (task_id, modifier_id, modifier["modifier_hash"], utc_now()))
            self.audit.append("modifier.bound", {"modifier_id": modifier_id, "modifier_hash": modifier["modifier_hash"]}, system_id=task["system_id"], task_id=task_id, connection=connection)
        return {"task_id": task_id, "modifier_id": modifier_id, "modifier_hash": modifier["modifier_hash"]}

    def for_task(self, task_id: str) -> dict[str, Any] | None:
        with self.database.connect() as connection:
            row = connection.execute("SELECT modifier_id,modifier_hash FROM task_modifier_bindings WHERE task_id=?", (task_id,)).fetchone()
        if not row:
            return None
        modifier = self.get(row["modifier_id"])
        if modifier["modifier_hash"] != row["modifier_hash"] or modifier["status"] not in {"approved", "superseded"}:
            raise PolicyDenied("bound task modifier is unavailable or changed")
        return modifier

    def list(self, system_id: str) -> list[dict[str, Any]]:
        with self.database.connect() as connection:
            rows = connection.execute("SELECT modifier_id FROM project_modifiers WHERE system_id=? ORDER BY created_at", (system_id,)).fetchall()
        return [self.get(row["modifier_id"]) for row in rows]

    def require_action(self, task_id: str, action: str) -> None:
        modifier = self.for_task(task_id)
        if modifier and action in modifier["modifier"]["deny_actions"]:
            raise PolicyDenied(f"project modifier denies {action}")

    @staticmethod
    def _validate(value: Any) -> dict[str, Any]:
        required = {"name", "description", "classification_floor", "preferred_local_adapter", "allowed_local_models", "max_repairs", "context_bytes", "add_required_gates", "research_mode", "cloud_review", "deployment_posture", "deny_actions", "component_ids", "path_prefixes"}
        if not isinstance(value, dict) or set(value) != required:
            raise ValidationError("project modifier fields are incomplete or unknown")
        require_id(value["name"], "modifier name")
        if not isinstance(value["description"], str) or not value["description"].strip() or len(value["description"].encode()) > 2048:
            raise ValidationError("modifier description is invalid")
        if value["classification_floor"] not in RANK:
            raise ValidationError("modifier classification floor is invalid")
        if value["preferred_local_adapter"] not in {"codex-local", "claude-local"}:
            raise ValidationError("modifier local adapter is invalid")
        models = value["allowed_local_models"]
        if not isinstance(models, list) or not models or len(models) > 20 or any(not isinstance(item, str) or not 1 <= len(item) <= 128 or any(character.isspace() for character in item) for item in models):
            raise ValidationError("modifier allowed models are invalid")
        if not isinstance(value["max_repairs"], int) or not 0 <= value["max_repairs"] <= 3:
            raise ValidationError("modifier repair limit is invalid")
        if not isinstance(value["context_bytes"], int) or not 4096 <= value["context_bytes"] <= 32768:
            raise ValidationError("modifier context limit is invalid")
        gates = value["add_required_gates"]
        if not isinstance(gates, list) or len(gates) > 32 or any(not isinstance(item, str) or not GATE.fullmatch(item) for item in gates):
            raise ValidationError("modifier quality gates are invalid")
        if value["research_mode"] not in {"cache-only", "official-if-approved"}:
            raise ValidationError("modifier research mode is invalid")
        if value["cloud_review"] not in {"disabled", "if-approved", "required"}:
            raise ValidationError("modifier cloud review mode is invalid")
        if value["deployment_posture"] not in {"none", "staging", "production-controlled"}:
            raise ValidationError("modifier deployment posture is invalid")
        if not isinstance(value["deny_actions"], list) or set(value["deny_actions"]) - DENIABLE:
            raise ValidationError("modifier deny_actions are invalid")
        for field in ("component_ids", "path_prefixes"):
            items = value[field]
            if not isinstance(items, list) or len(items) > 100 or any(not isinstance(item, str) or not item or ".." in item.split("/") for item in items):
                raise ValidationError(f"modifier {field} are invalid")
        clean = json.loads(json.dumps(value))
        clean["allowed_local_models"] = sorted(set(clean["allowed_local_models"]))
        clean["add_required_gates"] = sorted(set(clean["add_required_gates"]))
        clean["deny_actions"] = sorted(set(clean["deny_actions"]))
        return clean
