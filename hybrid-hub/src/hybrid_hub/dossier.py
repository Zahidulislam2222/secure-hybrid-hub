from __future__ import annotations

import copy
import json
import re
import uuid
from typing import Any

from .audit import AuditLog, SECRET_PATTERNS, sanitize
from .errors import AuthorizationRequired, PolicyDenied, ValidationError
from .storage import Database
from .util import canonical_json, sha256_json, utc_now

PROTECTED_AREAS = {"architecture", "data_flows", "security", "compliance", "cloud_scope", "environments", "owners", "deployment", "exceptions", "approved_commands"}
MECHANICAL_AREAS = {"verified_commits", "test_evidence", "artifact_ids", "dependency_versions"}
FORBIDDEN_KEYS = re.compile(r"(?i)^(secret|secrets|secret_value|password|credential|credentials|token|api.?key|patient_record|customer_record|privileged_communication|raw_log|database_dump)$")
FORBIDDEN_CONTENT = [*SECRET_PATTERNS, re.compile(r"(?i)SYNTHETIC PHI|SYNTHETIC PII|PRIVILEGED LEGAL COMMUNICATION")]


class DossierStore:
    def __init__(self, database: Database, audit: AuditLog):
        self.database = database
        self.audit = audit

    def create_draft(self, system_id: str, payload: dict[str, Any]) -> int:
        clean = self._validate_payload(payload)
        with self.database.transaction() as connection:
            row = connection.execute("SELECT COALESCE(MAX(version),0)+1 FROM dossier_versions WHERE system_id=?", (system_id,)).fetchone()
            version = int(row[0])
            digest = sha256_json(clean)
            connection.execute("INSERT INTO dossier_versions VALUES(?,?,?,?,?,?)", (system_id, version, 0, self.database.json(clean), digest, utc_now()))
            self.audit.append("dossier.drafted", {"version": version, "dossier_hash": digest}, system_id=system_id, connection=connection)
        return version

    def approve(self, system_id: str, version: int, approver: str) -> None:
        with self.database.transaction() as connection:
            changed = connection.execute("UPDATE dossier_versions SET approved=1 WHERE system_id=? AND version=?", (system_id, version)).rowcount
            if not changed:
                raise ValidationError("unknown dossier version")
            self.audit.append("dossier.approved", {"version": version, "approver": approver}, system_id=system_id, connection=connection)

    def current(self, system_id: str, approved_only: bool = True) -> dict[str, Any]:
        clause = "AND approved=1" if approved_only else ""
        with self.database.connect() as connection:
            row = connection.execute(f"SELECT * FROM dossier_versions WHERE system_id=? {clause} ORDER BY version DESC LIMIT 1", (system_id,)).fetchone()
        if not row:
            raise ValidationError("approved dossier unavailable" if approved_only else "dossier unavailable")
        return {"system_id": system_id, "version": row["version"], "approved": bool(row["approved"]), "hash": row["dossier_hash"], "payload": json.loads(row["payload_json"]), "created_at": row["created_at"]}

    def propose(self, system_id: str, changes: dict[str, Any], *, task_id: str | None = None) -> dict[str, Any]:
        if not changes or set(changes) - (PROTECTED_AREAS | MECHANICAL_AREAS):
            raise ValidationError("proposal contains unknown or empty areas")
        self._validate_payload(changes)
        requires_human = bool(set(changes) & PROTECTED_AREAS)
        proposal_id = str(uuid.uuid4())
        status = "pending" if requires_human else "auto-approved"
        with self.database.transaction() as connection:
            connection.execute("INSERT INTO dossier_proposals VALUES(?,?,?,?,?,?,?,NULL)", (proposal_id, system_id, task_id, status, int(requires_human), self.database.json(changes), utc_now()))
            self.audit.append("dossier.proposed", {"proposal_id": proposal_id, "areas": sorted(changes), "requires_human": requires_human}, system_id=system_id, task_id=task_id, connection=connection)
        if not requires_human:
            self._apply_proposal(proposal_id, "broker-mechanical")
        return {"proposal_id": proposal_id, "status": status, "requires_human": requires_human}

    def decide(self, proposal_id: str, approver: str, approve: bool) -> None:
        if not approve:
            with self.database.transaction() as connection:
                changed = connection.execute("UPDATE dossier_proposals SET status='rejected',decided_at=? WHERE proposal_id=? AND status='pending'", (utc_now(), proposal_id)).rowcount
                if not changed:
                    raise ValidationError("pending proposal unavailable")
                self.audit.append("dossier.proposal-rejected", {"proposal_id": proposal_id, "approver": approver}, connection=connection)
            return
        self._apply_proposal(proposal_id, approver)

    def _apply_proposal(self, proposal_id: str, approver: str) -> None:
        with self.database.transaction() as connection:
            proposal = connection.execute("SELECT * FROM dossier_proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
            if not proposal or proposal["status"] not in {"pending", "auto-approved"}:
                raise ValidationError("proposal unavailable")
            current = connection.execute("SELECT * FROM dossier_versions WHERE system_id=? AND approved=1 ORDER BY version DESC LIMIT 1", (proposal["system_id"],)).fetchone()
            if not current:
                raise ValidationError("approved dossier unavailable")
            payload = json.loads(current["payload_json"])
            payload.update(json.loads(proposal["change_json"]))
            clean = self._validate_payload(payload)
            version = int(current["version"]) + 1
            digest = sha256_json(clean)
            connection.execute("INSERT INTO dossier_versions VALUES(?,?,?,?,?,?)", (proposal["system_id"], version, 1, self.database.json(clean), digest, utc_now()))
            connection.execute("UPDATE dossier_proposals SET status='approved',decided_at=? WHERE proposal_id=?", (utc_now(), proposal_id))
            self.audit.append("dossier.proposal-applied", {"proposal_id": proposal_id, "approver": approver, "version": version, "dossier_hash": digest}, system_id=proposal["system_id"], task_id=proposal["task_id"], connection=connection)

    def safe_projection(self, system_id: str, sections: list[str]) -> dict[str, Any]:
        dossier = self.current(system_id)
        facts: dict[str, Any] = {}
        excluded: list[str] = []
        for section in sections:
            if section not in dossier["payload"]:
                excluded.append(section)
                continue
            value = dossier["payload"][section]
            try:
                self._scan(value, path=section)
            except PolicyDenied:
                excluded.append(section)
                continue
            facts[section] = copy.deepcopy(value)
        projection = {"system_id": system_id, "dossier_version": dossier["version"], "dossier_hash": dossier["hash"], "facts": facts, "excluded": sorted(excluded)}
        self._scan(projection)
        return projection

    def checkpoint(self, system_id: str, phase: str, state: str, payload: dict[str, Any], *, task_id: str | None = None, connection=None) -> str:
        self._scan(payload)
        checkpoint_id = f"{task_id or system_id}:{phase}:{state}"
        material = {"checkpoint_id": checkpoint_id, "system_id": system_id, "task_id": task_id, "phase": phase, "state": state, "payload": payload}
        digest = sha256_json(material)
        if connection is None:
            with self.database.transaction() as conn:
                self._insert_checkpoint(conn, checkpoint_id, system_id, task_id, phase, state, payload, digest)
        else:
            self._insert_checkpoint(connection, checkpoint_id, system_id, task_id, phase, state, payload, digest)
        return digest

    def _insert_checkpoint(self, connection, checkpoint_id, system_id, task_id, phase, state, payload, digest):
        connection.execute("INSERT INTO checkpoints VALUES(?,?,?,?,?,?,?,?)", (checkpoint_id, system_id, task_id, phase, state, self.database.json(payload), digest, utc_now()))
        self.audit.append("dossier.checkpoint", {"checkpoint_id": checkpoint_id, "phase": phase, "state": state, "checkpoint_hash": digest}, system_id=system_id, task_id=task_id, connection=connection)

    def _validate_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict) or not payload:
            raise ValidationError("dossier payload must be a non-empty object")
        self._scan(payload)
        return copy.deepcopy(payload)

    def _scan(self, value: Any, path: str = "") -> None:
        encoded = canonical_json(value)
        if len(encoded) > 1_048_576:
            raise PolicyDenied("dossier material exceeds size limit")
        if isinstance(value, dict):
            for key, item in value.items():
                if FORBIDDEN_KEYS.search(str(key)):
                    raise PolicyDenied(f"restricted dossier key at {path or '<root>'}")
                self._scan(item, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                self._scan(item, f"{path}[{index}]")
        elif isinstance(value, str):
            for pattern in FORBIDDEN_CONTENT:
                if pattern.search(value):
                    raise PolicyDenied(f"restricted dossier content at {path or '<root>'}")
