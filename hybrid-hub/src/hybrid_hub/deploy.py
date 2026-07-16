from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .audit import AuditLog, SECRET_PATTERNS, sanitize
from .errors import AdapterError, AuthorizationRequired, ConflictError, PolicyDenied, ValidationError
from .state import TaskManager
from .storage import Database
from .util import canonical_json, require_id, sha256_json, utc_now


DeploymentTransport = Callable[[dict[str, Any]], dict[str, Any]]


class DeploymentManager:
    """Credential-free deployment coordinator; transports own approved CI identities."""

    def __init__(self, database: Database, audit: AuditLog, tasks: TaskManager):
        self.database = database
        self.audit = audit
        self.tasks = tasks
        self.modifiers = None

    def release(self, task_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM release_records WHERE task_id=? ORDER BY created_at DESC LIMIT 1", (task_id,)).fetchone()
        if not row:
            raise ValidationError("verified release evidence is unavailable")
        return {**dict(row), "manifest": json.loads(row["manifest_json"])}

    def deploy_staging(self, task_id: str, adapter_id: str, transport: DeploymentTransport | None = None) -> dict[str, Any]:
        require_id(adapter_id, "deployment adapter")
        if self.modifiers:
            self.modifiers.require_action(task_id, "staging")
            modifier = self.modifiers.for_task(task_id)
            if modifier and modifier["modifier"]["deployment_posture"] == "none":
                raise PolicyDenied("project modifier disables deployment")
        task = self.tasks.get(task_id)
        if task["state"] != "VERIFIED":
            raise PolicyDenied("staging deployment requires a VERIFIED task")
        if transport is None:
            raise AuthorizationRequired("no approved staging CI/CD adapter is configured")
        release = self.release(task_id)
        request = self._request(release, "staging", "deploy")
        deployment_id = f"dep-{uuid.uuid4().hex[:16]}"
        self.tasks.transition(task_id, "STAGING_DEPLOYED", evidence=[release["manifest_hash"]])
        result = self._validate_result(transport(request), "staging")
        now = utc_now()
        with self.database.transaction() as connection:
            connection.execute("INSERT INTO deployment_records VALUES(?,?,?,?,?,?,?,?,?,?)", (deployment_id, release["release_id"], task_id, "staging", result["status"], adapter_id, self.database.json(result), None, now, now))
            self.audit.append("deployment.staging", {"deployment_id": deployment_id, "release_id": release["release_id"], "adapter_id": adapter_id, "status": result["status"], "evidence_hash": sha256_json(result)}, system_id=task["system_id"], task_id=task_id, connection=connection)
        if result["status"] != "healthy":
            self.tasks.transition(task_id, "FAILED_INFRA", reason="staging health gates failed")
        else:
            self.tasks.transition(task_id, "STAGING_VERIFIED", evidence=[sha256_json(result)])
        return self.get(deployment_id)

    def approve_production(self, task_id: str, approver: str, *, ttl_minutes: int = 30) -> dict[str, Any]:
        require_id(approver, "approver")
        if self.modifiers:
            self.modifiers.require_action(task_id, "production")
            modifier = self.modifiers.for_task(task_id)
            if modifier and modifier["modifier"]["deployment_posture"] != "production-controlled":
                raise PolicyDenied("project modifier does not allow controlled production promotion")
        if not 1 <= ttl_minutes <= 60:
            raise ValidationError("production approval lifetime is invalid")
        task = self.tasks.get(task_id)
        if task["state"] != "STAGING_VERIFIED":
            raise PolicyDenied("production approval requires verified staging evidence")
        release = self.release(task_id)
        approval_id = f"pa-{uuid.uuid4().hex[:16]}"
        expires = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).isoformat().replace("+00:00", "Z")
        scope = {"task_id": task_id, "release_id": release["release_id"], "manifest_hash": release["manifest_hash"], "action": "production-canary", "destructive_actions": False}
        with self.database.transaction() as connection:
            connection.execute("INSERT INTO production_approvals VALUES(?,?,?,?,?,?,?,NULL)", (approval_id, task_id, release["release_id"], approver, self.database.json(scope), expires, utc_now()))
            self.audit.append("production.approved", {"approval_id": approval_id, "release_id": release["release_id"], "approver": approver, "expires_at": expires, "scope_hash": sha256_json(scope)}, system_id=task["system_id"], task_id=task_id, connection=connection)
        self.tasks.transition(task_id, "PRODUCTION_APPROVAL", evidence=[sha256_json(scope)])
        return {"approval_id": approval_id, "expires_at": expires, "scope": scope, "consumed": False}

    def promote(self, task_id: str, approval_id: str, adapter_id: str, transport: DeploymentTransport | None = None) -> dict[str, Any]:
        require_id(adapter_id, "deployment adapter")
        if self.modifiers:
            self.modifiers.require_action(task_id, "production")
        if transport is None:
            raise AuthorizationRequired("no approved production CI/CD adapter is configured")
        task = self.tasks.get(task_id)
        if task["state"] != "PRODUCTION_APPROVAL":
            raise PolicyDenied("production promotion requires the explicit approval state")
        release = self.release(task_id)
        with self.database.transaction() as connection:
            approval = connection.execute("SELECT * FROM production_approvals WHERE approval_id=? AND task_id=? AND release_id=?", (approval_id, task_id, release["release_id"])).fetchone()
            if not approval or approval["consumed_at"]:
                raise ConflictError("production approval is missing or already consumed")
            expires = datetime.fromisoformat(approval["expires_at"].replace("Z", "+00:00"))
            if expires <= datetime.now(timezone.utc):
                raise PolicyDenied("production approval expired")
            connection.execute("UPDATE production_approvals SET consumed_at=? WHERE approval_id=?", (utc_now(), approval_id))
        self.tasks.transition(task_id, "PRODUCTION_CANARY", evidence=[release["manifest_hash"], approval_id])
        request = self._request(release, "production", "canary")
        result = self._validate_result(transport(request), "production")
        deployment_id = f"dep-{uuid.uuid4().hex[:16]}"
        if result["status"] != "healthy":
            rollback_request = self._request(release, "production", "rollback")
            rollback = self._validate_result(transport(rollback_request), "production", rollback=True)
            result["rollback"] = rollback
            final_status = "rolled-back" if rollback["status"] == "rolled-back" else "rollback-failed"
        else:
            final_status = "healthy"
        now = utc_now()
        with self.database.transaction() as connection:
            connection.execute("INSERT INTO deployment_records VALUES(?,?,?,?,?,?,?,?,?,?)", (deployment_id, release["release_id"], task_id, "production", final_status, adapter_id, self.database.json(result), approval_id, now, now))
            self.audit.append("deployment.production", {"deployment_id": deployment_id, "release_id": release["release_id"], "approval_id": approval_id, "adapter_id": adapter_id, "status": final_status, "evidence_hash": sha256_json(result)}, system_id=task["system_id"], task_id=task_id, connection=connection)
        if final_status == "healthy":
            self.tasks.transition(task_id, "PRODUCTION_VERIFIED", evidence=[sha256_json(result)])
        else:
            self.tasks.transition(task_id, "FAILED_INFRA", reason=f"production canary {final_status}")
        return self.get(deployment_id)

    def accept(self, task_id: str, approver: str) -> dict[str, Any]:
        require_id(approver, "approver")
        task = self.tasks.get(task_id)
        if task["state"] != "PRODUCTION_VERIFIED":
            raise PolicyDenied("human acceptance requires verified production evidence")
        result = self.tasks.transition(task_id, "HUMAN_ACCEPTED", evidence=[f"human:{approver}"])
        self.audit.append("production.human-accepted", {"approver": approver}, system_id=task["system_id"], task_id=task_id)
        return result

    def get(self, deployment_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM deployment_records WHERE deployment_id=?", (deployment_id,)).fetchone()
        if not row:
            raise ValidationError("unknown deployment")
        result = dict(row)
        result["evidence"] = json.loads(result.pop("evidence_json"))
        return result

    @staticmethod
    def diagnostic_bundle(values: dict[str, Any]) -> dict[str, Any]:
        allowed = {"commit", "version", "correlation_ids", "aggregate_metrics", "safe_config_names", "stack_summary", "synthetic_reproduction"}
        if not isinstance(values, dict) or set(values) - allowed:
            raise ValidationError("diagnostic bundle includes unapproved fields")
        safe = sanitize(values)
        encoded = canonical_json(safe).decode("utf-8")
        for pattern in SECRET_PATTERNS:
            if pattern.search(encoded):
                raise PolicyDenied("diagnostic bundle contains credential-like material")
        return {"diagnostic": safe, "bundle_hash": sha256_json(safe), "raw_logs_included": False, "production_records_included": False}

    @staticmethod
    def _request(release: dict[str, Any], environment: str, action: str) -> dict[str, Any]:
        return {"release_id": release["release_id"], "manifest_hash": release["manifest_hash"], "environment": environment, "action": action, "artifact_ids": [item["candidate_tree"] for item in release["manifest"]["repositories"]], "credential_values": None, "model_access": False}

    @staticmethod
    def _validate_result(value: Any, environment: str, rollback: bool = False) -> dict[str, Any]:
        required = {"status", "health_gates", "artifact_ids", "rollback_id"}
        if not isinstance(value, dict) or set(value) != required:
            raise AdapterError("deployment adapter result schema is invalid")
        allowed = {"rolled-back", "rollback-failed"} if rollback else {"healthy", "failed"}
        if value["status"] not in allowed or not isinstance(value["health_gates"], list) or not isinstance(value["artifact_ids"], list):
            raise AdapterError("deployment adapter status or evidence is invalid")
        encoded = canonical_json(value).decode("utf-8")
        for pattern in SECRET_PATTERNS:
            if pattern.search(encoded):
                raise PolicyDenied("deployment evidence contains credential-like material")
        result = json.loads(json.dumps(sanitize(value)))
        result["environment"] = environment
        return result
