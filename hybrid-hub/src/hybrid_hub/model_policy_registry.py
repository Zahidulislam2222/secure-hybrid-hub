from __future__ import annotations

from typing import Any

from .audit import AuditLog
from .errors import ConflictError, ValidationError
from .model_contracts import AutomationPolicy
from .model_store import load_record, require_system, write_record
from .storage import Database
from .util import require_id, utc_now


class ModelPolicyRegistry:
    def __init__(self, database: Database, audit: AuditLog):
        self.database = database
        self.audit = audit

    def propose(self, system_id: str, value: dict[str, Any], actor: str) -> dict[str, Any]:
        require_system(self.database, system_id)
        policy = AutomationPolicy.from_dict(value)
        payload = {"system_id": system_id, "status": "pending", "policy": policy.as_dict(), "proposed_by": require_id(actor, "proposer"), "approved_by": None, "updated_at": utc_now()}
        return write_record(self.database, self.audit, f"model-policy-pending:{system_id}", payload, "model.policy-proposed", system_id, actor, {"status": "pending", "mode": policy.mode})

    def approve(self, system_id: str, actor: str) -> dict[str, Any]:
        require_system(self.database, system_id)
        pending = load_record(self.database, f"model-policy-pending:{system_id}")
        if pending is None or pending.get("status") != "pending" or pending.get("system_id") != system_id:
            raise ConflictError("pending model policy unavailable")
        policy = AutomationPolicy.from_dict(pending.get("policy"))
        pending.update({"status": "approved", "approved_by": require_id(actor, "approver"), "updated_at": utc_now()})
        return write_record(self.database, self.audit, f"model-policy-active:{system_id}", pending, "model.policy-approved", system_id, actor, {"status": "approved", "mode": policy.mode})

    def active(self, system_id: str) -> AutomationPolicy:
        require_system(self.database, system_id)
        record = load_record(self.database, f"model-policy-active:{system_id}")
        if record is None or record.get("status") != "approved" or record.get("system_id") != system_id:
            raise ValidationError("approved model policy unavailable")
        return AutomationPolicy.from_dict(record.get("policy"))
