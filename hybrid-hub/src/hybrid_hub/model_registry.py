from __future__ import annotations

from typing import Any

from .errors import ConflictError, ValidationError
from .model_registry_base import ModelRegistryBase
from .model_store import write_record
from .model_validation import exact, number
from .util import require_id, utc_now


class ModelRegistry(ModelRegistryBase):
    def record_evaluation(self, system_id: str, model_id: str, evidence: dict[str, Any], actor: str) -> dict[str, Any]:
        fields = {"synthetic", "passed_packets", "total_packets", "security_violations", "invalid_outputs", "accepted_packet_cost_usd"}
        data = exact(evidence, fields, "model evaluation")
        if data["synthetic"] is not True:
            raise ValidationError("only synthetic model evaluation is accepted")
        names = ("passed_packets", "total_packets", "security_violations", "invalid_outputs")
        integers = [data[name] for name in names]
        if any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in integers):
            raise ValidationError("invalid model evaluation count")
        passed, total, violations, invalid = integers
        if total < 1 or passed > total or violations > total or invalid > total:
            raise ValidationError("inconsistent model evaluation")
        cost = number(data["accepted_packet_cost_usd"], "accepted packet cost", 0)
        current = self.get(system_id, model_id)
        if current["status"] not in {"quarantined", "evaluated"}:
            raise ConflictError("model cannot be evaluated in its current state")
        evaluation = {**data, "accepted_packet_cost_usd": cost, "success_rate": passed / total}
        current.update({"status": "evaluated", "evaluation": evaluation, "updated_at": utc_now()})
        summary = {"model_id": model_id, "status": "evaluated", "passed_packets": passed, "total_packets": total, "security_violations": violations}
        return write_record(self.database, self.audit, self._key(system_id, model_id), current, "model.evaluated", system_id, actor, summary)

    def approve(self, system_id: str, model_id: str, actor: str) -> dict[str, Any]:
        current = self.get(system_id, model_id)
        evaluation = current.get("evaluation")
        if current["status"] != "evaluated" or not evaluation or evaluation["passed_packets"] < 1 or evaluation["security_violations"] != 0:
            raise ConflictError("passing synthetic evaluation is required")
        current.update({"status": "approved", "approved_by": require_id(actor, "approver"), "updated_at": utc_now()})
        return write_record(self.database, self.audit, self._key(system_id, model_id), current, "model.approved", system_id, actor, {"model_id": model_id, "status": "approved"})

    def disable(self, system_id: str, model_id: str, actor: str) -> dict[str, Any]:
        current = self.get(system_id, model_id)
        current.update({"status": "disabled", "disabled_by": require_id(actor, "actor"), "updated_at": utc_now()})
        return write_record(self.database, self.audit, self._key(system_id, model_id), current, "model.disabled", system_id, actor, {"model_id": model_id, "status": "disabled"})
