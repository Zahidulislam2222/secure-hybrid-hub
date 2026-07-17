from __future__ import annotations

from typing import Any

from .audit import AuditLog
from .errors import PolicyDenied, ValidationError
from .model_contracts import ModelDefinition
from .model_policy_registry import ModelPolicyRegistry
from .model_registry import ModelRegistry
from .model_validation import CLASSIFICATIONS
from .util import require_id


class ModelRouter:
    def __init__(self, registry: ModelRegistry, policies: ModelPolicyRegistry, audit: AuditLog):
        self.registry = registry
        self.policies = policies
        self.audit = audit

    def plan(
        self,
        system_id: str,
        role: str,
        classification: str,
        *,
        require_structured_output: bool = True,
    ) -> dict[str, Any]:
        role = require_id(role, "model role")
        if classification not in CLASSIFICATIONS:
            raise ValidationError("invalid route classification")
        if not isinstance(require_structured_output, bool):
            raise ValidationError("structured-output requirement must be boolean")
        policy = self.policies.active(system_id)
        candidates: list[dict[str, Any]] = []
        for record in self.registry.list(system_id):
            if record.get("status") != "approved":
                continue
            definition = ModelDefinition.from_dict(record.get("definition"))
            evaluation = record.get("evaluation")
            if definition.model_id not in policy.allowed_model_ids or not isinstance(evaluation, dict):
                continue
            success_rate = evaluation.get("success_rate")
            accepted_cost = evaluation.get("accepted_packet_cost_usd")
            if isinstance(success_rate, bool) or not isinstance(success_rate, (int, float)):
                continue
            if isinstance(accepted_cost, bool) or not isinstance(accepted_cost, (int, float)):
                continue
            if role not in definition.roles or classification not in definition.allowed_classifications:
                continue
            if require_structured_output and not definition.structured_output:
                continue
            if success_rate < policy.min_success_rate or definition.benchmark_success_rate < policy.min_success_rate:
                continue
            if accepted_cost > policy.max_packet_cost_usd or definition.accepted_packet_cost_usd > policy.max_packet_cost_usd:
                continue
            if definition.location == "cloud" and (not policy.allow_cloud or definition.account_profile not in policy.allowed_cloud_account_profiles):
                continue
            candidates.append({"model_id": definition.model_id, "adapter": definition.adapter, "location": definition.location, "account_profile": definition.account_profile, "success_rate": float(success_rate), "accepted_packet_cost_usd": float(accepted_cost)})
        preferred = set(policy.preferred_model_ids)
        candidates.sort(key=lambda item: (0 if item["model_id"] in preferred else 1, 0 if item["location"] == "local" else 1, item["accepted_packet_cost_usd"], -item["success_rate"], item["model_id"]))
        if policy.mode == "pinned":
            candidates = [item for item in candidates if item["model_id"] == policy.pinned_model_id]
        if not candidates:
            raise PolicyDenied("no approved model satisfies the active project routing policy")
        result = {"system_id": system_id, "role": role, "classification": classification, "mode": policy.mode, "max_attempts": policy.max_attempts, "candidates": candidates}
        self.audit.append("model.route-planned", {"role": role, "classification": classification, "mode": policy.mode, "max_attempts": policy.max_attempts, "model_ids": [item["model_id"] for item in candidates]}, system_id=system_id)
        return result
