from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import ValidationError
from .model_validation import MODES, exact, ids, number
from .util import require_id


@dataclass(frozen=True)
class AutomationPolicy:
    mode: str
    allowed_model_ids: tuple[str, ...]
    preferred_model_ids: tuple[str, ...]
    pinned_model_id: str | None
    allowed_cloud_account_profiles: tuple[str, ...]
    allow_cloud: bool
    max_packet_cost_usd: float
    max_attempts: int
    min_success_rate: float

    @classmethod
    def from_dict(cls, value: Any) -> "AutomationPolicy":
        data = exact(value, set(cls.__dataclass_fields__), "automation policy")
        mode = data["mode"]
        if mode not in MODES:
            raise ValidationError("invalid automation mode")
        allowed = ids(data["allowed_model_ids"], "allowed model ID")
        preferred = ids(data["preferred_model_ids"], "preferred model ID", empty=True)
        pinned = data["pinned_model_id"]
        if pinned is not None:
            pinned = require_id(pinned, "pinned model ID")
        if not set(preferred) <= set(allowed):
            raise ValidationError("preferred models must be allowed")
        if mode == "auto" and (preferred or pinned is not None):
            raise ValidationError("auto mode cannot prefer or pin models")
        if mode == "preferred" and (not preferred or pinned is not None):
            raise ValidationError("preferred mode requires only preferred models")
        if mode == "pinned" and (pinned not in allowed or preferred):
            raise ValidationError("pinned mode requires one allowed pinned model")
        accounts = ids(data["allowed_cloud_account_profiles"], "cloud account profile", empty=True)
        allow_cloud = data["allow_cloud"]
        if not isinstance(allow_cloud, bool) or (not allow_cloud and accounts):
            raise ValidationError("cloud policy is inconsistent")
        cost = number(data["max_packet_cost_usd"], "maximum packet cost", 0)
        attempts = data["max_attempts"]
        if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= 10:
            raise ValidationError("invalid maximum attempts")
        success = number(data["min_success_rate"], "minimum success rate", 0, 1)
        return cls(mode, allowed, preferred, pinned, accounts, allow_cloud, cost, attempts, success)

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode, "allowed_model_ids": list(self.allowed_model_ids),
            "preferred_model_ids": list(self.preferred_model_ids),
            "pinned_model_id": self.pinned_model_id,
            "allowed_cloud_account_profiles": list(self.allowed_cloud_account_profiles),
            "allow_cloud": self.allow_cloud, "max_packet_cost_usd": self.max_packet_cost_usd,
            "max_attempts": self.max_attempts, "min_success_rate": self.min_success_rate,
        }
