from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import ValidationError
from .model_validation import CLASSIFICATIONS, LOCATIONS, exact, ids, number
from .util import require_id


@dataclass(frozen=True)
class ModelDefinition:
    model_id: str
    provider: str
    adapter: str
    location: str
    account_profile: str | None
    roles: tuple[str, ...]
    allowed_classifications: tuple[str, ...]
    retention_days: int
    regions: tuple[str, ...]
    structured_output: bool
    accepted_packet_cost_usd: float
    benchmark_success_rate: float

    @classmethod
    def from_dict(cls, value: Any) -> "ModelDefinition":
        data = exact(value, set(cls.__dataclass_fields__), "model definition")
        model_id = require_id(data["model_id"], "model ID")
        provider = require_id(data["provider"], "provider")
        adapter = require_id(data["adapter"], "adapter")
        location = data["location"]
        if location not in LOCATIONS:
            raise ValidationError("invalid model location")
        account = data["account_profile"]
        if account is not None:
            account = require_id(account, "account profile")
        if (location == "local" and account is not None) or (location == "cloud" and account is None):
            raise ValidationError("model location and account profile are inconsistent")
        roles = ids(data["roles"], "role")
        classifications = ids(data["allowed_classifications"], "classification")
        if not set(classifications) <= CLASSIFICATIONS:
            raise ValidationError("invalid allowed classification")
        retention = data["retention_days"]
        if isinstance(retention, bool) or not isinstance(retention, int) or not 0 <= retention <= 36500:
            raise ValidationError("invalid retention days")
        regions = ids(data["regions"], "region")
        structured = data["structured_output"]
        if not isinstance(structured, bool):
            raise ValidationError("structured_output must be boolean")
        cost = number(data["accepted_packet_cost_usd"], "accepted packet cost", 0)
        success = number(data["benchmark_success_rate"], "benchmark success rate", 0, 1)
        return cls(model_id, provider, adapter, location, account, roles, classifications, retention, regions, structured, cost, success)

    def as_dict(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id, "provider": self.provider,
            "adapter": self.adapter, "location": self.location,
            "account_profile": self.account_profile, "roles": list(self.roles),
            "allowed_classifications": list(self.allowed_classifications),
            "retention_days": self.retention_days, "regions": list(self.regions),
            "structured_output": self.structured_output,
            "accepted_packet_cost_usd": self.accepted_packet_cost_usd,
            "benchmark_success_rate": self.benchmark_success_rate,
        }
