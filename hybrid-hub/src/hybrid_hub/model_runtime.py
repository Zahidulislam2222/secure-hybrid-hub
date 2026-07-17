from __future__ import annotations

from typing import Any

from .model_executor import BoundedModelExecutor
from .model_policy_registry import ModelPolicyRegistry
from .model_registry import ModelRegistry
from .model_router import ModelRouter


class ModelRuntime:
    def __init__(self, hub: Any):
        self.registry = ModelRegistry(hub.database, hub.audit)
        self.policies = ModelPolicyRegistry(hub.database, hub.audit)
        self.router = ModelRouter(self.registry, self.policies, hub.audit)
        self.executor = BoundedModelExecutor(self.router, hub.audit)

    @classmethod
    def from_hub(cls, hub: Any) -> "ModelRuntime":
        return cls(hub)
