from __future__ import annotations

import tempfile
from pathlib import Path

from hybrid_hub.hub import Hub
from hybrid_hub.model_runtime import ModelRuntime


class RoutingFixture:
    def setup_routing(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        project = self.root / "project"
        project.mkdir()
        hub = Hub(self.root / "runtime")
        hub.registry.register_system("system-routing", "client-synthetic", "Synthetic routing", [str(project)], ["standard"])
        hub.registry.discover("system-routing")
        version = hub.dossier.create_draft("system-routing", {"purpose": "Synthetic routing", "provenance": [{"source": "test"}]})
        hub.dossier.approve("system-routing", version, "owner")
        hub.registry.approve_system("system-routing", "owner")
        self.hub = hub
        self.models = ModelRuntime.from_hub(hub)

    def teardown_routing(self):
        self.temporary.cleanup()

    @staticmethod
    def definition(model_id, cost, success):
        return {"model_id": model_id, "provider": "local", "adapter": "codex-local", "location": "local", "account_profile": None, "roles": ["coding"], "allowed_classifications": ["R1"], "retention_days": 0, "regions": ["local"], "structured_output": True, "accepted_packet_cost_usd": cost, "benchmark_success_rate": success}

    def add_model(self, model_id, cost, passed):
        self.models.registry.discover("system-routing", self.definition(model_id, cost, passed / 10), "tester")
        self.models.registry.record_evaluation("system-routing", model_id, {"synthetic": True, "passed_packets": passed, "total_packets": 10, "security_violations": 0, "invalid_outputs": 0, "accepted_packet_cost_usd": cost}, "tester")
        self.models.registry.approve("system-routing", model_id, "owner")

    def set_policy(self, mode, allowed, preferred=(), pinned=None, attempts=2):
        value = {"mode": mode, "allowed_model_ids": list(allowed), "preferred_model_ids": list(preferred), "pinned_model_id": pinned, "allowed_cloud_account_profiles": [], "allow_cloud": False, "max_packet_cost_usd": 1.0, "max_attempts": attempts, "min_success_rate": 0.5}
        self.models.policies.propose("system-routing", value, "tester")
        self.models.policies.approve("system-routing", "owner")
