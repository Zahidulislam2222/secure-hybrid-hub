from __future__ import annotations

import unittest

from hybrid_hub.errors import AdapterError, PolicyDenied, ValidationError
from hybrid_hub.model_executor import ModelAttemptError
from model_routing_fixture import RoutingFixture


class ModelRoutingTests(RoutingFixture, unittest.TestCase):
    def setUp(self):
        self.setup_routing()

    def tearDown(self):
        self.teardown_routing()

    def test_non_synthetic_evaluation_is_rejected(self):
        self.models.registry.discover("system-routing", self.definition("model-a", 0.1, 0.9), "tester")
        evidence = {"synthetic": False, "passed_packets": 9, "total_packets": 10, "security_violations": 0, "invalid_outputs": 0, "accepted_packet_cost_usd": 0.1}
        with self.assertRaises(ValidationError):
            self.models.registry.record_evaluation("system-routing", "model-a", evidence, "tester")

    def test_auto_order_and_retryable_fallback(self):
        self.add_model("model-a", 0.1, 8)
        self.add_model("model-b", 0.2, 9)
        self.set_policy("auto", ["model-a", "model-b"])
        plan = self.models.router.plan("system-routing", "coding", "R1")
        self.assertEqual([item["model_id"] for item in plan["candidates"]], ["model-a", "model-b"])
        calls = []
        def runner(candidate):
            calls.append(candidate["model_id"])
            if len(calls) == 1:
                raise ModelAttemptError("transport")
            return {"status": "ok"}
        result = self.models.executor.execute("system-routing", "coding", "R1", runner)
        self.assertEqual(result["attempt"], 2)
        self.assertEqual(calls, ["model-a", "model-b"])

    def test_preferred_and_pinned_modes(self):
        self.add_model("model-a", 0.1, 8)
        self.add_model("model-b", 0.2, 9)
        self.set_policy("preferred", ["model-a", "model-b"], ["model-b"])
        plan = self.models.router.plan("system-routing", "coding", "R1")
        self.assertEqual(plan["candidates"][0]["model_id"], "model-b")
        self.set_policy("pinned", ["model-a", "model-b"], pinned="model-a")
        plan = self.models.router.plan("system-routing", "coding", "R1")
        self.assertEqual([item["model_id"] for item in plan["candidates"]], ["model-a"])

    def test_stop_and_attempt_boundaries(self):
        self.add_model("model-a", 0.1, 8)
        self.add_model("model-b", 0.2, 9)
        self.set_policy("auto", ["model-a", "model-b"], attempts=1)
        calls = []
        def security(candidate):
            calls.append(candidate["model_id"])
            raise ModelAttemptError("security")
        with self.assertRaises(PolicyDenied):
            self.models.executor.execute("system-routing", "coding", "R1", security)
        self.assertEqual(len(calls), 1)
        with self.assertRaises(AdapterError):
            self.models.executor.execute("system-routing", "coding", "R1", lambda candidate: (_ for _ in ()).throw(RuntimeError("unknown")))
        with self.assertRaises(AdapterError):
            self.models.executor.execute("system-routing", "coding", "R1", lambda candidate: (_ for _ in ()).throw(ModelAttemptError("timeout")))


if __name__ == "__main__":
    unittest.main()
