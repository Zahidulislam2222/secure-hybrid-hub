from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

from hybrid_hub.errors import PolicyDenied
from hybrid_hub.model_cli import main
from hybrid_hub.model_executor import ModelAttemptError
from model_routing_fixture import RoutingFixture


class ModelRoutingEndToEndTests(RoutingFixture, unittest.TestCase):
    def setUp(self):
        self.setup_routing()

    def tearDown(self):
        self.teardown_routing()

    def invoke(self, arguments):
        output = io.StringIO()
        argv = ["--runtime", str(self.hub.database.layout.root), "model", *arguments]
        with redirect_stdout(output):
            code = main(argv)
        payload = json.loads(output.getvalue())
        self.assertEqual(code, 0, payload)
        return payload["result"]

    def write_object(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_cli_to_bounded_executor_and_audit(self):
        for model_id, cost, passed in (("model-a", 0.1, 8), ("model-b", 0.2, 9)):
            definition = self.write_object(f"{model_id}-definition.json", self.definition(model_id, cost, passed / 10))
            evidence = self.write_object(f"{model_id}-evaluation.json", {"synthetic": True, "passed_packets": passed, "total_packets": 10, "security_violations": 0, "invalid_outputs": 0, "accepted_packet_cost_usd": cost})
            self.invoke(["discover", "system-routing", "--definition", str(definition), "--actor", "tester"])
            self.invoke(["evaluate", "system-routing", model_id, "--evidence", str(evidence), "--actor", "tester"])
            self.invoke(["approve", "system-routing", model_id, "--actor", "owner"])
        policy = {"mode": "auto", "allowed_model_ids": ["model-a", "model-b"], "preferred_model_ids": [], "pinned_model_id": None, "allowed_cloud_account_profiles": [], "allow_cloud": False, "max_packet_cost_usd": 1.0, "max_attempts": 2, "min_success_rate": 0.5}
        policy_path = self.write_object("policy.json", policy)
        self.invoke(["policy-propose", "system-routing", "--policy", str(policy_path), "--actor", "tester"])
        self.invoke(["policy-approve", "system-routing", "--actor", "owner"])
        plan = self.invoke(["route", "system-routing", "--role", "coding", "--classification", "R1"])
        self.assertEqual([item["model_id"] for item in plan["candidates"]], ["model-a", "model-b"])
        calls = []
        def retry_then_succeed(candidate):
            calls.append(candidate["model_id"])
            if len(calls) == 1:
                raise ModelAttemptError("transport")
            return {"accepted": True}
        result = self.models.executor.execute("system-routing", "coding", "R1", retry_then_succeed)
        self.assertEqual(result["attempt"], 2)
        self.assertEqual(calls, ["model-a", "model-b"])
        stopped = []
        def security(candidate):
            stopped.append(candidate["model_id"])
            raise ModelAttemptError("security")
        with self.assertRaises(PolicyDenied):
            self.models.executor.execute("system-routing", "coding", "R1", security)
        self.assertEqual(stopped, ["model-a"])
        events = [event["event_type"] for event in self.hub.audit.export()]
        for expected in ("model.route-planned", "model.route-attempted", "model.route-attempt-failed", "model.route-succeeded"):
            self.assertIn(expected, events)
        self.assertTrue(self.hub.audit.verify())


if __name__ == "__main__":
    unittest.main()
