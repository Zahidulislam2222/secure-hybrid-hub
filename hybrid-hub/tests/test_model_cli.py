from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

from hybrid_hub.model_cli import main
from model_routing_fixture import RoutingFixture


class ModelCliTests(RoutingFixture, unittest.TestCase):
    def setUp(self):
        self.setup_routing()

    def tearDown(self):
        self.teardown_routing()

    def invoke(self, arguments):
        output = io.StringIO()
        argv = ["--runtime", str(self.hub.database.layout.root), "model", *arguments]
        with redirect_stdout(output):
            code = main(argv)
        return code, json.loads(output.getvalue())

    def test_list_and_route(self):
        self.add_model("model-a", 0.1, 8)
        self.add_model("model-b", 0.2, 9)
        self.set_policy("auto", ["model-a", "model-b"])
        code, payload = self.invoke(["list", "system-routing"])
        self.assertEqual(code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(len(payload["result"]), 2)
        code, payload = self.invoke(["route", "system-routing", "--role", "coding", "--classification", "R1"])
        self.assertEqual(code, 0)
        self.assertEqual(payload["result"]["candidates"][0]["model_id"], "model-a")

    def test_invalid_object_is_structured_error(self):
        invalid = self.root / "invalid.json"
        invalid.write_text("[]", encoding="utf-8")
        code, payload = self.invoke(["discover", "system-routing", "--definition", str(invalid), "--actor", "tester"])
        self.assertEqual(code, 2)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "ValidationError")

    def test_policy_show(self):
        self.add_model("model-a", 0.1, 8)
        self.set_policy("auto", ["model-a"])
        code, payload = self.invoke(["policy-show", "system-routing"])
        self.assertEqual(code, 0)
        self.assertEqual(payload["result"]["mode"], "auto")


if __name__ == "__main__":
    unittest.main()
