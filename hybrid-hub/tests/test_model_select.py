from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from model_routing_fixture import RoutingFixture

from hybrid_hub.errors import ConflictError, PolicyDenied, ValidationError
from hybrid_hub.model_select import (
    evidence_from_probe_state,
    find_choice,
    interactive_choice,
    load_catalog,
    select_model,
)
from hybrid_hub.model_store import load_record

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "config" / "model-catalog.example.json"

PASSING_EVIDENCE = {"synthetic": True, "passed_packets": 1, "total_packets": 1, "security_violations": 0, "invalid_outputs": 0, "accepted_packet_cost_usd": 0.0}
FAILING_EVIDENCE = {"synthetic": True, "passed_packets": 0, "total_packets": 1, "security_violations": 0, "invalid_outputs": 1, "accepted_packet_cost_usd": 0.0}


class CatalogTests(unittest.TestCase):
    def test_example_catalog_validates_and_lists_all_planned_platforms(self):
        catalog = load_catalog(CATALOG)
        platform_ids = [platform["platform_id"] for platform in catalog["platforms"]]
        self.assertEqual(platform_ids, ["local-ollama", "claude-subscription", "codex-subscription", "vendor-api"])
        platform, model = find_choice(catalog, "local-ollama", "qwen2-5-coder-7b")
        self.assertEqual(model["provider_model"], "qwen2.5-coder:7b")
        self.assertEqual(platform["adapter"], "claude-local")

    def test_catalog_rejects_definition_adapter_mismatch(self):
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        catalog["platforms"][0]["models"][0]["definition"]["adapter"] = "codex-local"
        with patch.object(Path, "read_text", return_value=json.dumps(catalog)):
            with self.assertRaises(ValidationError):
                load_catalog(CATALOG)

    def test_catalog_rejects_duplicate_model_ids(self):
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        catalog["platforms"][0]["models"].append(catalog["platforms"][0]["models"][0])
        with patch.object(Path, "read_text", return_value=json.dumps(catalog)):
            with self.assertRaises(ValidationError):
                load_catalog(CATALOG)

    def test_probe_state_maps_to_honest_evidence(self):
        self.assertEqual(evidence_from_probe_state("VERIFIED")["passed_packets"], 1)
        blocked = evidence_from_probe_state("BLOCKED_QUALITY")
        self.assertEqual((blocked["passed_packets"], blocked["invalid_outputs"], blocked["security_violations"]), (0, 1, 0))
        policy = evidence_from_probe_state("BLOCKED_POLICY")
        self.assertEqual((policy["passed_packets"], policy["security_violations"]), (0, 1))


class InteractiveChoiceTests(unittest.TestCase):
    def test_walks_platform_then_model_and_retries_invalid_input(self):
        catalog = load_catalog(CATALOG)
        answers = iter(["zero", "9", "1", "2"])
        lines: list[str] = []
        platform_id, model_id = interactive_choice(catalog, lambda _prompt: next(answers), lines.append)
        self.assertEqual((platform_id, model_id), ("local-ollama", "gemma3-1b"))
        self.assertTrue(any("not yet available" in line for line in lines))

    def test_gives_up_after_repeated_invalid_input(self):
        catalog = load_catalog(CATALOG)
        with self.assertRaises(ValidationError):
            interactive_choice(catalog, lambda _prompt: "no", lambda _line: None)


class SelectModelTests(RoutingFixture, unittest.TestCase):
    def setUp(self):
        self.setup_routing()
        self.catalog = load_catalog(CATALOG)

    def tearDown(self):
        self.teardown_routing()

    def select(self, probe_evidence, platform="local-ollama", model="qwen2-5-coder-7b"):
        calls: list[tuple] = []

        def probe(provider_model, adapter, **kwargs):
            calls.append((provider_model, adapter))
            return probe_evidence

        result = select_model(
            self.models, self.hub.database, self.hub.audit, "system-routing", self.catalog,
            platform, model, "owner", endpoint="http://127.0.0.1:11434",
            http_bridge_executable=None, timeout=60, probe=probe,
        )
        return result, calls

    def test_select_probes_registers_approves_and_pins_the_choice(self):
        result, calls = self.select(PASSING_EVIDENCE)
        self.assertEqual(calls, [("qwen2.5-coder:7b", "claude-local")])
        self.assertTrue(result["probed"])
        self.assertEqual(result["model_status"], "approved")
        policy = result["policy"]
        self.assertEqual(policy["mode"], "pinned")
        self.assertEqual(policy["pinned_model_id"], "qwen2-5-coder-7b")
        self.assertEqual(policy["max_attempts"], 1)
        self.assertFalse(policy["allow_cloud"])
        transport = load_record(self.hub.database, "model-transport:system-routing:qwen2-5-coder-7b")
        self.assertEqual(transport["provider_model"], "qwen2.5-coder:7b")
        route = self.models.router.plan("system-routing", "coding", "R1")
        self.assertEqual([item["model_id"] for item in route["candidates"]], ["qwen2-5-coder-7b"])

    def test_reselecting_an_approved_model_skips_the_probe(self):
        self.select(PASSING_EVIDENCE)
        result, calls = self.select(PASSING_EVIDENCE)
        self.assertEqual(calls, [])
        self.assertFalse(result["probed"])
        self.assertEqual(result["policy"]["pinned_model_id"], "qwen2-5-coder-7b")

    def test_failed_probe_blocks_approval_and_selection(self):
        with self.assertRaises(ConflictError):
            self.select(FAILING_EVIDENCE)
        record = self.models.registry.get("system-routing", "qwen2-5-coder-7b")
        self.assertEqual(record["status"], "evaluated")
        with self.assertRaises(ValidationError):
            self.models.policies.active("system-routing")

    def test_unimplemented_platform_fails_closed_without_probe(self):
        with self.assertRaises(PolicyDenied):
            self.select(PASSING_EVIDENCE, platform="vendor-api", model="vendor-api-model")
        with self.assertRaises(ValidationError):
            self.models.policies.active("system-routing")

    def test_subscription_platform_selects_with_cloud_policy(self):
        result, calls = self.select(PASSING_EVIDENCE, platform="claude-subscription", model="claude-haiku")
        self.assertEqual(calls, [("haiku", "claude-subscription-cli")])
        policy = result["policy"]
        self.assertTrue(policy["allow_cloud"])
        self.assertEqual(policy["allowed_cloud_account_profiles"], ["claude-subscription"])
        self.assertEqual(policy["pinned_model_id"], "claude-haiku")

    def test_unknown_platform_or_model_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.select(PASSING_EVIDENCE, platform="missing", model="qwen2-5-coder-7b")
        with self.assertRaises(ValidationError):
            self.select(PASSING_EVIDENCE, platform="local-ollama", model="missing")


class SelectCliTests(RoutingFixture, unittest.TestCase):
    def setUp(self):
        self.setup_routing()

    def tearDown(self):
        self.teardown_routing()

    def test_cli_select_requires_flags_when_not_interactive(self):
        from hybrid_hub.model_cli import main

        with patch("sys.stdin") as stdin, patch("builtins.print") as printer:
            stdin.isatty.return_value = False
            code = main(["--runtime", str(self.root / "runtime"), "model", "select", "system-routing", "--catalog", str(CATALOG), "--actor", "owner"])
        self.assertEqual(code, 2)
        payload = json.loads(printer.call_args.args[0])
        self.assertFalse(payload["ok"])
        self.assertIn("--platform and --model", payload["message"])

    def test_cli_select_with_flags_uses_selection_flow(self):
        from hybrid_hub import model_cli

        with patch.object(model_cli, "select_model", return_value={"ok": "yes"}) as selector, patch("builtins.print") as printer:
            code = model_cli.main(["--runtime", str(self.root / "runtime"), "model", "select", "system-routing", "--catalog", str(CATALOG), "--platform", "local-ollama", "--model", "gemma3-1b", "--actor", "owner"])
        self.assertEqual(code, 0)
        self.assertEqual(selector.call_args.args[6], "gemma3-1b")
        payload = json.loads(printer.call_args.args[0])
        self.assertTrue(payload["ok"])


if __name__ == "__main__":
    unittest.main()
