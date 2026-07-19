from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from test_integration import IntegrationBase

from hybrid_hub.errors import AdapterError, AuthorizationRequired, PolicyDenied, ValidationError
from hybrid_hub.http_api_worker import HttpApiConfig, HttpApiWorker
from hybrid_hub.secrets import read_api_key_file

SYNTHETIC_KEY = "hh-test-canary-0000000000000000"
ORIGIN = "https://api.synthetic.test"


def anthropic_body(text, input_tokens=1000, output_tokens=500, stop_reason="stop_sequence"):
    return json.dumps({
        "content": [{"type": "text", "text": text}],
        "stop_reason": stop_reason,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }).encode("utf-8")


def openai_body(text, prompt_tokens=1000, completion_tokens=500, finish_reason="stop"):
    return json.dumps({
        "choices": [{"message": {"content": text}, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
    }).encode("utf-8")


class ApiKeyFileTests(unittest.TestCase):
    def make(self, tmp, content="hh-synthetic-api-key-0123456789", mode=0o600):
        path = Path(tmp) / "api.key"
        path.write_text(content + "\n", encoding="utf-8")
        os.chmod(path, mode)
        return path

    def test_reads_a_private_single_line_key(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(read_api_key_file(self.make(tmp)), "hh-synthetic-api-key-0123456789")

    def test_rejects_relative_missing_multiline_and_short_keys(self):
        import tempfile

        with self.assertRaises(ValidationError):
            read_api_key_file(Path("relative.key"))
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValidationError):
                read_api_key_file(Path(tmp) / "missing.key")
            with self.assertRaises(ValidationError):
                read_api_key_file(self.make(tmp, content="line-one-0123456789abc\nline-two-0123456789abc"))
            with self.assertRaises(ValidationError):
                read_api_key_file(self.make(tmp, content="short"))

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits")
    def test_rejects_group_or_world_accessible_key_files(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyDenied):
                read_api_key_file(self.make(tmp, mode=0o644))


class HttpApiConfigTests(unittest.TestCase):
    def build(self, **overrides):
        values = {
            "name": "anthropic-api", "base_url": ORIGIN, "model": "synthetic-model",
            "api_key_file": "/synthetic/api.key", "input_cost_per_mtok": 1.0,
            "output_cost_per_mtok": 5.0, "max_task_cost_usd": 0.25,
        }
        values.update(overrides)
        return HttpApiConfig(**values)

    def test_accepts_both_protocols_and_exposes_the_origin(self):
        self.assertEqual(self.build().origin, ORIGIN)
        self.assertEqual(self.build(name="openai-compatible-api", base_url=ORIGIN + "/v1").origin, ORIGIN)

    def test_rejects_plain_http_credentialed_urls_and_unknown_adapters(self):
        with self.assertRaises(ValidationError):
            self.build(name="codex-local")
        with self.assertRaises(PolicyDenied):
            self.build(base_url="http://api.synthetic.test")
        with self.assertRaises(PolicyDenied):
            self.build(base_url="https://user:pass@api.synthetic.test")
        with self.assertRaises(PolicyDenied):
            self.build(base_url=ORIGIN + "?token=x")

    def test_rejects_missing_prices_caps_and_relative_key_file(self):
        with self.assertRaises(ValidationError):
            self.build(api_key_file="relative.key")
        with self.assertRaises(ValidationError):
            self.build(input_cost_per_mtok=-1)
        with self.assertRaises(ValidationError):
            self.build(max_task_cost_usd=0)
        with self.assertRaises(ValidationError):
            self.build(max_task_cost_usd=1000)


class HttpApiWorkerBase(IntegrationBase):
    def setUp(self):
        super().setUp()
        _, registration = self.register(git=True)
        self.task = self.hub.tasks.create("system-a", "Synthetic HTTP API worker", "R1", registration["policy"]["policy_hash"], "task-http-api")
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED", "WORKSPACES_READY"):
            self.hub.tasks.transition(self.task["task_id"], state)
        self.key_path = self.root / "synthetic-api.key"
        self.key_path.write_text(SYNTHETIC_KEY + "\n", encoding="utf-8")
        os.chmod(self.key_path, 0o600)

    def approve_provider(self, system_id="system-a", origin=ORIGIN, live=True, max_cost=1.0):
        profile = self.hub.provider_profiles.propose(system_id, {
            "provider": "vendor-api", "mode": "live", "endpoint": origin, "account_type": "api",
            "account_identity": "test-owner", "max_turns": 1, "max_seconds": 300, "max_cost_usd": max_cost,
        }, "test-owner")
        return self.hub.provider_profiles.approve(profile["profile_id"], "test-owner", enable_live=live)

    def worker(self, name="anthropic-api", base_url=ORIGIN, cap=0.25, input_cost=1.0, output_cost=5.0):
        config = HttpApiConfig(name, base_url, "synthetic-model", str(self.key_path), input_cost, output_cost, cap)
        return HttpApiWorker(self.hub.database, self.hub.audit, self.hub.leases, config, self.hub.provider_profiles)

    def audit_events(self, event):
        with self.hub.database.connect() as connection:
            rows = connection.execute("SELECT payload_json FROM audit_events WHERE event_type=? ORDER BY event_id", (event,)).fetchall()
        return [json.loads(row[0]) for row in rows]


class HttpApiWorkerTests(HttpApiWorkerBase):
    def test_anthropic_request_shape_key_header_and_metering(self):
        self.approve_provider()
        worker = self.worker()
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, anthropic_body("```python\ndef ready():\n    return True\n```\n"))) as post:
            result = worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        _, url, headers, body, timeout, _ = post.call_args.args
        self.assertEqual(url, ORIGIN + "/v1/messages")
        self.assertEqual(headers["x-api-key"], SYNTHETIC_KEY)
        self.assertIn("anthropic-version", headers)
        payload = json.loads(body)
        self.assertEqual(payload["model"], "synthetic-model")
        self.assertEqual(payload["temperature"], 0)
        self.assertEqual(payload["stop_sequences"], ["<<END_FILE>>"])
        self.assertEqual(payload["messages"][0]["content"], "Generate one synthetic file.")
        self.assertEqual(result["result"]["content"], "def ready():\n    return True\n")
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertEqual(metered[0]["usage_input"], 1000)
        self.assertEqual(metered[0]["usage_output"], 500)
        self.assertAlmostEqual(metered[0]["call_cost_usd"], (1000 * 1.0 + 500 * 5.0) / 1_000_000)

    def test_openai_compatible_request_uses_bearer_and_vendor_path_prefix(self):
        self.approve_provider()
        worker = self.worker(name="openai-compatible-api", base_url=ORIGIN + "/v1")
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, openai_body("def ready():\n    return True\n"))) as post:
            result = worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        _, url, headers, body, _, _ = post.call_args.args
        self.assertEqual(url, ORIGIN + "/v1/chat/completions")
        self.assertEqual(headers["Authorization"], f"Bearer {SYNTHETIC_KEY}")
        self.assertNotIn("x-api-key", headers)
        self.assertEqual(json.loads(body)["stop"], ["<<END_FILE>>"])
        self.assertEqual(result["result"]["content"], "def ready():\n    return True\n")

    def test_outbound_context_is_audited_even_when_the_call_fails(self):
        self.approve_provider()
        worker = self.worker()
        with patch("hybrid_hub.http_api_worker._http_post", side_effect=AdapterError("HTTP API request failed: URLError")):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        events = self.audit_events("worker.cloud-context-sent")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["adapter"], "anthropic-api")
        self.assertEqual(len(events[0]["prompt_sha256"]), 64)

    def test_refuses_without_live_enabled_matching_provider_profile(self):
        worker = self.worker()
        with patch("hybrid_hub.http_api_worker._http_post") as post:
            with self.assertRaises(AuthorizationRequired):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        post.assert_not_called()
        self.approve_provider(live=False)
        with self.assertRaises(AuthorizationRequired):
            worker.run_file(self.task["task_id"], "Generate one synthetic file.")

    def test_refuses_origin_mismatch_and_cap_above_provider_limit(self):
        self.approve_provider(origin="https://other.synthetic.test")
        worker = self.worker()
        with self.assertRaises(PolicyDenied):
            worker.run_file(self.task["task_id"], "Generate one synthetic file.")

    def test_cap_exceeding_call_blocks_and_next_call_never_egresses(self):
        self.approve_provider()
        worker = self.worker(cap=0.001, input_cost=100.0, output_cost=100.0)
        body = anthropic_body("def ready():\n    return True\n", input_tokens=10_000, output_tokens=10_000)
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, body)):
            with self.assertRaises(PolicyDenied):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertGreater(metered[0]["spent_usd"], metered[0]["cap_usd"])
        with patch("hybrid_hub.http_api_worker._http_post") as post:
            with self.assertRaises(PolicyDenied):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        post.assert_not_called()

    def test_secretlike_prompt_and_output_are_refused(self):
        self.approve_provider()
        worker = self.worker()
        with self.assertRaises(PolicyDenied):
            worker.run_file(self.task["task_id"], "Authenticate with password: synthetic-hunter2-value")
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, anthropic_body("api_key = 'synthetic-not-real-abcdef'\n"))):
            with self.assertRaises(PolicyDenied):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")

    def test_error_body_echoing_the_key_is_redacted(self):
        self.approve_provider()
        worker = self.worker()
        error = json.dumps({"error": {"message": f"invalid key {SYNTHETIC_KEY}"}}).encode("utf-8")
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(401, error)):
            with self.assertRaises(AdapterError) as caught:
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertNotIn(SYNTHETIC_KEY, str(caught.exception))
        self.assertIn("401", str(caught.exception))

    def test_truncated_missing_usage_oversized_and_invalid_responses_fail_closed(self):
        self.approve_provider()
        worker = self.worker()
        cases = [
            anthropic_body("x", stop_reason="max_tokens"),
            json.dumps({"content": [{"type": "text", "text": "x"}], "stop_reason": "stop_sequence"}).encode("utf-8"),
            b"not json",
            b"x" * (worker.config.max_output_bytes * 4 + 1),
        ]
        for body in cases:
            with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, body)):
                with self.assertRaises(AdapterError):
                    worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        openai_worker = self.worker(name="openai-compatible-api", base_url=ORIGIN + "/v1")
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, openai_body("x", finish_reason="length"))):
            with self.assertRaises(AdapterError):
                openai_worker.run_file(self.task["task_id"], "Generate one synthetic file.")

    def test_structured_mode_and_unreadable_key_fail_closed(self):
        self.approve_provider()
        worker = self.worker()
        with self.assertRaises(AdapterError):
            worker.run_structured(self.task["task_id"], "Return the required object.")
        os.chmod(self.key_path, 0o644)
        if os.name == "posix":
            with patch("hybrid_hub.http_api_worker._http_post") as post:
                with self.assertRaises(PolicyDenied):
                    worker.run_file(self.task["task_id"], "Generate one synthetic file.")
            post.assert_not_called()

    def test_preflight_reports_without_network(self):
        worker = self.worker()
        report = worker.preflight()
        self.assertEqual(report["transport"], "https-api")
        self.assertEqual(report["credential_source"], "key-file")
        self.assertTrue(report["available"])


class GuidedHttpApiFlowTests(IntegrationBase):
    def test_guided_run_verifies_with_http_api_adapter_identity(self):
        project = self.root / "api-guided-project"
        project.mkdir()
        (project / "README.md").write_text("# Synthetic API guided\n", encoding="utf-8")
        from test_integration import git_repo

        git_repo(project)
        registration = self.hub.registry.register_system("api-system", "api-client", "Api", [str(project)], ["standard"])
        discovery = self.hub.registry.discover("api-system")
        repo_id = discovery["repositories"][0]["repo_id"]
        version = self.hub.dossier.create_draft("api-system", {"purpose": "Synthetic API guided", "hierarchy": {"repositories": [repo_id]}, "provenance": [{"source": "synthetic-test"}]})
        self.hub.dossier.approve("api-system", version, "test-owner")
        self.hub.registry.approve_system("api-system", "test-owner")
        profile = self.hub.provider_profiles.propose("api-system", {
            "provider": "vendor-api", "mode": "live", "endpoint": ORIGIN, "account_type": "api",
            "account_identity": "test-owner", "max_turns": 1, "max_seconds": 300, "max_cost_usd": 1.0,
        }, "test-owner")
        self.hub.provider_profiles.approve(profile["profile_id"], "test-owner", enable_live=True)
        task = self.hub.tasks.create("api-system", "Synthetic API build", "R1", registration["policy"]["policy_hash"], "task-api-guided")
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED"):
            self.hub.tasks.transition(task["task_id"], state)
        plan = {
            "outcome": "A tested module", "non_goals": ["deployment"], "acceptance_criteria": ["module parses"],
            "packets": [{
                "packet_id": "core", "title": "Implement module", "objective": "Create the module",
                "repository_ids": [repo_id], "allowed_paths": {repo_id: ["app.py", "tests"]}, "context_paths": {repo_id: ["README.md"]},
                "deliverables": [
                    {"repo_id": repo_id, "path": "app.py", "purpose": "Implementation", "instructions": "Define only def ready() returning True."},
                    {"repo_id": repo_id, "path": "tests/test_app.py", "purpose": "Unit test", "instructions": "Use unittest to assert ready() is True."},
                ],
                "depends_on": [], "acceptance_criteria": ["ready returns True"], "test_focus": ["parse"],
                "research": [], "research_required": False, "research_guidance": [],
            }],
            "final_test_strategy": ["parse"], "unresolved_decisions": [],
        }
        self.hub.orchestrator.submit_guided_plan(task["task_id"], plan, "claude-interactive")
        workspace = self.hub.workspaces.create(task["task_id"], [repo_id])
        self.hub.tasks.transition(task["task_id"], "WORKSPACES_READY", evidence=[workspace["manifest_hash"]])
        key_path = self.root / "api-guided.key"
        key_path.write_text(SYNTHETIC_KEY + "\n", encoding="utf-8")
        os.chmod(key_path, 0o600)
        contents = {
            "app.py": "def ready():\n    return True\n",
            "tests/test_app.py": "import unittest\nfrom app import ready\nclass T(unittest.TestCase):\n    def test_ready(self):\n        self.assertTrue(ready())\n",
        }

        def fake_post(opener, url, headers, body, timeout, limit):
            prompt = json.loads(body)["messages"][0]["content"]
            target = prompt.split("GENERATE THIS ONE FILE NOW: ", 1)[1].splitlines()[0].split(":", 1)[1]
            return 200, anthropic_body(contents[target], input_tokens=200, output_tokens=100)

        config = HttpApiConfig("anthropic-api", ORIGIN, "synthetic-model", str(key_path), 1.0, 5.0, 0.25)
        worker = HttpApiWorker(self.hub.database, self.hub.audit, self.hub.leases, config, self.hub.provider_profiles)
        with patch("hybrid_hub.http_api_worker._http_post", side_effect=fake_post):
            def driver(task_id, prompt, attempt, role):
                return worker.run_file(task_id, prompt)["result"]

            report = self.hub.orchestrator.complete_guided(task["task_id"], driver, adapter="anthropic-api")
        self.assertTrue(report["verified"], report)
        self.assertEqual(report["implementation_attempts"][0]["adapter"], "anthropic-api")
        with self.hub.database.connect() as connection:
            metered = connection.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='worker.tokens-metered'").fetchone()[0]
        self.assertEqual(metered, 2)


if __name__ == "__main__":
    unittest.main()
