from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from test_integration import IntegrationBase

from hybrid_hub.errors import AdapterError, PolicyDenied, ValidationError
from hybrid_hub.subscription_worker import SubscriptionCliConfig, SubscriptionCliWorker


def completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class SubscriptionConfigTests(unittest.TestCase):
    def test_rejects_unknown_adapter_relative_path_and_wrong_basename(self):
        with patch.object(Path, "is_file", return_value=True):
            with self.assertRaises(ValidationError):
                SubscriptionCliConfig("codex-local", "/usr/bin/claude", "haiku")
            with self.assertRaises(ValidationError):
                SubscriptionCliConfig("claude-subscription-cli", "claude", "haiku")
            with self.assertRaises(ValidationError):
                SubscriptionCliConfig("claude-subscription-cli", "/usr/bin/codex", "haiku")
            with self.assertRaises(ValidationError):
                SubscriptionCliConfig("claude-subscription-cli", "/usr/bin/claude", "haiku", timeout=0)
            with self.assertRaises(ValidationError):
                SubscriptionCliConfig("claude-subscription-cli", "/usr/bin/claude", "haiku", effort="xhigh")
            with self.assertRaises(ValidationError):
                SubscriptionCliConfig("codex-subscription-cli", "/usr/bin/codex", "gpt-5.6-sol", effort="max")
            SubscriptionCliConfig("claude-subscription-cli", "/usr/bin/claude", "haiku")
            SubscriptionCliConfig("codex-subscription-cli", "/usr/bin/codex", "default")

    def test_rejects_missing_executable(self):
        with self.assertRaises(ValidationError):
            SubscriptionCliConfig("claude-subscription-cli", "/nonexistent/claude", "haiku")


class SubscriptionWorkerBase(IntegrationBase):
    def setUp(self):
        super().setUp()
        # "standard" permits cloud egress. The default fixture profile is
        # "confidential", which does NOT -- and every test in this file used to
        # run a no-egress system straight through a vendor-transmitting worker,
        # because the classification gate was dead code. Tests of normal
        # operation need a system that is actually allowed to transmit; the
        # refusal is asserted explicitly below.
        _, registration = self.register(git=True, profiles=["standard"])
        self.task = self.hub.tasks.create("system-a", "Synthetic subscription worker", "R1", registration["policy"]["policy_hash"], "task-subscription")
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED", "WORKSPACES_READY"):
            self.hub.tasks.transition(self.task["task_id"], state)

    def worker(self, adapter="claude-subscription-cli", executable="/usr/bin/claude", model="haiku", effort="high"):
        with patch.object(Path, "is_file", return_value=True):
            config = SubscriptionCliConfig(adapter, executable, model, effort=effort)
        return SubscriptionCliWorker(self.hub.database, self.hub.audit, self.hub.leases, config)

    def audit_events(self, event):
        with self.hub.database.connect() as connection:
            rows = connection.execute("SELECT payload_json FROM audit_events WHERE event_type=? ORDER BY event_id", (event,)).fetchall()
        return [json.loads(row[0]) for row in rows]


class ClaudeSubscriptionWorkerTests(SubscriptionWorkerBase):
    def test_run_file_uses_headless_print_mode_without_tools_or_api_keys(self):
        worker = self.worker()
        with patch("hybrid_hub.subscription_worker._subprocess_run", return_value=completed("```python\ndef ready():\n    return True\n```\n")) as process, \
                patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key", "OPENAI_API_KEY": "test-key", "HOME": "/home/synthetic"}):
            result = worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        argv = process.call_args.args[0]
        self.assertEqual(argv[1:5], ["-p", "--output-format", "text", "--no-session-persistence"])
        self.assertIn("--disallowedTools", argv)
        self.assertIn("--safe-mode", argv)
        self.assertEqual(argv[argv.index("--tools") + 1], "")
        self.assertEqual(argv[argv.index("--effort") + 1], "high")
        self.assertIn("--model", argv)
        self.assertEqual(argv[argv.index("--model") + 1], "haiku")
        self.assertNotIn("--fallback", argv)
        self.assertEqual(process.call_args.kwargs["input"], "Generate one synthetic file.")
        environment = process.call_args.kwargs["env"]
        self.assertNotIn("ANTHROPIC_API_KEY", environment)
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertEqual(environment["HOME"], "/home/synthetic")
        self.assertEqual(result["result"]["content"], "def ready():\n    return True\n")

    def test_outbound_context_is_audited_with_hash_before_generation(self):
        worker = self.worker()
        with patch("hybrid_hub.subscription_worker._subprocess_run", return_value=completed("content\n")):
            worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        events = self.audit_events("worker.cloud-context-sent")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["adapter"], "claude-subscription-cli")
        self.assertEqual(events[0]["model"], "haiku")
        self.assertEqual(events[0]["effort"], "high")
        self.assertEqual(events[0]["cli_version"], "not-preflighted")
        self.assertIn("safe-mode", events[0]["isolation_mode"])
        self.assertEqual(len(events[0]["argument_policy_hash"]), 64)
        self.assertEqual(events[0]["fallback"], "disabled")
        self.assertEqual(len(events[0]["prompt_sha256"]), 64)
        self.assertGreater(events[0]["prompt_bytes"], 0)

    def test_secretlike_prompt_and_output_are_refused(self):
        worker = self.worker()
        secretlike_prompt = "Authenticate with pass" + "word: synthetic-hunter2-value"
        with self.assertRaises(PolicyDenied):
            worker.run_file(self.task["task_id"], secretlike_prompt)
        secretlike_output = "api_" + "key = 'synthetic-not-real-abcdef'\n"
        with patch("hybrid_hub.subscription_worker._subprocess_run", return_value=completed(secretlike_output)):
            with self.assertRaises(PolicyDenied):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")

    def test_nonzero_exit_and_structured_mode_fail_closed(self):
        worker = self.worker()
        with patch("hybrid_hub.subscription_worker._subprocess_run", return_value=completed("", returncode=1, stderr="not logged in")):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        with self.assertRaises(AdapterError):
            worker.run_structured(self.task["task_id"], "Return the required object.")

    def test_default_model_omits_the_model_flag(self):
        worker = self.worker(model="default")
        with patch("hybrid_hub.subscription_worker._subprocess_run", return_value=completed("content\n")) as process:
            worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertNotIn("--model", process.call_args.args[0])


class ClassificationEgressRefusalTests(IntegrationBase):
    """The behavioural half of the P1 fix, at the boundary that transmits.

    A unit test on the policy helper proves the helper. This proves that a
    restricted system is REFUSED by the real worker, before any subprocess is
    launched -- which is what "the control is enforced" actually means. For
    seven sessions this was the missing test, and its absence is why a dead
    control read as a live one.
    """

    def worker_for(self, profiles, system_id):
        _, registration = self.register(system_id=system_id, client_id=f"client-{system_id}", git=True, profiles=profiles)
        task_id = f"task-{system_id}"
        self.hub.tasks.create(system_id, "Synthetic egress probe", "R1", registration["policy"]["policy_hash"], task_id)
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED", "WORKSPACES_READY"):
            self.hub.tasks.transition(task_id, state)
        with patch.object(Path, "is_file", return_value=True):
            config = SubscriptionCliConfig("claude-subscription-cli", "/usr/bin/claude", "haiku")
        return SubscriptionCliWorker(self.hub.database, self.hub.audit, self.hub.leases, config), task_id

    def test_restricted_systems_never_reach_the_vendor_cli(self):
        for profile in ("healthcare", "legal", "high-secret", "confidential", "gdpr", "financial", "production-critical"):
            with self.subTest(profile=profile):
                worker, task_id = self.worker_for([profile], f"system-{profile}")
                with patch("hybrid_hub.subscription_worker._subprocess_run", return_value=completed("content\n")) as process:
                    with self.assertRaises(PolicyDenied):
                        worker.run_file(task_id, "Generate one synthetic file.")
                # The refusal must happen BEFORE the vendor process starts.
                # Raising after the subprocess ran would still have leaked.
                process.assert_not_called()

    def test_a_permitted_system_still_reaches_the_vendor_cli(self):
        # Paired positive: without it, a worker that refused unconditionally
        # would pass every assertion above while breaking the product.
        worker, task_id = self.worker_for(["standard"], "system-permitted")
        with patch("hybrid_hub.subscription_worker._subprocess_run", return_value=completed("content\n")) as process:
            worker.run_file(task_id, "Generate one synthetic file.")
        process.assert_called()


class CodexSubscriptionWorkerTests(SubscriptionWorkerBase):
    def test_run_file_uses_read_only_exec_and_reads_last_message(self):
        worker = self.worker(
            adapter="codex-subscription-cli",
            executable="/usr/bin/codex",
            model="gpt-5.6-sol",
            effort="xhigh",
        )

        def fake_run(argv, **kwargs):
            last = Path(argv[argv.index("--output-last-message") + 1])
            last.parent.mkdir(parents=True, exist_ok=True)
            last.write_text("def ready():\n    return True\n", encoding="utf-8")
            return completed("noise that must be ignored\n")

        with patch("hybrid_hub.subscription_worker._subprocess_run", side_effect=fake_run) as process:
            result = worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        argv = process.call_args.args[0]
        self.assertEqual(argv[1], "exec")
        self.assertEqual(argv[argv.index("--sandbox") + 1], "read-only")
        self.assertIn("--skip-git-repo-check", argv)
        self.assertIn("--ephemeral", argv)
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("--ignore-rules", argv)
        self.assertEqual(argv[argv.index("-c") + 1], 'model_reasoning_effort="xhigh"')
        self.assertIn('model="gpt-5.6-sol"', argv)
        self.assertEqual(argv[-1], "-")
        self.assertNotIn("--model", argv)
        self.assertNotIn("--fallback", argv)
        self.assertEqual(process.call_args.kwargs["input"], "Generate one synthetic file.")
        self.assertEqual(result["result"]["content"], "def ready():\n    return True\n")

    def test_missing_last_message_fails_closed(self):
        worker = self.worker(adapter="codex-subscription-cli", executable="/usr/bin/codex", model="default")
        with patch("hybrid_hub.subscription_worker._subprocess_run", return_value=completed("stdout only\n")):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")


class GuidedSubscriptionFlowTests(IntegrationBase):
    def test_guided_run_verifies_with_subscription_adapter_identity(self):
        project = self.root / "guided-project"
        project.mkdir()
        (project / "README.md").write_text("# Synthetic subscription guided\n", encoding="utf-8")
        from test_integration import git_repo

        git_repo(project)
        registration = self.hub.registry.register_system("sub-system", "sub-client", "Sub", [str(project)], ["standard"])
        discovery = self.hub.registry.discover("sub-system")
        repo_id = discovery["repositories"][0]["repo_id"]
        version = self.hub.dossier.create_draft("sub-system", {"purpose": "Synthetic subscription guided", "hierarchy": {"repositories": [repo_id]}, "provenance": [{"source": "synthetic-test"}]})
        self.hub.dossier.approve("sub-system", version, "test-owner")
        self.hub.registry.approve_system("sub-system", "test-owner")
        task = self.hub.tasks.create("sub-system", "Synthetic subscription build", "R1", registration["policy"]["policy_hash"], "task-sub-guided")
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
        contents = {
            "app.py": "def ready():\n    return True\n",
            "tests/test_app.py": "import unittest\nfrom app import ready\nclass T(unittest.TestCase):\n    def test_ready(self):\n        self.assertTrue(ready())\n",
        }

        def fake_run(argv, **kwargs):
            target = kwargs["input"].split("GENERATE THIS ONE FILE NOW: ", 1)[1].splitlines()[0].split(":", 1)[1]
            return completed(contents[target])

        with patch("hybrid_hub.subscription_worker._subprocess_run", side_effect=fake_run):
            with patch.object(Path, "is_file", return_value=True):
                config = SubscriptionCliConfig("claude-subscription-cli", "/usr/bin/claude", "haiku")
            worker = SubscriptionCliWorker(self.hub.database, self.hub.audit, self.hub.leases, config)

            def driver(task_id, prompt, attempt, role):
                return worker.run_file(task_id, prompt)["result"]

            report = self.hub.orchestrator.complete_guided(task["task_id"], driver, adapter="claude-subscription-cli")
        self.assertTrue(report["verified"], report)
        self.assertEqual(report["implementation_attempts"][0]["adapter"], "claude-subscription-cli")


if __name__ == "__main__":
    unittest.main()
