from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from hybrid_hub.hub import Hub


def initialize_repo(path: Path, topology: dict | None = None) -> None:
    path.mkdir(parents=True)
    (path / "README.md").write_text(f"# {path.name} synthetic\n", encoding="utf-8")
    if topology:
        (path / "hub-topology.json").write_text(json.dumps(topology), encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "-c", "user.name=Hub Tests", "-c", "user.email=hub@example.invalid", "commit", "-qm", "synthetic baseline"], check=True)


class TopologyEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.hub = Hub(self.root / "runtime")

    def tearDown(self):
        self.temporary.cleanup()

    def register(self, suffix: str, roots: list[Path], deployment_order: list[str] | None = None, request: str = "Create verified code across the selected topology"):
        system_id = f"topology-{suffix}"
        registration = self.hub.registry.register_system(system_id, f"client-{suffix}", system_id, [str(item) for item in roots], ["standard"])
        discovery = self.hub.registry.discover(system_id)
        repo_ids = [item["repo_id"] for item in discovery["repositories"]]
        dossier = {"purpose": "Synthetic topology E2E", "hierarchy": {"repositories": repo_ids}, "provenance": [{"source": "synthetic"}], "quality_gates": registration["policy"]["gates"], "deployment": {"order": deployment_order or repo_ids}}
        version = self.hub.dossier.create_draft(system_id, dossier)
        self.hub.dossier.approve(system_id, version, "topology-owner")
        self.hub.registry.approve_system(system_id, "topology-owner")
        task_id = f"task-{suffix}"
        self.hub.tasks.create(system_id, request, "R1", registration["policy"]["policy_hash"], task_id)
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED"):
            self.hub.tasks.transition(task_id, state)
        self.hub.orchestrator.plan(task_id)
        manifest = self.hub.workspaces.create(task_id, repo_ids)
        self.hub.tasks.transition(task_id, "WORKSPACES_READY", evidence=[manifest["manifest_hash"]])
        return task_id, repo_ids, manifest

    @staticmethod
    def multi_repo_driver(task_id, prompt, attempt, role):
        request = json.loads(prompt)
        operations = []
        changed = []
        for index, repo_id in enumerate(request["repositories"], 1):
            app = f"def service_value():\n    return {index}\n"
            test = f"import unittest\nfrom app import service_value\nclass T(unittest.TestCase):\n    def test_value(self): self.assertEqual(service_value(), {index})\n"
            for path, content in (("app.py", app), ("tests/test_app.py", test)):
                operations.append({"repo_id": repo_id, "path": path, "action": "write", "content": content, "expected_hash": None, "executable": False})
                changed.append(f"{repo_id}:{path}")
        return {"status": "ok", "changed_paths": changed, "operations": operations}

    def test_polyrepo_microservices_change_and_release_manifest(self):
        roots = [self.root / name for name in ("contracts", "provider-service", "consumer-service")]
        for root in roots:
            initialize_repo(root)
        task_id, repo_ids, manifest = self.register("polyrepo", roots)
        # Replace the dossier's deterministic fallback order with a verified
        # explicit order matching the registered repository IDs.
        report = self.hub.orchestrator.complete(task_id, self.multi_repo_driver, adapter="codex-local")
        self.assertTrue(report["verified"], report)
        self.assertEqual(len(report["implementation_attempts"]), 1)
        release = self.hub.deployments.release(task_id)["manifest"]
        self.assertEqual(set(release["deployment_order"]), set(repo_ids))
        self.assertEqual(release["rollback_order"], list(reversed(release["deployment_order"])))
        self.assertEqual(len(release["repositories"]), 3)
        for item in manifest["repositories"]:
            self.assertTrue((Path(item["workspace"]) / "tests" / "test_app.py").is_file())

    def test_monorepo_two_components_are_changed_and_regression_tested(self):
        root = self.root / "monorepo"
        topology = {"components": [{"id": "alpha", "path": "packages/alpha", "type": "package"}, {"id": "beta", "path": "packages/beta", "type": "package"}], "dependencies": [{"from": "alpha", "to": "beta", "kind": "library"}]}
        initialize_repo(root, topology)
        task_id, repo_ids, manifest = self.register("monorepo", [root])

        def driver(task_id, prompt, attempt, role):
            repo_id = json.loads(prompt)["repositories"][0]
            values = {
                "packages/alpha/app.py": "def alpha():\n    return 'alpha'\n",
                "packages/beta/app.py": "def beta():\n    return 'beta'\n",
                "tests/test_packages.py": "import unittest\nfrom packages.alpha.app import alpha\nfrom packages.beta.app import beta\nclass T(unittest.TestCase):\n    def test_both(self): self.assertEqual((alpha(), beta()), ('alpha', 'beta'))\n",
            }
            return {"status": "ok", "changed_paths": [f"{repo_id}:{path}" for path in values], "operations": [{"repo_id": repo_id, "path": path, "action": "write", "content": content, "expected_hash": None, "executable": False} for path, content in values.items()]}

        report = self.hub.orchestrator.complete(task_id, driver, adapter="claude-local")
        self.assertTrue(report["verified"], report)
        targeted = self.hub.quality.latest(task_id, "targeted")
        self.assertEqual(set(targeted["affected_components"][repo_ids[0]]), {"alpha", "beta"})
        workspace = Path(manifest["repositories"][0]["workspace"])
        self.assertTrue((workspace / "packages" / "alpha" / "app.py").is_file())
        self.assertTrue((workspace / "packages" / "beta" / "app.py").is_file())

    def test_hybrid_monorepo_and_standalone_service_complete_together(self):
        monorepo = self.root / "platform"
        service = self.root / "service"
        initialize_repo(monorepo, {"components": [{"id": "web", "path": "web", "type": "app"}, {"id": "shared", "path": "shared", "type": "package"}], "dependencies": [{"from": "shared", "to": "web", "kind": "library"}]})
        initialize_repo(service, {"components": [{"id": "api", "path": ".", "type": "service"}], "dependencies": []})
        task_id, repo_ids, _ = self.register("hybrid", [monorepo, service])
        report = self.hub.orchestrator.complete(task_id, self.multi_repo_driver, adapter="codex-local")
        self.assertTrue(report["verified"], report)
        self.assertEqual(len(self.hub.deployments.release(task_id)["manifest"]["repositories"]), 2)
        self.assertEqual(set(self.hub.quality.latest(task_id, "full")["affected_components"]), set(repo_ids))

    def test_large_repository_uses_bounded_relevant_context_and_still_verifies(self):
        root = self.root / "large-repository"
        initialize_repo(root)
        modules = root / "modules"
        modules.mkdir()
        for index in range(300):
            (modules / f"module_{index:03d}.py").write_text(f"def value_{index}():\n    return {index}\n", encoding="utf-8")
        relevant = modules / "appointment_cancel.py"
        relevant.write_text("def can_cancel(status):\n    return False\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(root), "-c", "user.name=Hub Tests", "-c", "user.email=hub@example.invalid", "commit", "-qm", "large synthetic fixture"], check=True)
        task_id, repo_ids, _ = self.register("large", [root], request="Implement appointment cancellation eligibility")
        observations = {}

        def driver(task_id, prompt, attempt, role):
            observations["prompt_bytes"] = len(prompt.encode("utf-8"))
            request = json.loads(prompt)
            selected = {item["path"]: item for item in request["context_files"]}
            observations["selected"] = sorted(selected)
            current = selected["modules/appointment_cancel.py"]
            repo_id = repo_ids[0]
            values = {
                "modules/appointment_cancel.py": "def can_cancel(status):\n    return status in {'scheduled', 'confirmed'}\n",
                "tests/test_cancel.py": "import unittest\nfrom modules.appointment_cancel import can_cancel\nclass T(unittest.TestCase):\n    def test_rules(self):\n        self.assertTrue(can_cancel('scheduled'))\n        self.assertFalse(can_cancel('completed'))\n",
            }
            return {"status": "ok", "changed_paths": [f"{repo_id}:{path}" for path in values], "operations": [
                {"repo_id": repo_id, "path": path, "action": "write", "content": content, "expected_hash": current["hash"] if path == "modules/appointment_cancel.py" else None, "executable": False}
                for path, content in values.items()
            ]}

        report = self.hub.orchestrator.complete(task_id, driver, adapter="codex-local")
        self.assertTrue(report["verified"], report)
        self.assertLess(observations["prompt_bytes"], 32768)
        self.assertIn("modules/appointment_cancel.py", observations["selected"])
        self.assertLess(len(observations["selected"]), 301)


if __name__ == "__main__":
    unittest.main()
