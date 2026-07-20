from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from hybrid_hub.audit import sanitize
from hybrid_hub.errors import PathDenied, PolicyDenied
from hybrid_hub.hub import Hub
from hybrid_hub.paths import SafePaths

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


class AdversarialTests(unittest.TestCase):
    def test_all_unsafe_fixture_paths_are_denied(self):
        paths = json.loads((FIXTURES / "security" / "unsafe-paths.json").read_text())["paths"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            safe = SafePaths([root])
            for value in paths:
                with self.subTest(value=value):
                    with self.assertRaises(PathDenied):
                        safe.authorize(value)

    def test_security_fixtures_cannot_enter_dossier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            hub = Hub(Path(temporary) / "runtime")
            hub.registry.register_system("secure-system", "secure-client", "Secure", [str(root)], ["healthcare", "legal"])
            for name in ("regulated-records.txt", "privileged.txt"):
                content = (FIXTURES / "security" / name).read_text()
                with self.subTest(name=name):
                    with self.assertRaises(PolicyDenied):
                        hub.dossier.create_draft("secure-system", {"purpose": content})

    def test_canary_and_encoded_canary_are_not_preserved_by_audit_sanitizer(self):
        canary = "hh_test_CANARY_7F3A9C2E_NOT_REAL"
        cleaned = json.dumps(sanitize({"token": canary, "message": f"token={canary}"}))
        self.assertNotIn(canary, cleaned)

    def test_intentionally_failing_build_is_detected(self):
        result = subprocess.run(["python3", "-m", "unittest", "-q", "test_broken.py"], cwd=FIXTURES / "failing_project", capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("intentional synthetic failure", result.stderr)

    def test_malicious_page_is_only_fixture_data(self):
        page = (FIXTURES / "security" / "malicious-page.html").read_text()
        self.assertIn("UNTRUSTED TEST PAGE", page)
        self.assertIn("169.254.169.254", page)

    def test_external_anchor_detects_post_anchor_chain_divergence(self):
        with tempfile.TemporaryDirectory() as temporary:
            hub = Hub(Path(temporary) / "runtime")
            hub.audit.append("test.first", {"n": 1})
            hub.audit.append("test.second", {"n": 2})
            anchor = hub.audit.head()
            self.assertEqual(anchor["count"], 2)
            self.assertTrue(hub.audit.verify(anchor))
            # Any change after the anchor point — an extra event here, or a whole
            # rebuilt chain in a real attack — leaves internal verify() still
            # passing (it re-derives every hash) while the external anchor kept
            # out of the runtime no longer matches.
            hub.audit.append("test.injected", {"n": 3})
            self.assertTrue(hub.audit.verify())
            self.assertFalse(hub.audit.verify(anchor))
        self.assertFalse((FIXTURES / "security" / "uploaded.txt").exists())


if __name__ == "__main__":
    unittest.main()
