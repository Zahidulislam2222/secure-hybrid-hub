from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest


HUB_ROOT = Path(__file__).resolve().parents[1]


class ModelCliEntrypointTests(unittest.TestCase):
    def assert_model_help(self, command, environment=None):
        result = subprocess.run(command, cwd=HUB_ROOT.parent, env=environment, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("policy-propose", result.stdout)
        self.assertIn("route", result.stdout)

    def test_script_dispatches_model_command(self):
        self.assert_model_help([sys.executable, str(HUB_ROOT / "hub.py"), "model", "--help"])

    def test_module_dispatches_model_command(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(HUB_ROOT / "src")
        self.assert_model_help([sys.executable, "-m", "hybrid_hub", "model", "--help"], environment)


if __name__ == "__main__":
    unittest.main()
