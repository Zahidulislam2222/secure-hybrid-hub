from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
SKILLS = {"hybrid-init", "hybrid-run", "hybrid-status", "hybrid-resume", "hybrid-cancel", "hybrid-promote", "hybrid-dossier"}


class ProjectAssetTests(unittest.TestCase):
    def test_every_phase_has_a_valid_dossier_checkpoint(self):
        dossier = json.loads((ROOT / "dossier" / "development.json").read_text())
        self.assertEqual(len(dossier["phase_checkpoints"]), 7)
        for index, relative in enumerate(dossier["phase_checkpoints"]):
            checkpoint = json.loads((ROOT / "dossier" / relative).read_text())
            self.assertEqual(checkpoint["phase"], f"phase-{index}")
            self.assertEqual(checkpoint["state"], "completed")
            self.assertEqual(len(checkpoint["effective_policy_hash"]), 64)
            self.assertNotIn("pending", checkpoint["effective_policy_hash"])
        evidence = json.loads((ROOT / "verification" / "phase-4.json").read_text())
        self.assertEqual(evidence["automated_test_status"], "passed")
        self.assertFalse(evidence["production_readiness_claim"])
        research = json.loads((ROOT / "verification" / "phase-5.json").read_text())
        self.assertEqual(research["live_network_calls"], 0)
        self.assertFalse(research["searxng_installed_or_started"])
        dlp = json.loads((ROOT / "verification" / "phase-6.json").read_text())
        self.assertFalse(dlp["synthetic_canary_exposure"])
        self.assertEqual(dlp["bundle_transmission_attempts"], 0)

    def test_project_local_surfaces_are_present_and_promotion_is_explicit(self):
        codex = {path.parent.name for path in (WORKSPACE / ".agents" / "skills").glob("*/SKILL.md")}
        claude = {path.parent.name for path in (WORKSPACE / ".claude" / "skills").glob("*/SKILL.md")}
        self.assertEqual(codex, SKILLS)
        self.assertEqual(claude, SKILLS)
        self.assertIn("disable-model-invocation: true", (WORKSPACE / ".claude" / "skills" / "hybrid-promote" / "SKILL.md").read_text())
        self.assertFalse((WORKSPACE / ".codex" / "skills").exists())
        json.loads((WORKSPACE / ".vscode" / "tasks.json").read_text())
        dossier = (WORKSPACE / "PROJECT-DOSSIER.md").read_text()
        self.assertIn("## 4. Dossier hierarchy and tracing", dossier)
        self.assertIn("hybrid-hub/dossier/development.json", dossier)
        self.assertFalse((ROOT / "integrations" / "codex-skill").exists())
        self.assertFalse((ROOT / "integrations" / "claude-skill").exists())


if __name__ == "__main__":
    unittest.main()
