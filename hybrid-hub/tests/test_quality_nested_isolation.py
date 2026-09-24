from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hybrid_hub.hub import Hub
from hybrid_hub.sandbox_exec import inherited_outer_sandbox


class InheritedQualityIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.outer = Path(self.temporary.name)
        self.home = self.outer / "home"
        self.workspace = self.outer / "workspace"
        self.home.mkdir()
        self.workspace.mkdir()
        self.hub = Hub(self.home / "nested-runtime")

    def tearDown(self):
        self.temporary.cleanup()

    def recognition(self, *, effective_user: int = 0, outside_denied: bool = True):
        environment = {"HOME": str(self.home), "TMPDIR": str(self.home)}
        with (
            patch.dict(os.environ, environment, clear=True),
            patch("hybrid_hub.quality.os.geteuid", return_value=effective_user),
            patch("hybrid_hub.quality.Path.cwd", return_value=self.workspace),
            patch(
                "hybrid_hub.sandbox_exec.outside_root_read_is_denied",
                return_value=outside_denied,
            ),
        ):
            return inherited_outer_sandbox(self.hub.database.layout.root)

    def test_verified_outer_confinement_is_inherited(self):
        self.assertEqual(self.recognition(), self.outer.resolve())

    def test_unmapped_user_cannot_claim_inherited_isolation(self):
        self.assertIsNone(self.recognition(effective_user=1000))

    def test_readable_outside_root_prevents_inherited_isolation(self):
        self.assertIsNone(self.recognition(outside_denied=False))

    def test_distinct_temporary_root_prevents_inherited_isolation(self):
        other = self.outer / "other"
        other.mkdir()
        with (
            patch.dict(
                os.environ,
                {"HOME": str(self.home), "TMPDIR": str(other)},
                clear=True,
            ),
            patch("hybrid_hub.quality.os.geteuid", return_value=0),
            patch("hybrid_hub.quality.Path.cwd", return_value=self.workspace),
            patch(
                "hybrid_hub.sandbox_exec.outside_root_read_is_denied",
                return_value=True,
            ),
        ):
            self.assertIsNone(inherited_outer_sandbox(self.hub.database.layout.root))
