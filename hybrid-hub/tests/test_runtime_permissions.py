from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hybrid_hub.errors import PolicyDenied
from hybrid_hub.hub import Hub
from hybrid_hub.storage import RuntimeLayout


class RuntimePermissionTests(unittest.TestCase):
    def test_runtime_rejects_filesystem_that_ignores_private_directory_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            runtime.mkdir(mode=0o755)
            runtime.chmod(0o755)
            with patch("hybrid_hub.storage.os.chmod", return_value=None):
                with self.assertRaisesRegex(PolicyDenied, "0o700"):
                    RuntimeLayout(runtime).initialize()

    def test_runtime_rejects_filesystem_that_ignores_private_file_mode(self):
        exposed = SimpleNamespace(st_mode=stat.S_IFREG | 0o666)
        with tempfile.TemporaryDirectory() as temporary:
            with patch("hybrid_hub.storage.os.fstat", return_value=exposed):
                with self.assertRaisesRegex(PolicyDenied, "0o600"):
                    RuntimeLayout(Path(temporary) / "runtime").initialize()

    def test_runtime_and_database_are_owner_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            hub = Hub(Path(temporary) / "runtime")
            self.assertEqual(
                stat.S_IMODE(hub.database.layout.root.stat().st_mode), 0o700
            )
            self.assertEqual(
                stat.S_IMODE(hub.database.layout.db.stat().st_mode), 0o600
            )


if __name__ == "__main__":
    unittest.main()
