from __future__ import annotations

import json
import threading
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from hybrid_hub.task_authority import TaskAuthorityStore
from hybrid_hub.hub import Hub
from hybrid_hub.errors import (
    AuthorizationRequired,
    ConflictError,
    PolicyDenied,
    ValidationError,
)

_HUB_ERRORS = (
    AuthorizationRequired,
    ConflictError,
    PolicyDenied,
    ValidationError,
)


class TaskAuthorityStoreTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        project = root / "project"
        project.mkdir()
        hub = Hub(root / "hub")
        registration = hub.registry.register_system(
            "system-one",
            "client-one",
            "Synthetic",
            [str(project)],
            ["standard"],
        )
        hub.registry.discover("system-one")
        version = hub.dossier.create_draft(
            "system-one",
            {
                "purpose": "Synthetic task authority",
                "hierarchy": {"repositories": []},
                "provenance": [{"source": "synthetic-test"}],
            },
        )
        hub.dossier.approve("system-one", version, "human-reviewer")
        hub.registry.approve_system("system-one", "human-reviewer")
        hub.tasks.create(
            "system-one",
            "Synthetic task authority",
            "R1",
            registration["policy"]["policy_hash"],
            "task-one",
        )
        dossier_hash = hub.dossier.current("system-one")["hash"]
        self.hub = hub
        self.store = TaskAuthorityStore(hub.database, hub.audit, hub.dossier)
        self.selection = {
            "task_id": "task-one",
            "system_id": "system-one",
            "policy_hash": registration["policy"]["policy_hash"],
            "dossier_hash": dossier_hash,
            "access_mode": "subscription",
            "adapter": "codex-subscription-cli",
            "account_ref": "account-one",
            "model": "gpt-synthetic",
            "effort": "xhigh",
            "role": "coding",
            "artifact_scope": [{
                "repo_id": "repo-one",
                "path": "src/module.py",
                "sha256": "a" * 64,
            }],
            "fallback": [],
            "max_calls": 2,
            "timeout": 30,
            "max_output": 4096,
            "expires_at": self._expiry(1),
            "reuse_scope": "task-bounded",
        }

    @staticmethod
    def _expiry(days):
        value = datetime.now(timezone.utc) + timedelta(days=days)
        return value.isoformat().replace("+00:00", "Z")

    def _artifact(self):
        return deepcopy(self.selection["artifact_scope"][0])

    def _consume(self):
        return self.store.consume("task-one", "coding", self._artifact())

    def _reject(self, change):
        candidate = deepcopy(self.selection)
        change(candidate)
        try:
            with self.assertRaises((ValidationError, PolicyDenied)):
                self.store.create(candidate)
        finally:
            with self.hub.database.transaction() as connection:
                connection.execute(
                    "DELETE FROM metadata WHERE key=?",
                    ("task-selection:task-one",),
                )

    def test_create_get_consume_hash_audit_and_storage(self):
        with self.hub.database.connect() as connection:
            before = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        with patch.object(
            self.hub.audit, "append", wraps=self.hub.audit.append
        ) as logged:
            created = self.store.create(deepcopy(self.selection))
        self.assertEqual(
            {key: created[key] for key in self.selection},
            self.selection,
        )
        self.assertRegex(created["record_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(self.store.get("task-one"), created)
        used = self._consume()
        self.assertEqual(
            {key: used[key] for key in self.selection},
            self.selection,
        )
        self.assertEqual(used, self.store.get("task-one"))
        details = json.dumps(logged.call_args.args[1], sort_keys=True)
        self.assertIn(created["record_hash"], details)
        for value in (
            self.selection["account_ref"],
            self.selection["model"],
            self.selection["artifact_scope"][0]["path"],
        ):
            self.assertNotIn(value, details)
        with self.hub.database.connect() as connection:
            after = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            row = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                ("task-selection:task-one",),
            ).fetchone()
        self.assertEqual(after, before)
        self.assertIsNotNone(row)

    def test_exact_idempotence_and_conflict(self):
        first = self.store.create(deepcopy(self.selection))
        self.assertEqual(self.store.create(deepcopy(self.selection)), first)
        changed = deepcopy(self.selection)
        changed["model"] = "gpt-alternate"
        with self.assertRaises(ConflictError):
            self.store.create(changed)

    def test_live_authority_and_expiry(self):
        cases = (
            ("task", "task_id", "task-missing"),
            ("system", "system_id", "system-two"),
            ("policy", "policy_hash", "0" * 64),
            ("dossier", "dossier_hash", "1" * 64),
            ("expiry", "expires_at", self._expiry(-1)),
        )
        for name, field, value in cases:
            with self.subTest(name=name):
                self._reject(lambda item, f=field, v=value: item.update({f: v}))

    def test_shape_limits_and_enums(self):
        cases = [
            ("missing", lambda item: item.pop("role")),
            ("unknown", lambda item: item.update({"unexpected": "value"})),
        ]
        cases.extend(
            (f"boolean-{field}", lambda item, f=field: item.update({f: True}))
            for field in ("max_calls", "timeout", "max_output")
        )
        cases.extend((
            ("access", lambda item: item.update({"access_mode": "metered"})),
            ("adapter", lambda item: item.update({"adapter": "local-adapter"})),
            ("effort", lambda item: item.update({"effort": "maximum"})),
            ("blank-model", lambda item: item.update({"model": " "})),
            ("default-model", lambda item: item.update({"model": "default"})),
        ))
        for name, change in cases:
            with self.subTest(name=name):
                self._reject(change)

    def test_fallback_credentials_and_artifact_safety(self):
        cases = (
            ("duplicate-fallback", lambda item: item.update(
                {"fallback": ["gpt-alternate", "gpt-alternate"]}
            )),
            ("unsafe-fallback", lambda item: item.update(
                {"fallback": ["default"]}
            )),
            ("credential-value", lambda item: item.update(
                {"account_ref": "sk" + "-" + ("x" * 32)}
            )),
            ("artifact-repo", lambda item: item["artifact_scope"][0].update(
                {"repo_id": ".." + "/repo"}
            )),
            ("artifact-path", lambda item: item["artifact_scope"][0].update(
                {"path": ".." + "/module.py"}
            )),
            ("artifact-hash", lambda item: item["artifact_scope"][0].update(
                {"sha256": "z" * 64}
            )),
        )
        for name, change in cases:
            with self.subTest(name=name):
                self._reject(change)

    def test_missing_selection_requires_authorization(self):
        with self.assertRaises(AuthorizationRequired) as read_error:
            self.store.get("task-one")
        self.assertIn("task-selection-required", str(read_error.exception))
        with self.assertRaises(AuthorizationRequired) as use_error:
            self._consume()
        self.assertIn("task-selection-required", str(use_error.exception))

    def test_single_use_coherence_and_exhaustion(self):
        incoherent = deepcopy(self.selection)
        incoherent["reuse_scope"] = "single-use"
        with self.assertRaises(ValidationError):
            self.store.create(incoherent)

        coherent = deepcopy(self.selection)
        coherent["reuse_scope"] = "single-use"
        coherent["max_calls"] = 1
        self.store.create(coherent)
        first = self._consume()
        self.assertEqual(first["uses"], 1)
        with self.assertRaises(ConflictError):
            self._consume()
        self.assertEqual(self.store.get("task-one")["uses"], 1)

    def test_idempotent_create_preserves_uses_after_consume(self):
        self.store.create(deepcopy(self.selection))
        used = self._consume()
        self.assertEqual(used["uses"], 1)
        replayed = self.store.create(deepcopy(self.selection))
        self.assertEqual(replayed["uses"], 1)
        self.assertEqual(replayed["record_hash"], used["record_hash"])
        self.assertEqual(self.store.get("task-one")["uses"], 1)

    def test_account_reference_shapes(self):
        accepted = self.store.create(deepcopy(self.selection))
        self.assertEqual(accepted["account_ref"], "account-one")

        rejected_references = (
            "acct-one",
            "account",
            "account-",
            "sk" + "-" + ("p" * 32),
            "ghp" + "_" + ("q" * 36),
            ("AK" + "IA") + ("SYNTHETIC0EXAMPLE"[:16]),
            "r" * 64,
        )
        for reference in rejected_references:
            with self.subTest(reference=reference):
                self._reject(
                    lambda item, r=reference: item.update({"account_ref": r})
                )

    def test_fallback_diagnostic_accuracy(self):
        candidate = deepcopy(self.selection)
        candidate["fallback"] = ["gpt-synthetic"]
        with self.assertRaises(ValidationError) as caught:
            self.store.create(candidate)
        message = str(caught.exception)
        self.assertIn("unique", message)
        self.assertIn("distinct", message)
        self.assertIn("primary", message)
        self.assertNotIn("ordered", message)

    def test_bounded_ids_on_all_read_paths(self):
        for invalid in ("a" * 300, "bad" + chr(1) + "id", "", "-leading"):
            with self.subTest(identifier=repr(invalid)):
                with self.assertRaises(ValidationError):
                    self.store.get(invalid)
                with self.assertRaises(ValidationError):
                    self.store.consume(invalid, "coding", self._artifact())
                with self.assertRaises(ValidationError):
                    self.store.reject_legacy(invalid)

    def test_consume_role_and_artifact_binding(self):
        self.store.create(deepcopy(self.selection))

        with self.assertRaises(ValidationError):
            self.store.consume("task-one", "unknown-role", self._artifact())
        with self.assertRaises(ValidationError):
            self.store.consume("task-one", "coding", {"path": "src/module.py"})
        with self.assertRaises(PolicyDenied):
            self.store.consume("task-one", "review", self._artifact())

        wrong_entries = (
            {**self._artifact(), "repo_id": "repo-two"},
            {**self._artifact(), "path": "src/other.py"},
            {**self._artifact(), "sha256": "b" * 64},
        )
        for entry in wrong_entries:
            with self.subTest(entry=sorted(entry.items())):
                with self.assertRaises(PolicyDenied):
                    self.store.consume("task-one", "coding", entry)
        self.assertEqual(self.store.get("task-one")["uses"], 0)

        used = self._consume()
        self.assertEqual(used["uses"], 1)

    def test_overuse_tamper_and_legacy_refusal(self):
        selection = deepcopy(self.selection)
        selection["max_calls"] = 1
        self.store.create(selection)
        self._consume()
        with self.assertRaises((PolicyDenied, ConflictError)):
            self._consume()
        with self.hub.database.transaction() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                ("task-selection:task-one",),
            ).fetchone()
            wrapper = json.loads(row[0])
            wrapper["record_hash"] = "0" * 64
            connection.execute(
                "UPDATE metadata SET value=? WHERE key=?",
                (
                    self.hub.database.json(wrapper),
                    "task-selection:task-one",
                ),
            )
        with self.assertRaises(PolicyDenied):
            self.store.get("task-one")
        with self.assertRaises(PolicyDenied):
            self.store.reject_legacy("system-one")

    def _run_threads(self, workers):
        barrier = threading.Barrier(len(workers))
        outcomes = []
        lock = threading.Lock()

        def runner(worker):
            barrier.wait(timeout=30)
            try:
                result = worker()
            except _HUB_ERRORS as caught:
                with lock:
                    outcomes.append(("error", caught))
            else:
                with lock:
                    outcomes.append(("ok", result))

        threads = [
            threading.Thread(target=runner, args=(worker,))
            for worker in workers
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
            self.assertFalse(thread.is_alive())
        return outcomes

    def test_concurrent_identical_create_is_idempotent(self):
        outcomes = self._run_threads([
            lambda: self.store.create(deepcopy(self.selection)),
            lambda: self.store.create(deepcopy(self.selection)),
        ])
        self.assertEqual([status for status, _ in outcomes], ["ok", "ok"])
        first, second = (result for _, result in outcomes)
        self.assertEqual(first, second)
        with self.hub.database.connect() as connection:
            rows = connection.execute(
                "SELECT key FROM metadata WHERE key LIKE ?",
                ("task-selection:%",),
            ).fetchall()
        self.assertEqual(len(rows), 1)

    def test_concurrent_differing_create_single_winner(self):
        changed = deepcopy(self.selection)
        changed["model"] = "gpt-alternate"
        outcomes = self._run_threads([
            lambda: self.store.create(deepcopy(self.selection)),
            lambda: self.store.create(deepcopy(changed)),
        ])
        successes = [result for status, result in outcomes if status == "ok"]
        failures = [error for status, error in outcomes if status == "error"]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ConflictError)
        self.assertEqual(self.store.get("task-one"), successes[0])

    def test_concurrent_consume_respects_max_calls(self):
        self.store.create(deepcopy(self.selection))
        outcomes = self._run_threads([self._consume for _ in range(4)])
        successes = [result for status, result in outcomes if status == "ok"]
        failures = [error for status, error in outcomes if status == "error"]
        self.assertEqual(len(successes), self.selection["max_calls"])
        self.assertEqual(len(failures), 4 - self.selection["max_calls"])
        for error in failures:
            self.assertIsInstance(error, ConflictError)
        self.assertEqual(
            sorted(result["uses"] for result in successes),
            list(range(1, self.selection["max_calls"] + 1)),
        )
        self.assertEqual(
            self.store.get("task-one")["uses"], self.selection["max_calls"]
        )


if __name__ == "__main__":
    unittest.main()
