from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .util import canonical_json, sha256_bytes, utc_now


class RuntimeLayout:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.db = self.root / "hub.sqlite3"
        self.artifacts = self.root / "artifacts"
        self.workspaces = self.root / "workspaces"
        self.evidence = self.root / "evidence"
        self.egress = self.root / "egress"
        self.cache = self.root / "cache"
        self.locks = self.root / "locks"
        self.operations = self.root / "operations"
        self.backups = self.root / "backups"

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        for path in (self.artifacts, self.workspaces, self.evidence, self.egress, self.cache, self.locks, self.operations, self.backups):
            path.mkdir(exist_ok=True, mode=0o700)
            os.chmod(path, 0o700)


SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS systems(
  system_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, name TEXT NOT NULL,
  classification TEXT NOT NULL, profiles_json TEXT NOT NULL, roots_json TEXT NOT NULL,
  approved INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS repositories(
  repo_id TEXT PRIMARY KEY, system_id TEXT NOT NULL REFERENCES systems(system_id),
  path TEXT NOT NULL, kind TEXT NOT NULL, components_json TEXT NOT NULL,
  UNIQUE(system_id, path)
);
CREATE TABLE IF NOT EXISTS tasks(
  task_id TEXT PRIMARY KEY, system_id TEXT NOT NULL REFERENCES systems(system_id),
  request TEXT NOT NULL, state TEXT NOT NULL, classification TEXT NOT NULL,
  policy_hash TEXT NOT NULL, reason TEXT, cancelled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
  timestamp TEXT NOT NULL, event_type TEXT NOT NULL, system_id TEXT, task_id TEXT,
  payload_json TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS checkpoints(
  checkpoint_id TEXT PRIMARY KEY, system_id TEXT NOT NULL, task_id TEXT,
  phase TEXT NOT NULL, state TEXT NOT NULL, payload_json TEXT NOT NULL,
  checkpoint_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dossier_versions(
  system_id TEXT NOT NULL REFERENCES systems(system_id), version INTEGER NOT NULL,
  approved INTEGER NOT NULL, payload_json TEXT NOT NULL, dossier_hash TEXT NOT NULL,
  created_at TEXT NOT NULL, PRIMARY KEY(system_id, version)
);
CREATE TABLE IF NOT EXISTS dossier_proposals(
  proposal_id TEXT PRIMARY KEY, system_id TEXT NOT NULL, task_id TEXT,
  status TEXT NOT NULL, requires_human INTEGER NOT NULL, change_json TEXT NOT NULL,
  created_at TEXT NOT NULL, decided_at TEXT
);
CREATE TABLE IF NOT EXISTS leases(
  resource TEXT PRIMARY KEY, owner TEXT NOT NULL, acquired_at TEXT NOT NULL,
  expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts(
  digest TEXT PRIMARY KEY, media_type TEXT NOT NULL, size INTEGER NOT NULL,
  relative_path TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quality_command_sets(
  command_set_id TEXT PRIMARY KEY, system_id TEXT NOT NULL REFERENCES systems(system_id),
  status TEXT NOT NULL, commands_json TEXT NOT NULL, command_set_hash TEXT NOT NULL,
  proposed_by TEXT NOT NULL, approved_by TEXT, created_at TEXT NOT NULL,
  approved_at TEXT
);
CREATE TABLE IF NOT EXISTS quality_runs(
  run_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
  scope TEXT NOT NULL, passed INTEGER NOT NULL, summary_json TEXT NOT NULL,
  evidence_digest TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS research_policy_versions(
  policy_id TEXT PRIMARY KEY, system_id TEXT NOT NULL REFERENCES systems(system_id),
  status TEXT NOT NULL, policy_json TEXT NOT NULL, policy_hash TEXT NOT NULL,
  proposed_by TEXT NOT NULL, approved_by TEXT, live_enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, approved_at TEXT
);
CREATE TABLE IF NOT EXISTS research_evidence(
  evidence_id TEXT PRIMARY KEY, system_id TEXT NOT NULL REFERENCES systems(system_id),
  task_id TEXT NOT NULL REFERENCES tasks(task_id), source_url TEXT NOT NULL,
  retrieved_at TEXT NOT NULL, content_hash TEXT NOT NULL, artifact_digest TEXT NOT NULL,
  size INTEGER NOT NULL, media_type TEXT NOT NULL, metadata_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS research_index(
  system_id TEXT NOT NULL, token TEXT NOT NULL, evidence_id TEXT NOT NULL REFERENCES research_evidence(evidence_id),
  PRIMARY KEY(system_id, token, evidence_id)
);
CREATE TABLE IF NOT EXISTS secret_capabilities(
  capability_id TEXT PRIMARY KEY, system_id TEXT NOT NULL REFERENCES systems(system_id),
  status TEXT NOT NULL, capability_json TEXT NOT NULL, capability_hash TEXT NOT NULL,
  proposed_by TEXT NOT NULL, approved_by TEXT, created_at TEXT NOT NULL, approved_at TEXT
);
CREATE TABLE IF NOT EXISTS egress_bundles(
  bundle_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
  system_id TEXT NOT NULL REFERENCES systems(system_id), provider TEXT NOT NULL,
  status TEXT NOT NULL, manifest_json TEXT NOT NULL, bundle_hash TEXT NOT NULL,
  relative_path TEXT NOT NULL, created_at TEXT NOT NULL, approved_by TEXT,
  approved_at TEXT
);
CREATE TABLE IF NOT EXISTS provider_profiles(
  profile_id TEXT PRIMARY KEY, system_id TEXT NOT NULL REFERENCES systems(system_id),
  provider TEXT NOT NULL, status TEXT NOT NULL, profile_json TEXT NOT NULL,
  profile_hash TEXT NOT NULL, proposed_by TEXT NOT NULL, approved_by TEXT,
  live_enabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, approved_at TEXT
);
CREATE TABLE IF NOT EXISTS cloud_runs(
  run_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
  bundle_id TEXT NOT NULL REFERENCES egress_bundles(bundle_id), profile_id TEXT NOT NULL REFERENCES provider_profiles(profile_id),
  purpose TEXT NOT NULL, status TEXT NOT NULL, result_json TEXT NOT NULL,
  result_hash TEXT NOT NULL, turns INTEGER NOT NULL, elapsed_ms INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS implementation_attempts(
  attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
  adapter TEXT NOT NULL, attempt INTEGER NOT NULL, status TEXT NOT NULL,
  request_hash TEXT NOT NULL, result_hash TEXT NOT NULL, changed_paths_json TEXT NOT NULL,
  diff_hash TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(task_id, adapter, attempt)
);
CREATE TABLE IF NOT EXISTS release_records(
  release_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
  system_id TEXT NOT NULL REFERENCES systems(system_id), status TEXT NOT NULL,
  manifest_json TEXT NOT NULL, manifest_hash TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deployment_records(
  deployment_id TEXT PRIMARY KEY, release_id TEXT NOT NULL REFERENCES release_records(release_id),
  task_id TEXT NOT NULL REFERENCES tasks(task_id), environment TEXT NOT NULL,
  status TEXT NOT NULL, adapter_id TEXT NOT NULL, evidence_json TEXT NOT NULL,
  approval_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS production_approvals(
  approval_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
  release_id TEXT NOT NULL REFERENCES release_records(release_id), approver TEXT NOT NULL,
  scope_json TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, consumed_at TEXT
);
CREATE TABLE IF NOT EXISTS policy_exceptions(
  exception_id TEXT PRIMARY KEY, system_id TEXT NOT NULL REFERENCES systems(system_id),
  rule TEXT NOT NULL, reason TEXT NOT NULL, owner TEXT NOT NULL, status TEXT NOT NULL,
  expires_at TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operational_jobs(
  job_id TEXT PRIMARY KEY, job_type TEXT NOT NULL, status TEXT NOT NULL,
  summary_json TEXT NOT NULL, evidence_hash TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS project_modifiers(
  modifier_id TEXT PRIMARY KEY, system_id TEXT NOT NULL REFERENCES systems(system_id),
  name TEXT NOT NULL, status TEXT NOT NULL, modifier_json TEXT NOT NULL,
  modifier_hash TEXT NOT NULL, proposed_by TEXT NOT NULL, approved_by TEXT,
  created_at TEXT NOT NULL, approved_at TEXT
);
CREATE TABLE IF NOT EXISTS task_modifier_bindings(
  task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), modifier_id TEXT NOT NULL REFERENCES project_modifiers(modifier_id),
  modifier_hash TEXT NOT NULL, bound_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS guided_plans(
  plan_id TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id),
  system_id TEXT NOT NULL REFERENCES systems(system_id), source TEXT NOT NULL,
  status TEXT NOT NULL, plan_json TEXT NOT NULL, plan_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS guided_packets(
  task_id TEXT NOT NULL REFERENCES tasks(task_id), packet_id TEXT NOT NULL,
  sequence INTEGER NOT NULL, status TEXT NOT NULL, packet_json TEXT NOT NULL,
  packet_hash TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  result_hash TEXT, quality_digest TEXT, updated_at TEXT NOT NULL,
  PRIMARY KEY(task_id, packet_id), UNIQUE(task_id, sequence)
);
"""


class Database:
    def __init__(self, layout: RuntimeLayout):
        self.layout = layout
        layout.initialize()
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            connection.execute("INSERT OR IGNORE INTO metadata(key,value) VALUES('emergency_stop','0')")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.layout.db, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def put_artifact(self, payload: bytes, media_type: str = "application/json") -> str:
        digest = sha256_bytes(payload)
        relative = Path(digest[:2]) / digest
        destination = self.layout.artifacts / relative
        if not destination.exists():
            from .util import atomic_write

            atomic_write(destination, payload)
        with self.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO artifacts VALUES(?,?,?,?,?)",
                (digest, media_type, len(payload), str(relative), utc_now()),
            )
        return digest

    def set_emergency_stop(self, active: bool) -> None:
        with self.transaction() as connection:
            connection.execute("UPDATE metadata SET value=? WHERE key='emergency_stop'", ("1" if active else "0",))

    def emergency_stopped(self) -> bool:
        with self.connect() as connection:
            row = connection.execute("SELECT value FROM metadata WHERE key='emergency_stop'").fetchone()
        return row is None or row[0] != "0"

    @staticmethod
    def json(value: object) -> str:
        return canonical_json(value).decode("utf-8")
