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

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        for path in (self.artifacts, self.workspaces, self.evidence, self.egress, self.cache, self.locks):
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
