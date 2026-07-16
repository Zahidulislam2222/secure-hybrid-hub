from __future__ import annotations

import base64
import json
import re
import uuid
from typing import Any

from .storage import Database
from .util import canonical_json, sha256_bytes, utc_now

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|password|secret)\s*[:=]\s*(?!(?:os\.|process\.env|env\[|getenv\(|settings\.|config\.|vault\.|secret_ref|\[?REDACTED\]?|placeholder|test[-_]))[^\s,;]+"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"hh_test_CANARY_[A-Z0-9_]+"),
]


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if re.search(r"(?i)(secret|password|token|credential|api.?key)", key) else sanitize(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        result = value
        for pattern in SECRET_PATTERNS:
            result = pattern.sub("[REDACTED]", result)
        return result
    return value


class AuditLog:
    def __init__(self, database: Database):
        self.database = database

    def append(self, event_type: str, payload: dict[str, Any], *, system_id: str | None = None, task_id: str | None = None, connection=None) -> str:
        owns_transaction = connection is None
        context = self.database.transaction() if owns_transaction else _existing(connection)
        with context as conn:
            previous = conn.execute("SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
            previous_hash = previous[0] if previous else "0" * 64
            timestamp = utc_now()
            event_id = str(uuid.uuid4())
            safe_payload = sanitize(payload)
            material = {
                "event_id": event_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "system_id": system_id,
                "task_id": task_id,
                "payload": safe_payload,
                "previous_hash": previous_hash,
            }
            event_hash = sha256_bytes(canonical_json(material))
            conn.execute(
                "INSERT INTO audit_events(event_id,timestamp,event_type,system_id,task_id,payload_json,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?,?)",
                (event_id, timestamp, event_type, system_id, task_id, self.database.json(safe_payload), previous_hash, event_hash),
            )
            return event_hash

    def verify(self) -> bool:
        previous_hash = "0" * 64
        with self.database.connect() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
        for row in rows:
            payload = json.loads(row["payload_json"])
            material = {
                "event_id": row["event_id"], "timestamp": row["timestamp"],
                "event_type": row["event_type"], "system_id": row["system_id"],
                "task_id": row["task_id"], "payload": payload,
                "previous_hash": previous_hash,
            }
            if row["previous_hash"] != previous_hash or row["event_hash"] != sha256_bytes(canonical_json(material)):
                return False
            previous_hash = row["event_hash"]
        return True

    def export(self) -> list[dict[str, Any]]:
        with self.database.connect() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
        return [{key: row[key] if key != "payload_json" else json.loads(row[key]) for key in row.keys()} for row in rows]


class _existing:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *_):
        return False
