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

    def verify(self, anchor: dict[str, Any] | None = None) -> bool:
        anchor_count: int | None = None
        anchor_head: Any = None
        if anchor is not None:
            if not isinstance(anchor, dict):
                return False
            anchor_count = anchor.get("count")
            anchor_head = anchor.get("head_hash")
            if not isinstance(anchor_count, int) or isinstance(anchor_count, bool) or anchor_count < 0:
                return False
        previous_hash = "0" * 64
        prefix_head = "0" * 64
        with self.database.connect() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
        if anchor_count is not None and len(rows) < anchor_count:
            # The chain cannot have fewer events than were anchored: truncation.
            return False
        for index, row in enumerate(rows):
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
            if anchor_count is not None and index + 1 == anchor_count:
                prefix_head = previous_hash
        if anchor_count is not None and prefix_head != anchor_head:
            # An externally stored anchor commits to the chain head at the moment
            # it was taken. Re-deriving the prefix head and comparing catches a
            # whole-chain rewrite that the internal chain check cannot — a
            # consistently rebuilt chain still re-derives valid per-row hashes.
            # Prefix (not full-head) comparison so legitimate later appends stay
            # valid: the anchor asserts the recorded history is unchanged.
            return False
        return True

    def head(self) -> dict[str, Any]:
        """Return a small tamper-evidence anchor to store OUTSIDE the runtime.

        The head hash commits to every event recorded so far; storing it
        somewhere the runtime cannot rewrite (a git commit, a printed note) lets
        a later `verify(anchor=...)` detect any change to that recorded history,
        while still accepting events appended afterwards.
        """
        with self.database.transaction() as connection:
            row = connection.execute("SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
            count = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        return {"head_hash": row[0] if row else "0" * 64, "count": count, "anchored_at": utc_now()}

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
