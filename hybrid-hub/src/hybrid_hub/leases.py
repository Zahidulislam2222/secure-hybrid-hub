from __future__ import annotations

import time
from contextlib import contextmanager

from .errors import ConflictError
from .storage import Database
from .util import utc_now


class LeaseManager:
    def __init__(self, database: Database):
        self.database = database

    def acquire(self, resource: str, owner: str, ttl_seconds: int = 300) -> None:
        now = time.time()
        with self.database.transaction() as connection:
            connection.execute("DELETE FROM leases WHERE expires_at<=?", (now,))
            try:
                connection.execute("INSERT INTO leases VALUES(?,?,?,?)", (resource, owner, utc_now(), now + ttl_seconds))
            except Exception as exc:
                if "UNIQUE" in str(exc):
                    raise ConflictError(f"resource already leased: {resource}") from exc
                raise

    def release(self, resource: str, owner: str) -> None:
        with self.database.transaction() as connection:
            connection.execute("DELETE FROM leases WHERE resource=? AND owner=?", (resource, owner))

    def list(self) -> list[dict[str, object]]:
        now = time.time()
        with self.database.transaction() as connection:
            connection.execute("DELETE FROM leases WHERE expires_at<=?", (now,))
            rows = connection.execute("SELECT * FROM leases ORDER BY resource").fetchall()
        return [dict(row) for row in rows]

    def release_owner(self, owner: str) -> int:
        with self.database.transaction() as connection:
            return connection.execute("DELETE FROM leases WHERE owner=?", (owner,)).rowcount

    @contextmanager
    def held(self, resource: str, owner: str, ttl_seconds: int = 300):
        self.acquire(resource, owner, ttl_seconds)
        try:
            yield
        finally:
            self.release(resource, owner)
