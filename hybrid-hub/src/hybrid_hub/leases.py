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
                    holder = connection.execute("SELECT owner FROM leases WHERE resource=?", (resource,)).fetchone()
                    owned_by = f" held by {holder[0]}; cancel or resume that task to release it" if holder else ""
                    raise ConflictError(f"resource already leased: {resource}{owned_by}") from exc
                raise

    def acquire_or_renew(self, resource: str, owner: str, ttl_seconds: int = 300) -> None:
        """Take the lease, or extend it if this owner already holds it.

        `acquire` is strict: the UNIQUE constraint is on `resource` alone, so
        it raises even when the caller is the existing holder. That is right
        for taking a resource and wrong for RE-taking one, which is what
        recovery does -- a task that ended terminally had its leases released
        by final_report, but a task resumed from a pause still holds its own.
        Recovery must work in both cases and must still refuse a resource a
        DIFFERENT task has taken in the meantime.
        """
        now = time.time()
        with self.database.transaction() as connection:
            connection.execute("DELETE FROM leases WHERE expires_at<=?", (now,))
            holder = connection.execute("SELECT owner FROM leases WHERE resource=?", (resource,)).fetchone()
            if holder is None:
                connection.execute("INSERT INTO leases VALUES(?,?,?,?)", (resource, owner, utc_now(), now + ttl_seconds))
                return
            if holder[0] != owner:
                raise ConflictError(f"resource already leased: {resource} held by {holder[0]}; cancel or resume that task to release it")
            connection.execute("UPDATE leases SET expires_at=? WHERE resource=? AND owner=?", (now + ttl_seconds, resource, owner))

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
