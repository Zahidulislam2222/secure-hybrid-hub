from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

from .audit import AuditLog, SECRET_PATTERNS
from .errors import AdapterError, ConflictError, PolicyDenied, ValidationError
from .storage import Database
from .util import atomic_write, bounded_text, canonical_json, require_id, sha256_bytes, sha256_json, utc_now


DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
QUERY_FORBIDDEN = [
    *SECRET_PATTERNS,
    re.compile(r"(?i)(?:[A-Z]:\\|/mnt/[a-z]/|/home/|/Users/|\.env\b|client[_ -]?secret|patient|medical record|privileged communication)"),
    re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
]
INJECTION = re.compile(r"(?i)(?:ignore (?:all |the )?(?:previous|prior|system) instructions|read (?:the )?\.env|upload (?:the )?repository|reveal (?:secrets|credentials)|execute (?:this|the following) command|change (?:the )?(?:policy|permissions))")
TOKEN = re.compile(r"[a-z0-9][a-z0-9._+-]{1,63}")


def validate_domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("research domain must be text")
    try:
        normalized = value.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValidationError("research domain IDNA encoding failed") from exc
    if not DOMAIN.fullmatch(normalized) or normalized == "localhost":
        raise ValidationError("research domain must be an exact public DNS name")
    return normalized


def validate_url(url: str, domains: set[str]) -> str:
    bounded_text(url, 4096, "research URL")
    decoded = urllib.parse.unquote(url)
    if any(pattern.search(decoded) for pattern in QUERY_FORBIDDEN):
        raise PolicyDenied("research URL contains private, credential-like, regulated, or environment-specific context")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or not parsed.hostname or parsed.port not in {None, 443}:
        raise PolicyDenied("research permits only credential-free HTTPS URLs on port 443 without fragments")
    hostname = validate_domain(parsed.hostname)
    if hostname not in domains:
        raise PolicyDenied("research URL host is not explicitly approved")
    return urllib.parse.urlunsplit(("https", hostname, parsed.path or "/", parsed.query, ""))


def validate_public_resolution(hostname: str) -> list[str]:
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        raise AdapterError("research hostname resolution failed") from exc
    if not addresses:
        raise AdapterError("research hostname did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise PolicyDenied("research hostname resolved to a forbidden address")
    return addresses


class ResearchPolicyStore:
    def __init__(self, database: Database, audit: AuditLog):
        self.database = database
        self.audit = audit

    def propose(self, system_id: str, domains: list[str], proposed_by: str, *, max_bytes: int = 1_048_576, timeout: int = 20, minimum_interval: int = 2, searxng: bool = False) -> dict[str, Any]:
        require_id(proposed_by, "proposer")
        normalized = sorted({validate_domain(item) for item in domains})
        if not normalized or len(normalized) > 64:
            raise ValidationError("research policy requires 1 to 64 exact domains")
        if not 1024 <= max_bytes <= 5_242_880 or not 1 <= timeout <= 60 or not 1 <= minimum_interval <= 3600:
            raise ValidationError("research policy limits are invalid")
        with self.database.transaction() as connection:
            system = connection.execute("SELECT 1 FROM systems WHERE system_id=? AND approved=1", (system_id,)).fetchone()
            if not system:
                raise PolicyDenied("approved system is required")
            payload = {"domains": normalized, "max_bytes": max_bytes, "timeout_seconds": timeout, "minimum_interval_seconds": minimum_interval, "user_agent": "SecureHybridHubResearch/1.0", "robots_required": True, "javascript": False, "cookies": False, "authentication": False, "searxng_enabled": bool(searxng), "searxng_endpoint": "http://127.0.0.1:8888"}
            policy_id = f"rp-{uuid.uuid4().hex[:16]}"
            digest = sha256_json(payload)
            connection.execute("INSERT INTO research_policy_versions VALUES(?,?,?,?,?,?,NULL,0,?,NULL)", (policy_id, system_id, "pending", self.database.json(payload), digest, proposed_by, utc_now()))
            self.audit.append("research.policy-proposed", {"policy_id": policy_id, "policy_hash": digest, "domains": normalized, "proposed_by": proposed_by}, system_id=system_id, connection=connection)
        return {"policy_id": policy_id, "system_id": system_id, "status": "pending", "policy_hash": digest, "policy": payload, "live_enabled": False}

    def approve(self, policy_id: str, approver: str, *, enable_live: bool = False) -> dict[str, Any]:
        require_id(approver, "approver")
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM research_policy_versions WHERE policy_id=?", (policy_id,)).fetchone()
            if not row or row["status"] != "pending":
                raise ConflictError("pending research policy unavailable")
            connection.execute("UPDATE research_policy_versions SET status='superseded',live_enabled=0 WHERE system_id=? AND status='approved'", (row["system_id"],))
            connection.execute("UPDATE research_policy_versions SET status='approved',approved_by=?,live_enabled=?,approved_at=? WHERE policy_id=?", (approver, int(enable_live), utc_now(), policy_id))
            self.audit.append("research.policy-approved", {"policy_id": policy_id, "policy_hash": row["policy_hash"], "approver": approver, "live_enabled": enable_live}, system_id=row["system_id"], connection=connection)
        return self.get(policy_id)

    def get(self, policy_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM research_policy_versions WHERE policy_id=?", (policy_id,)).fetchone()
        if not row:
            raise ValidationError("unknown research policy")
        result = dict(row)
        result["policy"] = json.loads(result.pop("policy_json"))
        result["live_enabled"] = bool(result["live_enabled"])
        return result

    def active(self, system_id: str, *, require_live: bool = False) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM research_policy_versions WHERE system_id=? AND status='approved' ORDER BY approved_at DESC LIMIT 1", (system_id,)).fetchone()
        if not row:
            raise PolicyDenied("approved research policy is unavailable")
        if require_live and not row["live_enabled"]:
            raise PolicyDenied("live research network is not enabled for this system")
        result = dict(row)
        result["policy"] = json.loads(result.pop("policy_json"))
        result["live_enabled"] = bool(result["live_enabled"])
        return result


class ResearchManager:
    MAX_WORKER_OUTPUT = 6 * 1024 * 1024

    def __init__(self, database: Database, audit: AuditLog, policies: ResearchPolicyStore):
        self.database = database
        self.audit = audit
        self.policies = policies
        self._sandbox = Path(__file__).with_name("sandbox_exec.py").resolve()
        self._worker = Path(__file__).with_name("research_worker.py").resolve()
        self.modifiers = None

    def ingest_offline(self, task_id: str, source_url: str, content: str, media_type: str = "text/plain", retrieved_at: str | None = None) -> dict[str, Any]:
        task = self._task(task_id)
        policy = self.policies.active(task["system_id"])
        url = validate_url(source_url, set(policy["policy"]["domains"]))
        bounded_text(content, policy["policy"]["max_bytes"], "research content")
        return self._store(task, url, content, media_type, retrieved_at or utc_now(), {"transport": "offline-approved-ingest", "redirects": [], "robots_checked": False})

    def fetch(self, task_id: str, source_url: str) -> dict[str, Any]:
        if self.modifiers:
            self.modifiers.require_action(task_id, "live-research")
            modifier = self.modifiers.for_task(task_id)
            if modifier and modifier["modifier"]["research_mode"] == "cache-only":
                raise PolicyDenied("project modifier restricts research to cache-only")
        task = self._task(task_id)
        policy = self.policies.active(task["system_id"], require_live=True)
        settings = policy["policy"]
        url = validate_url(source_url, set(settings["domains"]))
        hostname = urllib.parse.urlsplit(url).hostname
        validate_public_resolution(hostname)
        self._rate_limit(task["system_id"], hostname, settings["minimum_interval_seconds"])
        request = {"mode": "fetch", "url": url, "domains": settings["domains"], "timeout": settings["timeout_seconds"], "max_bytes": settings["max_bytes"], "user_agent": settings["user_agent"]}
        result = self._run_worker(request, settings["timeout_seconds"], "fetch")
        evidence = self._store(task, result["source_url"], result["content"], result["media_type"], utc_now(), {"transport": "isolated-direct-official-source", "redirects": result["redirects"], "robots_checked": bool(result["robots_checked"]), "raw_hash": result["raw_hash"], "worker_filesystem_scope": "ephemeral-research-only"})
        with self.database.transaction() as connection:
            connection.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)", (f"research-rate:{task['system_id']}:{hostname}", str(time.time())))
        return evidence

    def discover(self, task_id: str, query: str, limit: int = 10) -> dict[str, Any]:
        if self.modifiers:
            self.modifiers.require_action(task_id, "live-research")
            modifier = self.modifiers.for_task(task_id)
            if modifier and modifier["modifier"]["research_mode"] == "cache-only":
                raise PolicyDenied("project modifier restricts research to cache-only")
        task = self._task(task_id)
        self._validate_query(query)
        if not 1 <= limit <= 20:
            raise ValidationError("research discovery limit is invalid")
        policy = self.policies.active(task["system_id"], require_live=True)
        settings = policy["policy"]
        if not settings.get("searxng_enabled"):
            raise PolicyDenied("SearXNG discovery is not approved for this system")
        result = self._run_worker({"mode": "discover", "query": query, "domains": settings["domains"], "limit": limit, "timeout": settings["timeout_seconds"]}, settings["timeout_seconds"], "discover")
        self.audit.append("research.discovered", {"query_hash": sha256_bytes(query.encode()), "result_count": result["count"], "endpoint": settings["searxng_endpoint"], "content_fetched": False}, system_id=task["system_id"], task_id=task_id)
        return {"task_id": task_id, "query_hash": sha256_bytes(query.encode()), **result}

    def resolve(self, task_id: str, query: str, official_urls: list[str] | None = None) -> dict[str, Any]:
        cached = self.search_cache(task_id, query, 10)
        if cached["results"]:
            return {"task_id": task_id, "mode": "cache", "evidence": cached["results"], "degraded_reasons": [], "network_used": False}
        if self.modifiers:
            modifier = self.modifiers.for_task(task_id)
            if modifier and (modifier["modifier"]["research_mode"] == "cache-only" or "live-research" in modifier["modifier"]["deny_actions"]):
                return {"task_id": task_id, "mode": "local-only", "evidence": [], "degraded_reasons": ["project modifier restricts research to cache-only"], "network_used": False}
        task = self._task(task_id)
        try:
            policy = self.policies.active(task["system_id"], require_live=True)
        except PolicyDenied as exc:
            return {"task_id": task_id, "mode": "local-only", "evidence": [], "degraded_reasons": [str(exc)], "network_used": False}
        candidates = list(official_urls or [])[:5]
        reasons: list[str] = []
        if not candidates and policy["policy"].get("searxng_enabled"):
            try:
                candidates = [item["url"] for item in self.discover(task_id, query, 5)["results"]]
            except (AdapterError, PolicyDenied, ValidationError) as exc:
                reasons.append(f"discovery unavailable: {type(exc).__name__}")
        evidence = []
        for url in candidates:
            try:
                evidence.append(self.fetch(task_id, url))
            except (AdapterError, PolicyDenied, ValidationError) as exc:
                reasons.append(f"official source unavailable: {type(exc).__name__}")
        return {"task_id": task_id, "mode": "direct-official" if evidence else "local-only", "evidence": evidence, "degraded_reasons": reasons, "network_used": bool(candidates)}

    def _run_worker(self, request: dict[str, Any], timeout: int, operation: str) -> dict[str, Any]:
        execution = self.database.layout.root / "research" / f"{operation}-{uuid.uuid4().hex[:16]}"
        execution.mkdir(parents=True, mode=0o700)
        worker = execution / "research_worker.py"
        shutil.copyfile(self._worker, worker)
        os.chmod(worker, 0o500)
        atomic_write(execution / "input.json", canonical_json(request), 0o400)
        unshare = shutil.which("unshare", path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        if not unshare:
            raise PolicyDenied("research isolation executable is unavailable")
        command = [unshare, "--user", "--map-root-user", "--pid", "--ipc", "--uts", "--fork", sys.executable, str(self._sandbox), "--allow-root", str(execution), "--research-network", "--", sys.executable, str(worker)]
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(execution), "TMPDIR": str(execution), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1", "NO_PROXY": "*", "no_proxy": "*"}
        try:
            completed = subprocess.run(command, cwd=execution, env=environment, capture_output=True, timeout=timeout * 6, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdapterError(f"isolated research worker failed: {type(exc).__name__}") from exc
        if len(completed.stdout) > self.MAX_WORKER_OUTPUT or len(completed.stderr) > 64 * 1024:
            raise AdapterError("research worker output exceeded limit")
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise AdapterError("research worker returned invalid JSON") from exc
        if completed.returncode or not response.get("ok"):
            raise AdapterError(f"research worker rejected request: {response.get('message', 'unknown error')[:300]}")
        return response["result"]

    def search_cache(self, task_id: str, query: str, limit: int = 5) -> dict[str, Any]:
        task = self._task(task_id)
        self._validate_query(query)
        if not 1 <= limit <= 20:
            raise ValidationError("research result limit is invalid")
        tokens = sorted(set(TOKEN.findall(query.lower())))[:32]
        if not tokens:
            raise ValidationError("research query has no indexable terms")
        placeholders = ",".join("?" for _ in tokens)
        with self.database.connect() as connection:
            rows = connection.execute(f"SELECT evidence_id,COUNT(*) AS score FROM research_index WHERE system_id=? AND token IN ({placeholders}) GROUP BY evidence_id ORDER BY score DESC,evidence_id LIMIT ?", (task["system_id"], *tokens, limit)).fetchall()
            evidence = [connection.execute("SELECT * FROM research_evidence WHERE evidence_id=? AND system_id=?", (row["evidence_id"], task["system_id"])).fetchone() for row in rows]
        results = []
        for row in evidence:
            if not row:
                continue
            metadata = json.loads(row["metadata_json"])
            results.append({"evidence_id": row["evidence_id"], "source_url": row["source_url"], "retrieved_at": row["retrieved_at"], "content_hash": row["content_hash"], "size": row["size"], "media_type": row["media_type"], "untrusted_content": True, "prompt_injection_detected": metadata["prompt_injection_detected"]})
        self.audit.append("research.cache-searched", {"query_hash": sha256_bytes(query.encode()), "result_count": len(results)}, system_id=task["system_id"], task_id=task_id)
        return {"task_id": task_id, "query_hash": sha256_bytes(query.encode()), "results": results, "network_used": False}

    def get_evidence(self, task_id: str, evidence_id: str) -> dict[str, Any]:
        task = self._task(task_id)
        require_id(evidence_id, "evidence ID")
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM research_evidence WHERE evidence_id=? AND system_id=?", (evidence_id, task["system_id"])).fetchone()
            artifact = connection.execute("SELECT relative_path FROM artifacts WHERE digest=?", (row["artifact_digest"],)).fetchone() if row else None
        if not row or not artifact:
            raise PolicyDenied("research evidence is unavailable in this system scope")
        path = self.database.layout.artifacts / artifact["relative_path"]
        content = path.read_text(encoding="utf-8")
        metadata = json.loads(row["metadata_json"])
        return {"evidence_id": evidence_id, "source_url": row["source_url"], "retrieved_at": row["retrieved_at"], "content_hash": row["content_hash"], "media_type": row["media_type"], "content": content, **metadata}

    def _store(self, task: dict[str, Any], source_url: str, content: str, media_type: str, retrieved_at: str, metadata: dict[str, Any]) -> dict[str, Any]:
        encoded = content.encode("utf-8")
        content_hash = sha256_bytes(encoded)
        artifact = self.database.put_artifact(encoded, f"{media_type}; charset=utf-8")
        evidence_id = f"re-{uuid.uuid4().hex[:16]}"
        detected = bool(INJECTION.search(content))
        safe_metadata = {**metadata, "prompt_injection_detected": detected, "untrusted_content": True, "content_is_instruction": False}
        with self.database.transaction() as connection:
            connection.execute("INSERT INTO research_evidence VALUES(?,?,?,?,?,?,?,?,?,?,?)", (evidence_id, task["system_id"], task["task_id"], source_url, retrieved_at, content_hash, artifact, len(encoded), media_type, self.database.json(safe_metadata), utc_now()))
            tokens = sorted(set(TOKEN.findall(content.lower())))[:50_000]
            connection.executemany("INSERT OR IGNORE INTO research_index VALUES(?,?,?)", ((task["system_id"], token, evidence_id) for token in tokens))
            self.audit.append("research.evidence-stored", {"evidence_id": evidence_id, "source_url": source_url, "retrieved_at": retrieved_at, "content_hash": content_hash, "size": len(encoded), "media_type": media_type, "prompt_injection_detected": detected}, system_id=task["system_id"], task_id=task["task_id"], connection=connection)
        return {"schema_version": "1.0.0", "evidence_id": evidence_id, "task_id": task["task_id"], "system_id": task["system_id"], "source_url": source_url, "retrieved_at": retrieved_at, "content_hash": content_hash, "artifact_digest": artifact, "size": len(encoded), "media_type": media_type, **safe_metadata}

    def _task(self, task_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT tasks.*,systems.approved FROM tasks JOIN systems USING(system_id) WHERE task_id=?", (task_id,)).fetchone()
        if not row or row["cancelled"] or not row["approved"]:
            raise PolicyDenied("research task unavailable, cancelled, or system disabled")
        return dict(row)

    @staticmethod
    def _validate_query(query: str) -> None:
        bounded_text(query, 2048, "research query")
        if any(pattern.search(query) for pattern in QUERY_FORBIDDEN):
            raise PolicyDenied("research query contains private, credential-like, regulated, or environment-specific context")

    def _rate_limit(self, system_id: str, hostname: str, minimum: int) -> None:
        with self.database.connect() as connection:
            row = connection.execute("SELECT value FROM metadata WHERE key=?", (f"research-rate:{system_id}:{hostname}",)).fetchone()
        if row and time.time() - float(row[0]) < minimum:
            raise PolicyDenied("research domain rate interval has not elapsed")
