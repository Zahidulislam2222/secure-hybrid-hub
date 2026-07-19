from __future__ import annotations

import base64
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from .audit import AuditLog, SECRET_PATTERNS, sanitize
from .errors import AdapterError, ConflictError, PolicyDenied, ValidationError
from .storage import Database
from .util import bounded_text, canonical_json, require_id, sha256_bytes, sha256_json, utc_now


ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
API_KEY_LINE = re.compile(r"^[A-Za-z0-9._~+/=-]{16,512}$")


def read_api_key_file(path: Path) -> str:
    """Read a provider API key from a dedicated single-line key file.

    Environment variables are deliberately not supported for adapter keys:
    a key in the environment leaks into every child process, while a key
    file is read here on demand and held only in a local variable. The file
    must be private to the owner so a multi-user machine cannot read it.
    """
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValidationError("API key file must be an absolute path")
    try:
        status = path.stat()
    except OSError as exc:
        raise ValidationError("API key file is unreadable") from exc
    if not path.is_file() or status.st_size > 4096:
        raise ValidationError("API key file must be a small regular file")
    if os.name == "posix" and status.st_mode & 0o077:
        raise PolicyDenied("API key file must not be group- or world-accessible (chmod 600)")
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1 or not API_KEY_LINE.fullmatch(lines[0]):
        raise ValidationError("API key file must contain exactly one key on a single line")
    return lines[0]


class SecretBackend(ABC):
    name: str

    @abstractmethod
    def get(self, identifier: str) -> str:
        raise NotImplementedError


class SyntheticMemoryBackend(SecretBackend):
    name = "synthetic-memory"

    def __init__(self, values: dict[str, str]):
        self._values = dict(values)
        for identifier, value in self._values.items():
            require_id(identifier, "synthetic secret identifier")
            if not isinstance(value, str) or not value.startswith("hh_test_CANARY_"):
                raise ValidationError("synthetic backend accepts only explicit test canaries")

    def get(self, identifier: str) -> str:
        try:
            return self._values[identifier]
        except KeyError as exc:
            raise PolicyDenied("approved synthetic secret identifier is unavailable") from exc


def secret_variants(secret: str) -> set[str]:
    encoded = secret.encode("utf-8")
    return {
        secret,
        base64.b64encode(encoded).decode("ascii"),
        base64.urlsafe_b64encode(encoded).decode("ascii"),
        encoded.hex(),
        urllib.parse.quote(secret, safe=""),
        json.dumps(secret)[1:-1],
    }


def redact_exact(text: str, values: list[str]) -> str:
    result = text
    variants = sorted({variant for value in values for variant in secret_variants(value)}, key=len, reverse=True)
    for variant in variants:
        if variant:
            result = result.replace(variant, "[REDACTED_SECRET]")
    return result


def assert_secret_absent(text: str, values: list[str]) -> None:
    if any(variant and variant in text for value in values for variant in secret_variants(value)):
        raise PolicyDenied("secret redaction verification failed")


class CapabilityRegistry:
    def __init__(self, database: Database, audit: AuditLog):
        self.database = database
        self.audit = audit

    def propose(self, system_id: str, capability: dict[str, Any], proposed_by: str) -> dict[str, Any]:
        require_id(proposed_by, "proposer")
        clean = self._validate(capability)
        with self.database.transaction() as connection:
            system = connection.execute("SELECT 1 FROM systems WHERE system_id=? AND approved=1", (system_id,)).fetchone()
            if not system:
                raise PolicyDenied("approved system is required")
            capability_id = f"cap-{uuid.uuid4().hex[:16]}"
            digest = sha256_json(clean)
            connection.execute("INSERT INTO secret_capabilities VALUES(?,?,?,?,?,?,NULL,?,NULL)", (capability_id, system_id, "pending", self.database.json(clean), digest, proposed_by, utc_now()))
            self.audit.append("secret.capability-proposed", {"capability_id": capability_id, "capability_hash": digest, "secret_identifiers": sorted(clean["secret_bindings"].values()), "proposed_by": proposed_by}, system_id=system_id, connection=connection)
        return {"capability_id": capability_id, "system_id": system_id, "status": "pending", "capability_hash": digest, "capability": clean}

    def approve(self, capability_id: str, approver: str) -> dict[str, Any]:
        require_id(approver, "approver")
        with self.database.transaction() as connection:
            row = connection.execute("SELECT * FROM secret_capabilities WHERE capability_id=?", (capability_id,)).fetchone()
            if not row or row["status"] != "pending":
                raise ConflictError("pending secret capability unavailable")
            connection.execute("UPDATE secret_capabilities SET status='approved',approved_by=?,approved_at=? WHERE capability_id=?", (approver, utc_now(), capability_id))
            self.audit.append("secret.capability-approved", {"capability_id": capability_id, "capability_hash": row["capability_hash"], "approver": approver}, system_id=row["system_id"], connection=connection)
        return self.get(capability_id)

    def get(self, capability_id: str) -> dict[str, Any]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM secret_capabilities WHERE capability_id=?", (capability_id,)).fetchone()
        if not row:
            raise ValidationError("unknown secret capability")
        result = dict(row)
        result["capability"] = json.loads(result.pop("capability_json"))
        return result

    @staticmethod
    def _validate(value: dict[str, Any]) -> dict[str, Any]:
        allowed = {"name", "argv", "secret_bindings", "timeout_seconds", "max_output_bytes", "network_mode", "environment"}
        if not isinstance(value, dict) or set(value) - allowed:
            raise ValidationError("secret capability contains unknown fields")
        name = require_id(value.get("name"), "capability name")
        argv = value.get("argv")
        if not isinstance(argv, list) or not argv or len(argv) > 64 or any(not isinstance(item, str) or not item or len(item.encode()) > 4096 or "\x00" in item for item in argv):
            raise ValidationError("secret capability argv is invalid")
        bindings = value.get("secret_bindings")
        if not isinstance(bindings, dict) or not bindings or len(bindings) > 16:
            raise ValidationError("secret capability requires bounded environment bindings")
        for environment_name, identifier in bindings.items():
            if not isinstance(environment_name, str) or not ENV_NAME.fullmatch(environment_name):
                raise ValidationError("secret capability environment name is invalid")
            require_id(identifier, "secret identifier")
        timeout = value.get("timeout_seconds", 120)
        maximum = value.get("max_output_bytes", 262_144)
        if not isinstance(timeout, int) or not 1 <= timeout <= 900 or not isinstance(maximum, int) or not 1024 <= maximum <= 2_097_152:
            raise ValidationError("secret capability resource limits are invalid")
        if value.get("network_mode", "none") != "none":
            raise PolicyDenied("Phase 6 secret capabilities are synthetic and network-disabled")
        if value.get("environment", "local-synthetic") != "local-synthetic":
            raise PolicyDenied("Phase 6 secret capabilities permit only local-synthetic environment")
        return {"name": name, "argv": list(argv), "secret_bindings": dict(sorted(bindings.items())), "timeout_seconds": timeout, "max_output_bytes": maximum, "network_mode": "none", "environment": "local-synthetic"}


class SecretRunner:
    def __init__(self, database: Database, audit: AuditLog, registry: CapabilityRegistry):
        self.database = database
        self.audit = audit
        self.registry = registry
        self._sandbox = Path(__file__).with_name("sandbox_exec.py").resolve()
        self.modifiers = None

    def run(self, task_id: str, capability_id: str, backend: SecretBackend) -> dict[str, Any]:
        if self.modifiers:
            self.modifiers.require_action(task_id, "secret-capability")
        if backend.name != "synthetic-memory":
            raise PolicyDenied("no real secret backend is authorized in Phase 6")
        with self.database.connect() as connection:
            task = connection.execute("SELECT tasks.*,systems.approved FROM tasks JOIN systems USING(system_id) WHERE task_id=?", (task_id,)).fetchone()
        capability = self.registry.get(capability_id)
        if not task or task["cancelled"] or not task["approved"] or capability["status"] != "approved" or capability["system_id"] != task["system_id"]:
            raise PolicyDenied("secret capability is unavailable in this task scope")
        specification = capability["capability"]
        values = {environment: backend.get(identifier) for environment, identifier in specification["secret_bindings"].items()}
        execution = self.database.layout.root / "secret-runs" / f"sr-{uuid.uuid4().hex[:16]}"
        execution.mkdir(parents=True, mode=0o700)
        executable, arguments = self._resolve(specification["argv"])
        if executable.lower().endswith(".exe"):
            raise PolicyDenied("Windows executables cannot be safely confined for secret capabilities")
        unshare = shutil.which("unshare", path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        if not unshare:
            raise PolicyDenied("secret runner isolation is unavailable")
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(execution), "TMPDIR": str(execution), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8", "NO_PROXY": "*", "no_proxy": "*", **values}
        command = [unshare, "--user", "--map-root-user", "--net", "--pid", "--ipc", "--uts", "--fork", sys.executable, str(self._sandbox), "--allow-root", str(execution), "--", executable, *arguments]
        started = time.monotonic()
        with tempfile.NamedTemporaryFile(dir=execution, delete=False) as output:
            output_path = Path(output.name)
            try:
                process = subprocess.Popen(command, cwd=execution, env=environment, stdout=output, stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=self._limits(specification["timeout_seconds"], specification["max_output_bytes"]))
                try:
                    exit_code = process.wait(timeout=specification["timeout_seconds"])
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
                    exit_code = 124
            except OSError as exc:
                raise AdapterError(f"secret capability launch failed: {type(exc).__name__}") from exc
        try:
            raw = output_path.read_bytes()[: specification["max_output_bytes"] + 1]
        finally:
            output_path.unlink(missing_ok=True)
        if len(raw) > specification["max_output_bytes"]:
            raise AdapterError("secret capability output exceeds limit")
        text = raw.decode("utf-8", errors="replace")
        secret_values = list(values.values())
        redacted = redact_exact(text, secret_values)
        redacted = sanitize(redacted)
        assert_secret_absent(redacted, secret_values)
        evidence_digest = self.database.put_artifact(redacted.encode("utf-8"), "text/plain; charset=utf-8")
        result = {"capability_id": capability_id, "capability_hash": capability["capability_hash"], "task_id": task_id, "backend": backend.name, "environment": specification["environment"], "exit_code": exit_code, "passed": exit_code == 0, "evidence_digest": evidence_digest, "output_hash": sha256_bytes(redacted.encode()), "duration_ms": int((time.monotonic() - started) * 1000), "secret_values_exposed": False}
        self.audit.append("secret.capability-completed", result, system_id=task["system_id"], task_id=task_id)
        return result

    @staticmethod
    def _resolve(argv: list[str]) -> tuple[str, list[str]]:
        first = argv[0]
        if first == "$PYTHON":
            executable = str(Path(sys.executable).resolve())
        elif Path(first).is_absolute():
            executable = str(Path(first).resolve(strict=True))
        else:
            executable = shutil.which(first, path="/usr/local/bin:/usr/bin:/bin") or ""
        if not executable or not Path(executable).is_file():
            raise ValidationError("approved secret capability executable is unavailable")
        return executable, argv[1:]

    @staticmethod
    def _limits(timeout: int, output_bytes: int):
        def apply() -> None:
            resource.setrlimit(resource.RLIMIT_CPU, (timeout + 5, timeout + 5))
            resource.setrlimit(resource.RLIMIT_FSIZE, (output_bytes + 4096, output_bytes + 4096))
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
            memory = 1024 * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        return apply
