from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from subprocess import run as _subprocess_run
from pathlib import Path
from typing import Any

from .audit import AuditLog, SECRET_PATTERNS
from .errors import AdapterError, PolicyDenied, ValidationError
from .leases import LeaseManager
from .storage import Database
from .util import bounded_text, sha256_bytes, sha256_json, utc_now
from .workers import LocalWorker

SUBSCRIPTION_ADAPTERS = frozenset({"claude-subscription-cli", "codex-subscription-cli"})
_EXECUTABLE_NAMES = {
    "claude-subscription-cli": {"claude", "claude.cmd", "claude.exe"},
    "codex-subscription-cli": {"codex", "codex.cmd", "codex.exe"},
}
# The subscription CLIs authenticate from their own login state under HOME.
# Provider API keys are deliberately never inherited: a leaked key in the
# parent environment must not silently switch billing from the subscription
# to metered API usage.
_ENVIRONMENT_ALLOWLIST = (
    "HOME", "PATH", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LC_ALL", "TMPDIR",
    "WSL_INTEROP", "WSL_DISTRO_NAME", "WSLENV", "WSL_UTF8", "SYSTEMROOT", "WINDIR",
)
# "default" means: run on the model the subscription CLI is configured with,
# passing no model flag at all.
DEFAULT_MODEL = "default"


@dataclass(frozen=True)
class SubscriptionCliConfig:
    name: str
    executable: str
    model: str
    timeout: int = 300
    max_prompt_bytes: int = 32768
    max_output_bytes: int = 65536

    def __post_init__(self):
        if self.name not in SUBSCRIPTION_ADAPTERS:
            raise ValidationError("unsupported subscription adapter")
        if not self.model or not isinstance(self.model, str) or len(self.model) > 128:
            raise ValidationError("invalid subscription model name")
        if not isinstance(self.timeout, int) or not 1 <= self.timeout <= 600:
            raise ValidationError("invalid subscription adapter timeout")
        path = Path(self.executable) if self.executable else None
        if path is None or not path.is_absolute() or not path.is_file() or path.name.lower() not in _EXECUTABLE_NAMES[self.name]:
            raise ValidationError("subscription CLI executable must be an existing absolute claude/codex path")


class SubscriptionCliWorker:
    """Headless subscription-CLI coding worker (claude -p / codex exec).

    The worker is text-only generation: it receives one bounded packet prompt
    and returns one raw file body. It runs in an empty scratch directory, the
    CLI's own tools are disabled or read-only sandboxed, and every outbound
    prompt is audit-logged with its hash BEFORE the call because this
    transport, unlike local workers, sends the packet context to the vendor.
    """

    def __init__(self, database: Database, audit: AuditLog, leases: LeaseManager, config: SubscriptionCliConfig):
        self.database = database
        self.audit = audit
        self.leases = leases
        self.config = config

    def preflight(self) -> dict[str, Any]:
        if self.database.emergency_stopped():
            raise PolicyDenied("emergency stop is active")
        completed = self._run([str(self.config.executable), "--version"], input_text=None, timeout=60, cwd=None)
        if completed.returncode:
            raise AdapterError(f"subscription CLI preflight exited {completed.returncode}: {completed.stderr.strip()[:200]}")
        version = completed.stdout.strip().splitlines()[0][:100] if completed.stdout.strip() else "unknown"
        report = {"adapter": self.config.name, "model": self.config.model, "transport": "subscription-cli", "version": version, "available": True}
        self.audit.append("worker.preflight", report)
        return report

    def run_file(self, task_id: str, prompt: str) -> dict[str, Any]:
        bounded_text(prompt, self.config.max_prompt_bytes, "file worker prompt")
        for pattern in SECRET_PATTERNS:
            if pattern.search(prompt):
                raise PolicyDenied("credential-like material is not allowed in file model context")
        if self.database.emergency_stopped():
            raise PolicyDenied("emergency stop is active")
        with self.database.connect() as connection:
            task = connection.execute("SELECT tasks.cancelled,tasks.system_id,tasks.state,systems.approved FROM tasks JOIN systems USING(system_id) WHERE task_id=?", (task_id,)).fetchone()
        if not task or task["cancelled"] or not task["approved"]:
            raise PolicyDenied("task unavailable or cancelled")
        if task["state"] not in {"WORKSPACES_READY", "LOCAL_IMPLEMENTING", "LOCAL_REPAIRING", "LOCAL_FIXING"}:
            raise PolicyDenied("task state does not permit a subscription file worker run")
        prompt_bytes = prompt.encode("utf-8")
        self.audit.append(
            "worker.cloud-context-sent",
            {"adapter": self.config.name, "model": self.config.model, "task_id": task_id, "prompt_sha256": sha256_bytes(prompt_bytes), "prompt_bytes": len(prompt_bytes)},
            system_id=task["system_id"], task_id=task_id,
        )
        with self.leases.held(f"subscription:{self.config.name}", task_id, ttl_seconds=self.config.timeout + 30):
            with tempfile.TemporaryDirectory(prefix="hub-subscription-") as scratch:
                text = self._generate(prompt, Path(scratch))
        text = LocalWorker._clean_file_text(text)
        if not text or len(text.encode("utf-8")) > self.config.max_output_bytes:
            raise AdapterError("subscription file generation is empty or exceeds the limit")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                raise PolicyDenied("subscription file generation contains credential-like material")
        result_payload = {"status": "ok", "changed_paths": [], "content": text}
        result = {"adapter": self.config.name, "model": self.config.model, "task_id": task_id, "result": result_payload, "output_hash": sha256_json(result_payload), "completed_at": utc_now()}
        self.audit.append("worker.file-completed", {key: result[key] for key in ("adapter", "model", "task_id", "output_hash")}, system_id=task["system_id"], task_id=task_id)
        return result

    def run_structured(self, task_id: str, prompt: str) -> dict[str, Any]:
        raise AdapterError("subscription CLI adapters support guided file generation only; use a guided plan")

    def _generate(self, prompt: str, scratch: Path) -> str:
        if self.config.name == "claude-subscription-cli":
            arguments = [str(self.config.executable), "-p", "--output-format", "text", "--no-session-persistence", "--disallowedTools", "Bash", "Edit", "Write", "NotebookEdit", "WebFetch", "WebSearch"]
            if self.config.model != DEFAULT_MODEL:
                arguments += ["--model", self.config.model]
            completed = self._run(arguments, input_text=prompt, timeout=self.config.timeout, cwd=scratch)
            if completed.returncode:
                raise AdapterError(f"subscription CLI exited {completed.returncode}: {completed.stderr.strip()[:200]}")
            output = completed.stdout
        else:
            last_message = scratch / "last-message.txt"
            arguments = [str(self.config.executable), "exec", "--sandbox", "read-only", "--skip-git-repo-check", "--cd", str(scratch), "--color", "never", "--output-last-message", str(last_message)]
            if self.config.model != DEFAULT_MODEL:
                arguments += ["--model", self.config.model]
            arguments.append("-")
            completed = self._run(arguments, input_text=prompt, timeout=self.config.timeout, cwd=scratch)
            if completed.returncode:
                raise AdapterError(f"subscription CLI exited {completed.returncode}: {completed.stderr.strip()[:200]}")
            try:
                output = last_message.read_text(encoding="utf-8")
            except OSError as exc:
                raise AdapterError("subscription CLI produced no final message") from exc
        if len(output.encode("utf-8")) > self.config.max_output_bytes * 4:
            raise AdapterError("subscription CLI output exceeds limit")
        return output

    @staticmethod
    def _run(arguments: list[str], *, input_text: str | None, timeout: int, cwd: Path | None) -> subprocess.CompletedProcess:
        environment = {name: os.environ[name] for name in _ENVIRONMENT_ALLOWLIST if name in os.environ}
        environment["NO_COLOR"] = "1"
        try:
            return _subprocess_run(
                arguments,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                cwd=str(cwd) if cwd else None,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdapterError(f"subscription CLI process failed: {type(exc).__name__}") from exc
