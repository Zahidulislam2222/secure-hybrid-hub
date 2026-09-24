from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditLog, SECRET_PATTERNS
from .errors import AdapterError, PolicyDenied, ValidationError
from .leases import LeaseManager
from .policy import require_cloud_egress
from .storage import Database
from .util import bounded_text, sha256_bytes, sha256_json, utc_now
from .workers import LocalWorker

SUBSCRIPTION_ADAPTERS = frozenset({"claude-subscription-cli", "codex-subscription-cli"})
SUBSCRIPTION_EFFORTS = {
    "claude-subscription-cli": frozenset({"low", "medium", "high", "max"}),
    "codex-subscription-cli": frozenset({"low", "medium", "high", "xhigh"}),
}
_EXECUTABLE_NAMES = {
    "claude-subscription-cli": {"claude", "claude.cmd", "claude.exe"},
    "codex-subscription-cli": {"codex", "codex.cmd", "codex.exe"},
}
_ENVIRONMENT_ALLOWLIST = (
    "HOME", "PATH", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LC_ALL", "TMPDIR",
    "WSL_INTEROP", "WSL_DISTRO_NAME", "WSLENV", "WSL_UTF8", "SYSTEMROOT", "WINDIR",
)
DEFAULT_MODEL = "default"
_HEARTBEAT_SECONDS = 30
_POLL_SECONDS = 1
_REAP_SECONDS = 5


def _subprocess_popen(arguments, *, input: str | None = None, **options):
    """Patchable process boundary that never sends prompts through a pipe."""
    del input
    return subprocess.Popen(arguments, **options)


@dataclass(frozen=True)
class SubscriptionCliConfig:
    name: str
    executable: str
    model: str
    timeout: int = 300
    effort: str = "high"
    max_prompt_bytes: int = 32768
    max_output_bytes: int = 65536

    def __post_init__(self):
        if self.name not in SUBSCRIPTION_ADAPTERS:
            raise ValidationError("unsupported subscription adapter")
        if not self.model or not isinstance(self.model, str) or len(self.model) > 128:
            raise ValidationError("invalid subscription model name")
        if not isinstance(self.timeout, int) or not 1 <= self.timeout <= 600:
            raise ValidationError("invalid subscription adapter timeout")
        if self.effort not in SUBSCRIPTION_EFFORTS[self.name]:
            raise ValidationError("unsupported subscription effort for adapter")
        path = Path(self.executable) if self.executable else None
        if path is None or not path.is_absolute() or not path.is_file() or path.name.lower() not in _EXECUTABLE_NAMES[self.name]:
            raise ValidationError("subscription CLI executable must be an existing absolute claude/codex path")


class SubscriptionCliWorker:
    """Headless, bounded subscription-CLI file generation."""

    def __init__(self, database: Database, audit: AuditLog, leases: LeaseManager, config: SubscriptionCliConfig):
        self.database = database
        self.audit = audit
        self.leases = leases
        self.config = config
        self._cli_version = "not-preflighted"

    def _argument_policy(self) -> dict[str, Any]:
        if self.config.name == "claude-subscription-cli":
            isolation = "empty-scratch+no-session-persistence+safe-mode+tools-disabled"
            fixed_arguments = [
                "-p",
                "--output-format=text",
                "--no-session-persistence",
                "--safe-mode",
                "--disallowedTools=Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch",
                "--tools=",
                f"--effort={self.config.effort}",
            ]
        else:
            isolation = "empty-scratch+read-only+ephemeral+ignore-user-config+ignore-rules"
            fixed_arguments = [
                "exec",
                "--sandbox=read-only",
                "--skip-git-repo-check",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                f"model_reasoning_effort={self.config.effort}",
                f"model={self.config.model}",
            ]
        return {
            "adapter": self.config.name,
            "model": self.config.model,
            "effort": self.config.effort,
            "isolation_mode": isolation,
            "fixed_arguments": fixed_arguments,
            "fallback": "disabled",
        }

    def _execution_evidence(self) -> dict[str, Any]:
        policy = self._argument_policy()
        return {
            "model": self.config.model,
            "effort": self.config.effort,
            "cli_version": self._cli_version,
            "isolation_mode": policy["isolation_mode"],
            "argument_policy_hash": sha256_json(policy),
            "fallback": "disabled",
        }

    def preflight(self) -> dict[str, Any]:
        if self.database.emergency_stopped():
            raise PolicyDenied("emergency stop is active")
        completed = self._run([str(self.config.executable), "--version"], input_text=None, timeout=60, cwd=None)
        if completed.returncode:
            raise AdapterError(f"subscription CLI preflight exited {completed.returncode}")
        version = completed.stdout.strip().splitlines()[0][:100] if completed.stdout.strip() else "unknown"
        self._cli_version = version
        report = {
            "adapter": self.config.name,
            "transport": "subscription-cli",
            "version": version,
            "available": True,
            **self._execution_evidence(),
        }
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
            task = connection.execute(
                "SELECT tasks.cancelled,tasks.system_id,tasks.state,systems.approved,systems.profiles_json "
                "FROM tasks JOIN systems USING(system_id) WHERE task_id=?",
                (task_id,),
            ).fetchone()
        if not task or task["cancelled"] or not task["approved"]:
            raise PolicyDenied("task unavailable or cancelled")
        if task["state"] not in {"WORKSPACES_READY", "LOCAL_IMPLEMENTING", "LOCAL_REPAIRING", "LOCAL_FIXING"}:
            raise PolicyDenied("task state does not permit a subscription file worker run")
        require_cloud_egress(json.loads(task["profiles_json"]))
        prompt_bytes = prompt.encode("utf-8")
        self.audit.append(
            "worker.cloud-context-sent",
            {
                "adapter": self.config.name,
                "task_id": task_id,
                "prompt_sha256": sha256_bytes(prompt_bytes),
                "prompt_bytes": len(prompt_bytes),
                **self._execution_evidence(),
            },
            system_id=task["system_id"],
            task_id=task_id,
        )
        with self.leases.held(f"subscription:{self.config.name}", task_id, ttl_seconds=self.config.timeout + 30):
            with tempfile.TemporaryDirectory(prefix="hub-subscription-") as scratch:
                text = self._generate(prompt, Path(scratch), task_id, task["system_id"])
        text = LocalWorker._clean_file_text(text)
        if not text or len(text.encode("utf-8")) > self.config.max_output_bytes:
            raise AdapterError("subscription file generation is empty or exceeds the limit")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                raise PolicyDenied("subscription file generation contains credential-like material")
        result_payload = {"status": "ok", "changed_paths": [], "content": text}
        result = {
            "adapter": self.config.name,
            "task_id": task_id,
            "result": result_payload,
            "output_hash": sha256_json(result_payload),
            "completed_at": utc_now(),
            **self._execution_evidence(),
        }
        self.audit.append(
            "worker.file-completed",
            {
                key: result[key]
                for key in (
                    "adapter",
                    "model",
                    "effort",
                    "cli_version",
                    "isolation_mode",
                    "argument_policy_hash",
                    "fallback",
                    "task_id",
                    "output_hash",
                )
            },
            system_id=task["system_id"],
            task_id=task_id,
        )
        return result

    def run_structured(self, task_id: str, prompt: str) -> dict[str, Any]:
        raise AdapterError("subscription CLI adapters support guided file generation only; use a guided plan")

    def _generate(self, prompt: str, scratch: Path, task_id: str, system_id: str) -> str:
        if self.config.name == "claude-subscription-cli":
            arguments = [
                str(self.config.executable),
                "-p",
                "--output-format",
                "text",
                "--no-session-persistence",
                "--disallowedTools",
                "Bash",
                "Edit",
                "Write",
                "NotebookEdit",
                "WebFetch",
                "WebSearch",
                "--safe-mode",
                "--tools",
                "",
                "--effort",
                self.config.effort,
            ]
            if self.config.model != DEFAULT_MODEL:
                arguments += ["--model", self.config.model]
            completed = self._run(
                arguments,
                input_text=prompt,
                timeout=self.config.timeout,
                cwd=scratch,
                task_id=task_id,
                system_id=system_id,
            )
            if completed.returncode:
                raise AdapterError(f"subscription CLI exited {completed.returncode}")
            output = completed.stdout
        else:
            last_message = scratch / "last-message.txt"
            arguments = [
                str(self.config.executable),
                "exec",
                "--sandbox",
                "read-only",
                "--skip-git-repo-check",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "--cd",
                str(scratch),
                "--color",
                "never",
                "--output-last-message",
                str(last_message),
                "-c",
                f'model_reasoning_effort="{self.config.effort}"',
            ]
            if self.config.model != DEFAULT_MODEL:
                arguments += ["-c", f'model="{self.config.model}"']
            arguments.append("-")
            completed = self._run(
                arguments,
                input_text=prompt,
                timeout=self.config.timeout,
                cwd=scratch,
                task_id=task_id,
                system_id=system_id,
            )
            if completed.returncode:
                raise AdapterError(f"subscription CLI exited {completed.returncode}")
            try:
                output = last_message.read_text(encoding="utf-8")
            except OSError:
                raise AdapterError("subscription CLI produced no final message") from None
        if len(output.encode("utf-8")) > self.config.max_output_bytes * 4:
            raise AdapterError("subscription CLI output exceeds limit")
        return output

    def _heartbeat(self, task_id: str, system_id: str | None, elapsed: int) -> None:
        payload = {
            "adapter": self.config.name,
            "task_id": task_id,
            "elapsed_bucket": elapsed,
            "state": "running",
        }
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr, flush=True)
        self.audit.append("worker.subscription-heartbeat", payload, system_id=system_id, task_id=task_id)

    @staticmethod
    def _kill_and_reap(process: subprocess.Popen) -> None:
        try:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.wait(timeout=_REAP_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=_REAP_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                pass

    def _read_capture(self, stream, maximum: int) -> str:
        if os.fstat(stream.fileno()).st_size > maximum:
            raise AdapterError("subscription CLI process output exceeds limit")
        stream.seek(0)
        return stream.read(maximum + 1).decode("utf-8", errors="replace")

    def _run(
        self,
        arguments: list[str],
        *,
        input_text: str | None,
        timeout: int,
        cwd: Path | None,
        task_id: str | None = None,
        system_id: str | None = None,
    ) -> subprocess.CompletedProcess:
        environment = {name: os.environ[name] for name in _ENVIRONMENT_ALLOWLIST if name in os.environ}
        environment["NO_COLOR"] = "1"
        if os.name != "posix":
            raise AdapterError(
                "subscription CLI process-group isolation requires POSIX or WSL"
            )
        maximum = self.config.max_output_bytes * 4
        process: subprocess.Popen | None = None
        try:
            with tempfile.TemporaryFile(mode="w+b") as incoming, \
                    tempfile.TemporaryFile(mode="w+b") as outgoing, \
                    tempfile.TemporaryFile(mode="w+b") as diagnostic:
                if input_text is not None:
                    incoming.write(input_text.encode("utf-8"))
                incoming.seek(0)
                process = _subprocess_popen(
                    arguments,
                    input=input_text,
                    stdin=incoming,
                    stdout=outgoing,
                    stderr=diagnostic,
                    cwd=str(cwd) if cwd else None,
                    env=environment,
                    start_new_session=True,
                )
                started = time.monotonic()
                heartbeat_at = _HEARTBEAT_SECONDS
                while True:
                    elapsed = time.monotonic() - started
                    if elapsed >= timeout:
                        raise AdapterError("subscription CLI process failed: TimeoutExpired")
                    try:
                        returncode = process.wait(timeout=min(_POLL_SECONDS, timeout - elapsed))
                        break
                    except subprocess.TimeoutExpired:
                        if os.fstat(outgoing.fileno()).st_size > maximum or os.fstat(diagnostic.fileno()).st_size > maximum:
                            raise AdapterError("subscription CLI process output exceeds limit")
                        elapsed = time.monotonic() - started
                        if elapsed >= timeout:
                            raise AdapterError("subscription CLI process failed: TimeoutExpired")
                        if task_id is not None and elapsed >= heartbeat_at:
                            bucket = int(elapsed // _HEARTBEAT_SECONDS) * _HEARTBEAT_SECONDS
                            self._heartbeat(task_id, system_id, bucket)
                            heartbeat_at = bucket + _HEARTBEAT_SECONDS
                stdout = self._read_capture(outgoing, maximum)
                stderr = self._read_capture(diagnostic, maximum)
                return subprocess.CompletedProcess(arguments, returncode, stdout, stderr)
        except (OSError, subprocess.SubprocessError) as exc:
            raise AdapterError(f"subscription CLI process failed: {type(exc).__name__}") from None
        finally:
            if process is not None:
                self._kill_and_reap(process)
