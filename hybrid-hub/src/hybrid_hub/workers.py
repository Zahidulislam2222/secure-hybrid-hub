from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditLog, SECRET_PATTERNS
from .errors import AdapterError, PolicyDenied, ValidationError
from .leases import LeaseManager
from .storage import Database
from .util import bounded_text, sha256_json, utc_now

ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _validate_loopback(endpoint: str) -> str:
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PolicyDenied("local adapter endpoint must be unauthenticated loopback HTTP")
    if parsed.path not in {"", "/"} or not parsed.hostname or parsed.port != 11434:
        raise PolicyDenied("local adapter endpoint must be the Ollama loopback port")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise AdapterError("local adapter hostname cannot be resolved") from exc
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_loopback for item in addresses):
        raise PolicyDenied("local adapter endpoint resolved outside loopback")
    return f"http://{parsed.hostname}:{parsed.port}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PolicyDenied("adapter redirects are forbidden")


@dataclass(frozen=True)
class LocalAdapterConfig:
    name: str
    endpoint: str
    model: str
    timeout: int = 120
    max_prompt_bytes: int = 32768
    max_output_bytes: int = 65536
    executable: str | None = None
    http_bridge_executable: str | None = None

    def __post_init__(self):
        if self.name not in {"codex-local", "claude-local"}:
            raise ValidationError("unsupported local adapter")
        _validate_loopback(self.endpoint)
        if not self.model or self.timeout < 1 or self.timeout > 600:
            raise ValidationError("invalid local adapter limits")
        if self.executable is not None:
            executable = Path(self.executable)
            if not executable.is_absolute() or not executable.is_file() or executable.name.lower() not in {"ollama", "ollama.exe"}:
                raise ValidationError("local Ollama executable must be an existing absolute ollama path")
        if self.http_bridge_executable is not None:
            bridge = Path(self.http_bridge_executable)
            if not bridge.is_absolute() or not bridge.is_file() or bridge.name.lower() not in {"curl", "curl.exe"}:
                raise ValidationError("local HTTP bridge must be an existing absolute curl executable")
            allowed_bridges = {Path("/usr/bin/curl").resolve(), Path("/mnt/c/Windows/System32/curl.exe").resolve()}
            if bridge.resolve() not in allowed_bridges:
                raise PolicyDenied("local HTTP bridge must be the pinned OS curl executable")


class LocalWorker:
    def __init__(self, database: Database, audit: AuditLog, leases: LeaseManager, config: LocalAdapterConfig):
        self.database = database
        self.audit = audit
        self.leases = leases
        self.config = config
        self.base = _validate_loopback(config.endpoint)
        self.opener = urllib.request.build_opener(_NoRedirect())

    def preflight(self) -> dict[str, Any]:
        if self.database.emergency_stopped():
            raise PolicyDenied("emergency stop is active")
        if self.config.http_bridge_executable:
            response = self._bridge_request("GET", "/api/tags", None)
            models = sorted(item.get("name", "") for item in response.get("models", []) if item.get("name"))
            transport = "bounded-windows-loopback-http"
        elif self.config.executable:
            completed = self._process(["list"])
            models = sorted(line.split()[0] for line in completed.splitlines()[1:] if line.split())
            transport = "bounded-ollama-cli"
        else:
            response = self._request("GET", "/api/tags", None)
            models = sorted(item.get("name", "") for item in response.get("models", []) if item.get("name"))
            transport = "loopback-http"
        expected = self.config.model
        available = expected in models or any(name.split(":")[0] == expected.split(":")[0] for name in models)
        report = {"adapter": self.config.name, "mode": "local", "endpoint": self.base, "transport": transport, "model": expected, "model_available": available, "installed_models": models, "network_scope": ["local Ollama process/loopback only"], "cloud_credentials_injected": False, "checked_at": utc_now()}
        self.audit.append("worker.preflight", report)
        if not available:
            raise AdapterError("configured model is not installed")
        return report

    def run_structured(self, task_id: str, prompt: str) -> dict[str, Any]:
        bounded_text(prompt, self.config.max_prompt_bytes, "worker prompt")
        for pattern in SECRET_PATTERNS:
            if pattern.search(prompt):
                raise PolicyDenied("credential-like material is not allowed in model context")
        if self.database.emergency_stopped():
            raise PolicyDenied("emergency stop is active")
        with self.database.connect() as connection:
            task = connection.execute("SELECT tasks.cancelled,tasks.system_id,tasks.state,systems.approved FROM tasks JOIN systems USING(system_id) WHERE task_id=?", (task_id,)).fetchone()
        if not task or task["cancelled"] or not task["approved"]:
            raise PolicyDenied("task unavailable or cancelled")
        if task["state"] not in {"WORKSPACES_READY", "LOCAL_IMPLEMENTING", "LOCAL_REPAIRING", "LOCAL_FIXING"}:
            raise PolicyDenied("task state does not permit a local worker run")
        with self.leases.held("ollama:inference", task_id, ttl_seconds=self.config.timeout + 30):
            if self.config.http_bridge_executable:
                body = {"model": self.config.model, "prompt": prompt, "stream": False, "format": "json", "options": {"temperature": 0, "num_predict": 4096}}
                response = self._bridge_request("POST", "/api/generate", body)
                text = response.get("response", "")
            elif self.config.executable:
                process_prompt = prompt
                if self.config.model.lower().startswith("qwen3") and "/no_think" not in process_prompt:
                    process_prompt += "\nReturn exactly one compact JSON object on one line. /no_think"
                text = self._process(["run", self.config.model, process_prompt, "--format", "json", "--nowordwrap", "--hidethinking"])
            elif self.config.name == "codex-local":
                body = {"model": self.config.model, "prompt": prompt, "stream": False, "format": "json", "options": {"temperature": 0}}
                response = self._request("POST", "/api/generate", body)
                text = response.get("response", "")
            else:
                body = {"model": self.config.model, "messages": [{"role": "user", "content": prompt}], "stream": False, "temperature": 0}
                response = self._request("POST", "/v1/messages", body)
                content = response.get("content", [])
                text = "".join(item.get("text", "") for item in content if isinstance(item, dict))
            if len(text.encode("utf-8")) > self.config.max_output_bytes:
                raise AdapterError("model output exceeds limit")
            parsed = self._parse_json(text)
            self._validate_result(parsed)
            result = {"adapter": self.config.name, "model": self.config.model, "task_id": task_id, "result": parsed, "output_hash": sha256_json(parsed), "completed_at": utc_now()}
            self.audit.append("worker.completed", {key: result[key] for key in ("adapter", "model", "task_id", "output_hash")}, system_id=task["system_id"], task_id=task_id)
            return result

    def run_file(self, task_id: str, prompt: str) -> dict[str, Any]:
        """Generate one broker-selected text file without giving path authority to the model."""
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
            raise PolicyDenied("task state does not permit a local file worker run")
        body = {"model": self.config.model, "prompt": prompt, "stream": False, "options": {"temperature": 0, "num_predict": 2048, "stop": ["<<END_FILE>>"]}}
        with self.leases.held("ollama:inference", task_id, ttl_seconds=self.config.timeout + 30):
            if self.config.http_bridge_executable:
                response = self._bridge_request("POST", "/api/generate", body)
            elif not self.config.executable:
                response = self._request("POST", "/api/generate", body)
            else:
                raise AdapterError("guided file generation requires bounded loopback HTTP; configure the local curl bridge instead of the Ollama CLI")
        if response.get("done") is not True or response.get("done_reason") == "length":
            raise AdapterError("local file generation reached its output limit before the stop sequence")
        text = response.get("response", "")
        if not isinstance(text, str):
            raise AdapterError("local file generation returned non-text content")
        text = self._clean_file_text(text)
        if not text or len(text.encode("utf-8")) > self.config.max_output_bytes:
            raise AdapterError("local file generation is empty or exceeds the limit")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                raise PolicyDenied("local file generation contains credential-like material")
        result_payload = {"status": "ok", "changed_paths": [], "content": text}
        result = {"adapter": self.config.name, "model": self.config.model, "task_id": task_id, "result": result_payload, "output_hash": sha256_json(result_payload), "completed_at": utc_now()}
        self.audit.append("worker.file-completed", {key: result[key] for key in ("adapter", "model", "task_id", "output_hash")}, system_id=task["system_id"], task_id=task_id)
        return result

    @staticmethod
    def _clean_file_text(text: str) -> str:
        clean = ANSI_ESCAPE.sub("", text).strip()
        if "<<END_FILE>>" in clean:
            clean = clean.split("<<END_FILE>>", 1)[0].rstrip()
        if clean.startswith("```"):
            lines = clean.splitlines()
            if len(lines) >= 3 and lines[-1].strip() == "```":
                clean = "\n".join(lines[1:-1]).strip()
        return clean + "\n" if clean else ""

    def _process(self, arguments: list[str]) -> str:
        if not self.config.executable:
            raise AdapterError("local executable transport is not configured")
        clean_environment = {
            "OLLAMA_HOST": "http://127.0.0.1:11434",
            "OLLAMA_NO_CLOUD": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "NO_COLOR": "1",
            "TERM": "dumb",
            "COLUMNS": "10000",
            "LINES": "1000",
        }
        # Windows executables launched from WSL need these transport markers.
        # They are allowlisted runtime metadata, not provider credentials or
        # arbitrary inherited application configuration.
        for name in ("WSL_INTEROP", "WSL_DISTRO_NAME", "WSLENV", "WSL_UTF8", "SYSTEMROOT", "WINDIR", "PATH", "LANG", "LC_ALL"):
            if name in os.environ:
                clean_environment[name] = os.environ[name]
        try:
            completed = subprocess.run(
                [self.config.executable, *arguments],
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
                check=False,
                env=clean_environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdapterError(f"local Ollama process failed: {type(exc).__name__}") from exc
        combined = completed.stdout
        if completed.returncode:
            raise AdapterError(f"local Ollama process exited {completed.returncode}: {completed.stderr.strip()[:200]}")
        if len(combined.encode("utf-8")) > self.config.max_output_bytes:
            raise AdapterError("local Ollama process output exceeds limit")
        return combined

    def _request(self, method: str, path: str, payload: dict[str, Any] | None) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(self.base + path, data=data, method=method, headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self.opener.open(request, timeout=self.config.timeout) as response:
                raw = response.read(self.config.max_output_bytes + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AdapterError(f"local Ollama request failed: {type(exc).__name__}") from exc
        if len(raw) > self.config.max_output_bytes:
            raise AdapterError("adapter response exceeds limit")
        try:
            result = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AdapterError("adapter returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise AdapterError("adapter returned a non-object")
        return result

    def _bridge_request(self, method: str, path: str, payload: dict[str, Any] | None) -> dict[str, Any]:
        if not self.config.http_bridge_executable:
            raise AdapterError("local HTTP bridge is not configured")
        if path not in {"/api/tags", "/api/generate"}:
            raise PolicyDenied("local HTTP bridge path is not approved")
        data = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(data) > self.config.max_prompt_bytes + 4096:
            raise AdapterError("local HTTP bridge request exceeds limit")
        command = [
            self.config.http_bridge_executable,
            "--silent", "--show-error", "--fail-with-body", "--noproxy", "*",
            "--connect-timeout", "5", "--max-time", str(self.config.timeout),
            "--header", "Content-Type: application/json", "--header", "Accept: application/json",
            "--request", method,
        ]
        if payload is not None:
            command.extend(["--data-binary", "@-"])
        command.append(self.base + path)
        environment = {"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost", "PATH": ""}
        for name in ("WSL_INTEROP", "WSL_DISTRO_NAME", "WSLENV", "WSL_UTF8", "SYSTEMROOT", "WINDIR"):
            if name in os.environ:
                environment[name] = os.environ[name]
        try:
            completed = subprocess.run(command, input=data, capture_output=True, timeout=self.config.timeout + 10, check=False, env=environment)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdapterError(f"local loopback HTTP bridge failed: {type(exc).__name__}") from exc
        if completed.returncode:
            error = completed.stderr.decode("utf-8", errors="replace")[:200]
            raise AdapterError(f"local loopback HTTP bridge exited {completed.returncode}: {error}")
        if len(completed.stdout) > self.config.max_output_bytes:
            raise AdapterError("local loopback HTTP bridge output exceeds limit")
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise AdapterError("local loopback HTTP bridge returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise AdapterError("local loopback HTTP bridge returned a non-object")
        return result

    @staticmethod
    def _parse_json(text: str) -> dict[str, Any]:
        text = ANSI_ESCAPE.sub("", text)
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            decoder = json.JSONDecoder()
            candidates: list[dict[str, Any]] = []
            for index, character in enumerate(text):
                if character != "{":
                    continue
                try:
                    candidate, _ = decoder.raw_decode(text[index:])
                except json.JSONDecodeError:
                    continue
                if isinstance(candidate, dict):
                    candidates.append(candidate)
            if not candidates:
                raise AdapterError("model output JSON is invalid")
            value = candidates[-1]
        if not isinstance(value, dict):
            raise AdapterError("model output must be a JSON object")
        return value

    @staticmethod
    def _validate_result(value: dict[str, Any]) -> None:
        if value.get("status") not in {"ok", "blocked", "failed"}:
            raise AdapterError("model result has an invalid or missing status")
        changed = value.get("changed_paths")
        if not isinstance(changed, list) or any(
            not isinstance(path, str)
            or not path
            or path.startswith(("/", "\\"))
            or ".." in Path(path).parts
            for path in changed
        ):
            raise AdapterError("model result has invalid or missing changed_paths")
