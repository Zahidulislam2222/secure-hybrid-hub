from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .audit import AuditLog, SECRET_PATTERNS
from .cloud import ProviderProfile, ProviderProfileStore
from .errors import AdapterError, AuthorizationRequired, PolicyDenied, ValidationError
from .leases import LeaseManager
from .model_store import load_record, write_record
from .secrets import read_api_key_file, redact_exact
from .storage import Database
from .util import bounded_text, sha256_bytes, sha256_json, utc_now
from .workers import LocalWorker, _NoRedirect

HTTP_API_ADAPTERS = frozenset({"anthropic-api", "openai-compatible-api"})
# The single authoritative definitions of the two supported wire protocols.
# Anthropic-native: POST {origin}/v1/messages with x-api-key.
# OpenAI-compatible (OpenAI, MiniMax, GLM, Kimi, ...): POST
# {base_url}/chat/completions with a bearer token; base_url carries the
# vendor's path prefix (e.g. https://api.openai.com/v1).
ANTHROPIC_MESSAGES_PATH = "/v1/messages"
OPENAI_CHAT_COMPLETIONS_PATH = "/chat/completions"
DEFAULT_ANTHROPIC_VERSION = "2023-06-01"
PROVIDER_IDENTITY = "vendor-api"
STOP_MARKER = "<<END_FILE>>"


def _http_post(opener: Any, url: str, headers: dict[str, str], body: bytes, timeout: int, limit: int) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read(limit + 1)
        except OSError:
            detail = b""
        return exc.code, detail
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AdapterError(f"HTTP API request failed: {type(exc).__name__}") from exc


@dataclass(frozen=True)
class HttpApiConfig:
    name: str
    base_url: str
    model: str
    api_key_file: str
    input_cost_per_mtok: float
    output_cost_per_mtok: float
    max_task_cost_usd: float
    api_version: str = DEFAULT_ANTHROPIC_VERSION
    timeout: int = 300
    max_prompt_bytes: int = 32768
    max_output_bytes: int = 65536
    max_output_tokens: int = 2048

    def __post_init__(self):
        if self.name not in HTTP_API_ADAPTERS:
            raise ValidationError("unsupported HTTP API adapter")
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise PolicyDenied("HTTP API base URL must be a credential-free HTTPS URL")
        if not self.model or not isinstance(self.model, str) or len(self.model) > 128:
            raise ValidationError("invalid HTTP API model name")
        if not isinstance(self.timeout, int) or not 1 <= self.timeout <= 600:
            raise ValidationError("invalid HTTP API adapter timeout")
        if not isinstance(self.max_output_tokens, int) or not 1 <= self.max_output_tokens <= 32768:
            raise ValidationError("invalid HTTP API output token limit")
        if not isinstance(self.api_version, str) or not self.api_version or len(self.api_version) > 64:
            raise ValidationError("invalid HTTP API version value")
        for value in (self.input_cost_per_mtok, self.output_cost_per_mtok):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= float(value) <= 1000:
                raise ValidationError("HTTP API token prices must be explicit USD per million tokens (0-1000)")
        if isinstance(self.max_task_cost_usd, bool) or not isinstance(self.max_task_cost_usd, (int, float)) or not 0 < float(self.max_task_cost_usd) <= 100:
            raise ValidationError("HTTP API per-task spend cap must be a positive USD amount up to 100")
        key_path = Path(self.api_key_file) if isinstance(self.api_key_file, str) and self.api_key_file else None
        if key_path is None or not key_path.is_absolute():
            raise ValidationError("HTTP API adapters require an absolute API key file path")

    @property
    def origin(self) -> str:
        parsed = urlparse(self.base_url)
        port = f":{parsed.port}" if parsed.port else ""
        return f"https://{parsed.hostname}{port}"


class HttpApiWorker:
    """Metered vendor HTTP API coding worker (Anthropic-native or OpenAI-compatible).

    Fail-closed by construction: every run requires an approved vendor-api
    provider profile with live egress explicitly enabled and an endpoint
    origin matching the configured base URL. The API key is read from a
    private key file at call time — never from the environment — and is
    redacted from any error text. Every outbound prompt is audit-logged with
    its hash BEFORE egress, and token usage is metered against an explicit
    per-task spend cap; when the cap is reached the hub blocks and asks the
    human rather than switching providers.
    """

    def __init__(self, database: Database, audit: AuditLog, leases: LeaseManager, config: HttpApiConfig, profiles: ProviderProfileStore):
        self.database = database
        self.audit = audit
        self.leases = leases
        self.config = config
        self.profiles = profiles
        self.opener = urllib.request.build_opener(_NoRedirect())

    def preflight(self) -> dict[str, Any]:
        if self.database.emergency_stopped():
            raise PolicyDenied("emergency stop is active")
        read_api_key_file(Path(self.config.api_key_file))
        report = {
            "adapter": self.config.name, "model": self.config.model, "transport": "https-api",
            "endpoint_origin": self.config.origin, "credential_source": "key-file",
            "max_task_cost_usd": float(self.config.max_task_cost_usd), "available": True,
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
            task = connection.execute("SELECT tasks.cancelled,tasks.system_id,tasks.state,systems.approved FROM tasks JOIN systems USING(system_id) WHERE task_id=?", (task_id,)).fetchone()
        if not task or task["cancelled"] or not task["approved"]:
            raise PolicyDenied("task unavailable or cancelled")
        if task["state"] not in {"WORKSPACES_READY", "LOCAL_IMPLEMENTING", "LOCAL_REPAIRING", "LOCAL_FIXING"}:
            raise PolicyDenied("task state does not permit an HTTP API file worker run")
        system_id = task["system_id"]
        self._authorize(system_id)
        cap = float(self.config.max_task_cost_usd)
        spent = self._accumulated(system_id, task_id)
        if spent >= cap:
            raise PolicyDenied("per-task API spend cap is exhausted; escalation is a human decision")
        key = read_api_key_file(Path(self.config.api_key_file))
        prompt_bytes = prompt.encode("utf-8")
        self.audit.append(
            "worker.cloud-context-sent",
            {"adapter": self.config.name, "model": self.config.model, "task_id": task_id, "prompt_sha256": sha256_bytes(prompt_bytes), "prompt_bytes": len(prompt_bytes)},
            system_id=system_id, task_id=task_id,
        )
        with self.leases.held(f"http-api:{self.config.name}", task_id, ttl_seconds=self.config.timeout + 30):
            text, input_tokens, output_tokens = self._generate(prompt, key)
        call_cost = (input_tokens * float(self.config.input_cost_per_mtok) + output_tokens * float(self.config.output_cost_per_mtok)) / 1_000_000
        spent = round(spent + call_cost, 8)
        write_record(
            self.database, self.audit, self._spend_key(system_id, task_id),
            {"system_id": system_id, "task_id": task_id, "spent_usd": spent, "updated_at": utc_now()},
            "worker.tokens-metered", system_id, self.config.name,
            # The audit sanitizer redacts any key containing "token", so the
            # metered counts are recorded as usage_input/usage_output.
            {"task_id": task_id, "model": self.config.model, "usage_input": input_tokens, "usage_output": output_tokens, "call_cost_usd": round(call_cost, 8), "spent_usd": spent, "cap_usd": cap},
        )
        if spent > cap:
            raise PolicyDenied("per-task API spend cap was exceeded by the last call; ask the human before continuing")
        text = LocalWorker._clean_file_text(text)
        if not text or len(text.encode("utf-8")) > self.config.max_output_bytes:
            raise AdapterError("HTTP API file generation is empty or exceeds the limit")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                raise PolicyDenied("HTTP API file generation contains credential-like material")
        result_payload = {"status": "ok", "changed_paths": [], "content": text}
        result = {"adapter": self.config.name, "model": self.config.model, "task_id": task_id, "result": result_payload, "output_hash": sha256_json(result_payload), "completed_at": utc_now()}
        self.audit.append("worker.file-completed", {key_name: result[key_name] for key_name in ("adapter", "model", "task_id", "output_hash")}, system_id=system_id, task_id=task_id)
        return result

    def run_structured(self, task_id: str, prompt: str) -> dict[str, Any]:
        raise AdapterError("HTTP API adapters support guided file generation only; use a guided plan")

    def _authorize(self, system_id: str) -> None:
        try:
            profile_row = self.profiles.active(system_id, PROVIDER_IDENTITY)
        except AuthorizationRequired as exc:
            raise AuthorizationRequired("vendor API egress requires an approved vendor-api provider profile: run `provider propose` then `provider approve --enable-live`") from exc
        profile = ProviderProfile.from_dict(profile_row["profile"])
        if profile.mode != "live" or not profile_row["live_enabled"]:
            raise AuthorizationRequired("vendor API egress is not live-enabled for this system; approve the provider profile with --enable-live")
        if profile.endpoint != self.config.origin:
            raise PolicyDenied("HTTP API base URL does not match the approved provider endpoint origin")
        if float(self.config.max_task_cost_usd) > profile.max_cost_usd:
            raise PolicyDenied("per-task spend cap exceeds the approved provider cost limit")

    @staticmethod
    def _spend_key(system_id: str, task_id: str) -> str:
        return f"api-spend:{system_id}:{task_id}"

    def _accumulated(self, system_id: str, task_id: str) -> float:
        record = load_record(self.database, self._spend_key(system_id, task_id))
        if record is None:
            return 0.0
        value = record.get("spent_usd")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise PolicyDenied("per-task API spend record is invalid")
        return float(value)

    def _generate(self, prompt: str, key: str) -> tuple[str, int, int]:
        if self.config.name == "anthropic-api":
            url = self.config.origin + ANTHROPIC_MESSAGES_PATH
            headers = {"Content-Type": "application/json", "Accept": "application/json", "x-api-key": key, "anthropic-version": self.config.api_version}
            body: dict[str, Any] = {"model": self.config.model, "max_tokens": self.config.max_output_tokens, "temperature": 0, "stop_sequences": [STOP_MARKER], "messages": [{"role": "user", "content": prompt}]}
        else:
            url = self.config.base_url.rstrip("/") + OPENAI_CHAT_COMPLETIONS_PATH
            headers = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {key}"}
            body = {"model": self.config.model, "max_tokens": self.config.max_output_tokens, "temperature": 0, "stop": [STOP_MARKER], "messages": [{"role": "user", "content": prompt}]}
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        limit = self.config.max_output_bytes * 4
        status, raw = _http_post(self.opener, url, headers, payload, self.config.timeout, limit)
        if len(raw) > limit:
            raise AdapterError("HTTP API response exceeds limit")
        text_body = raw.decode("utf-8", errors="replace")
        if status != 200:
            raise AdapterError(f"HTTP API returned status {status}: {redact_exact(text_body, [key])[:200]}")
        try:
            response = json.loads(text_body)
        except json.JSONDecodeError as exc:
            raise AdapterError("HTTP API returned invalid JSON") from exc
        if not isinstance(response, dict):
            raise AdapterError("HTTP API returned a non-object")
        return self._parse_response(response)

    def _parse_response(self, response: dict[str, Any]) -> tuple[str, int, int]:
        if self.config.name == "anthropic-api":
            if response.get("stop_reason") == "max_tokens":
                raise AdapterError("HTTP API generation reached its output token limit before the stop sequence")
            content = response.get("content")
            if not isinstance(content, list):
                raise AdapterError("HTTP API response content is invalid")
            text = "".join(item.get("text", "") for item in content if isinstance(item, dict) and item.get("type") == "text")
            usage = response.get("usage")
            names = ("input_tokens", "output_tokens")
        else:
            choices = response.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                raise AdapterError("HTTP API response choices are invalid")
            choice = choices[0]
            if choice.get("finish_reason") == "length":
                raise AdapterError("HTTP API generation reached its output token limit before the stop sequence")
            message = choice.get("message")
            text = message.get("content") if isinstance(message, dict) else None
            usage = response.get("usage")
            names = ("prompt_tokens", "completion_tokens")
        if not isinstance(text, str):
            raise AdapterError("HTTP API returned non-text content")
        if not isinstance(usage, dict):
            raise AdapterError("HTTP API response omitted token usage; refusing to treat metered output as free")
        input_tokens, output_tokens = usage.get(names[0]), usage.get(names[1])
        if isinstance(input_tokens, bool) or isinstance(output_tokens, bool) or not isinstance(input_tokens, int) or not isinstance(output_tokens, int) or input_tokens < 0 or output_tokens < 0:
            raise AdapterError("HTTP API token usage is invalid")
        return text, input_tokens, output_tokens
