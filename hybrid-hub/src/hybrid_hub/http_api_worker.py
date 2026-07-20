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
from .secrets import api_key_age_days, read_api_key_file, redact_exact
from .storage import Database
from .util import bounded_text, sha256_bytes, sha256_json, utc_now
from .workers import FILE_STOP_MARKER, LocalWorker, _NoRedirect

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
# Default allowance for the tokens a vendor adds around the prompt (system
# framing, message envelope, role markers): billed as input but absent from the
# prompt bytes, so a bound of one token per prompt byte alone can undercount.
# It is a per-adapter default, not a protocol constant — vendors frame requests
# differently — so HttpApiConfig.framing_token_overhead can raise it without a
# source edit if a vendor's observed input billing exceeds the prompt bytes by
# more than this.
DEFAULT_FRAMING_TOKEN_OVERHEAD = 64
# Absolute sanity ceiling on a vendor's reported token counts. JSON integers are
# unbounded, so an arbitrarily large report would either overflow the cost
# arithmetic or persist a spend total that permanently exhausts the task's cap.
# Anything above this is treated as unusable rather than as truth; it is far
# above any real call, so a genuine overshoot still reaches the post-call check.
MAX_REPORTED_TOKENS = 100_000_000


class TimedOutAfterSend(AdapterError):
    """The prompt was fully sent and no status arrived before the timeout.

    Distinguished from every other transport failure — including a timeout in
    the connect, TLS, or send phase, which never reached the vendor — because
    this is the one that a completed, billed generation looks like from the
    client side: the caller charges it at the worst case rather than free.
    """


def _http_post(opener: Any, url: str, headers: dict[str, str], body: bytes, timeout: int, limit: int) -> tuple[int, bytes, str]:
    """POST and return (status, body, read_error).

    Once the vendor has returned a status it has generated — and billed — the
    completion, so a failure while reading the body must NOT look the same as a
    request that never arrived. Such a response comes back with its status and a
    non-empty read_error for the caller to meter. Only a request that produced
    no usable status raises, and WHICH exception depends on the phase the
    failure happened in, never on how long it took: TimedOutAfterSend when the
    prompt was fully sent and the wait was for a response (which the caller
    charges), AdapterError otherwise — including a connect, TLS, or send-phase
    timeout, which elapses the same wall clock but never reached the vendor.
    """
    request = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read(limit + 1)
        except Exception:
            detail = b""
        finally:
            _close_quietly(exc)
        return exc.code, detail, ""
    except (PolicyDenied, AuthorizationRequired):
        # Policy controls raised from inside the opener — the redirect refusal
        # in _NoRedirect is one — keep their own meaning. Flattening them into a
        # transport error would erase the reason and make the orchestrator retry
        # a deliberate refusal.
        raise
    except Exception as exc:
        if _timed_out_after_sending(exc):
            # The prompt was fully sent and the timeout elapsed waiting for a
            # status. For a non-streaming completion the vendor sends headers
            # only once generation finishes, so this is the shape of a call that
            # WAS generated and billed while the client gave up waiting.
            raise TimedOutAfterSend(f"HTTP API request timed out after the prompt was sent: {type(exc).__name__}") from exc
        # Otherwise deliberately broad: not every transport failure is an
        # OSError (http.client.HTTPException subclasses such as BadStatusLine
        # are not), and one that escaped by type would skip the caller's
        # `worker.egress-unaccounted` audit and every orchestrator handler.
        raise AdapterError(f"HTTP API request failed: {type(exc).__name__}") from exc
    # A response object is in hand. From here nothing may raise in a way that
    # loses the fact that the vendor generated — and billed — the completion, so
    # the status is validated BEFORE the body is read (never discarding a body
    # already in hand) and the read and close are handled separately.
    status = getattr(response, "status", None)
    if not isinstance(status, int):
        _close_quietly(response)
        raise AdapterError("HTTP API response carried no usable status")
    try:
        raw, read_error = response.read(limit + 1), ""
    except Exception as exc:
        # Truncated/chunked-read failures are not all OSError (e.g.
        # http.client.IncompleteRead), so every read failure on an established
        # response is captured rather than caught by type.
        raw, read_error = b"", type(exc).__name__
    finally:
        _close_quietly(response)
    return status, raw, read_error


def _timed_out_after_sending(exc: BaseException) -> bool:
    """Whether a timeout happened with the prompt already fully sent.

    urllib separates the two phases: `AbstractHTTPHandler.do_open` wraps the
    connect/TLS/send phase in URLError, while a timeout waiting for the response
    propagates as a bare TimeoutError. So a URLError-wrapped timeout means the
    request never reached the vendor and must NOT be charged — charging it would
    let a passing network fault burn a real budget on $0 of actual spend — and a
    bare TimeoutError means the vendor is generating a completion it will bill.
    """
    return isinstance(exc, TimeoutError) and not isinstance(exc, urllib.error.URLError)


def _close_quietly(response: Any) -> None:
    """Close a response without letting the close itself lose a billed result."""
    try:
        response.close()
    except Exception:
        pass


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
    framing_token_overhead: int = DEFAULT_FRAMING_TOKEN_OVERHEAD

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
        if isinstance(self.framing_token_overhead, bool) or not isinstance(self.framing_token_overhead, int) or not 0 <= self.framing_token_overhead <= 4096:
            raise ValidationError("invalid HTTP API framing token overhead")
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

    Metering trust boundary: the cap is enforced against a worst-case bound
    before egress, and once a 2xx status is in hand the call is metered before
    its body is judged. The vendor bills at generation rather than at delivery,
    so a body that could not be read is charged at the worst case, a response
    whose connection merely failed to close is charged at its reported usage,
    and a request that timed out with the prompt fully sent — the shape a
    completed generation takes when the client stops waiting — is charged at the
    worst case, which also stops the orchestrator retrying it indefinitely. A
    timeout in the connect, TLS, or send phase never reached the vendor and is
    NOT charged; that case, and any other transport failure without a status,
    cannot be known to have been billed and is audited as
    `worker.egress-unaccounted`. Policy refusals raised from inside the opener
    (a forbidden redirect) are not transport failures: they propagate as
    themselves and are neither metered nor recorded as unaccounted egress.
    What a call is charged, otherwise, comes from the vendor's own reported
    usage. Reports that cannot be true
    (zero input tokens, or zero output tokens alongside returned text) are
    rejected and charged at the worst case, but an endpoint that consistently
    under-reports non-zero usage still advances the total more slowly than it
    bills. The per-call ceiling still applies; the per-task total does not
    detect that drift. Cross-check spend against the vendor's own billing
    console for any endpoint that is not the vendor's first-party API.
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
        key_path = Path(self.config.api_key_file)
        read_api_key_file(key_path)
        report = {
            "adapter": self.config.name, "model": self.config.model, "transport": "https-api",
            "endpoint_origin": self.config.origin, "credential_source": "key-file",
            "key_age_days": api_key_age_days(key_path),
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
        key = read_api_key_file(Path(self.config.api_key_file))
        prompt_bytes = prompt.encode("utf-8")
        # One task-wide spend lease covers read-check-egress-record, so
        # concurrent calls (even through different API adapters) cannot both
        # read a stale total and egress past the cap, and no call's cost can
        # be overwritten by a last-writer-wins record update.
        with self.leases.held(f"api-spend:{task_id}", task_id, ttl_seconds=self.config.timeout + 60):
            spent = self._accumulated(system_id, task_id)
            if spent >= cap:
                raise PolicyDenied("per-task API spend cap is exhausted; escalation is a human decision")
            # Pre-egress worst-case ceiling: refuse before the call whenever the
            # most this call could possibly cost would breach the cap. Input
            # tokens can never exceed the prompt's UTF-8 byte length (>=1 byte
            # per token) plus the configured framing margin, and output tokens
            # are bounded by max_output_tokens. The framing margin is an
            # estimate, so this is a conservative bound rather than a proven
            # one — the post-call check below remains the backstop — but it
            # makes the cap a ceiling instead of a check that always permits one
            # overshoot.
            worst_case_input = len(prompt_bytes) + self.config.framing_token_overhead
            worst_case_cost = self._cost(worst_case_input, self.config.max_output_tokens)
            if spent + worst_case_cost > cap:
                raise PolicyDenied("next call could exceed the per-task API spend cap; escalation is a human decision")
            self.audit.append(
                "worker.cloud-context-sent",
                {"adapter": self.config.name, "model": self.config.model, "task_id": task_id, "prompt_sha256": sha256_bytes(prompt_bytes), "prompt_bytes": len(prompt_bytes)},
                system_id=system_id, task_id=task_id,
            )
            timed_out = None
            status, raw, read_error = 0, b"", ""
            try:
                status, raw, read_error = self._call(prompt, key)
            except TimedOutAfterSend as exc:
                # Charged at the worst case like every other path where the cost
                # is unknown, because this is the shape a completed, billed
                # generation takes when the client stops waiting. It also bounds
                # the orchestrator's retries: each timed-out attempt advances the
                # ledger, so the pre-egress ceiling stops the loop instead of a
                # slow model being billed on every repair attempt while the hub
                # records $0. The failure is still raised, after metering.
                timed_out = exc
            except AdapterError as exc:
                # No status came back, so whether the vendor billed cannot be
                # known here: the request may have reached it and been generated,
                # or may never have left. Neither is metered, but the ambiguity
                # is recorded rather than left silent.
                self.audit.append(
                    "worker.egress-unaccounted",
                    {"adapter": self.config.name, "model": self.config.model, "task_id": task_id, "reason": "no response status", "detail": redact_exact(str(exc), [key])[:200]},
                    system_id=system_id, task_id=task_id,
                )
                raise
            if timed_out is not None:
                text, usage, failure = None, None, timed_out
            else:
                try:
                    text, usage, failure = self._interpret(status, raw, key)
                except Exception as exc:
                    # _interpret is written not to raise, but a billed response
                    # must never be able to skip metering because a body shape
                    # produced an unforeseen exception (a nested structure
                    # exhausting the parser's recursion limit, a malformed
                    # content block, ...). Anything that escapes is converted
                    # into a failure raised only after metering.
                    text, usage, failure = None, None, AdapterError(f"HTTP API response could not be interpreted: {type(exc).__name__}")
            # Any 2xx was billed by the vendor, whatever the body turned out to
            # contain, so it is metered BEFORE the body is judged. A truncated or
            # malformed success that raised before metering would leave real spend
            # invisible to the cap and let a repair loop bill without limit.
            if read_error:
                # The vendor answered — and billed — but its body never fully
                # arrived, so there is no usage to read and nothing to judge.
                usage = None
                failure = AdapterError(f"HTTP API response body could not be read: {read_error}")
            if timed_out is not None or 200 <= status < 300:
                # Everything from here to the spend record is guarded: this call
                # was billed, so no arithmetic or storage failure may end the run
                # without the ledger moving. A failure here is a policy block,
                # not a retryable adapter error — the orchestrator retries
                # AdapterError, and retrying with metering known to be broken is
                # how unbounded billing happens.
                try:
                    if usage is not None and (usage[0] <= 0 or (usage[1] <= 0 and not (text == "" and failure is None))):
                        # Zero input tokens for a non-empty prompt, or zero output
                        # tokens for anything other than a cleanly empty
                        # completion, cannot be what was billed. Treating such a
                        # report as truth would freeze the spend total and disable
                        # the cap entirely, so it is refused as unusable.
                        usage = None
                    if usage is None:
                        # Unusable usage means the true cost is unknown; charge the
                        # worst case rather than treating billed output as free, and
                        # still fail the run because the response cannot be trusted.
                        input_tokens, output_tokens, usage_basis = worst_case_input, self.config.max_output_tokens, "worst-case"
                        failure = failure or AdapterError("HTTP API response reported no usable token usage; refusing to treat metered output as free")
                    else:
                        input_tokens, output_tokens, usage_basis = usage[0], usage[1], "reported"
                    call_cost = self._cost(input_tokens, output_tokens)
                    spent = spent + call_cost
                    self._record_spend(system_id, task_id, spent, input_tokens, output_tokens, usage_basis, call_cost, cap, failure)
                except Exception as exc:
                    # BLOCKED_POLICY is terminal — neither cancellable nor
                    # resumable — so the recovery is a human reconciling the
                    # vendor's billing and starting a fresh run, not a state
                    # transition on this task.
                    detail = redact_exact(str(exc), [key])[:200]
                    raise PolicyDenied(f"API call was billed but could not be metered ({type(exc).__name__}: {detail}); the spend ledger is behind the vendor's. Reconcile the spend against the vendor's billing before starting a new run") from exc
        # Retained behind the pre-egress ceiling: a vendor billing more than the
        # worst-case bound still stops the task. The money signal is raised ahead
        # of any content failure so the human sees the cap breach first.
        if spent > cap:
            raise PolicyDenied("per-task API spend cap was exceeded by the last call; ask the human before continuing")
        if failure is not None:
            raise failure
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

    def _record_spend(self, system_id: str, task_id: str, spent: float, input_tokens: int, output_tokens: int, usage_basis: str, call_cost: float, cap: float, failure: AdapterError | None) -> None:
        write_record(
            self.database, self.audit, self._spend_key(system_id, task_id),
            {"system_id": system_id, "task_id": task_id, "spent_usd": spent, "updated_at": utc_now()},
            "worker.tokens-metered", system_id, self.config.name,
            # The audit sanitizer redacts any key containing "token", so the
            # metered counts are recorded as usage_input/usage_output. The
            # content failure is recorded here too: when a cap breach and a bad
            # body coincide only the cap breach is raised, and the operator
            # still needs to see why the response was rejected.
            {"task_id": task_id, "model": self.config.model, "usage_input": input_tokens, "usage_output": output_tokens, "usage_basis": usage_basis, "call_cost_usd": round(call_cost, 8), "spent_usd": spent, "cap_usd": cap, "content_failure": str(failure)[:200] if failure else ""},
        )

    def _cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens * float(self.config.input_cost_per_mtok) + output_tokens * float(self.config.output_cost_per_mtok)) / 1_000_000

    def _call(self, prompt: str, key: str) -> tuple[int, bytes, str]:
        """Perform the HTTP call only. Raises solely when no status came back;
        every response that produced a status — including error statuses and
        bodies that could not be read — is returned for the caller to meter and
        then interpret."""
        if self.config.name == "anthropic-api":
            url = self.config.origin + ANTHROPIC_MESSAGES_PATH
            headers = {"Content-Type": "application/json", "Accept": "application/json", "x-api-key": key, "anthropic-version": self.config.api_version}
            body: dict[str, Any] = {"model": self.config.model, "max_tokens": self.config.max_output_tokens, "temperature": 0, "stop_sequences": [FILE_STOP_MARKER], "messages": [{"role": "user", "content": prompt}]}
        else:
            url = self.config.base_url.rstrip("/") + OPENAI_CHAT_COMPLETIONS_PATH
            headers = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {key}"}
            body = {"model": self.config.model, "max_tokens": self.config.max_output_tokens, "temperature": 0, "stop": [FILE_STOP_MARKER], "messages": [{"role": "user", "content": prompt}]}
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        return _http_post(self.opener, url, headers, payload, self.config.timeout, self.config.max_output_bytes * 4)

    def _interpret(self, status: int, raw: bytes, key: str) -> tuple[str | None, tuple[int, int] | None, AdapterError | None]:
        """Read a response without raising: returns the generated text, the
        reported (input, output) token usage when it is usable, and the failure
        the caller must raise once the call has been metered."""
        if len(raw) > self.config.max_output_bytes * 4:
            return None, None, AdapterError("HTTP API response exceeds limit")
        text_body = raw.decode("utf-8", errors="replace")
        if status != 200:
            return None, None, AdapterError(f"HTTP API returned status {status}: {redact_exact(text_body, [key])[:200]}")
        try:
            response = json.loads(text_body)
        except (ValueError, RecursionError):
            # RecursionError is not a JSONDecodeError: a deeply nested body well
            # inside the size limit can exhaust the parser's recursion limit.
            return None, None, AdapterError("HTTP API returned invalid JSON")
        if not isinstance(response, dict):
            return None, None, AdapterError("HTTP API returned a non-object")
        # Usage is read independently of content validity: a truncated or
        # otherwise unusable generation still reports what the vendor billed.
        usage = self._usage(response)
        text, failure = self._content(response)
        return text, usage, failure

    def _usage(self, response: dict[str, Any]) -> tuple[int, int] | None:
        usage = response.get("usage")
        if not isinstance(usage, dict):
            return None
        names = ("input_tokens", "output_tokens") if self.config.name == "anthropic-api" else ("prompt_tokens", "completion_tokens")
        input_tokens, output_tokens = usage.get(names[0]), usage.get(names[1])
        if isinstance(input_tokens, bool) or isinstance(output_tokens, bool) or not isinstance(input_tokens, int) or not isinstance(output_tokens, int) or input_tokens < 0 or output_tokens < 0:
            return None
        if input_tokens > MAX_REPORTED_TOKENS or output_tokens > MAX_REPORTED_TOKENS:
            return None
        return input_tokens, output_tokens

    def _content(self, response: dict[str, Any]) -> tuple[str | None, AdapterError | None]:
        if self.config.name == "anthropic-api":
            if response.get("stop_reason") == "max_tokens":
                return None, AdapterError("HTTP API generation reached its output token limit before the stop sequence")
            content = response.get("content")
            if not isinstance(content, list):
                return None, AdapterError("HTTP API response content is invalid")
            # Each block's text is type-checked individually: a non-string value
            # in a text block would otherwise raise out of the join.
            blocks = [item.get("text") for item in content if isinstance(item, dict) and item.get("type") == "text"]
            if any(not isinstance(block, str) for block in blocks):
                return None, AdapterError("HTTP API response content is invalid")
            text: Any = "".join(blocks)
        else:
            choices = response.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                return None, AdapterError("HTTP API response choices are invalid")
            choice = choices[0]
            if choice.get("finish_reason") == "length":
                return None, AdapterError("HTTP API generation reached its output token limit before the stop sequence")
            message = choice.get("message")
            text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str):
            return None, AdapterError("HTTP API returned non-text content")
        return text, None
