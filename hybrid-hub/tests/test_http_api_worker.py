from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from test_integration import IntegrationBase

from hybrid_hub.errors import AdapterError, AuthorizationRequired, ConflictError, PolicyDenied, ValidationError
from hybrid_hub.http_api_worker import DEFAULT_FRAMING_TOKEN_OVERHEAD, HttpApiConfig, HttpApiWorker, _http_post
from hybrid_hub.secrets import read_api_key_file

SYNTHETIC_KEY = "hh-test-canary-0000000000000000"
ORIGIN = "https://api.synthetic.test"


def anthropic_body(text, input_tokens=1000, output_tokens=500, stop_reason="stop_sequence"):
    return json.dumps({
        "content": [{"type": "text", "text": text}],
        "stop_reason": stop_reason,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }).encode("utf-8")


def openai_body(text, prompt_tokens=1000, completion_tokens=500, finish_reason="stop"):
    return json.dumps({
        "choices": [{"message": {"content": text}, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
    }).encode("utf-8")


class ApiKeyFileTests(unittest.TestCase):
    def make(self, tmp, content="hh-synthetic-api-key-0123456789", mode=0o600):
        path = Path(tmp) / "api.key"
        path.write_text(content + "\n", encoding="utf-8")
        os.chmod(path, mode)
        return path

    def test_reads_a_private_single_line_key(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(read_api_key_file(self.make(tmp)), "hh-synthetic-api-key-0123456789")

    def test_rejects_relative_missing_multiline_and_short_keys(self):
        import tempfile

        with self.assertRaises(ValidationError):
            read_api_key_file(Path("relative.key"))
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValidationError):
                read_api_key_file(Path(tmp) / "missing.key")
            with self.assertRaises(ValidationError):
                read_api_key_file(self.make(tmp, content="line-one-0123456789abc\nline-two-0123456789abc"))
            with self.assertRaises(ValidationError):
                read_api_key_file(self.make(tmp, content="short"))

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits")
    def test_rejects_group_or_world_accessible_key_files(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyDenied):
                read_api_key_file(self.make(tmp, mode=0o644))


class HttpApiConfigTests(unittest.TestCase):
    def build(self, **overrides):
        values = {
            "name": "anthropic-api", "base_url": ORIGIN, "model": "synthetic-model",
            "api_key_file": "/synthetic/api.key", "input_cost_per_mtok": 1.0,
            "output_cost_per_mtok": 5.0, "max_task_cost_usd": 0.25,
        }
        values.update(overrides)
        return HttpApiConfig(**values)

    def test_accepts_both_protocols_and_exposes_the_origin(self):
        self.assertEqual(self.build().origin, ORIGIN)
        self.assertEqual(self.build(name="openai-compatible-api", base_url=ORIGIN + "/v1").origin, ORIGIN)

    def test_rejects_plain_http_credentialed_urls_and_unknown_adapters(self):
        with self.assertRaises(ValidationError):
            self.build(name="codex-local")
        with self.assertRaises(PolicyDenied):
            self.build(base_url="http://api.synthetic.test")
        with self.assertRaises(PolicyDenied):
            self.build(base_url="https://user:pass@api.synthetic.test")
        with self.assertRaises(PolicyDenied):
            self.build(base_url=ORIGIN + "?token=x")

    def test_rejects_missing_prices_caps_and_relative_key_file(self):
        with self.assertRaises(ValidationError):
            self.build(api_key_file="relative.key")
        with self.assertRaises(ValidationError):
            self.build(input_cost_per_mtok=-1)
        with self.assertRaises(ValidationError):
            self.build(max_task_cost_usd=0)
        with self.assertRaises(ValidationError):
            self.build(max_task_cost_usd=1000)

    def test_rejects_an_invalid_framing_token_overhead(self):
        for value in (-1, 4097, True, 1.5, "64"):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    self.build(framing_token_overhead=value)
        self.assertEqual(self.build(framing_token_overhead=0).framing_token_overhead, 0)


class HttpApiWorkerBase(IntegrationBase):
    def setUp(self):
        super().setUp()
        _, registration = self.register(git=True)
        self.task = self.hub.tasks.create("system-a", "Synthetic HTTP API worker", "R1", registration["policy"]["policy_hash"], "task-http-api")
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED", "WORKSPACES_READY"):
            self.hub.tasks.transition(self.task["task_id"], state)
        self.key_path = self.root / "synthetic-api.key"
        self.key_path.write_text(SYNTHETIC_KEY + "\n", encoding="utf-8")
        os.chmod(self.key_path, 0o600)

    def approve_provider(self, system_id="system-a", origin=ORIGIN, live=True, max_cost=1.0):
        profile = self.hub.provider_profiles.propose(system_id, {
            "provider": "vendor-api", "mode": "live", "endpoint": origin, "account_type": "api",
            "account_identity": "test-owner", "max_turns": 1, "max_seconds": 300, "max_cost_usd": max_cost,
        }, "test-owner")
        return self.hub.provider_profiles.approve(profile["profile_id"], "test-owner", enable_live=live)

    def worker(self, name="anthropic-api", base_url=ORIGIN, cap=0.25, input_cost=1.0, output_cost=5.0):
        config = HttpApiConfig(name, base_url, "synthetic-model", str(self.key_path), input_cost, output_cost, cap)
        return HttpApiWorker(self.hub.database, self.hub.audit, self.hub.leases, config, self.hub.provider_profiles)

    def audit_events(self, event):
        with self.hub.database.connect() as connection:
            rows = connection.execute("SELECT payload_json FROM audit_events WHERE event_type=? ORDER BY event_id", (event,)).fetchall()
        return [json.loads(row[0]) for row in rows]


class HttpApiWorkerTests(HttpApiWorkerBase):
    def test_anthropic_request_shape_key_header_and_metering(self):
        self.approve_provider()
        worker = self.worker()
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, anthropic_body("```python\ndef ready():\n    return True\n```\n"), "")) as post:
            result = worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        _, url, headers, body, timeout, _ = post.call_args.args
        self.assertEqual(url, ORIGIN + "/v1/messages")
        self.assertEqual(headers["x-api-key"], SYNTHETIC_KEY)
        self.assertIn("anthropic-version", headers)
        payload = json.loads(body)
        self.assertEqual(payload["model"], "synthetic-model")
        self.assertEqual(payload["temperature"], 0)
        self.assertEqual(payload["stop_sequences"], ["<<END_FILE>>"])
        self.assertEqual(payload["messages"][0]["content"], "Generate one synthetic file.")
        self.assertEqual(result["result"]["content"], "def ready():\n    return True\n")
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertEqual(metered[0]["usage_input"], 1000)
        self.assertEqual(metered[0]["usage_output"], 500)
        self.assertAlmostEqual(metered[0]["call_cost_usd"], (1000 * 1.0 + 500 * 5.0) / 1_000_000)

    def test_openai_compatible_request_uses_bearer_and_vendor_path_prefix(self):
        self.approve_provider()
        worker = self.worker(name="openai-compatible-api", base_url=ORIGIN + "/v1")
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, openai_body("def ready():\n    return True\n"), "")) as post:
            result = worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        _, url, headers, body, _, _ = post.call_args.args
        self.assertEqual(url, ORIGIN + "/v1/chat/completions")
        self.assertEqual(headers["Authorization"], f"Bearer {SYNTHETIC_KEY}")
        self.assertNotIn("x-api-key", headers)
        self.assertEqual(json.loads(body)["stop"], ["<<END_FILE>>"])
        self.assertEqual(result["result"]["content"], "def ready():\n    return True\n")

    def test_outbound_context_is_audited_even_when_the_call_fails(self):
        self.approve_provider()
        worker = self.worker()
        with patch("hybrid_hub.http_api_worker._http_post", side_effect=AdapterError("HTTP API request failed: URLError")):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        events = self.audit_events("worker.cloud-context-sent")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["adapter"], "anthropic-api")
        self.assertEqual(len(events[0]["prompt_sha256"]), 64)

    def test_refuses_without_live_enabled_matching_provider_profile(self):
        worker = self.worker()
        with patch("hybrid_hub.http_api_worker._http_post") as post:
            with self.assertRaises(AuthorizationRequired):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        post.assert_not_called()
        self.approve_provider(live=False)
        with self.assertRaises(AuthorizationRequired):
            worker.run_file(self.task["task_id"], "Generate one synthetic file.")

    def test_refuses_origin_mismatch_and_cap_above_provider_limit(self):
        self.approve_provider(origin="https://other.synthetic.test")
        worker = self.worker()
        with self.assertRaises(PolicyDenied):
            worker.run_file(self.task["task_id"], "Generate one synthetic file.")

    def test_refuses_cap_above_the_approved_provider_cost_limit(self):
        self.approve_provider(max_cost=0.10)
        worker = self.worker(cap=0.25)
        with patch("hybrid_hub.http_api_worker._http_post") as post:
            with self.assertRaises(PolicyDenied):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        post.assert_not_called()

    def test_worst_case_ceiling_refuses_the_first_call_before_egress(self):
        # With expensive prices the worst case for even the first call already
        # exceeds a tiny cap, so the strict pre-egress ceiling blocks BEFORE any
        # HTTP call or metering (no bounded overshoot — DEFECT-LOG row 6 fix).
        self.approve_provider()
        worker = self.worker(cap=0.001, input_cost=100.0, output_cost=100.0)
        with patch("hybrid_hub.http_api_worker._http_post") as post:
            with self.assertRaises(PolicyDenied):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        post.assert_not_called()
        self.assertEqual(self.audit_events("worker.tokens-metered"), [])
        self.assertEqual(self.audit_events("worker.cloud-context-sent"), [])

    def test_cap_admits_one_call_then_refuses_the_next_before_egress(self):
        # Cap sized so call 1's worst case fits but a second call's worst case
        # would breach it: call 1 egresses and is metered, call 2 is refused
        # pre-egress with no second HTTP call and no second metering event.
        self.approve_provider(max_cost=1.0)
        worker = self.worker(cap=0.011, input_cost=1.0, output_cost=5.0)
        body = anthropic_body("def ready():\n    return True\n", input_tokens=500, output_tokens=200)
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, body, "")) as post:
            worker.run_file(self.task["task_id"], "Generate one synthetic file.")
            self.assertEqual(post.call_count, 1)
            with self.assertRaises(PolicyDenied):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
            self.assertEqual(post.call_count, 1)
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertLessEqual(metered[0]["spent_usd"], metered[0]["cap_usd"])

    def test_truncated_billed_response_is_metered_before_it_fails(self):
        # A stop_reason=max_tokens 200 is a response the vendor BILLED. It must
        # be metered with its reported usage before the content failure is
        # raised, otherwise real spend stays invisible to the cap and a repair
        # loop can bill without limit (DEFECT-LOG row 7).
        self.approve_provider()
        worker = self.worker()
        body = anthropic_body("truncated", input_tokens=800, output_tokens=2048, stop_reason="max_tokens")
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, body, "")):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertEqual(metered[0]["usage_basis"], "reported")
        self.assertEqual(metered[0]["usage_input"], 800)
        self.assertEqual(metered[0]["usage_output"], 2048)
        self.assertAlmostEqual(metered[0]["spent_usd"], (800 * 1.0 + 2048 * 5.0) / 1_000_000)

    def test_billed_response_without_usage_is_metered_at_the_worst_case(self):
        # A 200 whose usage cannot be read was still billed an unknown amount:
        # charge the worst-case bound rather than treating it as free, and still
        # fail the run because the response cannot be trusted.
        self.approve_provider()
        worker = self.worker()
        prompt = "Generate one synthetic file."
        body = json.dumps({"content": [{"type": "text", "text": "x"}], "stop_reason": "stop_sequence"}).encode("utf-8")
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, body, "")):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], prompt)
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertEqual(metered[0]["usage_basis"], "worst-case")
        self.assertEqual(metered[0]["usage_input"], len(prompt.encode("utf-8")) + DEFAULT_FRAMING_TOKEN_OVERHEAD)
        self.assertEqual(metered[0]["usage_output"], worker.config.max_output_tokens)

    def test_every_billed_body_shape_is_metered_and_records_its_failure(self):
        # Criterion: EVERY billed 200 is metered, not only the two shapes with
        # dedicated tests. Each of these bodies is a response the vendor charged
        # for and the hub must reject; each must still move the spend total and
        # record why the body was refused.
        self.approve_provider()
        deep = ("[" * 4000) + ("]" * 4000)
        shapes = {
            "invalid JSON": b"not json",
            "recursive JSON": deep.encode("utf-8"),
            "non-object": b'"just a string"',
            "non-text content block": json.dumps({"content": [{"type": "text", "text": 123}], "stop_reason": "stop_sequence", "usage": {"input_tokens": 10, "output_tokens": 5}}).encode("utf-8"),
            "oversized body": b"x" * (65536 * 4 + 1),
        }
        for label, body in shapes.items():
            with self.subTest(shape=label):
                worker = self.worker()
                before = len(self.audit_events("worker.tokens-metered"))
                with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, body, "")):
                    with self.assertRaises(AdapterError):
                        worker.run_file(self.task["task_id"], "Generate one synthetic file.")
                metered = self.audit_events("worker.tokens-metered")
                self.assertEqual(len(metered), before + 1, f"{label} was billed but not metered")
                self.assertGreater(metered[-1]["call_cost_usd"], 0.0)
                self.assertTrue(metered[-1]["content_failure"], f"{label} recorded no reason")

    def test_impossible_reported_usage_is_charged_at_the_worst_case(self):
        # An endpoint reporting 0/0 forever would freeze the spend total and
        # disable the cap. Usage that cannot be true is refused, so the call is
        # charged the worst case and the run fails.
        self.approve_provider()
        worker = self.worker()
        body = anthropic_body("def ready():\n    return True\n", input_tokens=0, output_tokens=0)
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, body, "")):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertEqual(metered[0]["usage_basis"], "worst-case")
        self.assertGreater(metered[0]["spent_usd"], 0.0)

    def test_a_billed_response_whose_body_cannot_be_read_is_metered(self):
        # The vendor answered — and billed — but the body never fully arrived.
        # IncompleteRead is not an OSError, so this used to escape both the
        # worker and the orchestrator's except clause with nothing metered.
        import http.client

        self.approve_provider()
        worker = self.worker()

        class Truncating:
            status = 200

            def read(self, _limit):
                raise http.client.IncompleteRead(b"partial")

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        with patch.object(worker.opener, "open", return_value=Truncating()):
            with self.assertRaises(AdapterError) as caught:
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertIn("could not be read", str(caught.exception))
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertEqual(metered[0]["usage_basis"], "worst-case")
        self.assertGreater(metered[0]["call_cost_usd"], 0.0)

    def test_a_billed_response_is_metered_even_if_closing_the_socket_fails(self):
        # The body arrived complete with an honest usage report; only the close
        # failed. Losing the result there would charge $0 for a real call and
        # raise a RETRYABLE error, so the orchestrator would bill again.
        self.approve_provider()
        worker = self.worker()
        body = anthropic_body("def ready():\n    return True\n", input_tokens=100, output_tokens=50)

        class ClosesBadly:
            # Supports the context-manager protocol deliberately: against the
            # pre-fix worker (which used `with opener.open(...)`) this must fail
            # because the close discarded a billed result, not because the fake
            # was the wrong shape.
            status = 200

            def read(self, _limit):
                return body

            def close(self):
                raise OSError("connection reset on close")

            def __enter__(self):
                return self

            def __exit__(self, *_):
                self.close()
                return False

        with patch.object(worker.opener, "open", return_value=ClosesBadly()):
            result = worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertEqual(result["result"]["content"], "def ready():\n    return True\n")
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertEqual(metered[0]["usage_basis"], "reported")
        self.assertEqual(metered[0]["usage_input"], 100)

    def test_a_real_redirect_is_refused_as_a_policy_block_not_a_transport_error(self):
        # Drives an actual 3xx through the worker's real opener so _NoRedirect's
        # refusal is exercised, not simulated. Reporting it as an AdapterError
        # would erase the security reason AND make the orchestrator retry a
        # deliberate refusal.
        import http.server
        import threading

        self.approve_provider()
        worker = self.worker()

        class Redirector(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", "https://elsewhere.synthetic.test/v1/messages")
                self.end_headers()

            def log_message(self, *_):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Redirector)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/v1/messages"
            with patch.object(HttpApiWorker, "_call", lambda self_, prompt, key: _http_post(self_.opener, url, {"Content-Type": "application/json"}, b"{}", 10, 65536)):
                with self.assertRaises(PolicyDenied) as caught:
                    worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        finally:
            server.shutdown()
            server.server_close()
        self.assertIn("redirect", str(caught.exception).lower())
        self.assertEqual(self.audit_events("worker.tokens-metered"), [])

    def test_a_timeout_after_the_prompt_was_sent_is_charged_at_the_worst_case(self):
        # A non-streaming vendor sends headers only when generation completes, so
        # a client timeout is the shape of a call that WAS generated and billed.
        # Charging it also bounds the orchestrator's retries: without this, a
        # slow model bills on every repair attempt while the ledger reads $0.
        self.approve_provider()
        worker = self.worker()
        prompt = "Generate one synthetic file."
        with patch.object(worker.opener, "open", side_effect=TimeoutError("timed out")):
            with self.assertRaises(AdapterError) as caught:
                worker.run_file(self.task["task_id"], prompt)
        self.assertIn("timed out", str(caught.exception))
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertEqual(metered[0]["usage_basis"], "worst-case")
        self.assertEqual(metered[0]["usage_input"], len(prompt.encode("utf-8")) + DEFAULT_FRAMING_TOKEN_OVERHEAD)
        self.assertEqual(self.audit_events("worker.egress-unaccounted"), [])

    def test_a_timeout_before_the_prompt_was_sent_is_never_charged(self):
        # The negative half of the billed/not-billed classifier. urllib wraps
        # connect/TLS/send-phase timeouts in URLError; those never reached the
        # vendor, so charging them would let a passing network fault burn a real
        # budget on $0 of actual spend and permanently kill the task.
        import socket
        import urllib.error

        self.approve_provider()
        worker = self.worker()
        never_sent = urllib.error.URLError(socket.timeout("timed out"))
        with patch.object(worker.opener, "open", side_effect=never_sent):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertEqual(self.audit_events("worker.tokens-metered"), [])
        self.assertEqual(len(self.audit_events("worker.egress-unaccounted")), 1)

    def test_repeated_timeouts_exhaust_the_cap_instead_of_billing_forever(self):
        # The retry-amplification guard: each timed-out attempt advances the
        # ledger, so the pre-egress ceiling eventually refuses instead of the
        # orchestrator re-driving an unmetered billed call indefinitely.
        self.approve_provider()
        worker = self.worker(cap=0.05, input_cost=1.0, output_cost=5.0)
        attempts, refused = 0, False
        with patch.object(worker.opener, "open", side_effect=TimeoutError("timed out")):
            for _ in range(20):
                try:
                    worker.run_file(self.task["task_id"], "Generate one synthetic file.")
                except PolicyDenied:
                    refused = True
                    break
                except AdapterError:
                    attempts += 1
        self.assertTrue(refused, "the cap never refused a timed-out call")
        self.assertGreater(attempts, 0)
        self.assertEqual(len(self.audit_events("worker.tokens-metered")), attempts)

    def test_a_request_with_no_response_status_is_audited_as_unaccounted(self):
        # Whether the vendor billed cannot be known here, so nothing is metered
        # — but the ambiguity is recorded rather than left silent.
        self.approve_provider()
        worker = self.worker()
        with patch("hybrid_hub.http_api_worker._http_post", side_effect=AdapterError("HTTP API request failed: URLError")):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertEqual(self.audit_events("worker.tokens-metered"), [])
        self.assertEqual(len(self.audit_events("worker.egress-unaccounted")), 1)

    def test_a_billed_call_whose_spend_record_fails_blocks_instead_of_retrying(self):
        # If the ledger cannot be written the call is still billed. Failing as
        # PolicyDenied stops the task; AdapterError would be retried by the
        # orchestrator, billing again with metering known to be broken.
        self.approve_provider()
        worker = self.worker()
        with patch("hybrid_hub.http_api_worker.write_record", side_effect=RuntimeError("disk full")):
            with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, anthropic_body("def ready():\n    return True\n"), "")):
                with self.assertRaises(PolicyDenied) as caught:
                    worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertIn("could not be metered", str(caught.exception))

    def test_absurd_reported_usage_is_refused_instead_of_overflowing_the_cost(self):
        # JSON integers are unbounded. A 400-digit token count overflows the
        # float arithmetic in _cost, and a merely huge one persists a spend total
        # that permanently exhausts the task. Both are refused as unusable and
        # charged the worst case instead.
        self.approve_provider()
        for label, count in (("overflowing", int("9" * 400)), ("huge but finite", 10 ** 20)):
            with self.subTest(usage=label):
                worker = self.worker()
                before = len(self.audit_events("worker.tokens-metered"))
                body = json.dumps({
                    "content": [{"type": "text", "text": "def ready():\n    return True\n"}],
                    "stop_reason": "stop_sequence",
                    "usage": {"input_tokens": count, "output_tokens": 1},
                }).encode("utf-8")
                with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, body, "")):
                    with self.assertRaises(AdapterError):
                        worker.run_file(self.task["task_id"], "Generate one synthetic file.")
                metered = self.audit_events("worker.tokens-metered")
                self.assertEqual(len(metered), before + 1)
                self.assertEqual(metered[-1]["usage_basis"], "worst-case")
                self.assertLess(metered[-1]["spent_usd"], metered[-1]["cap_usd"])

    def test_zero_output_tokens_are_only_trusted_for_a_cleanly_empty_completion(self):
        # A malformed body reporting 0 output tokens must not be metered as $0
        # just because the content failed to parse and left text unset.
        self.approve_provider()
        worker = self.worker()
        body = json.dumps({
            "content": [{"type": "text", "text": 123}],
            "stop_reason": "stop_sequence",
            "usage": {"input_tokens": 1, "output_tokens": 0},
        }).encode("utf-8")
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, body, "")):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertEqual(metered[0]["usage_basis"], "worst-case")
        self.assertGreater(metered[0]["call_cost_usd"], 0.0)

    def test_a_non_200_success_status_is_still_metered(self):
        # 2xx, not 200, is the billing signal: a proxy answering 201 for a
        # completed generation must not slip through unmetered.
        self.approve_provider()
        worker = self.worker()
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(201, anthropic_body("def ready():\n    return True\n"), "")):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertGreater(metered[0]["call_cost_usd"], 0.0)

    def test_an_unforeseen_interpreter_failure_still_meters_the_billed_call(self):
        # The safety net around _interpret: a body shape nobody predicted must
        # not be able to skip metering just because it raised.
        self.approve_provider()
        worker = self.worker()
        with patch.object(HttpApiWorker, "_content", side_effect=AttributeError("unforeseen")):
            with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, anthropic_body("x"), "")):
                with self.assertRaises(AdapterError) as caught:
                    worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertIn("could not be interpreted", str(caught.exception))
        self.assertEqual(len(self.audit_events("worker.tokens-metered")), 1)

    def test_the_ceiling_compares_the_worst_case_without_rounding_it_away(self):
        # Both the cap and the worst-case cost sit below the 8-decimal rounding
        # grid, so `round(spent + worst_case, 8)` collapses to 0.0 and would
        # admit this call; the un-rounded comparison refuses it. The assertions
        # below pin that discrimination, so restoring the round() fails here.
        self.approve_provider()
        prompt = "Generate one synthetic file."
        worst_case_tokens = len(prompt.encode("utf-8")) + DEFAULT_FRAMING_TOKEN_OVERHEAD
        cap = 1e-9
        input_cost = 1.5e-9 * 1_000_000 / worst_case_tokens
        worst_case_cost = worst_case_tokens * input_cost / 1_000_000
        self.assertGreater(worst_case_cost, cap)
        self.assertLessEqual(round(worst_case_cost, 8), cap)
        worker = self.worker(cap=cap, input_cost=input_cost, output_cost=0.0)
        # side_effect rather than a body: if the ceiling ever admits this call
        # the failure names the reason instead of surfacing as an unpack error.
        with patch("hybrid_hub.http_api_worker._http_post", side_effect=AssertionError("the ceiling admitted a call it should have refused")):
            with self.assertRaises(PolicyDenied):
                worker.run_file(self.task["task_id"], prompt)

    def test_the_ceiling_counts_framing_tokens(self):
        # Cap sized between the prompt-bytes-only bound and the bound including
        # the framing allowance: without the allowance this call is admitted and
        # egresses, with it the call is refused before egress.
        self.approve_provider()
        prompt = "Generate one synthetic file."
        bytes_only = len(prompt.encode("utf-8")) * 1000.0 / 1_000_000
        with_framing = (len(prompt.encode("utf-8")) + DEFAULT_FRAMING_TOKEN_OVERHEAD) * 1000.0 / 1_000_000
        cap = (bytes_only + with_framing) / 2
        self.assertLess(bytes_only, cap)
        self.assertLess(cap, with_framing)
        worker = self.worker(cap=cap, input_cost=1000.0, output_cost=0.0)
        with patch("hybrid_hub.http_api_worker._http_post") as post:
            with self.assertRaises(PolicyDenied):
                worker.run_file(self.task["task_id"], prompt)
        post.assert_not_called()

    def test_non_200_responses_are_not_metered(self):
        # Vendors do not bill rejected requests, so an error status must not
        # consume the task's budget.
        self.approve_provider()
        worker = self.worker()
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(429, b'{"error":"rate limited"}', "")):
            with self.assertRaises(AdapterError):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertEqual(self.audit_events("worker.tokens-metered"), [])

    def test_usage_billed_beyond_the_worst_case_bound_still_stops_the_task(self):
        # The post-call cap check is retained behind the pre-egress ceiling: if a
        # vendor reports more usage than the worst-case bound predicted, the
        # overshoot is metered and the task blocks for a human.
        self.approve_provider()
        worker = self.worker(cap=0.25, input_cost=1.0, output_cost=5.0)
        body = anthropic_body("def ready():\n    return True\n", input_tokens=1000, output_tokens=60000)
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, body, "")):
            with self.assertRaises(PolicyDenied) as caught:
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertIn("exceeded by the last call", str(caught.exception))
        metered = self.audit_events("worker.tokens-metered")
        self.assertEqual(len(metered), 1)
        self.assertGreater(metered[0]["spent_usd"], metered[0]["cap_usd"])

    def test_secretlike_prompt_and_output_are_refused(self):
        self.approve_provider()
        worker = self.worker()
        with self.assertRaises(PolicyDenied):
            worker.run_file(self.task["task_id"], "Authenticate with password: synthetic-hunter2-value")
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, anthropic_body("api_key = 'synthetic-not-real-abcdef'\n"), "")):
            with self.assertRaises(PolicyDenied):
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")

    def test_error_body_echoing_the_key_is_redacted(self):
        self.approve_provider()
        worker = self.worker()
        error = json.dumps({"error": {"message": f"invalid key {SYNTHETIC_KEY}"}}).encode("utf-8")
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(401, error, "")):
            with self.assertRaises(AdapterError) as caught:
                worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        self.assertNotIn(SYNTHETIC_KEY, str(caught.exception))
        self.assertIn("401", str(caught.exception))

    def test_truncated_missing_usage_oversized_and_invalid_responses_fail_closed(self):
        # Each rejected case is still a billed 200 and is metered, so the cap is
        # set explicitly with room for all of them: this test is about the
        # fail-closed verdict, not about the spend ceiling.
        self.approve_provider()
        worker = self.worker(cap=1.0)
        cases = [
            anthropic_body("x", stop_reason="max_tokens"),
            json.dumps({"content": [{"type": "text", "text": "x"}], "stop_reason": "stop_sequence"}).encode("utf-8"),
            b"not json",
            b"x" * (worker.config.max_output_bytes * 4 + 1),
        ]
        for body in cases:
            with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, body, "")):
                with self.assertRaises(AdapterError):
                    worker.run_file(self.task["task_id"], "Generate one synthetic file.")
        openai_worker = self.worker(name="openai-compatible-api", base_url=ORIGIN + "/v1")
        with patch("hybrid_hub.http_api_worker._http_post", return_value=(200, openai_body("x", finish_reason="length"), "")):
            with self.assertRaises(AdapterError):
                openai_worker.run_file(self.task["task_id"], "Generate one synthetic file.")

    def test_structured_mode_and_unreadable_key_fail_closed(self):
        self.approve_provider()
        worker = self.worker()
        with self.assertRaises(AdapterError):
            worker.run_structured(self.task["task_id"], "Return the required object.")
        os.chmod(self.key_path, 0o644)
        if os.name == "posix":
            with patch("hybrid_hub.http_api_worker._http_post") as post:
                with self.assertRaises(PolicyDenied):
                    worker.run_file(self.task["task_id"], "Generate one synthetic file.")
            post.assert_not_called()

    def test_preflight_reports_without_network(self):
        worker = self.worker()
        report = worker.preflight()
        self.assertEqual(report["transport"], "https-api")
        self.assertEqual(report["credential_source"], "key-file")
        self.assertTrue(report["available"])
        self.assertIn("key_age_days", report)
        self.assertGreaterEqual(report["key_age_days"], 0.0)


class GuidedHttpApiFlowTests(IntegrationBase):
    def test_guided_run_verifies_with_http_api_adapter_identity(self):
        project = self.root / "api-guided-project"
        project.mkdir()
        (project / "README.md").write_text("# Synthetic API guided\n", encoding="utf-8")
        from test_integration import git_repo

        git_repo(project)
        registration = self.hub.registry.register_system("api-system", "api-client", "Api", [str(project)], ["standard"])
        discovery = self.hub.registry.discover("api-system")
        repo_id = discovery["repositories"][0]["repo_id"]
        version = self.hub.dossier.create_draft("api-system", {"purpose": "Synthetic API guided", "hierarchy": {"repositories": [repo_id]}, "provenance": [{"source": "synthetic-test"}]})
        self.hub.dossier.approve("api-system", version, "test-owner")
        self.hub.registry.approve_system("api-system", "test-owner")
        profile = self.hub.provider_profiles.propose("api-system", {
            "provider": "vendor-api", "mode": "live", "endpoint": ORIGIN, "account_type": "api",
            "account_identity": "test-owner", "max_turns": 1, "max_seconds": 300, "max_cost_usd": 1.0,
        }, "test-owner")
        self.hub.provider_profiles.approve(profile["profile_id"], "test-owner", enable_live=True)
        task = self.hub.tasks.create("api-system", "Synthetic API build", "R1", registration["policy"]["policy_hash"], "task-api-guided")
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED"):
            self.hub.tasks.transition(task["task_id"], state)
        plan = {
            "outcome": "A tested module", "non_goals": ["deployment"], "acceptance_criteria": ["module parses"],
            "packets": [{
                "packet_id": "core", "title": "Implement module", "objective": "Create the module",
                "repository_ids": [repo_id], "allowed_paths": {repo_id: ["app.py", "tests"]}, "context_paths": {repo_id: ["README.md"]},
                "deliverables": [
                    {"repo_id": repo_id, "path": "app.py", "purpose": "Implementation", "instructions": "Define only def ready() returning True."},
                    {"repo_id": repo_id, "path": "tests/test_app.py", "purpose": "Unit test", "instructions": "Use unittest to assert ready() is True."},
                ],
                "depends_on": [], "acceptance_criteria": ["ready returns True"], "test_focus": ["parse"],
                "research": [], "research_required": False, "research_guidance": [],
            }],
            "final_test_strategy": ["parse"], "unresolved_decisions": [],
        }
        self.hub.orchestrator.submit_guided_plan(task["task_id"], plan, "claude-interactive")
        workspace = self.hub.workspaces.create(task["task_id"], [repo_id])
        self.hub.tasks.transition(task["task_id"], "WORKSPACES_READY", evidence=[workspace["manifest_hash"]])
        key_path = self.root / "api-guided.key"
        key_path.write_text(SYNTHETIC_KEY + "\n", encoding="utf-8")
        os.chmod(key_path, 0o600)
        contents = {
            "app.py": "def ready():\n    return True\n",
            "tests/test_app.py": "import unittest\nfrom app import ready\nclass T(unittest.TestCase):\n    def test_ready(self):\n        self.assertTrue(ready())\n",
        }

        def fake_post(opener, url, headers, body, timeout, limit):
            prompt = json.loads(body)["messages"][0]["content"]
            target = prompt.split("GENERATE THIS ONE FILE NOW: ", 1)[1].splitlines()[0].split(":", 1)[1]
            return 200, anthropic_body(contents[target], input_tokens=200, output_tokens=100), ""

        config = HttpApiConfig("anthropic-api", ORIGIN, "synthetic-model", str(key_path), 1.0, 5.0, 0.25)
        worker = HttpApiWorker(self.hub.database, self.hub.audit, self.hub.leases, config, self.hub.provider_profiles)
        with patch("hybrid_hub.http_api_worker._http_post", side_effect=fake_post):
            def driver(task_id, prompt, attempt, role):
                return worker.run_file(task_id, prompt)["result"]

            report = self.hub.orchestrator.complete_guided(task["task_id"], driver, adapter="anthropic-api")
        self.assertTrue(report["verified"], report)
        self.assertEqual(report["implementation_attempts"][0]["adapter"], "anthropic-api")
        with self.hub.database.connect() as connection:
            metered = connection.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='worker.tokens-metered'").fetchone()[0]
        self.assertEqual(metered, 2)

    def test_missing_profile_blocks_cleanly_and_releases_the_repo_lease(self):
        # A guided run whose worker cannot authorize (no live-enabled provider
        # profile) must not strand the task silently in LOCAL_IMPLEMENTING with
        # an uncaught exception holding its workspace lease. It blocks cleanly
        # (terminal), which auto-releases the repo lease so a later run on the
        # same repo is not blocked (DEFECT-LOG row 4 fix).
        project = self.root / "api-noauth-project"
        project.mkdir()
        (project / "README.md").write_text("# Synthetic API no-auth\n", encoding="utf-8")
        from test_integration import git_repo

        git_repo(project)
        registration = self.hub.registry.register_system("noauth-system", "api-client", "NoAuth", [str(project)], ["standard"])
        discovery = self.hub.registry.discover("noauth-system")
        repo_id = discovery["repositories"][0]["repo_id"]
        version = self.hub.dossier.create_draft("noauth-system", {"purpose": "no auth", "hierarchy": {"repositories": [repo_id]}, "provenance": [{"source": "synthetic-test"}]})
        self.hub.dossier.approve("noauth-system", version, "test-owner")
        self.hub.registry.approve_system("noauth-system", "test-owner")
        task = self.hub.tasks.create("noauth-system", "Synthetic no-auth build", "R1", registration["policy"]["policy_hash"], "task-noauth")
        for state in ("REGISTERED_CONTEXT", "CLASSIFIED", "SCOPED"):
            self.hub.tasks.transition(task["task_id"], state)
        plan = {
            "outcome": "A module", "non_goals": ["deployment"], "acceptance_criteria": ["parses"],
            "packets": [{
                "packet_id": "core", "title": "Implement", "objective": "Create the module",
                "repository_ids": [repo_id], "allowed_paths": {repo_id: ["app.py"]}, "context_paths": {repo_id: ["README.md"]},
                "deliverables": [{"repo_id": repo_id, "path": "app.py", "purpose": "Impl", "instructions": "Define def ready() returning True."}],
                "depends_on": [], "acceptance_criteria": ["ready True"], "test_focus": ["parse"],
                "research": [], "research_required": False, "research_guidance": [],
            }],
            "final_test_strategy": ["parse"], "unresolved_decisions": [],
        }
        self.hub.orchestrator.submit_guided_plan(task["task_id"], plan, "claude-interactive")
        workspace = self.hub.workspaces.create(task["task_id"], [repo_id])
        self.hub.tasks.transition(task["task_id"], "WORKSPACES_READY", evidence=[workspace["manifest_hash"]])
        key_path = self.root / "noauth.key"
        key_path.write_text(SYNTHETIC_KEY + "\n", encoding="utf-8")
        os.chmod(key_path, 0o600)
        config = HttpApiConfig("anthropic-api", ORIGIN, "synthetic-model", str(key_path), 1.0, 5.0, 0.25)
        worker = HttpApiWorker(self.hub.database, self.hub.audit, self.hub.leases, config, self.hub.provider_profiles)

        def driver(task_id, prompt, attempt, role):
            return worker.run_file(task_id, prompt)["result"]

        report = self.hub.orchestrator.complete_guided(task["task_id"], driver, adapter="anthropic-api")
        self.assertFalse(report["verified"])
        self.assertEqual(report["task"]["state"], "BLOCKED_POLICY")
        self.assertIn("authorization required", report["task"]["reason"])
        # Terminal block auto-releases the workspace lease via final_report.
        self.assertEqual([item for item in self.hub.leases.list() if item["owner"] == task["task_id"]], [])


if __name__ == "__main__":
    unittest.main()
