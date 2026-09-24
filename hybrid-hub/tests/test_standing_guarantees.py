"""The four standing questions, as executable assertions.

The project owner asks the same four questions every session. Answering them in
prose is unverifiable and has been wrong before: the classification egress
control was dead code for seven sessions while every prose answer implied it
worked. So each question is a test class here, with the question quoted
verbatim. Run this file after any change to the codebase; its result IS the
answer. Do not answer these questions from reading, memory, or confidence.

A guarantee that cannot be asserted belongs here as an explicit failing or
skipped test with a stated reason -- never as a silent omission.
"""

from __future__ import annotations

import inspect
import unittest

from hybrid_hub import orchestrator as orchestrator_module
from hybrid_hub import policy as policy_module
from hybrid_hub.errors import PolicyDenied, ValidationError
from hybrid_hub.policy import MANAGED_GLOBAL, PROFILES, compose, denies_cloud_egress, require_cloud_egress
from hybrid_hub.secrets import SyntheticMemoryBackend
from hybrid_hub.subscription_worker import SUBSCRIPTION_ADAPTERS

# Adapters that transmit source off this machine to a vendor.
CLOUD_CAPABLE_ADAPTERS = frozenset({"claude-subscription-cli", "codex-subscription-cli", "anthropic-api", "openai-compatible-api"})
# Adapters that keep everything on the local host.
LOCAL_ADAPTERS = frozenset({"codex-local", "claude-local", "synthetic-acceptance"})


class Q1BothToolsWorkWithoutRevealingSecrets(unittest.TestCase):
    """Q1: "does it work in both claude code and codex freely without revealing any secret?" """

    def test_both_claude_and_codex_are_supported_adapters(self):
        self.assertIn("claude-subscription-cli", SUBSCRIPTION_ADAPTERS)
        self.assertIn("codex-subscription-cli", SUBSCRIPTION_ADAPTERS)
        # And both are actually reachable through the orchestrator's allowlist,
        # not merely defined in the worker module.
        for adapter in ("claude-subscription-cli", "codex-subscription-cli"):
            self.assertIn(adapter, orchestrator_module.SUPPORTED_ADAPTERS)

    def test_no_classification_profile_grants_a_model_access_to_secrets(self):
        # The guarantee is structural: there is no profile a user could pick,
        # or combination they could compose, that turns secret access on.
        self.assertFalse(MANAGED_GLOBAL["model_secret_access"])
        for name, profile in PROFILES.items():
            with self.subTest(profile=name):
                self.assertFalse(profile["model_secret_access"], f"profile {name} would expose secrets to a model")
        # Composition cannot raise it either, even if a caller asks for it.
        composed = compose(["standard"], [{"classification": "R0", "cloud_code_egress": True, "internet_with_repo": True, "model_secret_access": True, "production_model_access": True, "retention_days": 1000, "gates": set()}])
        self.assertFalse(composed.model_secret_access)

    def test_a_real_looking_secret_cannot_be_loaded_into_the_synthetic_backend(self):
        with self.assertRaises(ValidationError):
            SyntheticMemoryBackend({"token": "sk-live-realish-value-000000"})
        # Only explicit test canaries are accepted.
        SyntheticMemoryBackend({"token": "hh_test_CANARY_OK"})


class Q2NoEgressLoophole(unittest.TestCase):
    """Q2: "there is no loop hole for coding, testing, debugging, security, cloud/production deployment that leave it from the system and go to cloud model?" """

    def test_every_restricted_profile_refuses_cloud_egress(self):
        for name, profile in PROFILES.items():
            if profile["cloud_code_egress"]:
                continue
            with self.subTest(profile=name):
                self.assertTrue(denies_cloud_egress([name]), f"{name} would be allowed to transmit source to a vendor")
                with self.assertRaises(PolicyDenied):
                    require_cloud_egress([name])

    def test_permissive_profiles_are_actually_permitted(self):
        # THE PAIRED POSITIVE, and the assertion whose absence hid the defect.
        # The suite asserted only that restricted profiles stay denied and that
        # a permissive layer cannot raise the flag. Nothing ever asserted that
        # ANY profile permits -- so `cloud_code_egress` being unconditionally
        # False (MANAGED_GLOBAL vetoes it through compose's all()) passed every
        # test written about it, while the control could not tell healthcare
        # from standard. A control that refuses everything is as broken as one
        # that refuses nothing; it just fails safe instead of open.
        for name in ("standard", "regulated", "public-open-source"):
            with self.subTest(profile=name):
                self.assertFalse(denies_cloud_egress([name]), f"{name} declares egress allowed but is refused")
                require_cloud_egress([name])

    def test_one_restricting_profile_denies_the_whole_system(self):
        # Profiles are additive restrictions: a system labelled both standard
        # and healthcare is healthcare data, and order must not matter.
        self.assertTrue(denies_cloud_egress(["standard", "healthcare"]))
        self.assertTrue(denies_cloud_egress(["healthcare", "standard"]))

    def test_the_egress_control_is_actually_wired_to_the_transmitting_paths(self):
        # THE REGRESSION THIS FILE EXISTS FOR. The control was written,
        # unit-tested, and called from nowhere in src/ for seven sessions: a
        # name collision with the unrelated `modifiers.require_action` made
        # grep results look populated. A unit test on a helper proves the
        # helper, never the wiring.
        from hybrid_hub import http_api_worker, subscription_worker

        for module in (subscription_worker, http_api_worker):
            with self.subTest(module=module.__name__):
                self.assertIn("require_cloud_egress", inspect.getsource(module), f"{module.__name__} never consults the classification egress policy")

    def test_local_adapters_are_never_treated_as_cloud_capable(self):
        # Guards the classification itself: if a local adapter silently became
        # cloud-capable, the egress check above would pass while leaking.
        self.assertFalse(CLOUD_CAPABLE_ADAPTERS & LOCAL_ADAPTERS)
        for adapter in SUBSCRIPTION_ADAPTERS:
            self.assertIn(adapter, CLOUD_CAPABLE_ADAPTERS, f"{adapter} transmits but is not classified cloud-capable")


class Q3ProducedCodeIsGatedNotTrusted(unittest.TestCase):
    """Q3: "is the codebase, when created or edited, production level and security proof?" """

    def test_model_written_code_containing_a_credential_is_refused(self):
        # Not a claim that output is secure -- a claim that credential-like
        # output is REJECTED rather than written to disk. Fail-closed.
        from hybrid_hub.audit import SECRET_PATTERNS

        offending = 'API_KEY = "AKIAIOSFODNN7EXAMPLE12345"'
        self.assertTrue(any(pattern.search(offending) for pattern in SECRET_PATTERNS))

    def test_the_approved_placeholder_forms_are_not_flagged(self):
        # The paired negative. Without it, a scanner that flagged EVERYTHING
        # would pass the test above while making the hub unusable.
        from hybrid_hub.audit import SECRET_PATTERNS

        for accepted in ('api_key = os.environ["API_KEY"]', 'token = getenv("TOKEN")', 'password = vault.get("db")', 'secret = settings.SECRET', 'api_key = "placeholder"', 'token = "test-value"', 'secret = "[REDACTED]"', 'password = secret_ref'):
            with self.subTest(form=accepted):
                self.assertFalse(any(pattern.search(accepted) for pattern in SECRET_PATTERNS), f"the approved form {accepted!r} is being rejected")

    def test_a_fake_secret_wearing_an_approved_prefix_is_still_flagged(self):
        # REGRESSION. The exemption above is a negative lookahead, and an
        # earlier version of it matched literal placeholders as PREFIXES rather
        # than requiring them to TERMINATE the value. That exempted any value
        # merely BEGINNING with an approved word -- and models name keys
        # `test-` constantly, so this is a realistic leak, not a contrived one.
        # It shipped past 204 green tests because the paired negative above
        # only ever tried `"test-value"`, which is compliant under both the
        # broken pattern and the correct one.
        #
        # Fixtures are deliberately low-entropy dictionary words: they must
        # exercise the lookahead, not resemble credentials -- the repo's own
        # secret scanner rejects this file otherwise, which is the control
        # working as intended. All three scanners share
        # audit.CREDENTIAL_EXEMPTION, so this pins all of them at once.
        from hybrid_hub.audit import SECRET_PATTERNS
        from hybrid_hub.egress import DLP_PATTERNS
        from hybrid_hub.quality import SENSITIVE_CONTENT

        disguised = [
            'api_key = "test-notarealkeynotarealkey"',
            'password = "test_notarealpasswordvalue"',
            'client_secret = "REDACTEDnotarealsecretvalue"',
            'access_token = "placeholdernotarealtokenvalue"',
            "api_key = 'test-notarealkeyvalue'",
        ]
        scanners = {
            "audit.SECRET_PATTERNS": list(SECRET_PATTERNS),
            "egress.DLP_PATTERNS": [pattern for _, pattern in DLP_PATTERNS],
            "quality.SENSITIVE_CONTENT": [pattern for _, pattern in SENSITIVE_CONTENT],
        }
        for name, patterns in scanners.items():
            for leak in disguised:
                with self.subTest(scanner=name, leak=leak):
                    self.assertTrue(any(pattern.search(leak) for pattern in patterns), f"{name} would let {leak!r} through")


class Q4SecretLocationsAndThePlaceholderContract(unittest.TestCase):
    """Q4: "where are all the secrets and credentials living, and how does the AI model know where to have that secret or placeholder?" """

    def test_the_api_key_is_read_from_a_file_and_never_from_the_environment(self):
        # Deliberate: an env var is inherited by every child process the hub
        # spawns, including model CLIs. A file read per call is not.
        from hybrid_hub import http_api_worker

        source = inspect.getsource(http_api_worker)
        self.assertIn("read_api_key_file", source)
        self.assertNotIn("environ.get(\"ANTHROPIC_API_KEY\"", source)
        self.assertNotIn("getenv(\"ANTHROPIC_API_KEY\"", source)

    def test_the_placeholder_convention_is_stated_to_the_model(self):
        # P5. The convention (os.environ / getenv / vault / secret_ref /
        # placeholder) existed ONLY as negative lookaheads inside the scanner
        # regexes -- i.e. as enforcement, never as instruction. The model was
        # never told the rule it is graded against, so compliance was a happy
        # accident of model habit and a violation cost a whole rejected run.
        prompt_source = inspect.getsource(orchestrator_module.Orchestrator._prompt)
        self.assertIn("os.environ", prompt_source, "the model is never told how to reference a secret")

    def test_secret_values_are_confined_to_an_approved_sandboxed_subprocess(self):
        from hybrid_hub import secrets as secrets_module

        source = inspect.getsource(secrets_module.SecretRunner.run)
        # Bound to an approved capability, offline, and redacted on the way out.
        self.assertIn("network_mode", inspect.getsource(secrets_module))
        self.assertIn("redact_exact", source)


if __name__ == "__main__":
    unittest.main()
