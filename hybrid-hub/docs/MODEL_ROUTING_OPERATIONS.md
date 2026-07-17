# Model routing operations

This runbook covers the verified project-scoped model registry, automation policy, deterministic router, and bounded fallback executor. All commands must enter through `hybrid-hub/hub.py`; model adapters never bypass the broker. These steps are synthetic-only until client, provider, credential, data, and production scopes are separately authorized.

## Safe lifecycle

Set `RUNTIME` to the registered Hub runtime and replace only synthetic file paths and approved actor labels.

```bash
python3 hybrid-hub/hub.py --runtime "$RUNTIME" model discover SYSTEM_ID --definition synthetic-model.json --actor OPERATOR
python3 hybrid-hub/hub.py --runtime "$RUNTIME" model evaluate SYSTEM_ID MODEL_ID --evidence synthetic-evaluation.json --actor OPERATOR
python3 hybrid-hub/hub.py --runtime "$RUNTIME" model approve SYSTEM_ID MODEL_ID --actor OWNER
python3 hybrid-hub/hub.py --runtime "$RUNTIME" model list SYSTEM_ID
```

Discovery does not authorize use. Evaluation evidence must be synthetic and pass validation. Approval is a separate owner action. Disable a model immediately when its evaluation, digest, adapter, account profile, or authorization is no longer valid:

```bash
python3 hybrid-hub/hub.py --runtime "$RUNTIME" model disable SYSTEM_ID MODEL_ID --actor OWNER
```

## Project policy and route inspection

Propose and approve policy as two separate actions, then inspect the active policy and deterministic plan:

```bash
python3 hybrid-hub/hub.py --runtime "$RUNTIME" model policy-propose SYSTEM_ID --policy synthetic-policy.json --actor OPERATOR
python3 hybrid-hub/hub.py --runtime "$RUNTIME" model policy-approve SYSTEM_ID --actor OWNER
python3 hybrid-hub/hub.py --runtime "$RUNTIME" model policy-show SYSTEM_ID
python3 hybrid-hub/hub.py --runtime "$RUNTIME" model route SYSTEM_ID --role coding --classification R1
```

`route` returns a plan; it does not execute a model. The router considers only approved, evaluated models allowed by the active system policy. Ordering is deterministic: policy preference, local before cloud, accepted cost, success rate, then model ID. Pinned mode removes every non-pinned candidate. An empty eligible set fails closed.

## Bounded fallback

Execution uses the broker-owned `BoundedModelExecutor`. It never tries more than the active policy's `max_attempts`. Only capacity, invalid-output, timeout, and transport failures may advance to the next approved candidate. Account, authentication, classification, egress, policy, security, authorization, validation, and unclassified failures stop immediately. Exhaustion returns failure; it never converts partial work into success.

## Recovery and evidence

After interruption, read persisted state before resubmitting work:

```bash
python3 hybrid-hub/hub.py --runtime "$RUNTIME" status TASK_ID
python3 hybrid-hub/hub.py --runtime "$RUNTIME" audit verify
python3 hybrid-hub/hub.py --runtime "$RUNTIME" dossier show SYSTEM_ID
```

Treat only `VERIFIED` tasks with valid audit, deterministic quality evidence, and a release manifest as completed. Preserve blocked workspaces and exact task IDs. Record each activated commit, release, manifest, evidence digest, structured dossier version, and next safe action in `PROJECT-DOSSIER.md`. Never weaken scanners, tests, policy, or acceptance criteria to obtain a pass.
