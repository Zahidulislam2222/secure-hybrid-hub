# Guided high-model → research → local-model workflow

Guided execution is the production-shaped path for small local models. The
interactive Codex or Claude session performs architecture, decomposition, and
monitoring. The local model receives one bounded work packet at a time. It is
never asked to invent the whole system architecture.

The high model writes a JSON plan containing exactly these top-level fields:

```json
{
  "outcome": "The precise user-visible result",
  "non_goals": ["Anything intentionally excluded"],
  "acceptance_criteria": ["End-to-end observable requirements"],
  "packets": [
    {
      "packet_id": "contract-first",
      "title": "Add the public contract",
      "objective": "One narrow implementation objective",
      "repository_ids": ["registered-repository-id"],
      "allowed_paths": {
        "registered-repository-id": ["src/contracts", "tests/contracts"]
      },
      "context_paths": {
        "registered-repository-id": ["src/contracts", "README.md"]
      },
      "deliverables": [
        {
          "repo_id": "registered-repository-id",
          "path": "src/contracts/public.py",
          "purpose": "The exact public contract implementation",
          "instructions": "File-specific, detailed high-model coding instructions with required symbols, signatures, invariants, and exclusions"
        },
        {
          "repo_id": "registered-repository-id",
          "path": "tests/contracts/test_public.py",
          "purpose": "Focused deterministic tests for this packet",
          "instructions": "Exact test cases, imports, assertions, and forbidden shortcuts"
        }
      ],
      "depends_on": [],
      "acceptance_criteria": ["Packet-specific observable requirement"],
      "test_focus": ["Exact unit or contract behavior to prove"],
      "research": [
        {
          "query": "Generic technology and version documentation question",
          "official_urls": ["https://approved.official.example/docs/page"]
        }
      ],
      "research_required": true,
      "research_guidance": [
        "High-model summary of the relevant official fact, with no private context"
      ]
    }
  ],
  "final_test_strategy": ["Cross-packet integration and regression checks"],
  "unresolved_decisions": []
}
```

Rules:

- Use registered repository IDs, not paths to unrelated folders.
- Order packets so dependencies refer only to earlier packets.
- Keep each packet small enough for one local-model response.
- List every exact file the packet may create or modify in `deliverables`.
  Local output is rejected if it writes another file, even underneath an
  otherwise allowed directory.
- Give each deliverable precise `instructions`. Tiny local models receive this
  file-level contract instead of the broad system prompt. Architecture and
  decomposition remain the high model's responsibility.
- `allowed_paths` and `context_paths` map each selected repository ID to its own
  path list. They are enforcement boundaries, not guidance. A path approved in
  one microservice repository grants nothing in another repository.
- Research queries contain only generic public technology questions. They must
  not contain client names, source code, endpoints, logs, credentials, PHI,
  personal data, legal-matter facts, or filesystem paths.
- Official URLs still require a separately approved per-system research policy.
- Set `research_required` when the packet must not run from model memory or
  guidance alone. Missing approved/cache evidence then pauses before coding.
- `research_guidance` is written by the high-level supervisor from generic
  official-source research. The local coding model receives these concise
  instructions plus source hashes; raw fetched web text is withheld so a tiny
  model cannot copy a page or obey web prompt injection.
- Research runs without repository access. The local coding worker has no
  internet; it receives bounded evidence with source, date, and hash.
- Evidence matching prompt-injection patterns is withheld from model context.
- Deterministic targeted gates run after every packet, then cross-packet
  targeted and full gates run before verification.

Example command from an opted-in project:

```text
python3 HUB_ENTRY --runtime PROJECT_RUNTIME run "USER REQUEST" \
  --system SYSTEM_ID --through verified \
  --guided-plan /protected/runtime/inbox/plan.json \
  --supervisor-source codex-interactive \
  --adapter codex-local --model gemma3:1b
```

This does not enable a cloud provider, global connector, model download,
SearXNG installation, credential, or production access. Those remain separate
project-specific approvals.
