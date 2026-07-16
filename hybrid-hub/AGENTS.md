# Hub development rules

- Treat `../docs/FINAL_BUILD_PLAN.md` as authoritative.
- Use synthetic data only until an explicitly authorized later phase.
- Never access real client projects, secrets, PHI/PII, privileged material,
  production systems, sibling roots, or cloud providers during local tests.
- The deterministic broker, not a model, controls policy and state.
- Update and validate a dossier checkpoint for every completed phase.
- Do not weaken tests, scanners, policy, or acceptance criteria to pass.
