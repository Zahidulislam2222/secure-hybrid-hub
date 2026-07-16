---
name: hybrid-promote
description: Request a controlled staging or production promotion through the Secure Hybrid AI Development Hub. Use only for explicit deployment or promotion requests, never implicit coding requests.
---

# Hybrid Promote

Call the broker's explicit promote command and render its approval requirement.
Do not run cloud CLIs, use production credentials, bypass staging/canary gates,
or treat a general request to finish as production authorization. In the
local-only implementation slice, report the broker's later-phase blocker.
