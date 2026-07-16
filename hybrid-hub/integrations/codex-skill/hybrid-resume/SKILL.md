---
name: hybrid-resume
description: Resume a paused Secure Hybrid AI Development Hub task from persisted state. Use after the user supplies the exact missing input, authentication, or approval identified by the broker.
---

# Hybrid Resume

Confirm the broker's current pause reason, then call `hub.py resume TASK_ID --to
STATE` using the broker-allowed state. Never expand filesystem, network,
provider, credential, or production authority from a general “continue.”
