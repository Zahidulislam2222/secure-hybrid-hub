---
name: hybrid-status
description: Read policy-safe task status, checkpoints, and evidence from the Secure Hybrid AI Development Hub. Use for progress, failure, lease, or verification-status questions.
---

# Hybrid Status

Locate the hub root three directories above this file. Call `hub.py status` for
the task ID and render the returned state exactly. Use the audit verification
command when integrity is questioned. Do not read raw runtime database files or
infer completion from model language.
