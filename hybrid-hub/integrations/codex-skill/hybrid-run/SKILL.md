---
name: hybrid-run
description: Submit and follow a software task through the Secure Hybrid AI Development Hub. Use when the user asks to build, modify, debug, or verify a registered project through the broker-controlled local workflow.
---

# Hybrid Run

Locate the hub root three directories above this file. Invoke its `hub.py run`
command with the user's exact task, registered system ID, and explicit runtime.
Render structured broker events and status; do not implement a parallel workflow.

Do not add credentials, raw logs, regulated records, or new permissions to the
request. Never translate a pause or blocked status into success. Ask only for
the specific input or authorization named by the broker, then use
`$hybrid-resume`.
