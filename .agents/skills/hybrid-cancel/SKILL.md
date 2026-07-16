---
name: hybrid-cancel
description: Cancel a Secure Hybrid AI Development Hub task while retaining recoverable workspaces and non-secret evidence. Use when the user asks to stop an active task.
---

# Hybrid Cancel

Call `hub.py cancel TASK_ID`, show the confirmed `CANCELLED` state, and leave
workspaces and evidence intact. Use emergency stop only when the user requests
the global stop or an active security event requires it.
