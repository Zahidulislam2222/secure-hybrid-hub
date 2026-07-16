---
name: hybrid-promote
description: Request a controlled staging or production promotion through the broker.
disable-model-invocation: true
---

Call only the broker's explicit promotion command with `$ARGUMENTS`. Never run a
cloud CLI directly, handle production credentials, or bypass staging, canary,
health, approval, and rollback gates. Require the project-local marker and never
fall back to global configuration.
