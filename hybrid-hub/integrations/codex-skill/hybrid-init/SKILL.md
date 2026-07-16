---
name: hybrid-init
description: Register and deterministically discover a project in the Secure Hybrid AI Development Hub. Use when the user wants to onboard a single repository, monorepo, polyrepo microservice system, or hybrid system.
---

# Hybrid Init

Locate the hub root three directories above this file. Call `hub.py system init`
with only explicit project roots, client/system identifiers, purpose, and
profiles. Then call deterministic discovery and present the draft dossier.

Never approve the initial profile for the user. Never read environment values,
credentials, production data, sibling directories, or add cloud/provider scope.
