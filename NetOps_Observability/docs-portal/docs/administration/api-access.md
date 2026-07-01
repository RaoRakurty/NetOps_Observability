---
title: API access
sidebar_label: API access
sidebar_position: 6
description: Generate API keys, set token policy, and use the REST API.
---

# API access

Automate Correlix and integrate it with your tooling via the REST API. Manage access at <kbd>Administration → API Access</kbd>.

## Generate an API key

1. Go to <kbd>Administration → API Access</kbd> → **Generate API key**.
2. Name the key and (optionally) scope it to a role/permissions.
3. Copy the key **now** — it's shown once and stored encrypted.

Use the key as a bearer token on API requests.

## Token policy

Under **Token Policy**, set organization‑wide rules for API tokens — lifetime/expiry and rotation expectations — so automation credentials stay governed.

## REST API reference

The **REST API Reference** lists the available endpoints. API access is scoped and audited the same way the UI is — a key can only do what its role allows, within its tenant.

## Related

- **[Users & roles](/administration/identity-access)** — scope keys to the right permissions.
- **[Audit Log](/administration/overview)** — API actions are audited.
