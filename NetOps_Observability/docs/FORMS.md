# Filling the setup forms

This guide explains how to complete each configuration form/wizard in the
NetOps_Observability UI so it works the first time. Required fields are marked
with a red asterisk (`*`) and a legend; guided wizards will not let you advance a
step until that step's required fields are filled.

> Convention: secrets are **write-only** — once saved they show as “set”, never
> echoed back. Leaving a secret field blank on edit keeps the stored value.

---

## Infrastructure

### Add device (Infrastructure → Devices → “+ Add device”)
A two-step guided flow.
1. **Identity** — `Device ID *` (stable short name, e.g. `leaf1`) and `Address *`
   (IP or resolvable hostname). You can’t continue until both are set.
2. **Classification** *(optional)* — display name and vendor (helps grouping and
   vendor profiles; editable later).

### Connect (SSH) — Devices → “Connect”
Only shown when `FEATURE_DEVICE_SSH=true`. You authenticate to the device with
**your own** credentials; they are sent once over the encrypted socket and never
stored.
- `Username *`, then either a `Password *` or toggle **Use private key** and paste
  an OpenSSH `Private key *` (+ optional passphrase). `Port` defaults to 22.
- On first connect the device’s host-key fingerprint is recorded (TOFU). A later
  change is refused as a possible MITM — re-key the device deliberately if needed.

### SNMP Profile Manager (Infrastructure → SNMP Profile Manager)
One screen with two tabs:
- **Credentials** — `Name *`, `Version *` (v1/v2c/v3). For v1/v2c: `Community *`.
  For v3: `Security name *`, `Security level *`; `authNoPriv`/`authPriv` also need
  `Auth protocol *` + `Auth key *`; `authPriv` also `Privacy protocol *` +
  `Privacy key *`. Reference a credential from a device via its `credential_ref`.
- **Profiles** — the vendor OID/metric library; pick a vendor profile to apply
  its metric set.

---

## Tenants (Administration → Tenants)
The platform owner manages the namespace. The built-in tenant is the **Parent
Tenant**; everything you create is a **Child Tenant** (an isolated namespace for
devices, dashboards, alerts and users).
- **New child tenant:** `Tenant name *` (a short slug like `acme`) + optional
  note. The Parent Tenant can’t be deleted.

---

## API Access (Administration → API Access)
Mint a scoped key for a machine client.
- `Label *` (what it’s for). `Scopes` define what it can read/write (e.g.
  `read:metrics`, `write:incidents`); the RBAC role is derived from them.
- Optional hardening: per-minute rate limit, allowed source CIDRs, client/secret
  expiry, grant types, contacts.
- The **secret is shown once** at creation — copy it immediately; it can’t be
  retrieved later, only revoked + re-minted.

---

## Authentication (Administration → Authentication)
Configure one or more identity providers. Each is testable before save.
- **OIDC:** `Issuer URL *`, `Client ID *`, `Client secret *`, `Redirect URL *`
  (must match the IdP). Scopes default to `openid profile email`.
- **LDAP / AD:** `Host *`, `Bind DN *`, `Bind password *`, `User search base *`,
  and a user filter (e.g. `(uid=%s)`); set `Use TLS` for LDAPS.
- **TACACS+:** `Host *`, `Shared secret *` (PAP). Port defaults to 49.
- **SAML:** paste the IdP metadata or set `Entity ID *`, `SSO URL *`, and the
  signing `Certificate *`; add allowed RelayState targets.

---

## Notifications (Administration → Notifications)
Each channel is independent; fill only the ones you use, then **Test**.
- **SMTP (email):** `Host *`, `Port *`, `From *`; username/password if the relay
  requires auth.
- **Twilio (SMS):** `Account SID *`, `Auth token *`, `From number *`.
- **Slack / PagerDuty:** webhook URL / routing key (`*` each).
- **ntfy:** `Topic *` (and server URL if self-hosted).
- **Contact points:** reusable audiences (`Name *` + at least one email/slack/
  webhook target) referenced by reports and routing.

---

## ITSM integrations (Administration → Integrations) — guided wizard
Per-tenant ServiceNow / Jira. The wizard steps: **System → Connect → Routing →
Review**, and won’t advance until each step is valid.
- **ServiceNow:** `Instance URL *`, `Username *`, `Password *` (or OAuth), target
  table (default `incident`).
- **Jira:** `Base URL *`, `Email *`, `API token *`, `Project key *`, issue type.
- **Routing:** which severities auto-promote to a ticket; sync mode (one-way /
  bidirectional — bidirectional also needs `FEATURE_ITSM_INBOUND` and mints a
  webhook token + secret shown once).

---

## Reports (Reports → “New report”) — guided wizard
Steps: **Goal → Audience → Schedule → Recipients → Preview**.
- `Report name *`, a report **type/goal**, and a **schedule** (frequency, day,
  time, timezone). Recipients come from contact points or explicit emails; choose
  delivery as the rendered body or a secure expiring link. Preview before saving.

---

## Tips for a successful save
- Fill everything marked `*`; a wizard’s **Next** stays disabled until you do.
- Use **Test** (where present) before saving credentials — it validates
  connectivity without persisting a broken config.
- If a save is rejected, the error line states the exact field/reason; secrets
  left blank on edit are preserved, not cleared.
