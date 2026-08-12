---
title: Transport security
sidebar_label: Transport security
sidebar_position: 2
description: How Correlix secures communication between its own services, and exactly what is and is not covered today.
---

# Transport security

This page states what Correlix encrypts and authenticates, **and what it does
not**. Every claim here is one we can demonstrate on a running deployment; the
limits are stated as plainly as the guarantees, because a security page you
cannot stand behind is worse than no page at all.

## The claim, precisely

> Correlix secures communications between Correlix-managed services and protects
> stored application secrets and tenant access boundaries. Security of telemetry
> between customer devices and collectors depends on the protocol and device
> configuration.

We deliberately do **not** claim "end-to-end encrypted telemetry" — see
[device telemetry](#device-telemetry-what-we-do-not-claim).

## One install-time choice

Transport security is selected when the deployment is installed: the secured
configuration is a single installer option, and it is the shape this page
describes. (A plaintext variant exists for isolated labs and evaluation; it
makes none of the claims below.) Once installed secured, there is no
supported way to partially disable the mesh — the controls below are enforced
by the software, not by operator discipline.

## Between Correlix services: encrypted and mutually authenticated

Every Correlix-managed service — the API, the datastores, the event bus, the
telemetry pipeline, the correlation engine — receives its own short-lived
X.509 identity from a certificate authority created inside your deployment.
Services then authenticate **each other**, not just encrypt:

```
browser ──HTTPS──▶ nginx ──mutual TLS──▶ API ──mutual TLS──▶ datastores, bus,
                     │                    │                   pipeline, engine
              public/enterprise      internal CA (per deployment),
                 certificate         short-lived identities, auto-rotated
```

**Workload identity.** Each service carries a SPIFFE-style identity (such as
`spiffe://netops/ns/default/sa/api`) in its certificate. Connections between
services verify the peer's *specific identity* — a certificate issued by the
same authority *to a different service* is rejected, and that rejection is
counted and observable. Encryption alone is not treated as a boundary.

**This holds on the wire, not just in configuration.** The deployment has
been verified end to end: every in-scope service-to-service path encrypted,
every served identity checked at the endpoint, and the negative cases —
no certificate, wrong identity, stolen credential, anonymous access —
demonstrated to be refused.

**The certificate authority's key is sealed.** The CA root could mint an
identity for any service, so it is encrypted at rest under a sealed key. If
sealing is unavailable, **Correlix refuses to create the CA at all** rather
than write that key in cleartext.

## What the deployment refuses to do

There is **no plaintext fallback**. A secured deployment fails closed:

- A service whose certificate material is missing or unreadable **refuses to
  start** — with an error naming exactly what is missing — rather than
  starting unencrypted.
- The datastores **refuse plaintext clients at the server**. A database
  client that does not speak TLS is rejected before authentication — no
  password ever crosses the wire in the clear, even from a misconfigured
  client.
- The telemetry pipeline **refuses to load** if the keys protecting sensitive
  fields cannot be fetched, rather than running with protection silently
  absent.
- A production profile **refuses to boot** on any unsatisfied security
  control, with a message naming the control, what was observed, what is
  required, and how to fix it. There is no global override — exceptions are
  narrow, owned and expiring, never a switch that turns the validator off.

## Automatic certificate rotation

Certificate lifecycle requires no manual work and no calendar entries:

- Identities are minted at startup and **re-issued automatically at
  half-life**, so a compromised certificate ages out on its own.
- A scheduled propagation job pushes fresh certificates into every service —
  including those that load certificates only at startup — and then
  **verifies on the wire** that every endpoint serves the current
  certificate, failing loudly if any does not.
- An independent prober continuously watches what each endpoint **actually
  serves** (not what is on disk) and raises alerts well before expiry could
  affect clients.

## Seeing it for yourself

Platform administrators can read the live posture at
`GET /admin/security/posture`. The report distinguishes what is **configured**
from what is **observed** on the wire — and anything the platform cannot
verify at runtime is shown as **unverified**, never assumed green. The
posture page renders that report directly; the interface never computes
"secure" on its own.

## Sensitive fields and unattributable telemetry

When sealing is enabled (part of the secured configuration), two further
protections apply:

**Sealed fields.** Designated sensitive values are encrypted per tenant at
the edge of the pipeline, stored only as ciphertext, and revealed only
through an audited endpoint gated by a dedicated permission — every reveal
records who, why, and what context, never the value itself.

**Unattributable telemetry is quarantined, not stored in the clear.**
Telemetry sometimes arrives from a sender the deployment cannot yet map to a
tenant — a device not yet in the inventory, or an unknown sender. Rather than
storing such events as plaintext in a shared location, Correlix **encrypts
the entire event** under a dedicated key, stores only non-identifying
metadata alongside it, and keeps it in an operator-only quarantine that no
tenant-facing query path can reach. Quarantined events have **bounded
retention** (30 days by default, configurable), and recovery is an **audited
workflow**: once the device is assigned to a tenant, a platform operator with
the reveal permission can restore the events into that tenant's data — every
restore leaving an audit record. Attribution failure never silently becomes a
confidentiality downgrade.

## Data at rest

Application secrets — integration credentials, SNMP credentials, API tokens —
are encrypted with per-tenant keys under a sealed root key (AES-256-GCM).
Secret values are write-only through the API: once saved they are never
returned, never logged, and never sent back to the browser.

**Backups are the operator's responsibility.** Correlix does not provide
backup-specific encryption with its own key domain. Production deployments
must target an operator-provided encrypted volume or destination, and
Correlix reports when it cannot verify that. We therefore do **not** claim
"all data at rest is encrypted."

## Tenant isolation is enforced in the database

This is worth stating separately because it is independent of transport
security, and stronger than it:

- **ClickHouse row policies** and **PostgreSQL row-level security** scope every
  query to the caller's tenant *in the database*, not only in application code.
- The search store uses **per-tenant indices** with server-side filters.
- Automated tests **fail the build** if a tenant policy is written permissively.

A mutually authenticated connection proves *which service* is calling. It never
decides *which tenant's data* that call may see — those are separate controls,
and Correlix treats them separately.

## Device telemetry — what we do *not* claim {#device-telemetry-what-we-do-not-claim}

Correlix receives telemetry from network devices we do not control, over
protocols whose security is fixed by their specifications:

| Protocol | What is true |
|---|---|
| **SNMPv3 (authPriv)** | Authenticated and encrypted **when you configure it**. Correlix supports it and can require it per device. |
| **SNMP v1/v2c** | Unauthenticated, cleartext. Community strings are not meaningful credentials. |
| **SNMP traps v1/v2c** | Spoofable. Correlix marks these as unauthenticated in the event record. |
| **Syslog over TLS (RFC 5425)** | Supported at the collector; an onboarding runbook covers device-side setup. Device-plane certificate *management* is not yet shipped. |
| **Syslog UDP/TCP 514** | Unauthenticated — the sending hostname is an unverified claim. Carry it on a management network. |
| **NetFlow / IPFIX / sFlow** | Unauthenticated UDP; the exporter address is spoofable. No in-protocol authenticity is possible. |
| **gNMI** | TLS-capable; an onboarding runbook covers verified certificates per target. Managed device certificate lifecycle is not yet shipped. |

Where a protocol cannot be authenticated, Correlix's answer is **honesty plus
containment**, on a deliberate hardening ladder:

1. **Today:** carry device telemetry on an isolated management network
   (management VLAN, source allowlists, IPsec/MACsec where available), and
   let Correlix label what arrives over unauthenticated transports so it is
   visible in the product. Telemetry from senders the deployment cannot
   attribute is quarantined encrypted rather than stored in the clear (see
   above).
2. **Where your devices support it:** move each protocol up its own rung —
   SNMPv3 authPriv, syslog over TLS, gNMI with verified certificates — using
   the per-protocol onboarding runbooks shipped with the product.
3. **Direction of travel:** managed device-side certificate lifecycle, so the
   device leg can be authenticated without per-device manual ceremony.

## Current coverage

| Path | State |
|---|---|
| Browser → Correlix | **HTTPS** (TLS 1.2/1.3, HSTS, forward secrecy) |
| nginx → API | **Mutual TLS** with peer-identity allowlisting |
| Internal CA + service identities | **Live** — short-lived certificates, automatic re-issue, wire-verified rotation |
| API → data stores | **TLS/mutually authenticated**; the stores refuse plaintext clients |
| Event bus | **TLS with authenticated clients** and default-deny access control |
| Telemetry pipeline (collectors → storage) | **TLS with per-lane credentials** between Correlix services |
| Application secrets at rest | **Encrypted**, per-tenant keys under a sealed root |
| Sensitive fields / unattributable telemetry | **Encrypted at the edge / quarantined encrypted** — when sealing is enabled |
| Tenant isolation | **Database-enforced**, test-guarded |
| Device → collector | **Protocol-dependent** — see above; not claimed |

The posture report is the source of truth for this table on any given
deployment: if a control is not satisfied there, it is not in effect,
regardless of what this page says.

## Answering a security questionnaire

Short answers you can give today, each of which stays true:

**"Is data encrypted in transit?"** Between Correlix-managed services, yes —
TLS with mutually authenticated, automatically rotated certificates from the
deployment's own certificate authority, verified on the wire and enforced
fail-closed. Browser access is HTTPS. Telemetry from your network devices is
secured according to what each protocol and device supports; Correlix labels
telemetry that arrives over unauthenticated transports, and quarantines
(encrypted) telemetry it cannot attribute to a tenant.

**"How is multi-tenancy enforced?"** In the database — row policies and
row-level security scope every query to the caller's tenant, with per-tenant
indices in the search store and role-based authorization in the API. Automated
tests fail the build if a tenant policy is written permissively.

**"What happens if security is misconfigured?"** A secured deployment refuses
to start and names the exact control, with a link to the remediation runbook.
There is no global override, and no plaintext fallback: a service that cannot
meet its security configuration stops, loudly, instead of degrading.

**"Are backups encrypted?"** That depends on the destination you provide.
Correlix requires an operator-provided encrypted volume or destination and
reports when it cannot verify one. We do not claim product-level backup
encryption.
