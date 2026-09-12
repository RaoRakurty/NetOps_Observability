---
title: What Correlix secures, and what it does not
sidebar_label: Security claims
description: The claims a Correlix deployment can stand behind on the wire, the limits stated as plainly as the guarantees, and short answers for a security questionnaire.
page_type: concept
sidebar_position: 16
---

# What Correlix secures, and what it does not

Every claim on this page can be demonstrated on a running deployment. The limits
are stated as plainly as the guarantees, because a security page nobody can
stand behind is worse than no page at all.

The claim, precisely:

> Correlix secures communication between Correlix-managed services and protects
> stored application secrets and tenant access boundaries. Security of telemetry
> between your devices and the collectors depends on the protocol and on the
> device configuration.

Correlix deliberately does not claim end-to-end encrypted telemetry. See
[Device telemetry](#device-telemetry-what-we-do-not-claim).

## One choice, made at install time

Transport security is selected when the deployment is installed, as a single
installer option, and that secured configuration is the shape this page
describes. A plaintext variant exists for isolated labs and evaluation, and it
makes none of the claims below.

Once a deployment is installed secured, there is no supported way to partially
disable the mesh. The controls below are enforced by the software, not by
operator discipline.

See [Enable TLS and mTLS](/deploy/enable-tls) for the procedure.

## Between Correlix services

Every Correlix-managed service (the API, the datastores, the event bus, the
telemetry pipeline and the correlation engine) receives its own short-lived
X.509 identity from a certificate authority created inside your deployment. Services
then authenticate each other rather than only encrypting.

```text
browser ──HTTPS──▶ nginx ──mutual TLS──▶ API ──mutual TLS──▶ datastores, bus,
                     │                    │                   pipeline, engine
              public or enterprise   internal CA (per deployment),
                 certificate         short-lived identities, auto-rotated
```

**Workload identity.** Each service carries a SPIFFE-style identity such as
`spiffe://netops/ns/default/sa/api` in its certificate. A connection verifies
the peer's specific identity, so a certificate issued by the same authority to a
different service is rejected, and that rejection is counted and observable.
Encryption alone is not treated as a boundary.

**This holds on the wire, not only in configuration.** Every in-scope
service-to-service path has been verified encrypted, every served identity
checked at the endpoint, and the negative cases demonstrated to be refused: no
certificate, wrong identity, stolen credential, anonymous access.

**The certificate authority's key is sealed.** The root could mint an identity
for any service, so it is encrypted at rest under a sealed key. If sealing is
unavailable, Correlix refuses to create the authority at all rather than write
that key in cleartext.

## What a secured deployment refuses to do

There is no plaintext fallback. A secured deployment fails closed.

- A service whose certificate material is missing or unreadable **refuses to
  start**, with an error naming exactly what is missing, rather than starting
  unencrypted.
- The datastores **refuse plaintext clients at the server**. A database client
  that does not speak TLS is rejected before authentication, so no password
  crosses the wire in the clear even from a misconfigured client.
- The telemetry pipeline **refuses to load** if the keys protecting sensitive
  fields cannot be fetched, rather than running with the protection silently
  absent.
- A production profile **refuses to boot** on any unsatisfied security control,
  with a message naming the control, what was observed, what is required and how
  to fix it. There is no global override. Exceptions are narrow, owned and
  expiring, never a switch that turns the validator off.

## Certificate rotation

Certificate lifecycle needs no manual work and no calendar entries.

- Identities are minted at startup and re-issued automatically at half-life, so
  a compromised certificate ages out on its own.
- A scheduled job pushes fresh certificates into every service, including those
  that load certificates only at startup, then **verifies on the wire** that
  every endpoint serves the current certificate and fails loudly if one does
  not.
- An independent prober watches what each endpoint **actually serves**, not what
  sits on disk, and raises an alert well before expiry could affect a client.

## Reading the posture yourself

A platform administrator reads the live posture at
`GET /admin/security/posture`. The report separates what is **configured** from
what is **observed** on the wire, and anything the platform cannot verify at
runtime is reported **unverified**, never assumed green. The Transport Security
page renders that report directly; the console never computes "secure" on its
own.

See [Review transport security posture](/security/transport-security).

## Sensitive fields and unattributable telemetry

Two further protections apply when sealing is enabled.

**Sealed fields.** Designated sensitive values are encrypted per tenant at the
edge of the pipeline, stored only as ciphertext, and revealed only through an
audited endpoint behind a dedicated permission. Every reveal records who, why
and in what context. It never records the value.

**Unattributable telemetry is quarantined, not stored in the clear.** Telemetry
sometimes arrives from a sender the deployment cannot yet map to a tenant: a
device that is not in the inventory, or an unknown sender. Rather than storing
such an event as plaintext in a shared location, Correlix encrypts the whole
event under a dedicated key, stores only non-identifying metadata beside it, and
keeps it in an operator-only quarantine that no tenant-facing query path can
reach. Quarantined events have bounded retention, and recovery is an audited
workflow: once the device is assigned to a tenant, a platform operator holding
the reveal permission can restore the events into that tenant's data, and every
restore leaves an audit record.

Attribution failure never silently becomes a confidentiality downgrade.

## Data at rest

Application secrets (integration credentials, SNMP credentials and API tokens)
are encrypted with per-tenant keys under a sealed root key. Secret values are
write-only through the API: once saved they are never returned, never logged and
never sent back to the browser.

**Backups are the operator's responsibility.** Correlix does not provide
backup-specific encryption with its own key domain. A production deployment
targets an operator-provided encrypted volume or destination, and Correlix
reports when it cannot verify one. Correlix therefore does not claim that all
data at rest is encrypted.

## Tenant isolation is enforced in the database

This is worth stating separately, because it is independent of transport
security and stronger than it.

- ClickHouse row policies and PostgreSQL row-level security scope every query to
  the caller's tenant **in the database**, not only in application code.
- The search tier uses per-tenant indices with server-side filters.
- Automated tests fail the build if a tenant policy is written permissively.

A mutually authenticated connection proves *which service* is calling. It never
decides *which tenant's data* that call may see. Correlix treats those as
separate controls.

## Device telemetry {#device-telemetry-what-we-do-not-claim}

Correlix receives telemetry from network devices it does not control, over
protocols whose security is fixed by their specifications.

| Protocol | What is true |
|---|---|
| SNMPv3 (authPriv) | Authenticated and encrypted **when you configure it**. Correlix supports it and can require it per device. |
| SNMP v1 and v2c | Unauthenticated, cleartext. A community string is not a meaningful credential. |
| SNMP traps v1 and v2c | Spoofable. Correlix marks these as unauthenticated in the event record. |
| Syslog over TLS (RFC 5425) | Supported at the collector. Device-side certificate management is not shipped. |
| Syslog over UDP or TCP 514 | Unauthenticated. The sending hostname is an unverified claim. Carry it on a management network. |
| NetFlow, IPFIX, sFlow | Unauthenticated UDP. The exporter address is spoofable, and no in-protocol authenticity is possible. |
| gNMI | TLS-capable, with verified certificates per target. Managed device certificate lifecycle is not shipped. |

Where a protocol cannot be authenticated, the answer is honesty plus
containment, on a deliberate ladder.

1. **Today.** Carry device telemetry on an isolated management network:
   management VLAN, source allowlists, IPsec or MACsec where available. Correlix
   labels what arrives over an unauthenticated transport so it is visible in the
   product, and quarantines encrypted anything it cannot attribute.
2. **Where your devices support it.** Move each protocol up its own rung: SNMPv3
   authPriv, syslog over TLS, gNMI with verified certificates.
3. **Direction of travel.** Managed device-side certificate lifecycle, so the
   device leg can be authenticated without per-device manual ceremony.

## Current coverage

| Path | State |
|---|---|
| Browser to Correlix | HTTPS, TLS 1.2 and 1.3, HSTS, forward secrecy |
| Web tier to API | Mutual TLS with peer-identity allowlisting |
| Internal authority and service identities | Live. Short-lived certificates, automatic re-issue, wire-verified rotation |
| API to datastores | TLS, mutually authenticated. The stores refuse plaintext clients |
| Event bus | TLS with authenticated clients and default-deny access control |
| Telemetry pipeline between Correlix services | TLS with per-lane credentials |
| Application secrets at rest | Encrypted, per-tenant keys under a sealed root |
| Sensitive fields and unattributable telemetry | Encrypted at the edge, or quarantined encrypted, when sealing is enabled |
| Tenant isolation | Database-enforced, test-guarded |
| Device to collector | Protocol-dependent. Not claimed |

The posture report is the source of truth for this table on any given
deployment. If a control is not satisfied there, it is not in effect, whatever
this page says.

## Short answers for a security questionnaire

**Is data encrypted in transit?** Between Correlix-managed services, yes: TLS
with mutually authenticated, automatically rotated certificates from the
deployment's own authority, verified on the wire and enforced fail-closed.
Browser access is HTTPS. Telemetry from your network devices is secured
according to what each protocol and device supports. Correlix labels telemetry
that arrives over an unauthenticated transport, and quarantines encrypted
telemetry it cannot attribute to a tenant.

**How is multi-tenancy enforced?** In the database. Row policies and row-level
security scope every query to the caller's tenant, with per-tenant indices in
the search tier and role-based authorization in the API. Automated tests fail
the build if a tenant policy is written permissively.

**What happens if security is misconfigured?** A secured deployment refuses to
start and names the exact control. There is no global override and no plaintext
fallback: a service that cannot meet its security configuration stops, loudly,
instead of degrading.

**Are backups encrypted?** That depends on the destination you provide.
Correlix requires an operator-provided encrypted volume or destination and
reports when it cannot verify one. Correlix does not claim product-level backup
encryption.

## Related

- [Review transport security posture](/security/transport-security)
- [Enable TLS and mTLS](/deploy/enable-tls)
- [Review sensitive-data access](/administration/sensitive-data-access)
- [Tenants and organizations](/administration/tenants-orgs)
