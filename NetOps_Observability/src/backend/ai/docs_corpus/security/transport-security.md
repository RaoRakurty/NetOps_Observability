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

## How service-to-service security works

Correlix issues every one of its own services a short-lived X.509 identity from
a certificate authority created inside your deployment. Services then
authenticate **each other** — not just encrypt.

```
browser ──HTTPS──▶ nginx ──mutual TLS──▶ API ──▶ tenant-scoped data access
                     │                    │
              public/enterprise      internal CA (per deployment),
                 certificate         24-hour identities, auto-rotated
```

**Workload identity.** Each service receives a SPIFFE-style identity such as
`spiffe://netops/ns/default/sa/api`, carried as a URI SAN in its certificate.
The certificate is minted at boot, valid for 24 hours, and re-issued
automatically at half-life — so a compromised certificate expires on its own,
and there is no manual rotation to forget.

**Authentication *and* authorization.** Encryption alone is not a boundary. The
API allowlists the exact peer identity permitted to call it, so a certificate
issued by the same authority *to a different service* is rejected. Hostname and
SAN verification are mandatory and cannot be disabled in a production profile.

**The certificate authority's key is sealed.** The CA root is a long-lived
credential that could mint an identity for any service, so it is encrypted at
rest under a sealed key. If sealing is unavailable, **Correlix refuses to create
the CA at all** rather than write that key in cleartext.

## Data at rest

Application secrets — integration credentials, SNMP credentials, API tokens —
are encrypted with per-tenant keys under a sealed root key (AES-256-GCM). Secret
values are write-only through the API: once saved they are never returned, never
logged, and never sent back to the browser.

**Backups are the operator's responsibility.** Correlix does not provide
backup-specific encryption with its own key domain. Production deployments must
target an operator-provided encrypted volume or destination, and Correlix
reports when it cannot verify that. We therefore do **not** claim "all data at
rest is encrypted."

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

## Production refuses to start when it is not secure

Correlix ships a security validator that runs at startup, in CI, and on demand.
In a production profile, any unsatisfied control **aborts the boot** with a
message naming the exact control, the component, where the value came from, what
was observed, what is required, and how to fix it.

There is **no global override**. A deployment that needs an exception makes it
narrow, owned and expiring at the level of the individual control — never by
switching the validator off.

Lower profiles (`lab`, `development`, `staging`) report the same findings without
blocking, so operators can see exactly what production will refuse **before**
they get there.

## Seeing it for yourself

Platform administrators can read the live posture at
`GET /admin/security/posture`, which returns the validator's structured output:
every control, its state, and what remains. The posture page renders that report
directly — the interface never computes "secure" on its own, and anything it
cannot verify at runtime is shown as **unverified** rather than assumed green.

## Device telemetry — what we do *not* claim

Correlix receives telemetry from network devices we do not control, over
protocols whose security is fixed by their specifications:

| Protocol | What is true |
|---|---|
| **SNMPv3 (authPriv)** | Authenticated and encrypted **when you configure it**. Correlix supports it and can require it per device. |
| **SNMP v1/v2c** | Unauthenticated, cleartext. Community strings are not meaningful credentials. |
| **SNMP traps v1/v2c** | Spoofable. Correlix marks these as unauthenticated in the event record. |
| **Syslog over TLS (RFC 5425)** | Supported direction of travel; device-plane certificate management is not yet shipped. |
| **Syslog UDP/TCP 514** | Unauthenticated — the sending hostname is an unverified claim. Carry it on a management network. |
| **NetFlow / IPFIX / sFlow** | Unauthenticated UDP; the exporter address is spoofable. No in-protocol authenticity is possible. |
| **gNMI** | TLS-capable; managed device certificate lifecycle is not yet shipped. |

Where a protocol cannot be authenticated, Correlix's answer is **honesty plus
containment**: label the telemetry as unauthenticated so it is visible in the
product, and recommend network-level controls (management VLAN, source
allowlists, IPsec/MACsec) rather than implying cryptographic guarantees that do
not exist.

## Current coverage

| Path | State |
|---|---|
| Browser → Correlix | **HTTPS** (TLS 1.2/1.3, HSTS, forward secrecy) |
| nginx → API | **Mutual TLS** with peer-identity allowlisting |
| Internal CA + service identities | **Live**, 24-hour certificates, automatic rotation |
| Application secrets at rest | **Encrypted**, per-tenant keys under a sealed root |
| Tenant isolation | **Database-enforced**, test-guarded |
| API → data stores | **In progress** — the validator reports each remaining hop |
| Event bus (Kafka) | **In progress** — separately scheduled |
| Device → collector | **Protocol-dependent** — see above; not claimed |

The validator is the source of truth for this table on any given deployment: if
a control is not satisfied there, it is not in effect, regardless of what this
page says.

## Answering a security questionnaire

Short answers you can give today, each of which stays true:

**"Is data encrypted in transit?"** Between Correlix-managed services, yes —
TLS with mutually authenticated, automatically rotated certificates from the
deployment's own certificate authority. Browser access is HTTPS. Telemetry from
your network devices is secured according to what each protocol and device
supports; Correlix labels telemetry that arrives over unauthenticated transports.

**"How is multi-tenancy enforced?"** In the database — row policies and
row-level security scope every query to the caller's tenant, with per-tenant
indices in the search store and role-based authorization in the API. Automated
tests fail the build if a tenant policy is written permissively.

**"What happens if security is misconfigured?"** Production refuses to start and
names the exact control, with a link to the remediation runbook. There is no
global override.

**"Are backups encrypted?"** That depends on the destination you provide.
Correlix requires an operator-provided encrypted volume or destination and
reports when it cannot verify one. We do not claim product-level backup
encryption.
