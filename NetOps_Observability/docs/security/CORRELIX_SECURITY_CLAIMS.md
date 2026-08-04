# Correlix Security Claims — what we may and may not say

**Status: owner-approved 2026-08-04.** This document governs marketing copy,
sales answers, security questionnaires, the product UI, and the docs portal.
If a claim is not listed as permitted here, it may not be made.

**The governing principle:** a security claim is a *promise about behavior*.
Every claim below is paired with the evidence that must exist before it is
spoken. A claim we cannot evidence is a claim we cannot make — and if a
customer later discovers the gap, we lose far more than the deal it won.

---

## 1. The approved statement (verbatim)

> "Correlix secures communications between Correlix-managed services and
> protects stored application secrets and tenant access boundaries. Security of
> telemetry between customer devices and collectors depends on the protocol and
> device configuration."

Use this sentence, or a subset of it, as the anchor for any security
conversation. It is deliberately precise about where our control ends.

---

## 2. Claims Correlix MAY make (once the evidence exists)

| # | Permitted claim | Evidence required before saying it |
|---|---|---|
| C1 | "Communications between Correlix-managed services are encrypted with TLS." | Every v1-covered path verified at BOTH ends; production validator enforcing; posture page showing `observed` (not merely `configured`) |
| C2 | "Service-to-service connections are mutually authenticated with certificates issued by the deployment's internal CA and rotated automatically." | mTLS live on v1 paths; SAN verification on; auto-reissue proven; a *wrong* identity proven rejected by test |
| C3 | "Browser traffic to Correlix is served over HTTPS with modern TLS." | Ingress TLS shipped + validator check + no plaintext listener published in production |
| C4 | "Application secrets are encrypted at rest with per-tenant keys, and production refuses to start if sealing is unavailable." | Sealing enforced in production profile; unseal-failure test; secrets absent from logs test |
| C5 | "Tenant data access is enforced in the database, not only in application code." | ClickHouse row policies + Postgres FORCE-RLS + the tests that fail when a policy is written leniently |
| C6 | "Correlix refuses to start in production when a required security control is missing or invalid, and tells you exactly which one." | Validator implemented, each prohibited configuration covered by a test asserting the specific error |
| C7 | "Correlix shows you its own security posture, and marks anything it cannot verify as unverified." | Posture page live, states distinguish configured / observed / unknown / failed / n-a / deferred |
| C8 | "Telemetry that arrives over unauthenticated protocols is labeled as such." | The labeling implemented end-to-end (note: this is NEW work — see errata E7) |

**Rule for all of the above: none may be spoken while the control is
`implemented but disabled`.** Built-and-off is not a security property.

---

## 3. Claims Correlix MUST NOT make

| # | Prohibited claim | Why it is false or unprovable |
|---|---|---|
| P1 | **"Correlix provides end-to-end encrypted telemetry."** *(explicitly prohibited by the owner)* | The device→collector leg is outside our control. NetFlow/sFlow/syslog-UDP/SNMPv2c cannot be authenticated at all |
| P2 | "All data at rest is encrypted." | Backup encryption is explicitly out of v1. Until backups are covered, this is false |
| P3 | "Correlix is compliant with SOC 2 / ISO 27001 / PCI / HIPAA." | A product is not compliant; an organization's *deployment* achieves compliance. We may say the product *supports controls required by* those frameworks |
| P4 | "Device telemetry is authenticated." | True only for SNMPv3 authPriv and only where the customer configured it. Never as a blanket statement |
| P5 | "Our internal network is secure because containers share a private Docker network." | Network topology is not authentication. Explicitly rejected as a design position |
| P6 | "TLS means access is authorized." | TLS authenticates a peer; authorization is row policies, RLS, ACLs and RBAC. Never conflate them |
| P7 | "Zero trust" as an unqualified product claim | Only defensible per-path, with evidence. Use the specific claim instead |
| P8 | "Encryption is available as a premium upgrade." | Base-product security is included by decision. Withholding it would be both a bad-faith and a competitively fatal position |
| P9 | Any claim about a control that is `implemented but disabled` | Built ≠ enforced. This is the single easiest way to make an untrue statement in good faith |

---

## 4. Customer security-questionnaire language

Copy-paste answers. Each is honest under the current state and remains honest
after v1 ships.

**"Is data encrypted in transit?"**
> Between Correlix-managed services, yes — TLS with mutually authenticated
> certificates issued by the deployment's internal CA and rotated
> automatically. Browser access is HTTPS. Telemetry sent from your network
> devices to our collectors is secured according to what each protocol and
> device supports: SNMPv3 with authPriv and syslog over TLS are supported where
> your devices offer them, while NetFlow, sFlow and classic syslog are
> unauthenticated by protocol design and should be carried on a management
> network. Correlix labels telemetry that arrives over unauthenticated
> transports so you can see exactly what is and is not authenticated.

**"Is data encrypted at rest?"**
> Application secrets are encrypted with per-tenant keys under a sealed root
> key. Datastore volume encryption and backup encryption are the responsibility
> of the deployment environment — Correlix requires an operator-provided
> encrypted volume or destination for backups and reports when that cannot be
> verified. We do not claim product-level backup encryption.

**"How is multi-tenancy enforced?"**
> In the database, not only in application code: ClickHouse row policies and
> PostgreSQL row-level security scope every query to the caller's tenant, with
> per-tenant indices in the search store, plus role-based authorization in the
> API. Automated tests fail the build if a tenant policy is written permissively.

**"How do services authenticate to each other?"**
> With X.509 certificates carrying SPIFFE-style workload identities, issued by
> the deployment's internal certificate authority, short-lived and rotated
> automatically. Peer identities are allowlisted per connection; hostname and
> SAN verification are mandatory and cannot be disabled in production.

**"What happens if security is misconfigured?"**
> Production refuses to start and names the exact control, component,
> configuration source, observed value and required value, with a link to the
> remediation runbook. There is no global override switch. Emergency exceptions
> are narrow, owned, justified, audited, time-bounded and expire automatically.

**"Do you support customer-managed keys / HSM?"**
> Not in the base product today. It is on the roadmap as a commercial
> capability; the key hierarchy is designed to accommodate an external KMS or
> HSM without changing the application.

---

## 5. Device-telemetry limitations (say these plainly)

| Protocol | What we can honestly say |
|---|---|
| SNMPv3 (authPriv) | Authenticated and encrypted by the protocol, **when the customer configures it**. Correlix supports and can require it per device |
| SNMPv1/v2c | **Unauthenticated and cleartext.** Community strings are not credentials in any meaningful sense |
| SNMP traps v1/v2c | **Spoofable.** Correlix already marks these as unauthenticated in the event record |
| Syslog over TLS (RFC 5425) | Supportable — device-plane work is deferred; do not imply it ships today |
| Syslog UDP/TCP 514 | **Unauthenticated; the hostname is an unverified claim.** Carry on a management network |
| NetFlow / IPFIX / sFlow | **Unauthenticated UDP; the exporter address is spoofable.** No cryptographic authenticity is possible in-protocol |
| gNMI | TLS-capable; certificate lifecycle management is deferred. Do not claim managed device certificates |

---

## 6. Backup limitations (say these plainly)

- Correlix does **not** provide backup-specific encryption with its own key
  domain in v1. It is a known, documented, deferred gap.
- Production backups must target an **operator-provided encrypted volume or
  destination**; Correlix reports when encryption cannot be verified rather
  than silently writing to an unencrypted target.
- Backup keys, when built, will be **separate from live service credentials and
  from the transport PKI**. That separation is designed, not implemented.
- Therefore: **never answer "yes" to "are backups encrypted?"** on our behalf.
  The correct answer is that it depends on the destination the operator
  provides, and Correlix surfaces the verification state.

---

## 7. Review rule

Any new security claim — in a deck, a datasheet, the UI, the docs portal, or a
questionnaire response — must be added to §2 with its evidence requirement
before it is used externally. If it cannot be evidenced from the repository or
a live posture reading, it does not ship.
