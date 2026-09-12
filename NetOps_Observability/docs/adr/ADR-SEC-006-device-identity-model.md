# ADR-SEC-006 — Device identity: certificates for capable peers, per-device PSK for constrained ones

- **Status:** **Proposed — design accepted in principle, IMPLEMENTATION DEFERRED
  TO PHASE 2 (owner, 2026-08-04).** This ADR remains the design of record for
  device identity (HLD §11 open decision #1, "certificates vs PSK vs both" —
  recommendation: **both**), and it is **not** built in v1.
- **The v1 answer for devices (owner decision, 2026-08-04)** — no device PKI is
  constructed; instead:
  1. **Protocol-native security wherever the protocol already provides it** —
     SNMPv3 `authPriv` (the credential store already models and validates it:
     `src/backend/internal/snmpcred/store.go:28,121-138`), device SSH, and the
     existing per-connector webhook HMAC.
  2. **Honest labeling everywhere it does not** — `transport_authenticated=false`
     stamped on every event from an unauthenticated lane (the SNMP trap path
     already does exactly this: `src/backend/collectors/snmptrap.go:60`), and a
     declared plaintext exception with an owner and an expiry in the
     transport-policy table (ADR-SEC-001).
  3. **Network segmentation as the real control** for the protocols that cannot
     be fixed — dedicated telemetry VLAN/interface, source allowlists, rate
     limiting (HLD §6.6).
- **Why deferral is the right call for v1:** device PKI is the only part of this
  programme whose cost lands on **the customer's** hardware and change process.
  v1's customer-facing claim is scoped precisely — *every Correlix component
  communicates over TLS* — and that claim is fully deliverable without touching
  a single router. Phase 2 extends it to the device edge, where the honest
  statement becomes *"secure lanes are available and these devices are on them."*
- **Do not thin this ADR when Phase 2 starts:** the certificate-vs-PSK analysis,
  the tenant-in-identity binding rule and the rejected alternatives below are the
  design that Phase 2 executes.
- **Implementation state:** **nothing implemented.** No device certificate is
  ever issued: `src/backend/tls_ca.go:140-156` mints exactly two identities,
  `api` and `nginx`. There is no device trust domain, no device enrolment, no
  RFC 5425 syslog lane, no STAMP authenticated mode. What *does* exist is the
  per-device credential store for SNMPv3
  (`src/backend/internal/snmpcred/store.go`) and the tenancy-resolution
  machinery that a certificate binding would replace.
- **Relates to:** HLD §6.2, §6.6, §7 (device rows), §9 phase 5, §11.1;
  ADR-SEC-002 (device trust domain); ADR-SEC-001 (`protocol_native` mode);
  `docs/runbooks/security/rotate-device-ca.md`,
  `syslog-tls-onboarding.md`, `gnmi-certificate-onboarding.md`.

---

## Context

**Devices are the least-trusted peers Correlix has, and today none of them is
authenticated.** HLD §4 boundary ① classifies the customer estate as untrusted
and unauthenticated by default; the code agrees, in its own comments:

- **Syslog:** `deployment/docker/syslog-ng/syslog-ng.conf:84-85` listens on
  UDP+TCP/514, and `:42-43` states plainly that this source has "NO ACL and NO
  authentication: the hostname is an UNVERIFIED CLAIM by whoever sent the
  packet."
- **Flows:** goflow2 receives NetFlow/IPFIX/sFlow over UDP
  (`deployment/docker/goflow2/goflow2.yaml`). The exporter address is spoofable
  and the protocol has no authentication at all.
- **SNMP traps:** the event record carries `Authenticated bool` and stamps
  v1/v2c false because they are spoofable
  (`src/backend/collectors/snmptrap.go:60`) — correct honesty. But an *unknown*
  v3 sender is accepted rather than rejected: a verified **fail-open**
  (`docs/design/transport-encryption-2026-08-04.md` §2.3).
- **gNMI:** `deployment/docker/gnmic/gnmic.yaml:13` sets `skip-verify: true`
  globally and five targets set `insecure: true` (`:30,35,40,45,50`) — Correlix
  does not verify the device, and on those five targets does not encrypt at all.
- **STAMP:** `src/backend/collectors/stamp.go:18,31,37,54,76,111` implements RFC
  8762 **unauthenticated mode** throughout. RFC 8762 defines an authenticated
  mode (HMAC-SHA-256 with a per-peer key) — it is an empty slot, not a missing
  capability.
- **Remote vantage:** posts to the API with a shared API key (HLD §7 row), so
  any holder can publish as any vantage.

Because nothing authenticates the device, **tenancy is resolved from a
spoofable claim.** Vector's transforms look up the sender in a CSV enrichment
table exported by the API from its own inventory
(`deployment/docker/vector/vector.yaml:64-69`, lookups at `:409,469,576,593`;
`:391` states "the ONLY authority on tenancy is device_tenant.csv"). That design
is *good* — tenancy is re-derived server-side from inventory rather than trusted
from the payload — but its input key is a hostname or a source address, which
the device supplies.

Two facts constrain any fix:

1. **Most field devices cannot do mTLS.** A large installed base speaks SNMPv3
   and syslog and nothing else; requiring client certificates on them would mean
   simply not collecting from them.
2. **Some already have a per-peer secret model that works.** SNMPv3 USM is
   exactly a per-device credential with a security level, and Correlix already
   stores and validates it: `internal/snmpcred/store.go:28` defines
   `noAuthNoPriv|authNoPriv|authPriv`, `:121-138` validates the level and
   requires a privacy key for `authPriv`, and `sentinel.go:139` carries the level
   onto the poll target. What is missing is not the credential — it is a
   *policy* that rejects a peer arriving below its declared level.

## Decision (design of record — Phase 2 implementation)

**Adopt a two-mechanism device identity model in a single, separate device trust
domain: X.509 certificates for peers capable of them, and per-device pre-shared
keys for peers that are not. Both are first-class; neither is a fallback for a
failed attempt at the other.**

> **v1 status of this decision (owner, 2026-08-04):** *designed, not built.* In
> v1, every device row in the transport-policy table is populated with the
> mechanism it uses **today** — `protocol_native` + `min_level: authPriv` where
> SNMPv3 provides it, and `accept: [plaintext]` with a mandatory expiring
> exception everywhere else. The two-mechanism model below is what Phase 2
> migrates those rows onto. Nothing in v1 issues a device certificate or a
> Correlix-generated PSK.
>
> **The one v1 enforcement change worth taking early** is the SNMPv3 trap
> fail-open (see Context): rejecting an unknown v3 sender needs no PKI, no new
> credential and no customer action — only the rejection branch that is missing
> today. It is called out in "Migration implications" §4 as the cheapest first
> step and it can land inside v1 without opening Phase 2.

### 1. Two mechanisms, chosen per peer by capability

| Mechanism | Applies to | Policy expression (ADR-SEC-001) |
|---|---|---|
| **Certificate** | RFC 5425 syslog-over-TLS senders, gNMI targets, remote vantages, future site gateways | `outbound/accept: mtls`, identity = device SPIFFE URI SAN |
| **Per-device PSK** | SNMPv3 USM (auth/priv keys), STAMP authenticated mode (RFC 8762 HMAC-SHA-256), any peer with a shared-secret-only protocol | `mode: protocol_native` + `min_level` (e.g. `authPriv`) |
| **Neither possible** | NetFlow/IPFIX/sFlow, syslog UDP/514, SNMPv2c, TACACS+ | `accept: [plaintext]` **with a mandatory exception** (owner, reason, expiry) + segmentation + `transport_authenticated=false` stamped on every event |

The third row is not a loophole — it is HLD §6.6's honesty clause made
enforceable. **No claim of cryptographic authenticity may be made in the UI,
docs, or evidence chains for those peers.**

### 2. Device identity format carries the tenant

```
spiffe://correlix.device/tenant/<tenant_id>/kind/<device|vantage|gateway>/id/<device_id>
```

(HLD §6.2.) The tenant is *inside* the identity so that a secure syslog lane can
bind tenancy to the certificate instead of to a hostname string.

### 3. The binding rule — the most important sentence in this ADR

**A device identity is a *claim to be checked*, never an authorization grant, and
never an act of provisioning.**

- On connection, the presented tenant is **checked against the registered device
  record**. A mismatch is **rejected** and audited.
- An identity naming a tenant that does not exist is **rejected**. It does
  **not** create the tenant. It does not create the device.
- An identity naming a device that is not registered is **rejected**. Enrolment
  is an explicit administrative act, out of band from data ingestion.
- Transport identity still does not authorize data access: tenant scoping of
  *queries* remains at the data layer (ClickHouse row policies, PG FORCE-RLS,
  per-tenant OpenSearch indices). HLD §4 design law is unchanged.

Rationale: auto-creation on first sight would let anyone holding a mis-issued or
stolen device certificate mint tenants or devices, converting an authentication
control into a provisioning API. Root `CLAUDE.md` §3a.2 already forbids taking
the tenant from the request body; taking it unchecked from a certificate is the
same defect wearing a better costume.

### 4. Certificates and PSKs share the same policy object and the same audit trail

Both are `identity_ref` values on the per-peer transport policy (ADR-SEC-001).
"Show me every peer authenticated by PSK whose key is older than 90 days" and
"show me every peer with no authentication and a declared exception" must be the
same query against the same table.

### 5. Custody

Device PSKs (SNMPv3 auth/priv keys, STAMP keys) are **sealed** through the
existing envelope layer: per-tenant DEK, AAD binding
(`docs/design/secret-custody.md` §3–§4; SNMP credentials are already wired
through it — `secret-custody.md` §7 phase 1c ✅). Device *private keys* stay on
the device and are never held by Correlix; Correlix holds only the issued
certificate and the CA.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| **Certificates only** | Cleanest identity model and the one the platform already mints. Rejected because it excludes the majority of the installed base: a device that speaks only SNMPv3 or syslog/514 would become uncollectable, which converts a security control into a functionality regression. HLD §11.1 names this cost explicitly. |
| **PSK only** (Zabbix-style, no device PKI) | Genuinely simpler to deploy on constrained peers and it is why Zabbix ships PSKs at all (`transport-encryption-2026-08-04.md` §1.5). Rejected as the sole mechanism: it gives no chain of trust, no expiry, no revocation short of rotation, and it forfeits the SPIFFE identity Correlix already mints for the peers that *can* do certificates (syslog-TLS, gNMI, vantages). |
| **Reuse the workload trust domain for devices** | Rejected in ADR-SEC-002: a device certificate lives in an untrusted customer estate; sharing a root with `api`/`correlation` makes device compromise a service-impersonation path. |
| **IP allowlisting as the device identity** | Spoofable on UDP by construction. Retained as a *supplement* for the protocols with no alternative (flow exporters, syslog/514) and explicitly not accepted as identity. HLD §10 lists it as rejected-as-sole-control. |
| **Hostname/`sysName` as identity** (status quo) | This is precisely what `syslog-ng.conf:42-43` describes as an unverified claim. It is the current behaviour and the thing being fixed. |
| **Shared tenant-wide device credentials** (one SNMPv3 user per tenant) | Blast radius = every device in the tenant; a single compromised switch yields the credential for all of them. HLD §10 rejects it; per-device or per-group only. |
| **Auto-enrol on first sight (TOFU)** | Operationally attractive at 4 000 devices, and fatal: it makes the first packet from an attacker a provisioning event. Explicitly forbidden by decision 3. A *staged* enrolment queue ("unknown device seen, pending approval") is the acceptable form of the same convenience — see U4. |
| **Device certificates without tenant in the SAN**, tenant looked up from inventory | Workable, and arguably purer (identity ≠ authorization). Rejected because the whole value of the secure syslog lane is binding tenancy to something unspoofable at the moment of connection; the check-against-inventory rule in decision 3 preserves the purity anyway. |

## Consequences

**Positive**
- **Extends the "everything over TLS" claim to the device edge** — the one place
  v1 cannot reach. After Phase 2 the statement becomes checkable per device
  rather than per component, which is the difference between "our platform is
  encrypted" and "your telemetry is authenticated".
- Secure lanes get real, unspoofable tenancy binding — the single largest
  integrity improvement available to the ingestion plane (T1, T2, T7).
- Constrained devices are not excluded, so the control can actually be deployed
  rather than perpetually exempted.
- The known SNMPv3 trap fail-open acquires a rejection rule and an owner.
- Legacy plaintext peers become *declared, owned, expiring* rather than silently
  normal.

**Negative**
- **Two credential lifecycles.** Certificate issuance/renewal/revocation *and*
  PSK generation/distribution/rotation, with different tooling, different
  failure modes and different runbooks. This is the cost HLD §11.1 flags and it
  is real.
- **Device onboarding becomes a customer-facing workflow.** Someone must install
  a certificate or a key on the device — often via the customer's own change
  process, on hardware Correlix does not control.
- **PSK sprawl is a genuine risk.** Per-device secrets are only better than one
  shared token *if they are rotatable and revocable at scale*
  (`transport-encryption-2026-08-04.md` §7 R4). Without the lifecycle tooling we
  will have built a larger `INGEST_TOKEN` problem, not a smaller one.
- **Enforcement can blind the platform** (R1): requiring `authPriv` on a device
  that cannot do it stops collection. Mitigated by observation-before-enforcement
  and by surfacing `policy_blocked` as distinct from `down`.
- **Discovery interacts badly** (R3): SNMP discovery speaks plaintext; a peer
  that refuses it may become undiscoverable.

## Security implications

- **Mitigates T1** (telemetry spoofing), **T2** (device impersonation),
  **T7** (forged `tenant_id`) and **T8** (replay — via SNMPv3 engine boots/time
  and STAMP authenticated mode). T1/T2 are both HIGH today.
- **Closes the trap fail-open**: unknown sender or below-`min_level` → drop +
  `trap_policy_rejected{reason}` + audit.
- **Does not fix flows or syslog/514.** Those remain unauthenticated by protocol
  design; the controls are network-layer (dedicated telemetry VLAN/interface,
  source allowlists, rate limiting) plus a stamped `transport_authenticated=false`
  and a visible, expiring exception. Stating that honestly *is* the control —
  the alternative is a false assurance in an evidence chain.
- **Cross-tenant risk if the binding rule is weakened.** If the certificate's
  tenant were trusted without the inventory check, a mis-issued device
  certificate would place another tenant's telemetry into the wrong tenant's
  index — a cross-tenant write. Decision 3 is therefore a hard requirement, and
  the feature ships with an isolation test in the shape of
  `org_isolation_test.go` (root `CLAUDE.md` §3a.5).
- **PSK compromise has no expiry.** Unlike a 24 h SVID, a leaked SNMPv3 priv key
  is valid until someone rotates it. Rotation cadence is a control, not hygiene.

## Operational implications

- **Two runbooks minimum**, both currently pending implementation:
  `docs/runbooks/security/rotate-device-ca.md` and the per-lane onboarding
  outlines (`syslog-tls-onboarding.md`, `gnmi-certificate-onboarding.md`).
- **The device CA rotates independently** of the workload CA — different
  cadence, different blast radius, different customer coordination.
- **Legacy lanes must be marked, counted and aged**, not merely tolerated:
  a metric of unauthenticated peers per tenant and an exception-ageing report.
- **`gnmic.yaml`'s global `skip-verify: true` must become a per-target declared
  exception**, not a default. Production must refuse `insecure: true` outright
  (HLD §7 gnmic row).
- **Vector's `device_tenant.csv` remains the inventory authority** for legacy
  lanes; on secure lanes the certificate binding supersedes it. Both paths must
  agree, and a disagreement is an alertable condition rather than a silent
  precedence rule.

## Migration implications

1. **Phase 5 of the roadmap** (HLD §9), dependent on phases 2 (PKI) and 3
   (Kafka). Nothing here can start before the device trust domain exists.
2. **Legacy lanes stay up throughout**, marked unauthenticated with an expiry.
   Devices move one at a time onto the secure lane; the accept-set widening →
   verify → narrow sequence is per-device.
3. **Enrolment must precede enforcement.** A device that is not registered is
   rejected once enforcement is on — so the inventory must be complete and
   correct *before* the narrowing, or collection stops for anything missed.
4. **SNMPv3 `min_level` is the cheapest first step** and needs no PKI at all:
   the credential store already validates levels
   (`internal/snmpcred/store.go:121-138`); only the *rejection* is missing.
   Recommended as the first enforcement point after the trap fail-open.
5. **STAMP authenticated mode is additive** — the current unauthenticated
   implementation (`collectors/stamp.go`) stays for peers that do not support
   the authenticated mode, as a declared exception.

## Unresolved questions

- **PARTIALLY RESOLVED (owner, 2026-08-04):** device PKI is **deferred to Phase
  2**; v1 = protocol-native security + honest labeling + segmentation. The
  cert-vs-PSK question below stays open for Phase 2.
- **U1 — Certificates, PSK, or both?** HLD §11.1. Recommendation stands at
  **both**; ratification needed when Phase 2 opens, not before.
- **U2 — Who runs device enrolment?** A Correlix UI workflow, an API for the
  customer's provisioning system, or a manual CSV import? Nothing exists.
- **U3 — Device certificate TTL.** 24 h is impossible on field hardware with a
  manual install; a year is a revocation problem. No value proposed anywhere.
- **U4 — Is a staged "pending approval" queue for unknown devices acceptable**,
  or does that reintroduce TOFU by the back door?
- **U5 — Revocation for devices.** Short TTL is not available (U3), so CRL/OCSP
  or an explicit denylist is needed — the first place in the design where the
  "revocation by expiry" model breaks. See
  `docs/runbooks/security/revoke-compromised-identity.md`.
- **U6 — Legacy lane sunset policy and default exception expiry.** HLD §11.5
  recommends 90 days; owner unassigned.
- **U7 — Does a site-gateway/collector-at-customer-premises exist** (HLD §4
  boundary ②)? If so it is a third device kind with its own trust posture, and
  it is only named, never designed.
- **U8 — Multi-tenant devices.** A shared MSP switch reporting for several
  tenants has one certificate and one tenant field. Unaddressed by the identity
  format.
