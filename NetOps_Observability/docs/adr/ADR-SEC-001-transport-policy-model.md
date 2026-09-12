# ADR-SEC-001 — Transport policy model: per-peer outbound mode + inbound accept-set

- **Status:** **Accepted (owner, 2026-08-04)** — the model is adopted as
  designed. **v1 scope is bounded by owner decision: the policy object applies
  to INTRA-STACK and INGRESS paths only.** Device paths (syslog/flows/SNMP/gNMI/
  STAMP) are represented in v1 as *declared plaintext with an exception* and are
  not enforced until Phase 2 (see ADR-SEC-006).
- **Implementation state:** **not implemented.** Nothing in the repo carries a
  per-peer transport policy record (verified: no `TLSAccept`-shaped concept
  anywhere; the three nearest things are enumerated in
  `docs/design/transport-encryption-2026-08-04.md` §2.3 and none of them is a
  policy object).
- **Product outcome this serves:** the customer-facing claim *"every Correlix
  component communicates over TLS"* must be **demonstrable, not asserted.** The
  policy object is what turns that claim into a query — one table that lists
  every hop, its mode, and (for the honestly-unencryptable device protocols) who
  accepted the exception and when it expires.
- **Relates to:** `docs/security/CORRELIX_CLOUD_NATIVE_SECURITY_HLD.md` §6.3,
  `docs/design/transport-encryption-2026-08-04.md` §4–§5,
  ADR-SEC-006 (device identity), ADR-SEC-008 (fail-closed production).
- **Numbering note:** this repo's first ADR is
  `docs/adr/0001-privileged-network-operations-isolation.md` (numeric, Nygard-ish
  Status/Decision/Rationale/Consequences). The security series uses the
  `ADR-SEC-NNN` prefix the HLD already references (§ header line 7) so the two
  series do not collide; the section structure below is the fuller Nygard form.

---

## Context

**The question "is Correlix encrypted?" is currently unanswerable without
reading six config files per hop.** Transport posture today lives entirely in
deployment configuration, and it is scattered:

| Where posture is decided today | Evidence |
|---|---|
| Compose environment blocks | `deployment/docker/docker-compose.yml:207-210` — Kafka `KAFKA_LISTENERS: "PLAINTEXT://0.0.0.0:9092"`, security-protocol map `PLAINTEXT:PLAINTEXT` |
| Compose environment blocks | `docker-compose.yml:538` — OpenSearch `DISABLE_SECURITY_PLUGIN: "true"` |
| Compose URL scheme | `docker-compose.yml:973-974,1119-1120` — `http://opensearch:9200`, `http://clickhouse:8123` |
| Per-collector config files | `deployment/docker/gnmic/gnmic.yaml:13` (`skip-verify: true` globally) and `:30,35,40,45,50` (`insecure: true` per target) |
| A daemon config file | `deployment/docker/syslog-ng/syslog-ng.conf:84-85` — UDP+TCP/514, and `:42-43` states in its own comment that the hostname is "an UNVERIFIED CLAIM" |
| Go env vars, boot-time only | `TLS_CLIENT_ALLOWED_URIS` / `TLS_CLIENT_ALLOWED_DNS` (`docker-compose.yml:1458-1459`) feeding `tlsconfig.PeerPolicy` (`src/backend/tlsconfig/verify.go`) |
| A per-credential attribute | `src/backend/collectors/snmpv3.go` security level — *describes* a credential, but nothing rejects a peer that shows up below it |

Three properties are missing from every one of those, and they are the reason a
policy object is needed rather than more env vars:

1. **Nothing is per-peer.** `tlsconfig.PeerPolicy` is a single global,
   boot-time, env-driven allowlist. A stack with 4 000 devices cannot express
   "these 30 routers must be authPriv, the rest are on the 90-day legacy lane."
2. **Nothing is a set.** Every knob is a single value, so every cutover is a
   flag day. Zabbix's transferable insight (`transport-encryption-2026-08-04.md`
   §1.3) is that the **inbound accept-set** is what makes a migration
   zero-downtime: accept both, verify the encrypted path carries traffic, then
   narrow.
3. **Plaintext is inferred, never declared.** There is no place to record *who*
   accepted an unencrypted peer, *why*, or *when it expires*. That matters more
   here than in Zabbix because Correlix has peers that **cannot** be encrypted
   at all — NetFlow/IPFIX/sFlow, syslog UDP, SNMPv2c, TACACS+ (HLD §6.6).

There is also a **verified fail-open** that a policy object is the natural home
for: the SNMPv3 trap path resolves credentials per source, but an unknown
sender's trap is accepted rather than rejected
(`src/backend/collectors/snmptrap.go`; the event record honestly stamps
`Authenticated bool` false for v1/v2c at `snmptrap.go:60`, which is the correct
*honesty* behaviour and exactly the wrong *enforcement* behaviour). A
`TLSAccept`-shaped set is where that decision belongs.

## Decision

**Adopt a stored, per-peer `transport_policy` object with two independent
halves — one outbound mode and an inbound accept-SET — as the single source of
truth for transport posture, with two Correlix-specific extensions.**

### The object (schema authority: HLD §6.3; storage detail: LLD §6.2)

```yaml
transport_policy:
  name: vector-aggregator-to-kafka
  environment: production
  outbound:  { mode: mtls, server_name: kafka, trust_domain: correlix.workload,
               client_identity: "spiffe://correlix.workload/ns/ingestion/sa/vector-aggregator" }
  inbound_peer: { allowed_identities: [ "spiffe://correlix.workload/ns/streaming/sa/kafka" ] }
  accept: [mtls]                 # a SET; [plaintext, mtls] only during migration
  tls: { minimum_version: TLS1.2, hostname_verification: required,
         plaintext_fallback: prohibited }
  authorization: { kafka: { produce: [netops.syslog, netops.metrics], consume: [] } }
  rotation: { leaf_ttl: 24h, renew_before: 8h, overlapping_trust_window: 7d }
  enforcement: { fail_on_missing_certificate: true, fail_on_expired_certificate: true,
                 fail_on_plaintext: true }
  exception:                     # REQUIRED whenever accept ⊇ plaintext
    reason: "…"; owner: "…"; expires: "2026-09-30"; ticket: "SEC-0xx"
```

1. **`outbound.mode` is exactly one value; `accept` is a set.** Outbound
   fail-closed: if the configured outbound mode fails, **no other mode is
   tried** — there is no silent downgrade path, ever.
2. **Correlix extension #1 — a plaintext member of `accept` requires an
   `exception` block** carrying `owner`, `reason`, `expires` and `ticket`. A
   policy whose `accept` contains `plaintext` **without** a well-formed,
   unexpired exception is a validator failure, not a warning (ADR-SEC-008). No
   bypass may be permanent or anonymous.
3. **Correlix extension #2 — the `protocol_native` mode.** For channels where
   "TLS" is a category error but a security level genuinely exists: SNMPv3 (with
   `min_level: authPriv`), SSH (`FEATURE_DEVICE_SSH`,
   `src/backend/device_ssh.go`), TACACS+. `protocol_native` + `min_level` is
   enforceable; claiming those channels are "TLS-protected" would be a lie the
   product must not tell (HLD §6.6 honesty clause).
4. **Resolution is most-specific-wins:** peer record → tenant default →
   platform default. **A missing record means *inherit*, never *allow*.** The
   platform default ships as `accept: {plaintext}` carrying the exception reason
   `"platform default, not yet reviewed"` — so the first operator view of the
   posture page shows every peer as an unreviewed risk. That display *is* the
   migration prompt.
5. **Policy is tenant-scoped data, subject to the same isolation law as every
   other feature** (root `CLAUDE.md` §3a): `tenant_iso` FORCE-RLS + `withTenant`
   for PG, owner stamped from the token, cross-tenant get → 404, and an
   `org_isolation_test.go`-shaped test ships with it. Platform-global peers
   (intra-stack service↔service) are platform-scoped records behind
   `requirePlatformAdmin`, **not** tenant records — see Unresolved question U3.
6. **The policy object is never the tenant boundary.** It says *how* a peer
   connects and *who* it is. Tenant authorization stays where it is today —
   ClickHouse `ROW POLICY` (`src/backend/clickhouse_policies.go`), PG FORCE-RLS,
   per-tenant OpenSearch indices. HLD §4 states this as design law and this ADR
   does not weaken it.

### v1 scope (owner decision, 2026-08-04)

**In v1 the policy object governs intra-stack and ingress hops only** — browser→
nginx, nginx→api, api→every datastore, api→correlation, vector→Kafka,
collectors→ingest lanes, vector-router→api (sealing keys). Those are the hops
that carry the customer-facing "all components transported over TLS" claim, and
every one of them is inside our own deployment, so enforcement costs nothing on
the customer's side.

**Device-facing hops are represented but not enforced in v1.** Each gets a
policy row with `accept: [plaintext]` (or `protocol_native` where SNMPv3 already
provides `authPriv`) plus a mandatory exception naming an owner and an expiry.
That keeps the posture honest and complete — the table shows the whole estate —
without requiring any customer to touch a router in v1. Device enforcement is
Phase 2 (ADR-SEC-006).

This bounding is deliberate overhead control: it delivers the demonstrable claim
with **zero new operational components and zero customer-side change**.

### What is explicitly NOT decided here

Enforcement *severity* per environment is ADR-SEC-008. Which identity a peer
presents is ADR-SEC-003 (workloads) and ADR-SEC-006 (devices). This ADR decides
only that the **posture is data with these semantics**.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| **Keep env vars + compose (status quo)** | Not per-peer, not queryable, not auditable, and structurally incapable of a staged cutover. It is also demonstrably how the current gap arose: every `TLS_*` var exists in compose (`docker-compose.yml:1455-1472`) and none is set in the live `.env`, so "built" silently became "off" with nothing to report it. |
| **A single global "require encryption" switch** | Fails on the first device that cannot do TLS. Correlix's peer set includes protocols with no encryption at all (HLD §6.6); a boolean forces either a lie or a permanent "off". |
| **Copy Zabbix verbatim (`TLSConnect`/`TLSAccept`, no exception block)** | Zabbix never has to express "this peer is plaintext and that is an accepted, recorded risk" — both ends are Zabbix software. Verbatim adoption leaves plaintext as an untracked default, which is exactly today's failure mode wearing a new name. |
| **Derive posture by observation only** (report what collectors actually see, never declare) | Excellent as *half* of the answer, and Phase 1 of the rollout ships exactly that. But observation cannot express intent, so it can never enforce, and "observed plaintext" cannot be distinguished from "intended plaintext" — the distinction the exception block exists to make. |
| **Per-peer policy inside each collector's own config file** (gnmic YAML, syslog-ng conf, Vector TOML) | Reproduces today's scatter with more files. It also cannot be tenant-scoped, cannot be audited, cannot be edited by an operator without a redeploy, and cannot be aged for expiry. |
| **Encode the policy in the certificate** (e.g. a custom X.509 extension) | Couples posture changes to certificate re-issuance, is invisible to protocols with no certificates at all (SNMP, syslog-UDP, flows), and makes an exception's expiry a PKI operation. |
| **Model `accept` as an ordered preference list rather than a set** | Preference implies fallback, and fallback is the downgrade attack. A set with an explicit fail-closed outbound mode has no negotiation semantics to abuse. |

## Consequences

**Positive**
- Posture becomes a single query: "show every peer whose `accept` contains
  plaintext, with owner and expiry" is one table scan instead of a config audit.
- Migration becomes routine rather than a maintenance window: widen the set,
  verify traffic on the secure member, narrow the set.
- The SNMP-trap fail-open acquires a correct home: an unknown sender is not in
  the policy table, therefore inherits the default, therefore is rejected once
  the default is narrowed.
- A compliance export ("N peers encrypted, M with declared exceptions, here are
  the owners") becomes derivable rather than hand-assembled.

**Negative**
- A new stateful, tenant-scoped, audited object with a UI, an API, RLS
  migrations, isolation tests and a resolution algorithm — meaningful build cost
  for something that ships no user-visible feature on day one.
- **Two sources of truth exist during rollout.** Until every enforcement point
  reads the policy, compose/env still decides. Divergence between declared and
  actual posture is itself a defect class, which is why the posture view shows
  *observed* next to *declared* and drift is alertable.
- Most-specific-wins resolution is a correctness surface. A wrong precedence
  rule silently weakens a peer. It needs table-driven tests, not spot checks.

## Security implications

- **Closes a known fail-open.** The unknown-sender SNMPv3 trap path
  (`collectors/snmptrap.go`) currently accepts what it cannot authenticate; the
  accept-set is the mechanism that makes rejection expressible per source.
- **Removes silent downgrade as a concept.** `plaintext_fallback: prohibited`
  and single-valued outbound mode mean a failed secure handshake is a failure,
  not a fallback (`transport-encryption-2026-08-04.md` §1.4, §3 P3).
- **Makes risk acceptance attributable.** Today an unencrypted hop has no owner.
  After this, it has a name, a reason, a ticket and a date.
- **New privileged surface.** Whoever can edit a policy can *weaken* a peer.
  Widening `accept` (adding plaintext) must require step-up auth and a
  mandatory reason; the write must be audited with before/after values; and the
  gate for platform-global records is `requirePlatformAdmin`, not `requireAdmin`
  — a tenant admin holds full `administration:admin` and must not be able to
  weaken platform plumbing (root `CLAUDE.md` §3a.3).
- **Rubber-stamp risk is real** (`transport-encryption-2026-08-04.md` §7 R5).
  If every exception reads "lab", the model is decorative. The ageing report is
  not optional garnish — it is the control.

## Operational implications

- **New failure state that is not "down".** A device refused for being below
  `min_level` must surface as `policy_blocked`, distinctly from unreachable. A
  misleading down-state is its own incident (`transport-encryption-2026-08-04.md`
  §5, SNMP-poll row).
- **New metrics required** per channel: `*_policy_rejected{reason}`, plus
  declared-vs-observed drift. Silent enforcement violates root `CLAUDE.md` §10.
- **Discovery interacts badly with enforcement.** SNMP discovery
  (`ENABLE_SNMP_DISCOVERY`, default `10.0.0.0/8`) speaks plaintext by nature; a
  peer that refuses plaintext may become undiscoverable. Discovery must be
  policy-aware or explicitly exempted (R3).
- **Handshake cost is unmeasured.** Zabbix documents ~1 s per encrypted check
  with no session caching. Before enabling mTLS on high-fan-out collection, per-
  poll cost must be measured and connection reuse verified (R2).

## Migration implications

- **Phase order is fixed by the HLD roadmap** (§9) and by
  `transport-encryption-2026-08-04.md` §6: observation before enforcement.
  Phase 1 ships the object plus a read-only posture view; **no enforcement**.
- **Every existing peer is seeded as `accept: {plaintext}` with the unreviewed
  default exception.** Nothing breaks on the day the object lands — that is the
  point.
- Enforcement lands channel-by-channel, each with an accept-set widen → verify →
  narrow sequence and a test proving no data loss across the narrowing.
- **The existing env vars do not disappear.** `TLS_CLIENT_ALLOWED_URIS` and
  friends remain the boot-time floor; the policy object supplies the same
  allowlist from data. Removing the env path is a later cleanup, not part of
  this ADR.

## Unresolved questions

- **U1 — Scope of v1.** Intra-stack only (fast, invisible to customers) or the
  collection plane too (customer-visible differentiator, much larger)? HLD §11.7
  flags this as an owner decision; it is unanswered.
- **U2 — Default exception expiry.** HLD §11.5 recommends 90 days. Not ratified,
  and the owner of exceptions is unnamed.
- **U3 — Where do non-tenant peers live?** Intra-stack service↔service policies
  are platform-global; making everything tenant-scoped would either duplicate
  rows per tenant or create an unscoped table. This ADR assumes a
  platform-scoped table behind `requirePlatformAdmin` plus a tenant-scoped table
  for device/exporter/probe peers. Not ratified
  (`transport-encryption-2026-08-04.md` §8.3).
- **U4 — Does the posture view ship before enforcement?** Strong recommendation
  yes; not yet an owner decision (§8.4).
- **U5 — Is the compliance export customer-facing or internal hygiene?** Changes
  how much of Phase 4 matters (§8.5).
- **U6 — Policy versioning semantics.** `config_version` is in the sketched
  schema, but rollback semantics ("revert this peer to the previous policy")
  are undefined.
