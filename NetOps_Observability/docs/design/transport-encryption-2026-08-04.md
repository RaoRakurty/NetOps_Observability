# Transport encryption — per-peer policy (Zabbix-model) for Correlix

**Status: DRAFT v1 (assistant), 2026-08-04. Awaiting the owner's design for merge.**

Research input: Zabbix 7.4 encryption manual (`https://www.zabbix.com/documentation/7.4/en/manual/encryption`).
Ground truth: a full transport-posture inventory of this repo (2026-08-04) —
every claim below is code-verified; the gap table is reproduced in §3.

Companion docs that already exist and are NOT superseded:
`docs/design/tls-architecture.md` (the intra-stack mTLS/SPIFFE design, phases
1–4 landed) and `docs/runbooks/tls-mtls.md` (the enable sequence). This design
adds the piece neither has: **a per-peer encryption policy with staged
migration**, and it extends the model outward to the collection plane
(devices, probes, exporters) which the TLS architecture never covered.

---

## 1. What Zabbix actually does (the transferable idea)

Zabbix encrypts server↔proxy, server↔agent, proxy↔agent and utility
connections. Two authentication methods: **X.509 certificates** (issuer/subject
validated) and **pre-shared keys** (an *identity string* + a hex key). Neither
is the interesting part — every product has TLS. The transferable ideas are:

1. **Every peer carries a policy record, not a global switch.** Per-host and
   per-proxy, in the frontend UI, stored in the DB.
2. **The policy has two independent halves.**
   `TLSConnect` = the ONE mode used for outgoing connections
   (`unencrypted | psk | cert`); `TLSAccept` = the SET of modes accepted
   inbound. Asymmetry is explicitly supported (accept cert, connect PSK).
3. **The accept-SET is the migration mechanism.** `TLSAccept=unencrypted,cert`
   lets a peer be migrated with zero downtime: enable both, verify the
   encrypted path works, then narrow to `TLSAccept=cert`. This is the whole
   reason the model is worth copying.
4. **Fail-closed on the connect side:** "if the configured encryption type for
   connection fails, no other encryption types will be tried" — no silent
   downgrade.
5. **PSK exists because certificates are too heavy for some peers.** A PSK is
   an identity + secret, no PKI, no expiry management.

Zabbix's own documented limits are worth inheriting as warnings: full handshake
per connection (no session caching, ~ms cost per check), and network discovery
cannot speak encryption — a peer that refuses plaintext is invisible to it.
Both have direct analogues here (§6.4, §7 risk R3).

**What does NOT transfer:** Zabbix is an agent-based system where both ends are
Zabbix software, so it can mandate one uniform mechanism. Correlix's peers are
**third-party devices speaking fixed protocols** (SNMP, syslog, NetFlow, gNMI)
plus internal services. Some of those protocols cannot be encrypted at all
(NetFlow/sFlow over UDP). So our policy object must be able to express
"this peer is plaintext and that is an accepted, recorded risk" — Zabbix never
has to say that.

---

## 2. Where Correlix stands today (code-verified, 2026-08-04)

### 2.1 The headline: the hard part is built and switched off

`tlsconfig/` (policy floor, server/client builders, `PeerPolicy` allowlist,
SPIFFE federation), `internalca/` (stdlib ECDSA P-256 CA, SPIFFE-SAN leaf
issuance), `tls_ca.go` (CA custody sealed under the platform DEK, SVID
minting for api + nginx, TTL/2 reissue loop), `tls_server.go` (mTLS listener,
cert-expiry + handshake-error + identity-rejection metrics), and
`backend_client.go` (the mTLS client for OpenSearch/ClickHouse/VM/correlation)
are all **implemented and wired into `main.go`** — and **entirely dormant**,
because the live `.env` sets no `TLS_*` variable at all.

Fourteen call sites already route through `backendHTTPClient`; they would
inherit mTLS the moment the vars are set. **Phase 0 of this design is therefore
"turn on what we already built", not "build".**

Two defects found while inventorying, both cheap:
- `TLS_FEDERATED_BUNDLES` is implemented in Go but **absent from
  `docker-compose.yml`** — unreachable through the supported config surface.
- If `TLS_INTERNAL_CA=true` is set without `SEAL_PROVIDER`, the **CA private
  key is stored in plaintext** (`tls_ca.go:22-24` says so honestly). Enabling
  the CA must therefore *require* a seal provider, not merely recommend one.

### 2.2 What is actually encrypted right now

Exactly two things: the **nginx TLS front** (shipped 2026-08-03, TLS 1.2/1.3,
HSTS, PFS — but `:8000` plaintext is still published alongside it), and
**LDAP** (`internal/ldap` — the reference implementation: explicit CA bundle,
`InsecureSkipVerify` refused outside dev). SNMPv3 `authPriv` and device SSH
are encrypted when configured, per credential.

Everything else — Kafka, OpenSearch, VictoriaMetrics, ClickHouse, Postgres
(`sslmode=disable`), correlation, Valkey, syslog, flows, all four Vector
ingest lanes, nginx→api — is **plaintext**, and several carry credentials or
key material over it. The two that should make us move fastest:

- **Per-tenant sealing keys transit plaintext HTTP.** `cx-secret-backend.sh`
  fetches `cxseal.<tenant>` / `cxmac.<tenant>` from the API over
  `http://api:8080`, authenticated by the shared ingest Basic credential. The
  sealed-fields feature's whole value is undone by its own key-distribution hop.
- **OpenSearch has no authentication at all** (`DISABLE_SECURITY_PLUGIN=true`)
  and holds every tenant's logs.

### 2.3 Per-peer policy: does not exist

Zero hits repo-wide for any `TLSAccept`-shaped concept. The three nearest
things, and why each is not it:

| Existing | Why it isn't a policy object |
|---|---|
| `tlsconfig.PeerPolicy` (DNS/URI allowlist) | Global, boot-time, env-driven; not per-peer, not persisted, not editable |
| `snmpcred.Credential.SecurityLevel` (`noAuthNoPriv/authNoPriv/authPriv`) | Genuinely per-peer, but it's a *credential attribute*: nothing rejects a peer that shows up with less |
| `snmptrap.decodeTrapV3` per-source resolution | Per-peer and enforcing — but **fails open**: an unknown sender's cleartext v3 trap is accepted |

That last one is the single most instructive line in the inventory: it is
exactly where a Zabbix `TLSAccept` bitmask belongs, and its absence is a
fail-open default.

**PSK-shaped auth we already have:** one stack-wide `INGEST_TOKEN` (HTTP Basic,
six clients, plaintext transport, no per-client identity, no rotation story),
and per-connector inbound **webhook HMAC** — the only genuinely per-peer shared
secret in the codebase, and the closest existing pattern to Zabbix PSK.

---

## 3. Design principles

**P1 — Policy is data, not deployment.** A peer's transport requirement is a
stored, tenant-scoped, admin-editable record with an audit trail; not an env
var, not a compose comment. (Zabbix's core insight.)

**P2 — Two halves, asymmetric, accept is a SET.** `connect` = one mode;
`accept` = a set. The set is what makes migration possible without a
maintenance window. Copy verbatim.

**P3 — Fail-closed at the enforcement point, and say so out loud.** A peer
whose policy says `require: encrypted` is REJECTED in the clear, with a
counted, categorized, tenant-scoped audit event. Never "log and accept".

**P4 — Plaintext must be *declared*, never inferred.** Because some protocols
cannot be encrypted, the policy object has an explicit
`plaintext_accepted_reason` + `accepted_by` + `accepted_at`. An unencrypted
peer becomes a *recorded risk acceptance* rather than an accident. This is our
addition to the Zabbix model and the thing that makes it honest for a
network-observability product.

**P5 — Reuse the built machinery.** The internal CA mints SVIDs; `tlsconfig`
is the only place TLS is configured; the vault seals PSKs and keys. No second
crypto stack, no new dependency (§6 allowlist untouched — everything here is
stdlib + what is already vendored).

**P6 — Identity before encryption, where they conflict.** An encrypted channel
to an unauthenticated peer is worth less than an authenticated plaintext one on
a trusted segment. Where we must choose an order, authenticate first.

---

## 4. The policy object

One concept, three scopes. Stored per-tenant (`tenant_iso` FORCE-RLS + the
existing kv/PG store pattern), versioned, audited.

```
transport_policy
  id, tenant_id, public_id            opaque, immutable
  peer_kind      device | exporter | probe | service | broker | tenant_default
  peer_ref       device id / source CIDR / probe id / service name
  channel        snmp | snmptrap | syslog | flow | gnmi | stamp |
                 ingest | api | bus | store        (the enforceable surfaces)
  connect        unencrypted | psk | cert | protocol_native
  accept         SET of the same values             ← migration lever (P2)
  identity_ref   → SVID subject / PSK identity / SNMPv3 user / cert fingerprint
  min_level      protocol-specific floor (e.g. SNMPv3 authPriv)
  plaintext_accepted_reason, accepted_by, accepted_at    (P4; required when
                                                          accept ⊇ unencrypted)
  status, config_version, created/updated_by
```

Resolution is **most-specific-wins**: peer record → tenant default → platform
default. A missing record does NOT mean "allow"; it means "inherit", and the
platform default ships as `accept: {unencrypted}` with a loud
`plaintext_accepted_reason: "platform default, not yet reviewed"` so the very
first admin view of the page shows every peer as an unreviewed risk. That is
the migration prompt.

`protocol_native` is the honest value for channels where the protocol carries
its own scheme and "TLS" is meaningless: SNMPv3 USM, SSH, TACACS+ obfuscation.
It pairs with `min_level` (e.g. `authPriv`) to become enforceable.

---

## 5. Enforcement points (where the policy is actually read)

A policy object nothing consults is decoration. Each row below is a concrete
insertion point identified in the inventory:

| Channel | Enforcement point | Behavior when policy is violated |
|---|---|---|
| SNMP poll | `collectors/poller.go` target build (v2c/v3 split) | Refuse to poll with a credential below `min_level`; surface the device as `policy_blocked`, not "down" — a misleading down-state is its own incident |
| SNMP trap | `collectors/snmptrap.go decodeTrapV3` — the fail-open branch | Unknown sender or below-level trap → drop + `trap_policy_rejected{reason}` metric + audit; **this closes the identified fail-open** |
| Syslog | Vector `syslog_in` TLS listener + syslog-ng `tls()` | Per-source policy: plaintext accepted only with a declared reason; RFC 5425 client cert binds tenancy to the certificate (the syslog-ng config file itself names this as the correct fix) |
| Flow | goflow2 exporter allowlist | Cannot encrypt (UDP): policy value is `unencrypted` + mandatory reason; enforcement is exporter-address allowlisting + the existing spoof-bounding |
| gNMI | `gnmic.yaml` per-target `tls-ca`/`skip-verify` | Policy generates the target block; `skip-verify: true` becomes a *declared exception* instead of a global default |
| STAMP | `collectors/stamp.go` | RFC 8762 **authenticated mode** (HMAC-SHA-256, per-peer key) — an empty, protocol-native PSK slot we can fill without inventing anything |
| Ingest lanes | `collectors/ingest_auth.go` + Vector `http_server` `tls:` | Per-client identity replaces the one shared token; `IngestAuthConfigured()` already exists to say "unauthenticated" out loud — extend it to say "unencrypted" |
| Remote vantage | `probe_paths_ingest.go` | Per-vantage credential (SVID or PSK) instead of a shared `infrastructure:write` API key that lets any holder publish as any vantage |
| Intra-stack | `tlsconfig` server/client builders (already the chokepoint) | mTLS + `PeerPolicy`; policy record supplies the allowlist instead of env vars |
| Broker | `BROKER_URLS` + Vector/goflow2 sink config | SASL/TLS becomes *expressible* — today an external managed broker cannot be configured at all |

---

## 6. Phasing

Deliberately ordered by (risk removed ÷ effort), not by architectural tidiness.

### Phase 0 — Turn on what exists (days, no new code)
Set the `TLS_*` vars; enable `TLS_INTERNAL_CA` **with** a seal provider (gated:
refuse to boot the CA unsealed — see §2.1); enable the api mTLS listener and
`backend_client` mTLS; add the shipped nginx→api `proxy_ssl_*` block from the
runbook; declare `TLS_FEDERATED_BUNDLES` in compose. Fix `sslmode=verify-full`
for Postgres and give ClickHouse/OpenSearch/VM real TLS listeners.
**Removes the largest number of plaintext hops for the least work**, using
machinery that is already tested.

### Phase 1 — The policy object (the Zabbix core)
Storage + resolution + API + the `accept`-set semantics + audit/metrics
vocabulary. No enforcement yet — a read-only "posture" view that shows every
peer's current *actual* transport (derived from what the collectors observe)
next to its *declared* policy. Shipping observation before enforcement is what
makes the rollout safe, and it immediately answers "how exposed are we?".

### Phase 2 — Enforcement, channel by channel, accept-set first
Order: **snmptrap** (closes the known fail-open) → **ingest lanes** (kills the
plaintext sealing-key hop and the single shared token) → **syslog TLS** →
**SNMP poll min_level** → **remote vantage identity** → gNMI → STAMP auth mode.
Each channel ships with: the enforcement point, a `*_policy_rejected` metric,
an audit event, and a migration test proving `accept:{unencrypted,cert}` →
verify → `accept:{cert}` works without dropping data.

### Phase 3 — Operator surface
Admin → Identity & Access → **Transport Security**: the posture table (peer,
channel, declared policy, observed transport, last verified, drift), inline
policy editing with step-up for narrowing/widening, the plaintext-acceptance
dialog that *requires* a reason, PSK issuance/rotation, CA + SVID visibility
(none of which has any UI today), and per-peer "test connection".

### Phase 4 — Bulk + lifecycle
Tenant-wide "require encryption for all devices" with a dry-run diff; PSK and
cert rotation workflows; expiry alerting (the metrics already exist); a
compliance export ("N peers encrypted, M with declared plaintext, here are the
reasons and who accepted them").

---

## 7. Risks and honest limits

- **R1 — Enforcement can blind the platform.** Turning on `require` for a peer
  whose device can't do v3/TLS stops collection. Mitigations: observation
  before enforcement (Phase 1), dry-run diffs, and `policy_blocked` as a
  distinct state from `down`.
- **R2 — Handshake cost at scale.** Zabbix documents ~1 s added per encrypted
  check with no session caching. Our per-poll cost must be measured, and
  connection reuse verified, before enabling mTLS on high-fan-out collection.
- **R3 — Discovery vs encryption.** Zabbix's discovery cannot speak encryption;
  our SNMP discovery has the same shape. A peer that refuses plaintext may
  become undiscoverable — discovery must be policy-aware or explicitly exempt.
- **R4 — PSK sprawl.** Per-peer PSKs are only better than one shared token if
  they are rotatable and revocable. If Phase 4's lifecycle slips, we will have
  built a bigger version of the `INGEST_TOKEN` problem.
- **R5 — Plaintext-by-declaration can become a rubber stamp.** P4's reason
  field is worthless if everyone types "lab". The compliance export and an
  ageing indicator ("accepted 9 months ago, never revisited") are what keep it
  meaningful.
- **R6 — Protocols we cannot fix.** NetFlow/sFlow/syslog-UDP/TACACS+ are
  plaintext or weakly obfuscated by design. The policy records that truthfully;
  the real controls are network-layer (management VRF, IPsec, ACLs) and belong
  in deployment guidance, not in code that pretends otherwise.

---

## 8. Open questions for the merge

1. **Scope of v1:** intra-stack only (Phase 0+1, fast, invisible to customers),
   or collection-plane too (the customer-visible differentiator)?
2. **PSK vs cert for devices/probes:** PSK is far easier for customers to
   deploy on constrained peers; certs give us SPIFFE identity we already mint.
   Zabbix ships both — do we, or do we pick one and stay simpler?
3. **Where does policy live for non-tenant peers** (intra-stack services)?
   Platform-global records, or does everything become tenant-scoped?
4. **Does the posture view ship before enforcement** (my strong recommendation),
   or do we go straight to enforcement on the two known fail-open paths?
5. **Compliance framing:** is "N% of peers encrypted, with declared exceptions"
   a customer-facing report we want to sell, or internal hygiene only? That
   answer changes how much Phase 4 matters.
