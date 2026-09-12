# Correlix Cloud-Native Security — Low-Level Design

**Status: DRAFT for owner review. 2026-08-04. No implementation until the HLD §12
do-not-implement boundary is lifted.**

Binding parent: **`docs/security/CORRELIX_CLOUD_NATIVE_SECURITY_HLD.md`** — its
trust domains (§6.1), SPIFFE identity formats (§6.2), transport-policy sketch
(§6.3), deployment profiles (§6.5), component matrix (§7) and phase order (§9)
are **contract**. Where this LLD found the HLD to be inaccurate it says so
explicitly in **§7 (HLD corrections)** rather than diverging silently.

Predecessors this document **builds on and does not replace**:
`docs/design/tls-architecture.md` (the intra-stack mTLS/SPIFFE design — phases
1–5(1/3) landed in code, dormant in deployment), `docs/runbooks/tls-mtls.md`
(the enable sequence), `docs/design/secret-custody.md` (#17 envelope custody),
`docs/design/transport-encryption-2026-08-04.md` (the Zabbix per-peer policy
model this LLD renders as a concrete schema in §6.2).

## How to read this document

- Every assertion about the current system carries a **`path:line`** citation.
  An uncited claim about current behavior is a bug in this document.
- A path is called **encrypted** only where **both ends** were verified. Where
  only one end was checked, the text says "client side ready, server side
  unverified".
- **`[ASSUMPTION]`** marks a design choice that is defensible but not derived
  from repo evidence. **`[UNKNOWN]`** marks something that must be measured or
  decided before implementation. **`[DECISION-REQUIRED]`** maps to an HLD §11
  owner decision.
- **No new third-party Go dependency is proposed anywhere in this document.**
  Every Go control is stdlib or an already-vendored module (CLAUDE.md §6).
- **Nothing here weakens tenant isolation.** Where a control touches tenancy the
  text states the CLAUDE.md §3a rule it preserves.

## Verification baseline

Branch `feat/observability-platform`, 2026-08-04. The single most important
as-built fact, and the premise of the whole migration:

> The intra-stack PKI is **built and switched off**. The live
> `deployment/docker/.env` contains **no key matching `TLS|SEAL|CERT|SSL|HTTPS`
> at all**; every knob therefore falls to its empty compose default
> (`docker-compose.yml:1448-1450`, `:1455-1472`). `scripts/install.py` never
> writes a `TLS_*` or `SEAL_*` key and never generates a certificate — its only
> seal-related output is two data directories (`install.py:944-945`).

A second as-built fact that changes the scope of everything below:

> The tracked `docker-compose.yml` is **not the whole deployment.** A
> gitignored `deployment/docker/docker-compose.override.yml` is present on the
> lab host and adds (a) the nginx TLS front on `443:8443`
> (`docker-compose.override.yml:4-11`) and (b) a **`cloud-ingest` service that
> is a real Kafka producer holding `INGEST_TOKEN`**
> (`docker-compose.override.yml:27-70`, token at `:37`). Any inventory,
> validator or network policy that reads only the tracked compose will be
> **incomplete**. §6.21 and §6.22 treat this as a first-class problem.

---

# 0. Owner decisions and the v1 scope line

The HLD §11 open decisions were resolved by the owner on 2026-08-04. The steer:

> *"Pick secure methods, don't add too much overhead, not overkill. I want to
> show customers this is a secure environment where all components are
> transported via TLS securely."*

and, on the shape of this document:

> *"We will stick with our design for the most part; I am just giving high-level
> direction where you have to make decisions for me."*

**Therefore: this LLD is complete. Every section is designed at
implementation-ready depth, including the parts that are not v1.** The owner
decisions set the **phase label** and pick the **chosen option** inside each
section — they do not shrink the design. The value of a fully designed Phase 2+
is that when it is wanted, nothing has to be re-derived.

## 0.1 Decisions (binding)

**Canonical numbering is the HLD's** — `CORRELIX_CLOUD_NATIVE_SECURITY_HLD.md`
§11.0 "The v1 decision set", rows **D1–D10** (`HLD:584-596`). The table below is
the same decision set expressed as what the LLD must implement. Where this
document says `[decision Dn]`, `n` is the **HLD's** number.

| # | HLD §11 question | Decision | Rationale to state to customers |
|---|---|---|---|
| **D1** | Scope of v1 | **Intra-stack + public ingress only.** Every Correlix-owned component speaks TLS: nginx, api, correlation, vector-aggregator, vector-router, Go collectors, Kafka, OpenSearch, ClickHouse, VictoriaMetrics, Postgres, Valkey, Keycloak, Grafana, OSD. **Customer device lanes (syslog, SNMP, gNMI, flows) are Phase 2** — we cannot force customer hardware. | "Every hop inside the Correlix platform is encrypted and mutually authenticated." Device lanes stay honestly labelled (§6.15.4) rather than overclaimed. |
| **D2** | Where the CA lives | **v1 = the existing in-process internal CA** (`internalca/ca.go` + `tls_ca.go`), which already mints SPIFFE-SAN leaves and re-issues at TTL/2. No SPIRE, no Vault PKI, no cert-manager, no offline-root ceremony. | Zero new operational surface; rotation is already automatic. Offline root is documented (§6.3.2) as the Phase 2+ upgrade path. |
| **D3** | CA custody | **Sealing is mandatory — boot refusal if `TLS_INTERNAL_CA=true` without `SEAL_PROVIDER`** (§6.19.7), closing the verified plaintext-CA-key defect (`tls_ca.go:23-24`). | One check, large risk removed. |
| **D4** | Trust domains | **v1 = two.** (a) public/enterprise chain for the browser-facing nginx certificate; (b) **one workload trust domain** for everything internal. Device and operator intermediates are **designed (§6.3.2) and deferred** with the device lanes. | Three intermediates for a single-appliance deployment is ceremony without benefit today. |
| **D5** | Kafka authn | **mTLS with the same internal CA.** Not SASL/SCRAM. | SASL/SCRAM would add a **second credential store** to create, distribute, rotate and audit. mTLS reuses certificates we already mint and rotate automatically — **lower** operational overhead, and one identity model for the whole stack. |
| **D6** | Datastore authz | **TLS + each store's simplest sufficient native auth.** Use mTLS where the client is ours and the CA mints anyway (it costs nothing extra). Do **not** invent elaborate per-client role matrices where one scoped service user is enough. **The existing ClickHouse row policies and Postgres FORCE-RLS are the tenant boundary and are kept exactly as they are.** | Fewer moving parts; the strong control (database-enforced tenancy) is already built and tested and is not touched. |
| **D7** | Service mesh | **None.** | HLD §8 anti-goal: a mesh must never make an insecure datastore *look* secure; and there is no k8s substrate. |
| **D8** | PSK infrastructure | **None in v1.** SNMPv3 already carries its own credential scheme; STAMP authenticated mode is Phase 2. | Avoids PSK sprawl (HLD standing risk R4) entirely for now. |
| **D9** | How hard production fails | **Fail-closed validator with clear, actionable error messages.** The lab profile is the escape hatch. | A misconfigured production upgrade must stop, and must tell the operator exactly which policy, which field, and which fix. |
| **D10** | Customer-facing deliverable | **A read-only "Transport Security" posture view plus an exportable report** listing every component-to-component path as TLS ✓ with certificate identity and expiry. | This is the point of the programme. §6.23 (metrics) and §6.24 (UI) are written to serve this directly. |

## 0.2 Phase labels used throughout

Every subsection carries one of:

- **`[v1]`** — in scope for the first shipped increment (HLD phases 0–4 + 6).
- **`[Phase 2+]`** — fully designed here, **not built in v1**. Its rationale,
  schema and enforcement points are complete so that starting it later is
  configuration and code, not re-derivation.
- **`[Design-only]`** — Kubernetes (§6.20) and anything gated on a substrate we
  do not have.

## 0.3 What v1 delivers, in one table

| Path | v1 target | Section |
|---|---|---|
| Browser → nginx | TLS 1.2/1.3 + HSTS (already shipped; plaintext `:8000` retired) | §6.13 |
| nginx → api | **mTLS**, URI-SAN allowlist | §6.13.4 |
| api → ClickHouse / OpenSearch / VictoriaMetrics / correlation | **mTLS** via the existing `backend_client.go` transport | §6.8–6.10, §6.14 |
| api → Postgres | TLS `verify-full` + SCRAM | §6.11 |
| api → Valkey | TLS + named ACL user | §6.12 |
| vector-aggregator / vector-router / goflow2 / correlation → Kafka | **mTLS + topic ACLs** | §6.7 |
| vector-router → OpenSearch / ClickHouse | TLS + service identity | §6.8, §6.9 |
| vector-router → api (sealing keys) | **mTLS, dedicated identity** — closes the plaintext key-fetch | §6.13.9 |
| Go collectors / prober → Vector ingest lanes | TLS + per-collector identity (replaces the one shared token) | §6.13.10 |
| syslog-ng → Vector `:6601` | TLS | §6.15.5 |
| gnmic → VictoriaMetrics | TLS via vmauth | §6.10 |
| Keycloak, Grafana, OSD | TLS behind the existing gates + native auth on | §6.8.6, §6.13.7 |
| **Device → Correlix (syslog / SNMP / gNMI / flow)** | **unchanged in v1**, honestly labelled `transport_authenticated=false` | §6.15–6.18 |
| Secrets | `SEAL_PROVIDER` required in production; CA-key boot refusal | §6.19 |
| Posture | read-only Transport Security view + export | §6.23, §6.24 |

## 0.4 What v1 explicitly does not do

Designed here, deferred: device PKI and the `correlix.device` trust domain
(§6.3.2, §6.15.2), the RFC 5425 secure syslog lane (§6.15.1), gNMI certificate
onboarding (§6.17.4), SNMPv3 per-device rollout to `authPriv` as a *hard*
production gate (§6.16.5 — the collector-side defects are still fixed in v1),
STAMP authenticated mode (§6.2.3), PSK infrastructure, the offline root and the
three-intermediate hierarchy (§6.3.2), the operator intermediate, SPIRE / Vault
PKI / cert-manager (§6.3.9), backup-encryption authority (§6.19.11), and
Kubernetes (§6.20).

One v1 exception inside a deferred area: **the SNMP trap fail-open
(`collectors/snmptrap.go:671-681`) is closed in v1** (§6.16.6). It is a
Correlix-side code defect, not a customer-hardware dependency, and it is the
sharpest single finding in the inventory.

---

# 6.1 Configuration hierarchy

## 6.1.1 Where security configuration lives today (verified)

Security-relevant configuration is currently scattered across six unrelated
shapes with no common owner:

| Shape | Example | Evidence |
|---|---|---|
| compose environment | `TLS_*`, `SEAL_*`, `DISABLE_SECURITY_PLUGIN` | `docker-compose.yml:1455-1472`, `:538` |
| mounted service config | nginx CSP, syslog-ng listeners, gnmic `skip-verify` | `nginx/default.conf:63`, `syslog-ng/syslog-ng.conf:84-85`, `gnmic/gnmic.yaml:13` |
| Vector YAML | ingest Basic auth, Kafka sinks, OpenSearch index templates | `vector/vector.yaml:128-130`, `vector-router/vector.yaml:548` |
| SQL/DDL in Go | ClickHouse row policies | `internal/chschema/policies.go:10`, `internal/chschema/ch_sql.go:47` |
| generated `.env` | every secret | `scripts/install.py:305-324` |
| gitignored override | TLS front + cloud-ingest | `docker-compose.override.yml:4-11,27-70` |

There is **no production profile concept**: `DEPLOY_PROFILE` does not exist
anywhere in the repo. The nearest things are compose profiles
(`install.py:50-52`, written to `.env` at `:669`), a host-sizing profile
(`install.py:251-289`) and a retention profile (`install.py:331`). None of them
gates a security control.

## 6.1.2 Proposed `security/` tree

The tree lives **beside** the compose file — `deployment/docker/security/` —
because (a) every consumer of it is a compose service or the installer, both of
which already resolve paths relative to `deployment/docker/`, and (b) the repo's
existing convention is exactly this: one directory per concern next to
`docker-compose.yml` (`nginx/`, `vector/`, `vector-router/`, `syslog-ng/`,
`gnmic/`, `clickhouse/`, `opensearch/`, `grafana/`, `swtpm-sidecar/`,
`cloud-fixtures/`). Putting it under `src/config/` would split it from the
services that mount it; putting it at repo root would break the "compose sees
the slice of tree it needs" build-context rule (`docker-compose.yml:4-6`).

```
deployment/docker/security/
├── README.md                         # what each subtree is, and who reads it
├── profiles/
│   ├── lab.yaml                      # HLD §6.5 profile: what is allowed to be plaintext
│   ├── development.yaml
│   ├── staging.yaml
│   └── production.yaml               # the fail-closed one
├── policies/
│   ├── transport/                    # one TransportPolicy per channel (§6.2)
│   │   ├── nginx-to-api.yaml
│   │   ├── vector-aggregator-to-kafka.yaml
│   │   ├── vector-router-to-opensearch.yaml
│   │   ├── vector-router-to-clickhouse.yaml
│   │   ├── vector-router-to-api-sealing.yaml
│   │   ├── api-to-{clickhouse,opensearch,victoria,postgres,valkey,correlation}.yaml
│   │   ├── correlation-to-{kafka,clickhouse,postgres}.yaml
│   │   ├── goflow2-to-kafka.yaml
│   │   ├── collectors-to-vector-{traps,probes,metrics,bus}.yaml
│   │   ├── syslogng-to-vector.yaml
│   │   ├── device-syslog-secure.yaml     # lane A, 6514 RFC 5425
│   │   ├── device-syslog-legacy.yaml     # lane B, 514 — carries an exception block
│   │   ├── device-snmp-poll.yaml         # protocol_native, min_level authPriv
│   │   ├── device-snmp-trap.yaml
│   │   ├── device-gnmi.yaml
│   │   └── device-flow.yaml              # unencryptable — exception block mandatory
│   ├── authorization/
│   │   ├── kafka-acl.yaml            # §6.7 matrix, machine-readable
│   │   ├── opensearch-roles.yaml     # §6.8
│   │   ├── clickhouse-grants.yaml    # §6.9 (row policies stay in Go — see §6.9.4)
│   │   ├── postgres-roles.yaml       # §6.11
│   │   ├── valkey-acl.yaml           # §6.12
│   │   └── vmauth.yaml               # §6.10
│   └── exceptions/
│       └── register.yaml             # every live exception: owner, reason, expiry, ticket
├── pki/
│   ├── trust-domains.yaml            # the five domains of HLD §6.1
│   ├── issuance.yaml                 # TTLs, renewal windows, SAN rules (§6.3)
│   ├── identities.yaml               # the §6.4 workload-identity table, machine-readable
│   └── ceremonies/
│       ├── root-ceremony.md          # offline root: witnessed, scripted, auditable
│       └── emergency-rotation.md     # the break-glass CA rotation runbook
└── validation/
    ├── rules/                        # one file per §4.4-class rule, id + severity + fix
    ├── schema/                       # JSON Schema for policy/profile/identity files
    └── baselines/                    # ratchet baselines (see §6.26.5)
```

**Nothing in this tree is a secret.** Keys and certificates never live here —
they live under the runtime `data/` volume (§6.5), which is gitignored. The tree
is declarative input; the validator (§6.1.4) is the thing that reads it.

## 6.1.3 Precedence

Most-specific wins, and a missing record means **inherit**, never **allow** —
the rule already stated in `docs/design/transport-encryption-2026-08-04.md:176-180`:

```
1. per-peer TransportPolicy      (policies/transport/<name>.yaml, or a stored
                                  per-device record for device-plane peers)
2. tenant default                (stored, per-tenant — device lanes only)
3. profile default               (profiles/<profile>.yaml)
4. platform default              — accept: [] ⇒ REFUSE. There is no implicit allow.
```

The platform default differs from the draft on purpose. The draft proposed
shipping `accept: {unencrypted}` so the first admin view shows every peer as an
unreviewed risk. That is right for the **device plane** (a device that stops
being collected is a customer-visible outage). It is wrong for the
**intra-stack plane**, where we control both ends and a default-open would
re-create today's posture in a new file. So:

- **Intra-stack channels**: platform default is `accept: []` → refuse. There is
  no such thing as an undeclared internal channel.
- **Device channels**: platform default is `accept: [unencrypted]` **with a
  synthetic exception** whose `reason` is `"platform default — not yet
  reviewed"` and whose `expires` is install-date + the profile's
  `default_exception_days`. It ages and it is visible from day one.

## 6.1.4 Where the tree is consumed

The repo already has the right hooks; none of them checks a security property
today (`scripts/preflight-configs.sh` validates Vector/nginx/VM/syslog-ng
*syntax* only: `:55-100`, `:103-115`, `:121-140`, `:143-157`;
`scripts/preflight-install.py` validates compose↔installer integrity only:
`:122`, `:136`, `:171`, `:201`, `:222`).

| Consumer | New behavior | Enforcement |
|---|---|---|
| `scripts/preflight-security.sh` (new, invoked from `scripts/preflight.sh:23-28`) | loads `profiles/` + `policies/` + the **tracked compose AND any override file present**, evaluates `validation/rules/` | warn in lab/dev; **exit non-zero** in staging/production |
| API boot (`main.go`, beside the existing fail-closed calls at `:270`, `:284`, `:1332`, `:1339`) | `validateSecurityProfile()` | `log.Fatalf` in production profile (§6.21.9) |
| CI (`.github/workflows/`) | runs the validator against `production.yaml` | blocking (CLAUDE.md §12) |
| Admin UI (§6.24) | renders the resolved policy + observed transport | read-only in phase 1 |

`scripts/preflight-security.sh` is a shell script and therefore falls under
CLAUDE.md §16 / `scripts/CLAUDE.md` — it must never swallow an error, must
declare its own `PATH`, and must be safe to run from cron.

---

# 6.2 Transport policy schema

## 6.2.1 Object

Versioned, Kubernetes-shaped on purpose: the same file must survive the
Compose→k8s move (§6.20) without a rewrite, and the shape is already familiar to
every operator who will read it.

```yaml
apiVersion: security.correlix.io/v1alpha1
kind: TransportPolicy
metadata:
  name: vector-aggregator-to-kafka        # unique, stable, kebab-case
  channel: bus                            # enum, §6.2.3
  scope: platform                         # platform | tenant
  tenant: ""                              # required iff scope=tenant; "" is not a wildcard
  labels:
    phase: "3"                            # HLD §9 phase that owns it
    priority: P0
spec:
  environment: production                 # lab | development | staging | production
  peer:
    kind: service                         # service | device | exporter | probe | broker | gateway
    ref: kafka                            # service name / device id / CIDR / vantage id
  outbound:                               # exactly ONE mode — never a list (no downgrade ladder)
    mode: mtls                            # plaintext | tls | mtls | psk | protocol_native
    server_name: kafka                    # REQUIRED unless mode ∈ {plaintext, protocol_native}
    trust_domain: correlix.workload
    client_identity: spiffe://correlix.workload/ns/ingestion/sa/vector-aggregator
  inbound:
    accept: [mtls]                        # SET — the migration lever
    allowed_identities:                   # exact strings; no wildcards, no regex
      - spiffe://correlix.workload/ns/streaming/sa/kafka
    allowed_sources: []                   # CIDRs; ONLY meaningful for unauthenticable protocols
  tls:
    minimum_version: TLS1.2               # TLS1.2 | TLS1.3
    hostname_verification: required       # required | not_applicable
    plaintext_fallback: prohibited        # prohibited | allowed  (allowed ⇒ exception required)
    cipher_policy: ecdhe-aead             # the tlsconfig/policy.go floor; not free-form
  protocol_native:                        # present iff outbound.mode == protocol_native
    protocol: snmpv3                      # snmpv3 | ssh | tacacs
    min_level: authPriv                   # snmpv3: noAuthNoPriv | authNoPriv | authPriv
    auth_algorithms: [SHA256, SHA384, SHA512]
    priv_algorithms: [AES128]
  authorization:                          # AUTHZ, not authn. Never inferred from the certificate.
    kafka:
      produce: [netops.syslog, netops.applogs]
      consume: []
      consumer_groups: []
      describe: [netops.syslog, netops.applogs]
    opensearch: { roles: [] }
    clickhouse: { user: "", roles: [] }
    postgres: { role: "" }
    valkey: { user: "" }
    http: { paths: [] }                   # e.g. the sealing-key fetch scope
  rotation:
    leaf_ttl: 24h
    renew_before: 12h                     # MUST be >= leaf_ttl/2 — see §6.2.5 rule V-07
    overlapping_trust_window: 7d
    credential_rotation: 90d              # non-cert credentials (PSK, DB password, ACL user)
  enforcement:
    fail_on_missing_certificate: true
    fail_on_expired_certificate: true
    fail_on_plaintext: true
    fail_on_unknown_peer: true
    on_violation: refuse                  # refuse | mark   ("mark" is lab/dev only)
  telemetry:
    stamp_transport_authenticated: true   # writes transport_authenticated into the event (§6.15.4)
    metrics_label: vector_aggregator_kafka # BOUNDED cardinality — see §6.23.1
  exception: null                         # REQUIRED and non-null iff plaintext is reachable
status:                                   # written by the platform, never hand-edited
  observed_mode: plaintext
  observed_at: "2026-08-04T00:00:00Z"
  drift: true
  last_handshake_error: ""
audit:
  created_by: ""
  created_at: ""
  updated_by: ""
  updated_at: ""
  config_version: 1                       # monotonic; every change increments
  change_reason: ""                       # free text, required on narrow/widen
```

## 6.2.2 The `exception` block

Required and structurally non-empty whenever `plaintext` ∈ `spec.inbound.accept`
**or** `spec.outbound.mode == plaintext` **or**
`spec.tls.plaintext_fallback == allowed` **or** an unauthenticable protocol is in
play. All four fields are mandatory; none may be empty; none may be a
placeholder.

```yaml
exception:
  reason: "Cisco IOS 15.x on this site cannot do RFC 5425; migration blocked on IOS-XE upgrade CX-4412"
  owner: "network-ops@customer.example"   # a REACHABLE identity, not a team alias with no owner
  accepted_by: "rao@correlix.io"          # who authorized it (platform side)
  accepted_at: "2026-08-04"
  expires: "2026-11-02"                   # REQUIRED. Bounded by profile.max_exception_days.
  ticket: "SEC-014"
  compensating_controls:                  # at least one, free text
    - "dedicated telemetry VLAN 3021, no route to the app subnet"
    - "source allowlist on the syslog-ng listener"
  review_interval: 30d
```

An exception that has **expired** does not silently keep working. Behavior by
profile: lab/dev → warn; staging → validator fails on *new* violations and the
UI shows the row red; production → the validator fails at install and at API
boot (§6.21.9). This is the "no permanent bypass" constraint made mechanical.

## 6.2.3 Field vocabulary

- `channel` ∈ `{ingress, api, bus, store, ingest, sealing, syslog, snmp,
  snmptrap, flow, gnmi, stamp, ssh, operator, backup}` — chosen to match the
  actual enforcement points that exist in this repo (see
  `docs/design/transport-encryption-2026-08-04.md:193-205`).
- `outbound.mode` is **one** value. Zabbix's fail-closed connect rule is adopted
  verbatim: if the configured mode fails, no other mode is tried.
- `inbound.accept` is a **set**, and it is the only migration lever.
  `[plaintext, mtls]` → verify → `[mtls]`.
- `protocol_native` exists so that SNMPv3, SSH and TACACS+ can carry a real,
  enforceable security level without the dishonest claim that "TLS" secures
  them. **Generic TLS does not secure SNMPv3** (§6.16.1).

## 6.2.4 Defaults

| Field | Default | Note |
|---|---|---|
| `spec.tls.minimum_version` | `TLS1.2` | matches `tlsconfig/policy.go:23` (`MinVersion = tls.VersionTLS12`) |
| `spec.tls.hostname_verification` | `required` | `tlsconfig` cannot express anything else — `ClientConfig` requires `ServerName` + explicit roots (`tlsconfig/config.go:70-72`) |
| `spec.tls.cipher_policy` | `ecdhe-aead` | `tlsconfig/policy.go:30,42,48-54` (ECDHE+AEAD, `RenegotiateNever`) |
| `spec.tls.plaintext_fallback` | `prohibited` | |
| `spec.rotation.leaf_ttl` | `24h` | matches `TLS_SVID_TTL` default (`docker-compose.yml:1464`) |
| `spec.rotation.renew_before` | `12h` | the existing re-issue loop runs at TTL/2 (`tls_ca.go:161`) |
| `spec.enforcement.*` | `true` | |
| `spec.enforcement.on_violation` | `refuse` | `mark` is rejected by the production profile |
| `spec.inbound.accept` | `[]` for intra-stack; `[plaintext]`+synthetic exception for device | §6.1.3 |

## 6.2.5 Validation rules

Every rule has an id, is implemented in `validation/rules/`, and is unit-tested
(§6.26.1). Severity `E` = error (fails the validator), `W` = warning.

| Id | Rule | Sev |
|---|---|---|
| V-01 | `metadata.name` unique across the tree; matches `^[a-z0-9][a-z0-9-]{2,62}$` | E |
| V-02 | `scope: tenant` ⇒ `tenant` non-empty and resolvable; `scope: platform` ⇒ `tenant` empty | E |
| V-03 | `outbound.mode ∈ {tls,mtls}` ⇒ `server_name` non-empty | E |
| V-04 | `outbound.mode == mtls` ⇒ `client_identity` present, well-formed SPIFFE, and listed in `pki/identities.yaml` | E |
| V-05 | `inbound.accept` non-empty **unless** the channel is outbound-only | E |
| V-06 | `allowed_identities` contains no `*`, no regex metacharacter, no empty string | E |
| V-07 | `renew_before >= leaf_ttl / 2` and `renew_before < leaf_ttl` | E |
| V-08 | `overlapping_trust_window >= 2 × leaf_ttl` | W |
| V-09 | plaintext reachable ⇒ `exception` present with all mandatory fields non-empty | E |
| V-10 | `exception.expires` parses as a date, is in the future, and is ≤ today + `profile.max_exception_days` | E |
| V-11 | `exception.reason` length ≥ 24 chars and not in the banned list (`lab`, `test`, `tbd`, `temp`, `n/a`, `later`) | E |
| V-12 | `exception.owner` and `accepted_by` are distinct non-empty identities | E |
| V-13 | `protocol_native` present iff `outbound.mode == protocol_native` | E |
| V-14 | `protocol_native.protocol == snmpv3` ⇒ `min_level` set; production ⇒ `min_level == authPriv` | E |
| V-15 | `protocol_native.priv_algorithms ⊆` what the collector actually implements (§6.16.3) | E |
| V-16 | `authorization` grants only topics/indices/tables/roles that exist in the corresponding `policies/authorization/*` file | E |
| V-17 | Every service in `pki/identities.yaml` is reachable by ≥1 policy; every policy peer exists in the compose inventory (**including override files**) | E |
| V-18 | `telemetry.metrics_label` matches `^[a-z][a-z0-9_]{2,40}$` and is not derived from a tenant, device, IP or hostname (§6.23.1) | E |
| V-19 | `audit.config_version` strictly increases on every write | E |
| V-20 | No two policies claim the same `(peer.kind, peer.ref, channel)` triple | E |

## 6.2.6 Forbidden combinations (hard-fail, no override)

| Id | Forbidden | Why |
|---|---|---|
| F-01 | `environment: production` **AND** plaintext reachable (`plaintext ∈ accept`, `outbound.mode == plaintext`, or `plaintext_fallback: allowed`) | HLD §6.5: production prohibits plaintext. The **only** relief is an exception that the production profile explicitly permits for a named unauthenticable channel (`flow`, `syslog` legacy lane, `snmp` v2c) — and even then `plaintext_fallback` stays `prohibited`, because "fallback" is a downgrade, not a declared lane |
| F-02 | `environment: production` **AND** `hostname_verification: not_applicable` on a TLS channel | HLD non-negotiable invariant: no hostname-verification disablement |
| F-03 | `environment: production` **AND** `enforcement.on_violation: mark` | fail-closed is the production contract |
| F-04 | `outbound.mode: mtls` **AND** `inbound.allowed_identities: []` | encryption without authorization is HLD §10's rejected option |
| F-05 | Any `allowed_identities` entry containing `*` or a shared identity used by >1 service | HLD invariant: no wildcard or shared service identities |
| F-06 | `exception` present **AND** `expires` absent/empty/in the past | constraint 18 |
| F-07 | `exception.expires - accepted_at > profile.max_exception_days` | prevents a 10-year "temporary" bypass |
| F-08 | `spec.authorization` empty on a `bus` or `store` channel | an authenticated peer still needs ACLs |
| F-09 | `protocol_native.protocol: snmpv3` **AND** `min_level: noAuthNoPriv` **AND** `environment: production` | HLD §7 SNMP row |
| F-10 | Two policies with the same `client_identity` and different `authorization` | one identity, one privilege set |
| F-11 | `trust_domain: correlix.device` on a `service`-kind peer, or `correlix.workload` on a `device`-kind peer | ADR-SEC-002 domain separation |
| F-12 | `telemetry.stamp_transport_authenticated: true` on a channel whose `outbound.mode` is `plaintext` and whose accept-set has no authenticated member | never claim authenticity we do not have |

## 6.2.7 Migration / legacy-exception fields

`inbound.accept` widening (adding `plaintext`) is a **privileged, audited,
step-up-authenticated** operation that:

1. requires an `exception` block in the same write (V-09 rejects the write
   otherwise — you cannot widen first and justify later);
2. increments `audit.config_version` and records `change_reason`;
3. emits `netops_transport_policy_changed_total{action="widen"}` (§6.23);
4. is refused outright in the production profile unless the channel is on the
   profile's `unauthenticable_channels` list.

Narrowing (removing `plaintext`) requires only that `status.observed_mode`
already equals the target mode for ≥ `profile.narrow_soak` (default 24h) — the
observation-before-enforcement rule from
`docs/design/transport-encryption-2026-08-04.md:221-227`.

## 6.2.8 Versioning behavior

- `apiVersion` is `v1alpha1` until Phase 8 completes, then `v1`.
- A reader that encounters an **unknown `apiVersion`** refuses the file. It does
  not "best-effort parse" — a policy engine that silently ignores fields it does
  not understand is a bypass.
- A reader that encounters an **unknown field** within a known `apiVersion`
  refuses the file (strict decoding). This is the same fail-closed posture as
  `tlsconfig`'s refusal to expose an `InsecureSkipVerify` knob
  (`tlsconfig/policy.go:12`).
- `audit.config_version` is monotonic per object and is the concurrency token:
  a write carrying a stale version is rejected.
- Schema evolution: additive fields ship in a new `apiVersion` with a
  documented, mechanical up-converter under `validation/schema/`.

---

# 6.3 PKI hierarchy

## 6.3.1 What exists today

`src/backend/internalca/ca.go` is a complete, stdlib CA:

- ECDSA **P-256** for both the root (`internalca/ca.go:45`) and every leaf
  (`:157`).
- Root is **constrained**: `IsCA: true`, `KeyUsage: CertSign|CRLSign|DigitalSignature`,
  `MaxPathLen: 0`, `MaxPathLenZero: true` (`internalca/ca.go:59-63`) — it can
  sign leaves but **not** an intermediate. That is a real constraint the
  three-intermediate design in HLD §6.1 must change.
- Root lifetime **10 years** (`tls_ca.go:33` — `caValidity = 10 * 365 * 24 * time.Hour`).
- Leaves carry a **URI SAN** (`internalca/ca.go:181`), `ExtKeyUsage` set per
  `Client`/`Server` request flags (`:165-170`), `KeyUsage:
  DigitalSignature|KeyEncipherment` (`:178`), `NotAfter = now + req.TTL` (`:177`).

`src/backend/tls_ca.go` is the custody + bootstrap layer:

- The CA private key is sealed under the **platform DEK** with AAD field-id
  `tls.ca.key` (`tls_ca.go:32`); the CA certificate is stored plaintext as a
  public trust anchor (`tls_ca.go:16-17`).
- **The verified defect:** `tls_ca.go:23-24` states plainly — *"When the Vault is
  also dormant the CA key is stored plaintext (passthrough) — turning on
  `SEAL_PROVIDER=swtpm` seals it."* `bootstrapInternalCA` (`tls_ca.go:118-133`)
  does **not** check that the Vault is active. §6.19.7 designs the boot refusal.
- Bootstrap mints **exactly two** SVIDs — `api` and `nginx`
  (`tls_ca.go:138-156`) — plus the trust bundle. **No other service has any
  certificate path today.**
- Re-issue loop at **TTL/2** (`tls_ca.go:159-181`), started only when the TLS
  server is actually up (`main.go:1361`).

## 6.3.2 Target hierarchy `[Phase 2+ — designed, not v1]`

**v1 uses the flat structure that already exists**: one self-signed root
(`internalca.Generate`, `ca.go:41-63`), one trust domain
(`TLS_TRUST_DOMAIN`, default `netops` → target value `correlix.workload`),
leaves issued directly off it. Per owner decision **D2/D3**, no intermediate is
introduced in v1 and no ceremony is required. The one v1 change to this layer is
**mandatory sealing of the CA key** (§6.19.7) and extending issuance beyond
`api`+`nginx` to every workload identity (§6.4).

The hierarchy below is the **Phase 2+** target, designed now so the migration is
mechanical later. It is reachable from the v1 state without re-issuing any
identity string: the SPIFFE IDs do not change, only the chain under them.

```mermaid
flowchart TB
  subgraph OFFLINE["AIR-GAPPED — never on a stack host"]
    ROOT["Correlix Root CA<br/>ECDSA P-384 · 10y · pathlen 1<br/>key: HSM / offline TPM / paper-split"]
  end
  ROOT -->|"ceremony, 1y validity, pathlen 0"| WI["Workload Intermediate<br/>correlix.workload"]
  ROOT -->|"ceremony, 1y validity, pathlen 0"| DI["Device Intermediate<br/>correlix.device"]
  ROOT -->|"ceremony, 1y validity, pathlen 0"| OI["Operator Intermediate<br/>correlix.operator"]
  WI --> WL["Workload SVIDs · 24h · ECDSA P-256<br/>api · nginx · vector-* · collectors · datastores · kafka"]
  DI --> DL["Device certs · 90d · ECDSA P-256<br/>syslog-TLS · gNMI · vantages · site gateways"]
  OI --> OL["Operator certs · 8h · ECDSA P-256<br/>break-glass · securityadmin · admin automation"]
  PUB["Public / enterprise CA<br/>(entirely separate chain)"] --> NGX["nginx browser-facing cert"]
  KEK["Secret-encryption authority<br/>TPM/HSM/KMS-sealed KEK → per-tenant DEKs<br/>NOT a transport CA"]
  BKP["Backup-encryption authority<br/>separate keys from every live credential"]
```

Separation rationale (HLD §6.1 / ADR-SEC-002, restated as an implementation
constraint): a device intermediate must be **incapable** of minting a workload
identity. That is enforced two ways, both required:

1. **Chain**: distinct intermediates, `MaxPathLen: 0` on each, so no
   intermediate can sign another CA.
2. **Verifier**: `tlsconfig.FederationTrust` already binds a peer's SPIFFE trust
   domain to the CA root that anchored its chain
   (`tlsconfig/federation.go:179`, `tls-architecture.md:139-161`). Registering
   `correlix.workload` → workload-intermediate root and `correlix.device` →
   device-intermediate root makes a device certificate presenting a
   `spiffe://correlix.workload/...` ID a **rejected** connection, not a trusted
   one. This is existing, tested code being pointed at a new problem — no new
   Go dependency.

## 6.3.3 TTLs and windows

Rows marked `[v1]` are what v1 actually runs; the rest are Phase 2+.

| Layer | Algorithm | Validity | Renew before | Notes |
|---|---|---|---|---|
| **`[v1]` Workload root (self-signed, in-process)** | ECDSA P-256 | **10y** (`tls_ca.go:34`) | n/a | unchanged; key sealed (§6.19.7) |
| **`[v1]` Workload SVID** | ECDSA P-256 (`ca.go:157`) | **24h** (`docker-compose.yml:1464`) | **12h** — TTL/2, already implemented (`tls_ca.go:163`) | hot-reloaded, no restart |
| **`[v1]` nginx public cert** | per issuer | per issuer | 30d | ACME or manual; separate chain (§6.13.1) |
| `[Phase 2+]` Offline root | ECDSA P-384 | 10y | 2y (overlap) | ceremony only. P-384 for the root only — the leaf floor stays P-256 to match `ca.go:157` |
| `[Phase 2+]` Intermediate (each) | ECDSA P-256 | 1y | 90d | online, sealed at rest (§6.19) |
| `[Phase 2+]` Device cert | ECDSA P-256 | **90d** | 21d | renewal is a customer-visible operation; short TTLs are hostile on field gear `[ASSUMPTION]` |
| `[Phase 2+]` Operator cert | ECDSA P-256 | **8h** | n/a — reissue | time-boxed like the existing break-glass |

`[UNKNOWN]` The 24h workload TTL has never been exercised under load in this
stack. HLD §11 standing risk (handshake cost) applies: measure handshake rate
and connection reuse on the high-fan-out lanes (`vector-aggregator` → Kafka,
collectors → Vector) before Phase 3 cutover.

## 6.3.4 Certificate lifecycle

```mermaid
stateDiagram-v2
  [*] --> Requested: service starts / renew timer fires
  Requested --> Issued: intermediate signs (SPIFFE URI SAN + DNS SANs)
  Issued --> Distributed: writeFileAtomic cert 0644 / key 0600 (tls_ca.go:104-107)
  Distributed --> Active: CertReloader modtime poll picks it up (tlsconfig/reload.go:106)
  Active --> Renewing: age >= renew_before (TTL/2 loop, tls_ca.go:159-181)
  Renewing --> Issued: re-issue succeeds
  Renewing --> Degraded: re-issue fails
  Degraded --> Issued: retry succeeds (old cert still served — reload.go keeps last good)
  Degraded --> Expired: TTL elapses with no successful re-issue
  Expired --> [*]: handshakes fail closed; netops_tls_cert_expiry_seconds <= 0 alerts
  Active --> Revoked: emergency rotation (§6.3.7)
  Revoked --> [*]: identity removed from allowlists + trust bundle rolled
```

The `Degraded` state is real behavior, not aspiration: `tlsconfig/reload.go`
keeps the last good certificate on a reload error and the failure is logged
(`tls-architecture.md:108-111`), while `/admin/readyz` asserts cert validity with
a 5-minute margin (`tls-architecture.md:120`). §6.23 adds the metric that makes
`Degraded` visible before it becomes `Expired`.

## 6.3.5 Renewal and rotation windows

- **Leaf**: renew at TTL/2. Already implemented. Hot-reload means zero
  connection loss for the Go API; §6.6 enumerates which other services can do
  the same and which cannot.
- **Intermediate**: publish the new intermediate into every trust bundle
  **before** any leaf is issued under it. Overlap ≥ 2× the longest leaf TTL
  (48h for workload, 180d for device).
- **Root**: dual-root, §6.3.6.

## 6.3.6 Dual-root rotation `[v1 — same sequence, one root]`

The sequence below is written for the Phase 2+ offline root, but **v1 runs the
identical choreography with the in-process root**: `tlsconfig.TrustBundle`
already carries multiple roots (`tlsconfig/trust.go:16-64`), and `LoadTrustBundle`
accepts a list of paths (`trust.go:26`). So a v1 CA rotation is: generate the new
CA, publish a two-root bundle, wait for `netops_tls_trust_bundle_version` to
converge, let the TTL/2 loop re-mint every leaf under the new root, then publish
the single-root bundle. No ceremony, no downtime, no new code — this is the
rotation story we show customers, and it is exercised in staging as an HLD §9
Phase 6 completion criterion.

```mermaid
sequenceDiagram
  participant OPS as Operator (ceremony)
  participant ROOT as Offline root store
  participant INT as Online intermediate
  participant BUNDLE as Trust bundle (data/api/tls/ca.pem)
  participant SVC as Every service

  Note over ROOT: T0 — generate ROOT-B offline
  OPS->>ROOT: ceremony: create ROOT-B (witnessed, logged)
  OPS->>BUNDLE: publish bundle = [ROOT-A, ROOT-B]
  BUNDLE->>SVC: distribute (§6.5); each end RELOADS trust
  Note over SVC: T0+soak — every service trusts BOTH roots.<br/>Nothing is issued under ROOT-B yet.
  SVC-->>OPS: netops_tls_trust_bundle_version == N+1 on 100% of services
  OPS->>ROOT: ceremony: sign INT-B under ROOT-B
  ROOT->>INT: INT-B installed, INT-A still live
  Note over INT: T1 — switch issuance to INT-B
  INT->>SVC: next TTL/2 re-issue mints ROOT-B leaves
  Note over SVC: T1 + 2×leaf_ttl — every leaf chains to ROOT-B
  SVC-->>OPS: zero leaves anchored to ROOT-A
  OPS->>BUNDLE: publish bundle = [ROOT-B]
  BUNDLE->>SVC: distribute; reload
  Note over ROOT: T2 — ROOT-A retired, key destroyed per ceremony doc
```

The gating condition between each step is a **metric**, not a stopwatch:
proceed only when `netops_tls_trust_bundle_version` has converged across every
service (§6.23). `tlsconfig.TrustBundle` already carries multiple roots and
reloads (`tlsconfig/trust.go:16-64`), which is why this sequence needs no new
Go machinery — only the distribution and the convergence signal.

## 6.3.7 Revocation and emergency rotation

**Revocation is by short TTL.** No CRL, no OCSP — the position already taken in
`tls-architecture.md:27` and `:104`, and the right one at this scale. Concretely:

1. Remove the identity from every `inbound.allowed_identities` (this is
   immediate — it is an allowlist check in `tlsconfig/verify.go:49`, not a
   revocation list lookup).
2. Stop re-issuing that identity.
3. Within one leaf TTL (24h workload / 90d device), the certificate is dead.

That gap is unacceptable for a **device** cert (90d). So the device plane gets a
second, immediate control: the cert→device→tenant binding is a **database
lookup** at connection time (§6.15.2). Marking the device record revoked kills
the binding in seconds, regardless of certificate validity. **The certificate
authenticates; the registry authorizes.**

**Emergency CA rotation** (suspected intermediate or root compromise) collapses
§6.3.6 into a break-glass runbook (`security/pki/ceremonies/emergency-rotation.md`):
issue the new root, push a bundle containing **only** the new root, accept that
every service must re-obtain a leaf, and accept a bounded outage. Rehearsed in
staging as a Phase 6 completion criterion (HLD §9 Phase 6).

## 6.3.8 Trust-bundle distribution and versioning

Today the bundle is one file written by the API at `TLS_CLIENT_CA_FILE`
(`tls_ca.go:139-143`) via `writeFileAtomic` (`tls_ca.go:185-196`). Target:

- The bundle is a **PEM concatenation of active roots**, plus a sidecar
  `ca.version` file containing a monotonic integer and a SHA-256 of the bundle.
- Every consumer exports `netops_tls_trust_bundle_version` and
  `netops_tls_trust_bundle_age_seconds`. Divergence is the drift alert (HLD T19).
- Distribution on Compose is the **shared `data/api/tls` volume** already used by
  the runbook (`docs/runbooks/tls-mtls.md:42`). Services that cannot read a Go
  file watcher (nginx, Kafka, OpenSearch, ClickHouse, Postgres, Valkey) get the
  bundle mounted read-only and a reload driven by §6.6.
- `TLS_FEDERATED_BUNDLES` is implemented in Go
  (`backend_client.go:42`, `tlsconfig/federation.go:90`) but **absent from
  `docker-compose.yml`** — verified: the compose TLS block is
  `docker-compose.yml:1455-1472` and contains no such key. Phase 2 adds it.

## 6.3.9 Key custody

| Key | Today | **v1** | Phase 2+ |
|---|---|---|---|
| Internal CA private key | in-process, sealed under the platform DEK when a provider is set (`tls_ca.go:16-17,33`); **plaintext when not** (`tls_ca.go:23-24`) | **unchanged location, but boot refusal when unsealed** (§6.19.7) | intermediate-only; root offline |
| Root key | single self-signed root (`internalca/ca.go:41-63`) | same | **offline** — HSM, offline TPM, or split-knowledge backup |
| Leaf keys | 0600 on disk (`tls_ca.go:107`) | unchanged; §6.5 adds ownership + read-only-mount rules | same |
| KEK | swtpm sidecar, opt-in profile (`docker-compose.yml:1686-1699`) | **`SEAL_PROVIDER` required in the production profile** | real TPM/HSM/KMS behind the same `SealingProvider` (`secret-custody.md:58-62`) |

**Resolved (D2).** Moving the root offline would change the appliance install
from "zero-touch" to "import an intermediate", and the owner's steer is
explicitly against that overhead in v1. The **Phase 2+** path, when wanted, is a
profile split rather than a rewrite: lab/dev keep today's self-bootstrap
(`TLS_INTERNAL_CA=true`); staging/production require an imported intermediate and
refuse to self-generate. Nothing in v1 forecloses it — `loadOrCreateCA`
(`tls_ca.go:118-133`) already separates "load" from "create", so "load an
imported intermediate, never create" is a flag, not a redesign.

The **only** custody change v1 makes is the one that closes a real hole: the CA
key must be sealed. That is §6.19.7, and it is a v1 blocker.

---

# 6.4 Workload identities

## 6.4.1 The identity string, and the one code change it needs

`tls_ca.go:91-93` emits:

```go
func (m *caManager) spiffeID(svc string) string {
	return "spiffe://" + m.trustDomain + "/ns/default/sa/" + svc
}
```

The **shape** matches the HLD §6.2 format, but the namespace is the hardcoded
literal `default`. The HLD's per-namespace format
(`spiffe://correlix.workload/ns/<ns>/sa/<svc>`) therefore **requires a code
change**, not just configuration. This is a **v1** change and it is small:
`spiffeID` takes a namespace, and the issuance table below supplies it. See §7
for the HLD correction.

Rules (HLD §6.2, restated as validator rules — V-04, V-06, F-05, F-11):

- **No wildcards.** `tlsconfig/verify.go:78` compares URI SANs by exact,
  case-sensitive string equality — there is no glob to abuse, and none will be
  added.
- **One identity per service role.** `vector-aggregator` and `vector-router` are
  two identities, not one "vector".
- **SAN carries both** the URI SAN (identity) and the DNS names actually
  dialled. `issueService` already takes a `dns []string` (`tls_ca.go:97`); today
  it is called with `{"api","localhost"}` and `{"nginx"}` (`tls_ca.go:146,152`).
- **Hostname verification is mandatory** — structurally, not by policy:
  `tlsconfig/config.go:80` requires a non-empty `ServerName`.

## 6.4.2 The v1 least-privilege gap that must close with it

`tlsconfig/verify.go:62-64`: **an empty `PeerPolicy` allowlist returns `nil`** —
chain verification alone suffices. So with `TLS_CLIENT_ALLOWED_URIS` unset, *any*
holder of *any* mesh certificate is accepted. mTLS without an allowlist is
authentication without authorization, which is HLD §10's explicitly rejected
option. **v1 rule: every mTLS server in the stack sets a non-empty
`allowed_identities`; the production validator rejects an empty one (F-04).**

## 6.4.3 Identity table — every service in `docker-compose.yml`

Namespaces are the HLD §6.2 set: `ingress`, `app`, `ingestion`, `streaming`,
`storage`, `identity`, `ops`.

Columns: **Compose service** (exact `docker-compose.yml` key) · **Profile** ·
**Logical SPIFFE ID** · **Compose certificate identity / files** · **Future k8s
ServiceAccount** · **v1?**

| Compose service | Profile | SPIFFE ID | Compose cert files (under the shared TLS dir, §6.5) | k8s ServiceAccount | v1 |
|---|---|---|---|---|---|
| `nginx` (`:1712`) | — | `spiffe://correlix.workload/ns/ingress/sa/nginx` | `nginx/nginx.{crt,key}` — **already minted** (`tls_ca.go:150-155`) | `ingress/nginx` | ✅ |
| `frontend` (`:1701`) | — | *(none)* — static asset server, never dialled over TLS by another service; reached only via nginx on the compose network | — | `ingress/frontend` | n/a |
| `api` (`:1054`) | — | `spiffe://correlix.workload/ns/app/sa/api` | `api.{crt,key}` — **already minted** (`tls_ca.go:145-148`) | `app/api` | ✅ |
| `correlation` (`:958`) | — | `spiffe://correlix.workload/ns/app/sa/correlation` | `correlation/correlation.{crt,key}` | `app/correlation` | ✅ |
| `prober` (`:1534`) | `prober` | `spiffe://correlix.workload/ns/ingestion/sa/prober` | `prober/prober.{crt,key}` | `ingestion/prober` | ✅ |
| `vector-aggregator` (`:412`) | — | `spiffe://correlix.workload/ns/ingestion/sa/vector-aggregator` | `vector-aggregator/{tls.crt,tls.key}` | `ingestion/vector-aggregator` | ✅ |
| `vector-router` (`:462`) | — | `spiffe://correlix.workload/ns/ingestion/sa/vector-router` | `vector-router/{tls.crt,tls.key}` | `ingestion/vector-router` | ✅ |
| `syslog-ng` (`:272`) | — | `spiffe://correlix.workload/ns/ingestion/sa/syslog-ng` | `syslog-ng/{tls.crt,tls.key}` | `ingestion/syslog-ng` | ✅ (client cert to Vector `:6601`, §6.15.5) |
| `goflow2` (`:358`) | — | `spiffe://correlix.workload/ns/ingestion/sa/goflow2` | `goflow2/{tls.crt,tls.key}` | `ingestion/goflow2` | ✅ (Kafka client only — its UDP ingress is unauthenticable, §6.18) |
| `gnmic` (`:330`) | — | `spiffe://correlix.workload/ns/ingestion/sa/gnmic` | `gnmic/{tls.crt,tls.key}` | `ingestion/gnmic` | ✅ (northbound to vmauth; its southbound device leg is §6.17) |
| `telegraf` (`:313`) | `legacy` | `spiffe://correlix.workload/ns/ingestion/sa/telegraf` | *not issued* — the service must not run (§6.21.4) | `ingestion/telegraf` | ❌ |
| `cloud-ingest` (**override only**, `docker-compose.override.yml:27`) | — | `spiffe://correlix.workload/ns/ingestion/sa/cloud-ingest` | `cloud-ingest/{tls.crt,tls.key}` | `ingestion/cloud-ingest` | ✅ — **must be tracked in compose first** (§6.21.2) |
| `kafka` (`:190`) | `embedded-bus` | `spiffe://correlix.workload/ns/streaming/sa/kafka` | `kafka/{server.crt,server.key}` + `kafka/{controller.crt,controller.key}` (§6.7.2) | `streaming/kafka` | ✅ |
| `kafka-init` (`:247`) | `embedded-bus` | `spiffe://correlix.workload/ns/streaming/sa/kafka-admin` | `kafka-admin/{tls.crt,tls.key}` | `streaming/kafka-admin` | ✅ |
| `kafka-exporter` (`:732`) | `self-monitoring` | `spiffe://correlix.workload/ns/ops/sa/kafka-exporter` | `kafka-exporter/{tls.crt,tls.key}` | `ops/kafka-exporter` | ✅ |
| `opensearch` (`:519`) | — | `spiffe://correlix.workload/ns/storage/sa/opensearch` | `opensearch/{node.crt,node.key}` + `opensearch/{admin.crt,admin.key}` (§6.8.4) | `storage/opensearch` | ✅ |
| `opensearch-init` (`:567`) | — | `spiffe://correlix.workload/ns/ops/sa/opensearch-init` | `opensearch-init/{tls.crt,tls.key}` | `ops/opensearch-init` | ✅ |
| `opensearch-dashboards` (`:590`) | `osd` | `spiffe://correlix.workload/ns/ops/sa/opensearch-dashboards` | `osd/{tls.crt,tls.key}` | `ops/opensearch-dashboards` | ✅ |
| `clickhouse` (`:901`) | — | `spiffe://correlix.workload/ns/storage/sa/clickhouse` | `clickhouse/{server.crt,server.key}` | `storage/clickhouse` | ✅ |
| `victoria` (`:612`) | — | `spiffe://correlix.workload/ns/storage/sa/victoria` | `victoria/{tls.crt,tls.key}` | `storage/victoria` | ✅ |
| `vmalert` (`:683`) | — | `spiffe://correlix.workload/ns/ops/sa/vmalert` | `vmalert/{tls.crt,tls.key}` | `ops/vmalert` | ✅ |
| `postgres` (`:55`) | — | `spiffe://correlix.workload/ns/storage/sa/postgres` | `postgres/{server.crt,server.key}` | `storage/postgres` | ✅ |
| `redis` — **Valkey** (`:87`) | — | `spiffe://correlix.workload/ns/storage/sa/valkey` | `valkey/{server.crt,server.key}` | `storage/valkey` | ✅ (service key stays `redis` — `REDIS_HOST` consumers are untouched, `docker-compose.yml:92-94`) |
| `keycloak` (`:143`) | `sso` | `spiffe://correlix.workload/ns/identity/sa/keycloak` | `keycloak/{tls.crt,tls.key}` | `identity/keycloak` | ✅ |
| `grafana` (`:834`) | `self-monitoring` | `spiffe://correlix.workload/ns/ops/sa/grafana` | `grafana/{tls.crt,tls.key}` | `ops/grafana` | ✅ |
| `cadvisor` (`:750`) | `self-monitoring` | `spiffe://correlix.workload/ns/ops/sa/cadvisor` | `cadvisor/{tls.crt,tls.key}` | `ops/cadvisor` | ✅ (scrape target only) |
| `node-exporter` (`:820`) | `self-monitoring` | `spiffe://correlix.workload/ns/ops/sa/node-exporter` | `node-exporter/{tls.crt,tls.key}` | `ops/node-exporter` | ✅ (scrape target only) |
| `secrets-seal` (`:1686`) | `seal` | **no network identity — by design** | none. Its only channel is a Unix socket (`secrets_swtpm.go:23-24`), gated by filesystem permissions | `ops/secrets-seal` | ✅ (unchanged) |
| `gotenberg` (`:1667`) | `pdf` | `spiffe://correlix.workload/ns/ops/sa/gotenberg` | `gotenberg/{tls.crt,tls.key}` | `ops/gotenberg` | ⚠ TLS optional — renders untrusted HTML; §6.22 confines it by network policy instead |
| `netbox` (`:1772`) | `netbox` | `spiffe://correlix.workload/ns/app/sa/netbox` | `netbox/{tls.crt,tls.key}` | `app/netbox` | ✅ |
| `netbox-postgres` (`:1755`) | `netbox` | `spiffe://correlix.workload/ns/storage/sa/netbox-postgres` | `netbox-postgres/{server.crt,server.key}` | `storage/netbox-postgres` | ✅ |
| `mock-servicenow` (`:1615`) | `mock-snow` | **no identity** | none | none | ❌ — test fixture; §6.21.9 refuses the profile in production |
| `mock-nms` (`:1645`) | `mock-nms` | **no identity** | none | none | ❌ — same |

**32 tracked compose services + 1 override-only service.** Every row is
enumerated from the file; none is guessed.

## 6.4.4 Identities that are *not* workloads

| Identity | Trust domain | Phase | Notes |
|---|---|---|---|
| Browser-facing nginx certificate | **public / enterprise CA** | v1 | Separate chain. A public-CA mis-issuance must never be able to speak inside the mesh (`tls-architecture.md:53-58`) |
| Device certificates | `correlix.device` | Phase 2+ | `spiffe://correlix.device/tenant/<tenant_id>/kind/<device\|vantage\|gateway>/id/<device_id>` (HLD §6.2). §6.15.2 |
| Operator / break-glass certificates | `correlix.operator` | Phase 2+ | 8h TTL; `securityadmin` (§6.8.4) is the first consumer |
| Remote vantage | `correlix.device` | Phase 2+ | Today a shared `infrastructure:write` API key with the vantage id taken **from the request body** (`probe_paths_ingest.go:28,41,50`) — any holder can publish as any vantage. §6.13.11 |

## 6.4.5 Issuance change required in `tls_ca.go` `[v1]`

`provisionFromEnv` (`tls_ca.go:138-156`) mints **exactly two** SVIDs. v1 replaces
the two hardcoded blocks with a table-driven loop fed by
`security/pki/identities.yaml`:

```
for each identity in identities.yaml:
    issueService(<dir>/<name>.crt, <dir>/<name>.key,
                 namespace, name, ttl, dnsNames, client, server)
```

Constraints this must preserve, all already true today:
- `writeFileAtomic` for both files (`tls_ca.go:104,107`) — never a partial cert.
- cert `0644`, key `0600` (`tls_ca.go:104,107`).
- Re-entrant: `provisionFromEnv` is called both at boot and from the TTL/2 loop
  (`tls_ca.go:174`), so it must stay idempotent.
- Fail-closed: any issuance error aborts boot (`main.go:1331-1334`).

`[UNKNOWN]` Certificate **distribution** on Compose. `tls_ca.go` writes into the
API's own `/data` volume (`docker-compose.yml:1504`). Other services need those
files. Two candidate mechanisms, both dependency-free — the choice must be made
before Phase 2 build: (a) one shared named volume mounted read-only into every
service at a per-service subpath, or (b) a tiny init container per service that
copies its pair from the shared volume. (a) is fewer moving parts and is the
`[ASSUMPTION]` this document proceeds on; §6.5 specifies the layout for it.

---

# 6.5 Certificate file layout

## 6.5.1 Never in Git — verified

- `.gitignore:41-42` ignores `deployment/docker/nginx/certs/` (the whole
  directory), with the comment "TLS certs/keys for the nginx front".
- `git ls-files | grep -Ei '\.(key|pem|crt|p12|jks)$'` returns **nothing** — no
  key or certificate material is tracked anywhere in the repo.
- Runtime material lives under `data/`, which is gitignored per CLAUDE.md.
- `scripts/gen-dev-cert.sh:12,26,32` writes the lab self-signed pair into that
  ignored directory and `chmod 600`s the key.

**Rule (validator + CI):** a pre-commit/CI check greps the index for
`BEGIN (EC |RSA |)PRIVATE KEY` and for the extensions above, and fails. This is
cheap insurance against the one mistake that is unrecoverable.

## 6.5.2 Directory layout

```
data/api/tls/                          # the shared TLS volume (host: ../../data/api/tls)
├── ca.pem                             # trust bundle — 0644, world-readable ON PURPOSE
├── ca.version                         # monotonic int + sha256 of ca.pem  (§6.3.8)
├── api/        api.crt (0644)   api.key (0600)
├── nginx/      nginx.crt        nginx.key
├── correlation/ correlation.crt correlation.key
├── vector-aggregator/ tls.crt   tls.key
├── vector-router/     tls.crt   tls.key
├── syslog-ng/         tls.crt   tls.key
├── goflow2/           tls.crt   tls.key
├── gnmic/             tls.crt   tls.key
├── prober/            tls.crt   tls.key
├── cloud-ingest/      tls.crt   tls.key
├── kafka/      server.crt server.key  controller.crt controller.key
├── kafka-admin/       tls.crt   tls.key
├── kafka-exporter/    tls.crt   tls.key
├── opensearch/ node.crt node.key      admin.crt admin.key      # admin: 0600, mounted ONLY into the bootstrap job
├── opensearch-init/   tls.crt   tls.key
├── osd/               tls.crt   tls.key
├── clickhouse/ server.crt server.key
├── victoria/          tls.crt   tls.key
├── vmalert/           tls.crt   tls.key
├── postgres/   server.crt server.key
├── valkey/     server.crt server.key
├── keycloak/          tls.crt   tls.key
├── grafana/           tls.crt   tls.key
├── netbox/            tls.crt   tls.key
└── netbox-postgres/   server.crt server.key

deployment/docker/nginx/certs/         # BROWSER-facing chain only — separate on purpose
├── fullchain.pem                      # public/enterprise issuer
└── privkey.pem  (0600)
```

The browser chain stays in its own directory because it is a **different trust
domain** (§6.4.4) with a different lifecycle (ACME/manual vs 24h automatic). One
directory for both would invite the exact cross-domain mistake the design forbids.

## 6.5.3 Ownership and modes

Container users, verified:

| Service | Runs as | Evidence |
|---|---|---|
| `api` | `${CORRELIX_UID:-65532}:${CORRELIX_GID:-65532}` | `docker-compose.yml:1062`; image default `nonroot` (`Dockerfile.backend:36`) |
| `nginx` | uid **101** | `Dockerfile.nginx:15` (`USER 101`), compose comment `:1713-1714` |
| `frontend` | uid **101** | `Dockerfile.frontend:49` |
| `correlation` | `appuser` | `Dockerfile.correlation:27`, compose `:959` |
| `grafana` | `${CORRELIX_UID:-472}:${CORRELIX_GID:-472}` | `docker-compose.yml:839` |
| `opensearch` | uid **1000** | `opensearch/Dockerfile:50` |
| `prober` | `0:0` + `cap_drop: ALL` + `cap_add: NET_RAW` | `docker-compose.yml:1549-1559` |
| `cloud-ingest` | `poller` | `docker-compose.override.yml:32` |
| `postgres` / `clickhouse` / `kafka` / `victoria` / `valkey` | image defaults (not pinned in compose) | — |

Rules:

| Artifact | Mode | Owner | Mount |
|---|---|---|---|
| `ca.pem`, `ca.version` | `0644` | writer (api uid) | **read-only** into every service |
| `<svc>/*.crt` | `0644` | writer | **read-only** into that service only |
| `<svc>/*.key` | `0600` | **the consuming service's uid** | **read-only** into that service only |
| `opensearch/admin.key` | `0600` | init-job uid | mounted **only** into `opensearch-init`, never into a long-lived service (§6.8.4) |
| `nginx/certs/privkey.pem` | `0600` | uid 101 | read-only |

The heterogeneous-uid problem is real and already bit this project once: the API
image's default uid could not write a customer-created `data/api`, which is why
`CORRELIX_UID` exists at all (`docker-compose.yml:1057-1061`). Keys written by
the API (uid 65532) and read by nginx (uid 101), OpenSearch (1000) or Grafana
(472) will not be readable at `0600`.

**Resolution (v1):** a per-service key is written `0640` with **group** =
`CORRELIX_GID`, and every service that must read a key is run with
`CORRELIX_GID` as a supplementary group via compose `user: "<uid>:${CORRELIX_GID}"`.
`install.py` already computes and writes `CORRELIX_UID`/`CORRELIX_GID`, so this
is configuration, not new machinery. `[ASSUMPTION]` — `0640`+shared group is a
deliberate, documented relaxation from `0600`; the alternative (per-service
`chown` from a privileged init container) reintroduces a root container, which
is worse. The validator asserts the mode is exactly `0640` and the group is not
`root`/`0`.

## 6.5.4 Read-only mounts

Every certificate mount is `:ro`. This is already the repo's habit for config
(`docker-compose.yml:283`, `:321`, `:350`, `:440`, `:489`, `:585`, `:892`,
`:925-941`, `:1503`, `:1507`, `:1724-1725`). A service that could rewrite its own
certificate could mint itself a new identity from a stolen key without the CA
noticing.

**Exception:** the writer (`api`) mounts the TLS dir read-write — it is the
issuer. §6.22 constrains that with the network matrix; §6.20 does it properly
with a k8s CSI volume.

## 6.5.5 Atomic replace

Already implemented and correct — `tls_ca.go:185-196`:

```go
tmp := path + ".tmp"
os.WriteFile(tmp, data, perm)   // :192 — written with the FINAL perm, not 0644-then-chmod
os.Rename(tmp, path)            // :195 — atomic within a filesystem
```

Consumers therefore never observe a half-written key. Two v1 refinements:

1. **`fsync` before rename** — `writeFileAtomic` does not sync (`tls_ca.go:192`).
   On an unclean shutdown the rename can land with empty contents. The reissue
   loop is deliberately tracked rather than a bare goroutine for exactly this
   reason (`main.go:1350-1352`); adding the sync closes the remaining window.
2. **Write key before cert.** A consumer polling on the *cert*'s modtime
   (`tlsconfig/reload.go:121`) must not pick up a new cert paired with an old
   key. `issueService` already writes cert then key (`tls_ca.go:104-107`) — this
   is the wrong order for a modtime-triggered reloader and must be swapped.
   `[UNKNOWN]` whether this has ever produced a real mismatch; the reloader parses
   the pair and keeps the last good one on error (`tlsconfig/reload.go:41`), so
   the failure is self-correcting on the next poll — but it is still a
   transient, avoidable error.

## 6.5.6 Chain and bundle formats

| Artifact | Format | Note |
|---|---|---|
| Trust bundle `ca.pem` | PEM concatenation of active roots | `tlsconfig.LoadTrustBundle` accepts multiple files and multiple certs per file (`tlsconfig/trust.go:26`) |
| Leaf cert | PEM, **leaf first**, then intermediates (Phase 2+), root omitted | `FederationTrust.bindChainToDomain` documents leaf-first/root-last (`tlsconfig/federation.go:178`) |
| Leaf key | PEM `EC PRIVATE KEY` (SEC1) | `internalca/ca.go:28` |
| OpenSearch | PEM; the security plugin wants separate `pemcert`/`pemkey`/`pemtrustedcas` | §6.8.2 |
| Kafka | **JKS or PKCS#12** — Kafka's `ssl.keystore.type` does not read raw PEM in all paths | §6.7.2. `[UNKNOWN]` whether `apache/kafka:4.1.1` supports `ssl.keystore.type=PEM` end-to-end; must be verified before Phase 3, and if not, a conversion step (`openssl pkcs12 -export`) runs in the cert-init job |
| Postgres | PEM `server.crt`/`server.key`, key mode ≤ `0600` or Postgres refuses to start | §6.11.1 |
| ClickHouse | PEM in `config.d/tls.xml` | §6.9.1 |
| Valkey | PEM | §6.12.1 |

---

# 6.6 Certificate reload design

The question this section answers, per service: **can it pick up a rotated
certificate without dropping a connection?** A 24h leaf TTL means this happens
twice a day, every day. Anything that requires a restart is a twice-daily
telemetry gap unless it is handled.

| Service | Hot reload? | Mechanism | Restart needed? | Draining | Telemetry-loss risk | v1 approach |
|---|---|---|---|---|---|---|
| **`api`** | **Yes** | `tlsconfig.CertReloader` — modtime poll, `GetCertificate`/`GetClientCertificate` (`tlsconfig/reload.go:33,77,83,106`); watcher started at `main.go:1353-1357`; interval `TLS_RELOAD_INTERVAL` default 30s (`tls_server.go:123`) | **No** | n/a — new handshakes get the new cert, in-flight connections keep the old | **None** | unchanged — this is the reference implementation |
| **`nginx`** | **Yes, with a signal** | `SIGHUP` re-reads `ssl_certificate`, `proxy_ssl_certificate` and `proxy_ssl_trusted_certificate`. Old workers finish their connections (graceful) | No | **Yes — nginx's own graceful worker shutdown** | None | a tiny sidecar or the api's reissue loop `docker kill -s HUP netops-nginx-1`. `[ASSUMPTION]` — reaching the Docker socket from the API is undesirable; preferred is a **1-line reload sidecar** watching `ca.version` + the cert modtime. `[UNKNOWN]` exact mechanism — decide before Phase 1 |
| **`kafka`** | **Yes** | Kafka reloads keystore/truststore when `ssl.keystore.location` file changes **and** the store is re-pointed via a dynamic broker config update (`kafka-configs.sh --alter --entity-type brokers`). File-only rewrite is **not** picked up reliably | No, if driven by the admin API | Existing connections unaffected | **High if mishandled** — the bus is the spine | v1: cert-init job rewrites the keystore, then issues the dynamic-config update using the `kafka-admin` identity. `[UNKNOWN]` verify on `apache/kafka:4.1.1` in staging before Phase 3 |
| **`opensearch`** | **Partial** | The security plugin hot-reloads **transport and http certificates** when `plugins.security.ssl.certificates_hot_reload.enabled: true`; **the truststore/CA is not hot-reloaded in 2.x** | Restart required for a **CA** change | Single-node (`discovery.type: single-node`, `docker-compose.yml:535`) → a restart **is** an outage | Indexing pauses; Vector's sink retries with backoff | v1: enable hot reload for leaves; schedule CA rotation as a maintenance action. Multi-node rolling restart is a Phase 2+ concern |
| **`clickhouse`** | **Yes** | ClickHouse watches `config.d/` and reloads certificates on change (no restart) | No | n/a | Low — the Vector sink retries | v1: rewrite `config.d/tls.xml` paths never change; only the PEM files do |
| **`postgres`** | **Yes, with a signal** | `SIGHUP` / `pg_reload_conf()` re-reads `ssl_cert_file`, `ssl_key_file`, `ssl_ca_file`. Existing sessions keep the old cert | No | Existing sessions unaffected | None | v1: reload sidecar sends `SIGHUP` (same mechanism as nginx) |
| **`valkey`** | **Yes, with a command** | `CONFIG SET tls-cert-file` / `tls-key-file` / `tls-ca-cert-file`, or Valkey 8's automatic reload on file change `[UNKNOWN]` — verify on `valkey/valkey:8-alpine` | No | n/a | Low — Valkey holds TTL'd collector caches (`docker-compose.yml:93-94`) | v1: reload sidecar issues `CONFIG SET` over the ACL user |
| **`victoria` / `vmalert` / `vmauth`** | **Yes** | VictoriaMetrics components reload TLS certificates from disk automatically (`-tls*` flags re-read on change) `[UNKNOWN]` — verify on `v1.101.0` | No | n/a | Low | v1: file rewrite only |
| **`vector-aggregator` / `vector-router`** | **No — restart** | Vector reads `tls.crt_file`/`key_file` at topology build. `--watch-config` (`docker-compose.yml:476`) reloads on **config file** change, not cert change | **Yes** | Vector drains sources on reload and validates the new topology, keeping the old one on error (`docker-compose.yml:473-475`) | **Real** — the aggregator is the funnel for four ingest lanes and syslog | v1: the cert-init job **touches the config file** after rewriting certs, turning a cert rotation into a config reload the router already handles safely. Aggregator has no `--watch-config` today → add it, or accept a rolling restart with the F-04 disk buffer (`docker-compose.yml:441-444`) absorbing the gap |
| **`syslog-ng`** | **Yes, with a signal** | `SIGHUP` reloads the configuration including `tls()` blocks | No | Reload is graceful; the F-48 disk buffer (`docker-compose.yml:286-288`) covers the window | Low — buffered | v1: reload sidecar |
| **`goflow2`** | **No — restart** | No documented cert-reload path | Yes | UDP ingress is connectionless; a restart drops in-flight datagrams | **Low but non-zero** — flows are lossy by protocol anyway | v1: restart on rotation, scheduled off-peak |
| **`gnmic`** | **No — restart** | Config read at start | Yes | gNMI subscriptions re-establish | Gap = reconnect time | v1: restart on rotation |
| **`correlation`** | **No — restart** `[UNKNOWN]` | Python/httpx client built once (`main.py:1830`); a Kafka/CH client rebuild would be new code | Yes, unless code is added | Consumer group rebalance; offsets are committed, so **no loss**, only latency | Low — at-least-once with idempotent consumers | v1: restart on rotation. The DLQ (`docker-compose.yml:968-971`) is the safety net |
| **`keycloak` / `grafana` / `osd` / `netbox`** | Varies | Keycloak: restart. Grafana: restart. OSD: restart | Yes | Human-facing; brief 502 | None (no telemetry) | v1: restart on rotation |
| **`prober` / `cloud-ingest` / `kafka-exporter` / `cadvisor` / `node-exporter`** | No | — | Yes | — | None / low | v1: restart on rotation |

## 6.6.1 The reload sidecar `[v1]`

Four services need a **signal** (`nginx`, `postgres`, `syslog-ng`) or a
**command** (`valkey`, `kafka`) rather than a file watch. Rather than five
bespoke mechanisms, v1 ships one small, auditable component:

- Watches `data/api/tls/ca.version` and each service's cert modtime.
- On change, performs that service's declared reload action, read from
  `security/pki/identities.yaml` (`reload: {kind: sighup|command|restart|none, ...}`).
- Emits `netops_tls_reload_total{service,outcome}` (§6.23).
- Written in Go against the stdlib, or as a shell script under `scripts/` — in
  which case CLAUDE.md §16 / `scripts/CLAUDE.md` applies in full (never swallow
  an error, hostile-cron environment, explicit `PATH`).
- **It must not hold the Docker socket** if avoidable. Signals to processes in
  other containers require either the socket or a shared PID namespace; the
  preferred design is **one reloader per service** in the same PID namespace
  (`pid: "service:<name>"`), which needs no socket at all. `[ASSUMPTION]`

## 6.6.2 Reload failure is not a silent event

Existing behavior to preserve: a reload error keeps the **last good**
certificate and logs (`tlsconfig/reload.go:41`, `tls-architecture.md:108-111`) —
serving a still-valid cert beats dropping the listener. v1 adds:

- `netops_tls_reload_total{service,outcome="error"}` increments,
- an alert at `outcome="error"` for > 2 consecutive intervals,
- and the posture view (§6.24) shows the service as **Degraded**, not **OK**,
  which is the customer-visible half of decision D10.

---

# 6.7 Kafka LLD `[v1]`

## 6.7.1 Current state

```yaml
KAFKA_LISTENERS: "PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093"     # :207
KAFKA_ADVERTISED_LISTENERS: "PLAINTEXT://kafka:9092"                       # :208
KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: "PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT"  # :210
KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"                                    # :217
```

No TLS, no SASL, **no ACLs, no authentication of any kind**. Single-node KRaft;
broker and controller are the same process (`docker-compose.yml:202`). Nothing
is published to the host (`:204-206`) — the *only* current control is compose
network reachability. Health check is a bare TCP accept (`:232`).

## 6.7.2 Listeners

Three named listeners, replacing the two:

```yaml
KAFKA_LISTENERS: "CLIENT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093,MIGRATION://0.0.0.0:9094"
KAFKA_ADVERTISED_LISTENERS: "CLIENT://kafka:9092,MIGRATION://kafka:9094"
KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: "CLIENT:SSL,CONTROLLER:SSL,MIGRATION:PLAINTEXT"
KAFKA_CONTROLLER_LISTENER_NAMES: "CONTROLLER"
KAFKA_INTER_BROKER_LISTENER_NAME: "CLIENT"        # single node; explicit anyway
```

| Listener | Port | Protocol | Purpose | Lifetime |
|---|---|---|---|---|
| `CLIENT` | 9092 | **SSL (mTLS)** | every producer and consumer | permanent |
| `CONTROLLER` | 9093 | **SSL (mTLS)** | KRaft quorum. Single-node today, but leaving it plaintext would make a future multi-node cluster insecure by default | permanent |
| `MIGRATION` | 9094 | PLAINTEXT | **temporary**, §6.7.10 | **expires** |

Broker TLS settings:

```
ssl.keystore.location=/etc/kafka/tls/kafka.server.keystore.p12
ssl.keystore.type=PKCS12                 # or PEM — see §6.5.6 [UNKNOWN]
ssl.truststore.location=/etc/kafka/tls/kafka.truststore.p12
ssl.client.auth=required                 # mTLS, not optional — this is the authn
ssl.endpoint.identification.algorithm=HTTPS   # hostname verification ON (HLD invariant)
ssl.enabled.protocols=TLSv1.3,TLSv1.2
ssl.cipher.suites=<the tlsconfig/policy.go:31-39 ECDHE+AEAD set>
```

`ssl.endpoint.identification.algorithm` **must not** be blank. Blank is Kafka's
documented way to disable hostname verification and is forbidden by the HLD
non-negotiable invariants and by validator rule F-02.

## 6.7.3 Why mTLS, not SASL_SSL `[decision D5]`

SASL/SCRAM would introduce a **second credential store** — SCRAM credentials
live in the cluster metadata, are created with `kafka-configs.sh`, and have
their own creation, distribution, rotation and audit story. That is a whole
parallel lifecycle to build and operate.

mTLS reuses certificates the platform **already mints and already rotates
automatically** (`tls_ca.go:159-181`). One identity model, one rotation
mechanism, one place to revoke. The cost — every client must handle certificates
— is real for goflow2 and the Python correlation service, and §6.7.9 addresses
each. It is still less operational surface than a second credential store.

## 6.7.4 Principal mapping

Kafka derives a principal from the client certificate's **subject DN** by
default: `User:CN=...,OU=...`. Our leaves set
`Subject: pkix.Name{CommonName: req.SPIFFEID}` (`internalca/ca.go:175`), so the
DN is literally `CN=spiffe://correlix.workload/ns/ingestion/sa/vector-aggregator`.

```
ssl.principal.mapping.rules=RULE:^CN=spiffe://[^/]+/ns/([^/]+)/sa/([^,/]+).*$/$1.$2/,DEFAULT
```

This maps the certificate to the principal `User:ingestion.vector-aggregator` —
short, stable, and readable in ACL output and audit logs.

Two properties that matter:

1. **The mapping is derived from the CN, which the CA controls.** A client
   cannot choose its own principal.
2. **`DEFAULT` is retained deliberately**, so a certificate that does *not* match
   the SPIFFE shape maps to its raw DN and therefore matches **no ACL** —
   fail-closed, and visible in the denial log as an obviously-wrong principal.

`[UNKNOWN]` Kafka also supports mapping from the **URI SAN**
(`ssl.principal.mapping.rules` operates on the DN only in current releases).
Since `internalca` puts the SPIFFE ID in *both* the CN (`ca.go:175`) and the URI
SAN (`ca.go:181`), DN-based mapping is sufficient and needs no change to
issuance. Verify on `apache/kafka:4.1.1`.

## 6.7.5 Topic ownership

Enumerated from the actual configs — every topic, its producer, its consumers,
and the citation for each.

| Topic | Pre-created | Producer(s) | Consumer(s) |
|---|---|---|---|
| `netops.applogs` | `:255` | vector-aggregator (`vector/vector.yaml:1013`) | vector-router (`vector-router/vector.yaml:107`) |
| `netops.syslog` | `:255` | vector-aggregator (`:1021`) | vector-router (`:114`), correlation (`main.py:137`) |
| `netops.flows` | `:255` | **goflow2** (`docker-compose.yml:395`) | vector-router (`:121`), correlation (`main.py:137`) |
| `netops.snmptrap` | `:255` | vector-aggregator (`:1070`) | vector-router (`:128`), correlation (`main.py:137`) |
| `netops.probes` | `:256` | vector-aggregator (`:1105`) | correlation (`main.py:137`) |
| `netops.metrics` | `:256` | vector-aggregator (`:1148`) | correlation (`main.py:137`) |
| `netops.cloud` | `:256` | vector-aggregator (`:994`) | correlation (`main.py:137`) |
| `netops.cloudlogs` | `:258` | vector-aggregator (`:1005`), cloud-ingest | vector-router (`:139`) |
| `netops.cloudcosts` | `:258` | cloud-ingest | vector-router (`:162`) |
| `netops.deadletter` | `:258` | vector-aggregator (`:1035`) | vector-router (`:151`) |
| `netops.app.identities.v1` | `:256` | api **via the bus bridge** (`fusion_worker.go:86` → `vector/vector.yaml:1188`) | correlation (`main.py:137`) |
| `netops.controller_events` | `:257` | api via bus bridge (`nms/topics.go:11`) | correlation (`main.py:137`) |
| `netops.app.edge` | `:257` | *(no producer found)* | correlation (`main.py:137`) |
| `netops.verification` | `:257` | api via bus bridge (`verify_service.go:25`) | correlation (`main.py:137`) |
| `netops.events` | **not pre-created** | api via bus bridge (`nms/topics.go:14`) | — |
| `netops.wireless_sessions` | **not pre-created** | *(bus bridge)* | correlation (`main.py:141`) |
| `netops.wireless_events` | **not pre-created** | *(bus bridge)* | correlation (`main.py:141`) |
| `netops.port.{inventory,metrics,lanes,optical,events,health}.v1` | **not pre-created** | Port Intelligence collectors (`portintel/topics.go:13-18`) | router (planned) |

**Finding:** four to ten topics exist only by broker auto-creation
(`docker-compose.yml:217`). With ACLs on and `auto.create.topics.enable=false`
(§6.7.8), those lanes **break**. The `kafka-init` list at `:255-258` must be
extended to the full set above **before** Phase 3, or those consumers fail
closed at exactly the wrong moment. This is a v1 blocker and is cheap.

## 6.7.6 The bus bridge is the sharpest ACL problem

The Go API has **no Kafka client** — the backend is stdlib-only
(`bus_producer.go:17-23`). It produces by POSTing envelopes to the Vector
aggregator's `bus_in` HTTP source at `:8692` (`bus_producer.go:29-40`,
`docker-compose.yml:1097`), and Vector's `kafka_bus` sink writes to a
**templated topic** taken from the envelope: `topic: "{{ __topic }}"`
(`vector/vector.yaml:1188`).

The only guard is a prefix check in VRL:

```
t = to_string(.topic) ?? ""                              # vector/vector.yaml:772
if !starts_with(t, "netops.") { abort }                  # vector/vector.yaml:773
```

The file says so itself (`vector/vector.yaml:96-99`, `:162-163`): *"the netops.*
prefix check in bus_bridge is a routing guard, never an identity guard."* And
`collectors/ingest_auth.go:17-24` records the consequence: a foothold with the
shared token could "inject events onto any netops.* topic carrying a FORGED
tenant_id, which vector-router then routes into that tenant's OpenSearch index."

**Consequence for the ACL matrix:** `vector-aggregator` holds the union of every
bus-bridge topic's produce right. Kafka ACLs cannot subdivide it, because Kafka
sees one principal. So the subdivision must happen **before** Kafka:

1. **v1 (required):** replace the prefix check with an **allowlist** of the exact
   topics the bus bridge may target, in the same VRL transform. A topic not on
   the list aborts and increments a counter. This turns "any `netops.*`" into
   "these 7".
2. **v1 (required):** the `bus_in` lane gets its **own** Vector `http_server`
   source with its **own** client identity (§6.13.10), so a compromised
   *collector* credential cannot reach the bus bridge at all.
3. `[Phase 2+]` If per-caller topic scoping is ever needed, the API becomes a
   real Kafka client — which needs a Kafka library and therefore a CLAUDE.md §6
   allowlist amendment. **Not proposed here.**

## 6.7.7 ACL matrix

Principals are the §6.7.4 mapped names. `P` = Write (produce), `C` = Read
(consume), `D` = Describe. Cluster-level rights are called out separately.

| Principal | Topic | P | C | D |
|---|---|---|---|---|
| `ingestion.vector-aggregator` | `netops.applogs` | ✅ | | ✅ |
| | `netops.syslog` | ✅ | | ✅ |
| | `netops.snmptrap` | ✅ | | ✅ |
| | `netops.probes` | ✅ | | ✅ |
| | `netops.metrics` | ✅ | | ✅ |
| | `netops.cloud` | ✅ | | ✅ |
| | `netops.cloudlogs` | ✅ | | ✅ |
| | `netops.deadletter` | ✅ | | ✅ |
| | `netops.app.identities.v1` | ✅ | | ✅ | *(bus bridge)* |
| | `netops.controller_events` | ✅ | | ✅ | *(bus bridge)* |
| | `netops.verification` | ✅ | | ✅ | *(bus bridge)* |
| | `netops.events` | ✅ | | ✅ | *(bus bridge)* |
| | `netops.wireless_sessions`, `netops.wireless_events` | ✅ | | ✅ | *(bus bridge)* |
| | **anything else** | ❌ | ❌ | ❌ | |
| `ingestion.vector-router` | `netops.applogs`, `netops.syslog`, `netops.flows`, `netops.snmptrap`, `netops.cloudlogs`, `netops.cloudcosts`, `netops.deadletter` | | ✅ | ✅ |
| | **produce: nothing** | ❌ | | | the router is read-only on the bus |
| `ingestion.goflow2` | `netops.flows` | ✅ | | ✅ |
| | **anything else** | ❌ | ❌ | ❌ |
| `ingestion.cloud-ingest` | `netops.cloudcosts`, `netops.cloudlogs` | ✅ | | ✅ |
| | **anything else** | ❌ | ❌ | ❌ |
| `app.correlation` | `netops.syslog`, `netops.flows`, `netops.metrics`, `netops.probes`, `netops.snmptrap`, `netops.cloud`, `netops.app.identities.v1`, `netops.controller_events`, `netops.app.edge`, `netops.verification`, `netops.wireless_sessions`, `netops.wireless_events` (`main.py:137-141`) | | ✅ | ✅ |
| | **produce: nothing** | ❌ | | | correlation writes to ClickHouse/PG, never back to the bus |
| `app.api` | — | ❌ | ❌ | ❌ | **not a Kafka principal** (`bus_producer.go:17-23`). Its `BROKER_URLS` use is a **TCP reachability probe only** (`docker-compose.yml:1093-1096`) — which under mTLS becomes a TLS dial without a client cert and will be *rejected*; §6.7.11 |
| `streaming.kafka-admin` (`kafka-init`) | `netops.*` | | | ✅ | + cluster `Create`, `DescribeConfigs`, `AlterConfigs` |
| `ops.kafka-exporter` | `^netops\..*` (`docker-compose.yml:740`) | | | ✅ | Describe only. **Never Read** — the exporter must not be able to consume tenant telemetry |

**Consumer groups** (exact names, verified):

| Principal | Group | Right |
|---|---|---|
| `ingestion.vector-router` | `netops-router-applogs` (`vector-router/vector.yaml:108`), `netops-router-syslog` (`:115`), `netops-router-flows` (`:122`), `netops-router-snmptrap` (`:129`), `netops-router-cloudlogs` (`:140`), `netops-router-deadletter` (`:152`), `netops-router-cloudcosts` (`:163`) | Read |
| `app.correlation` | `netops-correlation` (`main.py:2233`) | Read |
| `ops.kafka-exporter` | `^netops-.*` (`docker-compose.yml:741`) | **Describe only** |

Group ACLs are **exact-name**, not prefixed — a prefixed `netops-router-*` grant
would let a compromised router hijack the correlation group and steal its
offsets. The exporter's `--group.filter` regex needs Describe on the group
resource, which is a separate right from Read on it.

**Cluster-level:**

| Principal | Cluster operation | Note |
|---|---|---|
| `streaming.kafka-admin` | `Create`, `Describe`, `DescribeConfigs`, `AlterConfigs` | topic pre-creation + the dynamic keystore reload (§6.6) |
| `ops.kafka-exporter` | `Describe` | |
| everyone else | **none** | no `IdempotentWrite` unless a producer needs it `[UNKNOWN]` — Vector's `rdkafka` sink may require `IdempotentWrite` on the cluster; verify in staging and grant narrowly if so |

## 6.7.8 Broker authorization settings

```
authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer   # KRaft
allow.everyone.if.no.acl.found=false
super.users=User:streaming.kafka-admin
auto.create.topics.enable=false
```

- **`allow.everyone.if.no.acl.found=false`** is the whole point. With it `true`,
  a topic with no ACL is world-writable — which is today's posture with extra
  steps.
- **`auto.create.topics.enable=false`** (currently `true`,
  `docker-compose.yml:217`). Auto-creation lets a client conjure a topic that no
  ACL covers, and the compose comment at `:243-246` already identifies the
  race it causes on fresh installs. Turning it off **requires** §6.7.5's
  completed `kafka-init` list.
- `super.users` is exactly one principal, used only by the init/admin job.

## 6.7.9 Per-client migration notes

| Client | Cert support | Note |
|---|---|---|
| `vector-aggregator` / `vector-router` | ✅ | Vector's Kafka sink/source expose `tls.enabled`, `tls.ca_file`, `tls.crt_file`, `tls.key_file`. Certs are read at topology build → §6.6 restart/config-touch story |
| `goflow2` | `[UNKNOWN]` | goflow2 v2.2.1 configures Kafka via `-transport.kafka.*` flags (`docker-compose.yml:385-397`). **Whether it exposes TLS/keypair flags must be verified before Phase 3.** If it does not, the fallback is to keep goflow2 on the `MIGRATION` listener behind a network policy (§6.22) with a declared, expiring exception — or replace its Kafka transport with a Vector hop. Decide before Phase 3 |
| `correlation` (aiokafka) | ✅ | `aiokafka` accepts an `ssl_context` built from `ssl.create_default_context(cafile=...)` + `load_cert_chain(...)`. Stdlib Python, no new dependency |
| `kafka-exporter` | ✅ | `danielqsj/kafka-exporter` supports `--tls.enabled`, `--tls.ca-file`, `--tls.cert-file`, `--tls.key-file` |
| `kafka-init` | ✅ | `kafka-topics.sh --command-config` with a client properties file |
| `cloud-ingest` | `[UNKNOWN]` | its `broker_client.py` must be read before Phase 3 |

## 6.7.10 Migration listener and deadline

The `MIGRATION` plaintext listener on `:9094` exists so clients can be cut over
one at a time without a bus outage — the accept-set idea applied at the listener
level.

Rules, enforced by the validator:

- It is declared by an explicit `TransportPolicy` with an `exception` block
  (V-09) whose `expires` is set at creation.
- It is **only** present when `KAFKA_MIGRATION_LISTENER=true` is explicitly set.
  The default compose value is absent.
- While it exists, `netops_kafka_plaintext_connections_total` is exported and
  alerts on any non-zero value after the cutover milestone (§6.23).
- It is bound to the compose network only and never published to the host.
- **The Phase 3 completion criterion is its removal**, matching HLD §9 Phase 3
  ("Done when: plaintext listener removed and
  `allow.everyone.if.no.acl.found=false`").

Cutover order (lowest blast radius first, telemetry-continuity-checked between
each): `kafka-exporter` → `kafka-init` → `vector-router` → `correlation` →
`vector-aggregator` → `goflow2` → `cloud-ingest`.

## 6.7.11 Health checks over TLS

Today: `nc -z 127.0.0.1 9092` (`docker-compose.yml:232`) — a TCP accept. Under
mTLS a TCP accept still succeeds while every real client is being rejected, so
the health check would report a healthy broker during a total authentication
outage. That is precisely the "a fix whose own failure mode is invisible" shape
this codebase already calls out (`collectors/ingest_auth.go:88-91`).

**v1 health check:** `kafka-broker-api-versions.sh --bootstrap-server kafka:9092
--command-config /etc/kafka/tls/healthcheck.properties`, using the
`kafka-admin` identity. It proves TLS, the client certificate, and the API
surface. Cost is a JVM per probe, which is why the interval moves from 10s to
30s and `start_period` stays generous.

The API's separate stack-health TCP probe (`docker-compose.yml:1093-1096`) has
the same blindness. **v1: it must be updated to attempt a TLS handshake**, or it
will report the bus healthy when the bus is refusing everyone. `[UNKNOWN]`
whether `stack_health.go` can do that without a Kafka client — a bare
`tls.Dial` with the API's own SVID against `kafka:9092` proves handshake +
client-cert acceptance without speaking the Kafka protocol, and needs only
stdlib.

## 6.7.12 Secured flow

```mermaid
flowchart LR
  subgraph PRODUCERS["Producers — mTLS, ACL-scoped"]
    VA["vector-aggregator<br/>ns/ingestion/sa/vector-aggregator"]
    GF["goflow2<br/>ns/ingestion/sa/goflow2"]
    CI["cloud-ingest<br/>ns/ingestion/sa/cloud-ingest"]
  end
  API["api<br/>NOT a Kafka client"] -->|"HTTPS + mTLS<br/>bus_in :8692<br/>TOPIC ALLOWLIST"| VA
  subgraph BROKER["kafka — SSL:9092 client · SSL:9093 controller"]
    AUTHZ["StandardAuthorizer<br/>allow.everyone.if.no.acl.found=false<br/>auto.create.topics.enable=false"]
    T1["netops.applogs · syslog · snmptrap<br/>probes · metrics · cloud<br/>cloudlogs · deadletter · bus-bridge topics"]
    T2["netops.flows"]
    T3["netops.cloudcosts · cloudlogs"]
  end
  VA -->|"produce (allowlisted)"| AUTHZ
  GF -->|"produce netops.flows ONLY"| AUTHZ
  CI -->|"produce costs/logs ONLY"| AUTHZ
  AUTHZ --> T1 & T2 & T3
  subgraph CONSUMERS["Consumers — mTLS, group-scoped"]
    VR["vector-router<br/>groups netops-router-*"]
    CORR["correlation<br/>group netops-correlation"]
    KE["kafka-exporter<br/>DESCRIBE ONLY"]
  end
  T1 & T2 & T3 --> VR
  T1 & T2 --> CORR
  AUTHZ -.->|"Describe only — never Read"| KE
  X["Any unauthenticated peer"] -.->|"TLS handshake refused<br/>netops_tls_handshake_errors_total"| BROKER
```

---

# 6.8 OpenSearch LLD `[v1]`

## 6.8.1 Current state, and the one piece of good news

```yaml
DISABLE_SECURITY_PLUGIN: "true"    # dev default; flip for prod and add certs   :538
```

OpenSearch runs with **no authentication at all** over every tenant's logs, and
OSD likewise (`DISABLE_SECURITY_DASHBOARDS_PLUGIN: "true"`,
`docker-compose.yml:601`). `vector-router` writes to
`http://opensearch:9200` with **no `auth:` block** at all
(`vector-router/vector.yaml:541,559,571,583,595,607`); the API reads it over
plain HTTP (`docker-compose.yml:1119`).

The good news, verified: **the security plugin is deliberately retained** in the
slim image —

> `opensearch/Dockerfile:11-13`: *"opensearch-security (45 MB): disabled by env
> in compose, but the documented prod-hardening path is 'flip
> DISABLE_SECURITY_PLUGIN and add certs' — removing the plugin would silently
> break that promise."*

So this is configuration, not a rebuild.

## 6.8.2 Enabling the plugin

Remove `DISABLE_SECURITY_PLUGIN` (do not set it to `"false"` — the entrypoint
keys on presence in some versions `[UNKNOWN]`; removing is unambiguous), and mount
`config/opensearch-security/` plus:

```yaml
plugins.security.ssl.transport.pemcert_filepath: node.crt
plugins.security.ssl.transport.pemkey_filepath: node.key
plugins.security.ssl.transport.pemtrustedcas_filepath: ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: true
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: node.crt
plugins.security.ssl.http.pemkey_filepath: node.key
plugins.security.ssl.http.pemtrustedcas_filepath: ca.pem
plugins.security.ssl.http.clientauth_mode: OPTIONAL      # see §6.8.5
plugins.security.allow_default_init_securityindex: false
plugins.security.audit.type: internal_opensearch
plugins.security.certificates_hot_reload.enabled: true   # §6.6
plugins.security.restapi.roles_enabled: ["all_access"]
```

**Node transport TLS** (port 9300) is mandatory even single-node: it is the
channel a future second node joins on, and leaving it plaintext means the
cluster is insecure by default the moment it grows.

**REST HTTPS** on 9200 means every client URL changes from `http://` to
`https://`: `vector-router/vector.yaml:541,559,571,583,595,607`,
`docker-compose.yml:1119` (api), `:973` (correlation), `:571`
(opensearch-init), `:600` (OSD), `vector/vector.yaml:203,225` (the aggregator's
two `http_client` stats sources — easy to miss, and they will start failing
loudly rather than silently, which is correct).

## 6.8.3 Node DN restrictions

```yaml
plugins.security.nodes_dn:
  - "CN=spiffe://correlix.workload/ns/storage/sa/opensearch"
plugins.security.authcz.admin_dn:
  - "CN=spiffe://correlix.workload/ns/ops/sa/opensearch-admin"
```

`nodes_dn` is what stops a *client* certificate — any client certificate from our
own CA — from joining the cluster as a node. Without it, mTLS from the mesh CA
would be enough to become a data node. This is the OpenSearch-specific instance
of the general rule that authentication is not authorization.

## 6.8.4 Admin certificate isolation

The admin certificate bypasses **all** authorization, including index-level
restrictions. Rules:

- It is a **separate identity**
  (`spiffe://correlix.workload/ns/ops/sa/opensearch-admin`), never the node
  identity and never a service identity.
- Its key is `0600` and is mounted **only** into the `opensearch-init` job
  (`docker-compose.yml:567-588`), which is a one-shot that exits (`restart: "no"`,
  `:569`). No long-lived service ever mounts it.
- `[Phase 2+]` it moves to the `correlix.operator` intermediate with an 8h TTL.
- Every use is audited (§6.8.7) and alerted on (§6.23) — `securityadmin` running
  outside a declared maintenance window is an incident.

## 6.8.5 Identities and role mappings

Per decision **D6**: the simplest sufficient auth. Each of our services gets one
certificate identity mapped to one role with exactly the index privileges it
needs — not a per-tenant role matrix (tenancy is enforced by index naming plus
the API's own filters, and is **not** being moved into OpenSearch roles).

`clientauth_mode: OPTIONAL` rather than `REQUIRE` because OSD's browser-facing
side terminates through nginx and cannot present a client certificate; internal
service clients present one and are authenticated by it.

| Identity | Role | Index privileges | Cluster privileges |
|---|---|---|---|
| `ns/ingestion/sa/vector-router` | `correlix_writer` | `netops-*`: `crud`, `create_index`, `indices:admin/mapping/put` | `indices:data/write/bulk` |
| `ns/app/sa/api` | `correlix_reader` | `netops-*`: `read`, `indices:admin/mappings/get`, `indices:monitor/*` | `cluster:monitor/*`, `indices:admin/aliases/get` |
| `ns/ingestion/sa/vector-aggregator` | `correlix_stats` | none | `cluster:monitor/*` only — it reads `_cluster/health` and indexing stats (`vector/vector.yaml:203,225`) |
| `ns/ops/sa/opensearch-init` | `correlix_ism` | `netops-*`: `indices:admin/settings/update` | `cluster:admin/opendistro/ism/*`, `cluster:admin/repository/*`, `cluster:admin/snapshot/*` |
| `ns/ops/sa/opensearch-dashboards` | `correlix_osd` | `netops-*`: `read`; `.kibana*`: `crud` | `cluster:monitor/*` |
| `ns/app/sa/correlation` | *(none)* | — | — | correlation does **not** talk to OpenSearch despite `OPENSEARCH_URL` being set (`docker-compose.yml:973`) — `[UNKNOWN]`, verify; if truly unused, **remove the variable** rather than grant a role |
| Snapshot | reuses `correlix_ism` | | `cluster:admin/snapshot/*`, `cluster:admin/repository/*` | the F-59 repo at `path.repo` (`docker-compose.yml:545,554`) |

**Role mapping** is by certificate DN (`backend_roles` via
`plugins.security.ssl.http.clientauth_mode` + the `clientcert` authc domain),
not by username/password — no shared secrets to distribute or rotate.

## 6.8.6 Index naming — the existing tenant model, preserved

The per-tenant index pattern is **already** in place and must not change:

- `netops-{{ log_index_base }}-{{ tenant_seg }}-%Y.%m.%d` — `vector-router/vector.yaml:548`
- `netops-syslog-{{ tenant_seg }}-%Y.%m.%d` — `:574`
- `netops-snmptrap-{{ tenant_seg }}-%Y.%m.%d` — `:586`
- `netops-cloudlogs-{{ tenant_seg }}-%Y.%m.%d` — `:598`
- `netops-flows-{{ tenant_seg }}-%Y.%m.%d` — `:610`
- `netops-deadletter-%Y.%m.%d` — `:562` — **no tenant segment**, deliberately

`tenant_seg` derivation (`vector-router/vector.yaml:183-185`, duplicated for the
flows lane at `:376`):

```
seg = downcase(to_string(.tenant_id) ?? "")
if seg == "" { seg = "untagged" } else { seg = replace(seg, r'[^a-z0-9_-]', "-") }
.tenant_seg = seg
```

The Go side mirrors it: `internal/oslog/oslog.go:18` (`IndexBase`), `:46`
(`IndexTenantSeg`), `:70` (`TenantIndexPattern`), with the restricted-tenant
filter at `logs.go:341-360` failing **closed** (empty list) on a parse error.

**Design law preserved (CLAUDE.md §3a):** OpenSearch roles are **not** the tenant
boundary and are not being made into one. The tenant boundary stays where it is —
per-tenant indices plus `TenantIndexPattern` plus the doc-level filter
(`logs.go:72`, `ai_datasource_ops.go:77`). What the roles add is that an
*anonymous* reader no longer exists at all. That is the gap being closed.

`[Phase 2+]` If per-tenant OpenSearch roles are ever wanted (defence in depth
inside the store), the index naming already supports it exactly:
`index_patterns: ["netops-*-<tenant_seg>-*"]`. Designed; not v1, because it
would multiply role count by tenant count for a boundary that is already
enforced twice.

## 6.8.7 Audit logging

```yaml
plugins.security.audit.type: internal_opensearch
plugins.security.audit.config.disabled_rest_categories: [AUTHENTICATED, GRANTED_PRIVILEGES]
plugins.security.audit.config.disabled_transport_categories: [AUTHENTICATED, GRANTED_PRIVILEGES]
plugins.security.audit.config.resolve_bulk_requests: false
plugins.security.audit.config.exclude_sensitive_headers: true
```

Log **failures and privileged operations**, not successes — success logging on a
telemetry store means auditing every bulk index, which is a volume problem, not a
security control. `resolve_bulk_requests: false` and
`exclude_sensitive_headers: true` are non-negotiable: the former would write
**tenant document bodies** into the audit index, the latter would write
`Authorization` headers. Both would be a worse leak than the thing being audited.

The audit index is itself `netops-`-adjacent and inherits the ISM retention
policy (`docker-compose.yml:564-566`).

## 6.8.8 `securityadmin` bootstrap

The security configuration lives in a **system index**, not in files — it must be
loaded once with `securityadmin.sh`:

```
securityadmin.sh -cd config/opensearch-security -icl -nhnv=false \
  -cacert ca.pem -cert admin.crt -key admin.key -h opensearch -p 9200
```

- `-nhnv=false` keeps hostname verification **on**. `-nhnv` (its enabled form) is
  the OpenSearch spelling of "skip verify" and is forbidden (F-02).
- Runs from the existing `opensearch-init` one-shot
  (`docker-compose.yml:567-588`), extending `apply-ism.sh`.
- `plugins.security.allow_default_init_securityindex: false` means the cluster
  does **not** silently self-initialize with the demo configuration if the job
  fails — it stays unconfigured and unreachable, which is the fail-closed
  behavior we want.
- Idempotent by construction (`-icl` reloads from the same directory), matching
  the repo's converge-on-boot habit (`clickhouse_policies.go:11-14`).

## 6.8.9 Zero-downtime migration

OpenSearch is `discovery.type: single-node` (`docker-compose.yml:535`), so
"zero-downtime" is not literally achievable — enabling the security plugin
requires a restart. What *is* achievable is **zero data loss**:

1. **Pre-flight**: register/verify the snapshot repository and take a snapshot.
   The repo is already wired (`docker-compose.yml:545,554,581`) and F-59 records
   that before it existed there was *no backup of any search index, ever*.
2. **Freeze the writer**: stop `vector-router` only. Its Kafka consumer groups
   (`netops-router-*`) hold committed offsets, so the bus buffers and nothing is
   lost — bounded by `KAFKA_LOG_RETENTION_MS` (default 3 days,
   `docker-compose.yml:221`), which is ample.
3. **Restart OpenSearch** with the plugin on; run `securityadmin`.
4. **Verify**: `curl --cert --key https://opensearch:9200/_cluster/health` as
   each identity; assert that an **anonymous** request now fails.
5. **Point clients at `https://`** and restart them: `vector-router`, `api`,
   `opensearch-init`, OSD, and the aggregator's two stats sources.
6. **Unfreeze**; watch consumer lag return to zero.
7. **Re-prove tenant isolation** — HLD §9 Phase 4 requires this explicitly. Run
   the existing isolation suite (`logs`-touching tests plus
   `route_isolation_test.go` / `route_isolation_coverage_test.go`) against the
   secured cluster before declaring done.

Rollback at any step: re-set `DISABLE_SECURITY_PLUGIN: "true"`, restart, revert
client URLs. The snapshot from step 1 is the floor.

---

# 6.9 ClickHouse LLD `[v1]`

## 6.9.1 Current state

One shared user, Basic credentials over plaintext HTTP:

- `CLICKHOUSE_USER: ${CLICKHOUSE_USER:-netops}` / `CLICKHOUSE_PASSWORD:
  ${CLICKHOUSE_PASSWORD:?...}` (`docker-compose.yml:912-913`) — password is
  fail-closed required, which is good.
- `CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: "1"` (`:914`) — the `netops` user can
  create row policies, which is how convergence works.
- `vector-router` sends Basic over `http://clickhouse:8123`
  (`vector-router/vector.yaml:618,621-624` and `:634,637-640`).
- `api` and `correlation` likewise (`docker-compose.yml:1120-1122`, `:974-976`).
- `init.sql` defines **no users, no passwords, no TLS** — it is pure schema
  (verified: no `CREATE USER`/`IDENTIFIED`/`PASSWORD`/TLS keyword anywhere in
  `clickhouse/init.sql`).

## 6.9.2 TLS

Add `config.d/tls.xml`:

```xml
<clickhouse>
  <https_port>8443</https_port>
  <tcp_port_secure>9440</tcp_port_secure>
  <openSSL><server>
    <certificateFile>/etc/clickhouse-server/tls/server.crt</certificateFile>
    <privateKeyFile>/etc/clickhouse-server/tls/server.key</privateKeyFile>
    <caConfig>/etc/clickhouse-server/tls/ca.pem</caConfig>
    <verificationMode>relaxed</verificationMode>   <!-- see §6.9.3 -->
    <preferServerCiphers>true</preferServerCiphers>
    <disableProtocols>sslv2,sslv3,tlsv1,tlsv1_1</disableProtocols>
  </server></openSSL>
</clickhouse>
```

The plaintext `<http_port>8123</http_port>` stays during migration (§6.25) and is
**removed** at cutover. Client URLs move to `https://clickhouse:8443`:
`docker-compose.yml:1120` (api), `:974` (correlation),
`vector-router/vector.yaml:618,634`.

Health check moves from `wget http://127.0.0.1:8123/ping`
(`docker-compose.yml:946`) to an HTTPS probe with the CA bundle — otherwise, as
with Kafka, the container reports healthy while every real client is refused.

## 6.9.3 Client-certificate auth

ClickHouse supports `IDENTIFIED WITH ssl_certificate CN '<subject CN>'`. Our
leaves put the SPIFFE ID in the CN (`internalca/ca.go:175`), so:

```sql
CREATE USER IF NOT EXISTS ingest
  IDENTIFIED WITH ssl_certificate CN 'spiffe://correlix.workload/ns/ingestion/sa/vector-router';
```

`verificationMode: relaxed` is chosen deliberately: `strict` would require a
client certificate on **every** connection including the health probe and any
operator `clickhouse-client` session. Relaxed accepts a connection without a
certificate and then **fails the user's authentication** if that user is
`IDENTIFIED WITH ssl_certificate` — which is the same fail-closed outcome per
user, without breaking the probe. `[ASSUMPTION]` verified in staging as part of
Phase 4.

Password-identified users are retained as the migration bridge and for the
Grafana datasource (which cannot present a client cert through the provisioning
file `[UNKNOWN]`).

## 6.9.4 Users and roles

Per decision **D6**: one scoped user per consumer, no elaborate matrix.

| User | Auth | Role | Grants | Replaces |
|---|---|---|---|---|
| `ingest` | client cert (`ns/ingestion/sa/vector-router`) | `correlix_ingest` | `INSERT ON netops.flows`, `INSERT ON netops.cloud_costs` | vector-router's use of `netops` (`vector-router/vector.yaml:623,639`) |
| `api` | client cert (`ns/app/sa/api`) | `correlix_api` | `SELECT ON netops.*`, `INSERT ON netops.*` (the API writes several tables), `ALTER`/`CREATE`/`DROP ROW POLICY` on `netops.*` (convergence, §6.9.5), `SET` on the `tenant_scope` custom setting | api's use of `netops` (`docker-compose.yml:1121-1122`) |
| `correlation` | client cert (`ns/app/sa/correlation`) | `correlix_correlation` | `INSERT ON netops.corr_*`, `INSERT ON netops.findings`, `SELECT ON netops.corr_*` | correlation's use of `netops` (`docker-compose.yml:975-976`) |
| `grafana_ro` | password (`GRAFANA_CH_PASSWORD`, already generated at `install.py:311`) | `correlix_grafana` | `SELECT` on the panels' tables only; forced `tenant_scope=''` | already exists in intent (`docker-compose.yml:887-889`) — now with an explicit role |
| `backup` | client cert (`ns/ops/sa/ch-backup`) | `correlix_backup` | `SELECT ON netops.*`, `BACKUP` | new; §6.19.11 |
| `operator` | password + step-up | `correlix_operator` | `SELECT`; **no** `ALTER ROW POLICY` | break-glass; audited |
| `netops` (today's shared user) | password | — | **retained during migration only**, then dropped | §6.25 |

`CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: "1"` (`docker-compose.yml:914`) is
narrowed: only the `api` user needs access management, and only for row policies.

**None of these users is per-tenant.** Tenancy is the row policies (below), not
the user. That is a deliberate, load-bearing choice: making users per-tenant
would move the boundary from a tested, database-enforced mechanism to a
credential-distribution problem.

## 6.9.5 Row policies — preserved exactly, and hardened against silent absence

This is the strongest control in the platform and it is **not being changed**.

Current mechanism, verified end to end:

- `ensureCHRowPolicies()` (`clickhouse_policies.go:25`) runs on every API start
  (`main.go:1165`), building the DDL list with
  `chschema.ConvergeStmts(...)` (`clickhouse_policies.go:30`) and executing via
  `chExecAll` (`:38`, defined `clickhouse_client.go:94`).
- Two policy shapes:
  - **Lenient** — `internal/chschema/policies.go:10`:
    `CREATE ROW POLICY IF NOT EXISTS tenant_iso_<t> ON netops.<t> USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' OR tenant_id = '' TO ALL`
    Applied only to `flows`, `findings`, `tunnels` (`policies.go:53-55`).
  - **Strict** — `internal/chschema/ch_sql.go:47`: identical **minus** the
    `OR tenant_id = ''` escape, and using `OR REPLACE` so a pre-2026-07-02
    lenient policy is *upgraded in place* rather than skipped (`ch_sql.go:16-19`).
- Guarded by tests that fail on lenient correlation-family policies:
  `clickhouse_policies_test.go:76-78` (the core assertion — errors if any
  `corr_*`/`path_*` policy contains `tenant_id = ''`), `:79-81` (must contain
  `getSetting('tenant_scope')` and `'__all__'`), `:82-84` (`TO ALL`),
  `:107-109` (all ten strict tables use `OR REPLACE`), `:114-118` (**no
  statement may `DROP ROW POLICY`** — no policyless window), `:138-145` (inverse
  guard: the three telemetry policies must *keep* their untagged clause).
  `TestRowPolicyGrammarShape` (`:161-185`) locks the statement prefix.

### 6.9.5.1 The gap this section must close

Three facts combine into a real hole:

1. Convergence is **best-effort and never fatal** — after 10 attempts it logs
   `WARNING — could not ensure tenant row policies after retries; telemetry
   isolation relies on the app layer until ClickHouse is reachable`
   (`clickhouse_policies.go:46-51`).
2. It is gated on `CLICKHOUSE_URL` being set (`:26-29`) — unset means **no
   policies are ever created** and nothing says so.
3. There is **no read-back**. Nothing queries `system.row_policies` to confirm
   the policies exist in the shape intended. The self-healing property after an
   access-storage reset is asserted only in a comment (`ch_sql.go:19`).

And the precedent is not hypothetical: the `CREATE OR REPLACE ROW POLICY`
grammar inversion shipped, **failed 1,560 times, never once succeeded**, and
`cloud_costs` — per-tenant financial data — was left with **no row policy at
all**, while four literal-pinning tests passed (`policies.go:20-29`,
`clickhouse_policies_test.go:149-160`). The DDL was correct in the test and
rejected by the server, and nothing noticed.

### 6.9.5.2 The boot-time policy-safety check `[v1 — required]`

A new function, `assertCHPoliciesConverged`, runs **after** `ensureCHRowPolicies`
completes (or after its retry budget expires), and:

**1. Reads the live state.**

```sql
SELECT database, table, name, short_name, select_filter, is_restrictive, apply_to_all
  FROM system.row_policies
 WHERE database = 'netops'
```

**2. Compares against the intended set**, derived from the *same*
`chschema.ConvergeStmts()` output the boot path executed — so the check can never
drift from the thing it checks.

**3. Fails on any of these conditions:**

| Id | Condition | Meaning |
|---|---|---|
| CHP-01 | A table in the intended list has **no** policy | convergence silently failed, or access storage was reset and the boot pass has not run |
| CHP-02 | A `corr_*` / `path_*` policy's `select_filter` contains `tenant_id = ''` | **lenient policy on a strict table — a cross-tenant leak.** This is the condition the brief names |
| CHP-03 | A policy's filter does not reference `getSetting('tenant_scope')` | the policy exists but does not scope |
| CHP-04 | A policy exists on a `netops.*` table that is **not** in the intended set | someone created a policy out of band |
| CHP-05 | `apply_to_all` is false (i.e. not `TO ALL`) | a policy that applies to no one is not a policy |
| CHP-06 | A `netops.*` table carrying a `tenant_id` column has **no** policy at all | the `cloud_costs` failure shape, generalized |

**4. Behavior by profile** (D9 — clear, actionable messages):

| Profile | On CHP-0x |
|---|---|
| lab / development | `logWarn` + metric |
| staging | `logError` + metric + `/admin/readyz` reports not-ready |
| **production** | **`log.Fatalf`** — the API refuses to serve |

Precedent for the production behavior is directly in-repo:
`assertRLSCapable` (`internal/platformdb/db.go:186-207`) aborts boot when the
Postgres role would bypass RLS, with the rationale (`db.go:179-185`) that a
silent tenancy hole "would silently disable tenant isolation (a multi-tenant data
breach with no error). Refusing to start turns that silent hole into an
unmissable abort." **CHP is the ClickHouse instance of exactly that argument.**

The production error message must name the table, the expected filter and the
found filter, and point at the runbook — a `log.Fatalf` that says "policy check
failed" is not actionable.

**5. Access-storage reset detection.** ClickHouse access objects live in
`/var/lib/clickhouse/access`, inside the bind-mounted data volume
(`docker-compose.yml:924`). A wipe or restore-from-old-backup removes every
policy while leaving the data. CHP-01/CHP-06 catch it on the next boot; a
periodic re-run (reusing the existing named worker registry —
`"ch-row-policies"` at `main.go:895`) catches it **without** a restart. Cadence:
every 15 minutes `[ASSUMPTION]`, cheap (one `system.row_policies` read).

**6. Metric + alert** (§6.23): `netops_ch_row_policies_expected`,
`netops_ch_row_policies_present`, `netops_ch_row_policy_violations_total{rule}`.
An alert on `present < expected` for > 5m is a page. This is the signal that did
not exist during the 1,560-failure incident.

**7. Tests** (§6.26): a table-driven unit test feeding synthetic
`system.row_policies` rows for each CHP-0x condition, plus an integration test
that **deletes a policy** and asserts the checker fails — the ratchet-shaped
guard the codebase already favors.

## 6.9.6 Two related findings worth fixing in v1

1. **`users.d/tenant-scope.xml` does not exist.** `clickhouse/custom-settings.xml:7`
   says *"The profile DEFAULT for tenant_scope lives in users.d/tenant-scope.xml
   (users config), not here"* — but `deployment/docker/clickhouse/` contains no
   such file and compose mounts no such file (`docker-compose.yml:925-941`). The
   comment is stale or the file was lost. Since a policy referencing an **unset**
   custom setting makes ClickHouse **error** the query, this is currently masked
   by every caller passing `tenant_scope` explicitly. Either restore the file
   with a default of `__none__` (fail-shut) or delete the comment. **Do not
   default it to `__all__`.**

2. **`__all__` is a global bypass value** (`policies.go:10`, `ch_sql.go:48`) and
   any principal that can set `tenant_scope` can use it. That is correct and
   intended — the Go side makes the scope an explicit, visible choice at each
   call site (`clickhouse_client.go:110-117`, `chTenantScope` at `:279`) and the
   correlation service counts cross-tenant inserts
   (`main.py:1725,1746-1751`, metric `corr_cross_tenant_inserts_total` at
   `:3414`). v1 adds the equivalent on the **read** side: count and expose
   `netops_ch_queries_total{scope="all"}` so cross-tenant reads are visible in
   the posture view rather than invisible.

## 6.9.7 Tenant-isolation enforcement — transport identity is not tenant authz

```mermaid
flowchart TB
  subgraph T["TRANSPORT LAYER — proves WHO"]
    C1["client cert<br/>CN=spiffe://correlix.workload/ns/app/sa/api"]
    C2["mTLS handshake<br/>chain verified + PeerPolicy allowlist<br/>tlsconfig/verify.go:49"]
    C1 --> C2
  end
  subgraph A["APPLICATION LAYER — proves WHICH TENANT"]
    P1["JWT / API-key claims"]
    P2["principalTenant(claims)<br/>tenancy.go:63"]
    P3["requirePerm + reachesTenant<br/>access.go:51"]
    P1 --> P2 --> P3
  end
  subgraph D["DATA LAYER — ENFORCES it"]
    D1["ClickHouse: SETTINGS tenant_scope=&lt;tenant&gt;<br/>chTenantScope, clickhouse_client.go:279"]
    D2["ROW POLICY tenant_iso_*<br/>chschema/ch_sql.go:47"]
    D3["Postgres FORCE-RLS + withTenant"]
    D4["OpenSearch per-tenant index + filter<br/>oslog.go:70, logs.go:341"]
  end
  C2 -->|"authenticated peer<br/>NOT a tenant grant"| A
  P3 --> D1 --> D2
  P3 --> D3
  P3 --> D4
  X["A valid mesh certificate<br/>with NO tenant claim"] -.->|"reaches the API,<br/>then gets ZERO rows"| D2
  note["DESIGN LAW: an mTLS peer is AUTHENTICATED,<br/>never AUTHORIZED for a tenant.<br/>Removing transport security would not<br/>weaken tenancy; adding it does not strengthen it."]
```

---

# 6.10 VictoriaMetrics LLD `[v1]`

## 6.10.1 Current state

`victoria` listens on `:8428` with **no authentication of any kind** — the
command block (`docker-compose.yml:616-636`) sets retention, dedup, memory and
scrape config, and nothing else. Writers and readers today:

| Client | Direction | Evidence |
|---|---|---|
| `gnmic` (two outputs) | write | `gnmic/gnmic.yaml:135`, `:155` — `http://victoria:8428/api/v1/write`, no auth |
| `vector-aggregator` | write | `vector/vector.yaml:1114` — `prometheus_remote_write`, no auth, `healthcheck: false` (`:1115`) |
| `api` | read + write | `docker-compose.yml:1110`, `:1118` |
| `prober` | write | `docker-compose.yml:1570-1571` |
| `vmalert` | read + **remote write** | `docker-compose.yml:692-694` — datasource, remoteWrite and remoteRead all plaintext |
| `grafana` | read | provisioned datasource |
| VM's own scraper | read | `--promscrape.config` (`docker-compose.yml:632`), jobs at `src/config/vmscrape.yml:22-96` |

Anything on the compose network can write arbitrary series into any tenant's
metrics and read all of them.

## 6.10.2 vmauth in front

VictoriaMetrics single-node has no native auth; `vmauth` is the project's own
answer and is part of the same release train (`v1.101.0`), so it adds no new
vendor.

```
victoria:  --httpListenAddr=127.0.0.1:8428    # LOOPBACK ONLY — see §6.10.5
vmauth:    --auth.config=/etc/vmauth/auth.yml
           --tls --tlsCertFile=/tls/tls.crt --tlsKeyFile=/tls/tls.key
           --tlsCipherSuites=<policy.go:31-39 set>  --tlsMinVersion=TLS12
           --httpListenAddr=:8427
```

`[UNKNOWN]` vmauth's client-certificate *verification* support (as opposed to
presenting one upstream) must be confirmed on `v1.101.0`. If it cannot verify
client certificates, v1 falls back to per-identity **bearer tokens over TLS**
generated by `install.py` alongside the other secrets (`install.py:305-324`) —
still a large improvement over anonymous, and explicitly the "simplest
sufficient" choice under D5. Decide before Phase 4.

## 6.10.3 Identities and routes

| Identity | Route | Allowed URL prefixes | Method | Rate limit |
|---|---|---|---|---|
| `ns/ingestion/sa/gnmic` | ingest | `/api/v1/write` | POST | `max_concurrent_requests: 8` |
| `ns/ingestion/sa/vector-aggregator` | ingest | `/api/v1/write` | POST | 8 |
| `ns/ingestion/sa/prober` | ingest | `/api/v1/write` | POST | 4 |
| `ns/app/sa/api` | query+ingest | `/api/v1/query`, `/api/v1/query_range`, `/api/v1/series`, `/api/v1/labels`, `/api/v1/label/`, `/api/v1/write` | GET/POST | 16 |
| `ns/ops/sa/vmalert` | query+ingest | `/api/v1/query`, `/api/v1/query_range`, `/api/v1/write` | GET/POST | 8 |
| `ns/ops/sa/grafana` | query | `/api/v1/query*`, `/api/v1/series`, `/api/v1/labels`, `/api/v1/label/` | GET | 8 |
| `ns/ops/sa/vm-admin` | admin | `/api/v1/admin/tsdb/delete_series`, `/-/reload`, `/snapshot/*` | POST | 1 |
| anyone else | — | **none** | — | — |

**`/api/v1/admin/tsdb/delete_series` is the one that matters most.** Today it is
reachable, unauthenticated, by anything on the network — an unauthenticated
series-deletion endpoint over every tenant's metrics. Confining it to a
dedicated admin identity is the single highest-value line in this section.

URL filtering is explicit-allow: a path not listed is rejected. This also stops
`/metrics`, `/flags` and `/debug/pprof` from being reachable by a query
identity.

## 6.10.4 Tenant route mapping

VictoriaMetrics **single-node has no native multi-tenancy** (that is `vmcluster`
and its `/insert/<accountID>/` paths). So tenancy here is, and stays,
**label-based**: series carry `tenant_id`/`device` labels and the API filters on
them.

**Design law, restated:** vmauth is *not* the tenant boundary. It is
authentication plus route confinement. The tenant boundary for metrics remains
the API's own label filtering, and no vmauth rule is permitted to be described as
tenant isolation.

`[Phase 2+]` If real per-tenant metric isolation is wanted, the honest route is
`vmcluster` with `/insert/<accountID>/` and `/select/<accountID>/` — a
substantial deployment change, designed here only to record that the option
exists and what it would cost.

## 6.10.5 Prohibit direct backend exposure

The whole design collapses if a client can bypass vmauth and hit `:8428`. Three
layers, all v1:

1. `--httpListenAddr=127.0.0.1:8428` — VM binds loopback inside its own network
   namespace, so nothing on the compose network reaches it at all.
   `[UNKNOWN]` vmauth must then run in the **same** network namespace
   (`network_mode: "service:victoria"`) for the loopback to be reachable. The
   alternative is keeping VM on the network and relying on §6.22's network policy.
   Loopback is stronger and is the preferred option.
2. `victoria` publishes no host port today (`docker-compose.yml:612-648` has no
   `ports:`) — keep it that way.
3. Every client URL changes to `https://vmauth:8427`:
   `gnmic/gnmic.yaml:135,155`, `vector/vector.yaml:1114`,
   `docker-compose.yml:1110,1118,1571,692-694`, plus the Grafana datasource
   provisioning and `src/config/vmscrape.yml` targets.

`vmalert`'s `-remoteWrite.url` (`docker-compose.yml:693`) deserves a note: it
writes `ALERTS`/`ALERTS_FOR_STATE` back into VM, which the watchdog and the
in-app boards read (`docker-compose.yml:674-679`). If that write is broken by
the migration, alert *state* silently stops being queryable while alerting
*appears* to work. It goes in the Phase 4 verification list.

---

# 6.11 PostgreSQL LLD `[v1]`

## 6.11.1 Current state

- No TLS: the image runs with defaults; the command block
  (`docker-compose.yml:65-76`) sets only memory/connection tuning.
- The API's DSN is `DATABASE_URL` (`docker-compose.yml:1395`), and the runbook
  documents `sslmode=verify-full` as the target (`docs/runbooks/tls-mtls.md:82`),
  but the shipped configuration does not set it — HLD §7 records it as
  `sslmode=disable`, which is the effective posture for a DSN with no `sslmode`
  reaching a server with `ssl=off`.
- Correlation's DSN is built inline and has **no TLS parameters at all**:
  `POSTGRES_DSN: "postgresql://${DB_USER}:${DB_PASSWORD}@postgres:5432/${DB_NAME:-netops}"`
  (`docker-compose.yml:977`).
- Keycloak connects over JDBC, also plaintext (`docker-compose.yml:169-171`).
- **The strong part**: `assertRLSCapable` (`internal/platformdb/db.go:186-207`)
  refuses to start if the role is a superuser or has `BYPASSRLS`, unless
  `STORE_PG_ALLOW_RLS_BYPASS=true` downgrades it to a warning (`db.go:199-203`).
  FORCE-RLS + `withTenant` is the tenant boundary and is **not changed**.

## 6.11.2 Server TLS

```
ssl = on
ssl_cert_file = '/etc/postgresql/tls/server.crt'
ssl_key_file  = '/etc/postgresql/tls/server.key'      # MUST be 0600 or PG refuses to start
ssl_ca_file   = '/etc/postgresql/tls/ca.pem'
ssl_min_protocol_version = 'TLSv1.2'
ssl_prefer_server_ciphers = on
```

Postgres **refuses to start** if the key is group- or world-readable. That
directly collides with the shared-group scheme in §6.5.3, so the Postgres key is
the one exception: mode `0600`, owned by the postgres uid, delivered by the
cert-init job with an explicit `chown`. `[ASSUMPTION]` — verify the image's
runtime uid (the compose file does not pin `user:` for `postgres`), and pin it
once known.

## 6.11.3 `pg_hba.conf`

```
# TYPE     DATABASE  USER            ADDRESS        METHOD
hostssl    all       all             ::0/0          scram-sha-256   clientcert=verify-ca
hostssl    all       all             0.0.0.0/0      scram-sha-256   clientcert=verify-ca
local      all       all                            scram-sha-256
# NO 'host' (non-SSL) line. NO 'trust'. NO 'md5'.
```

`hostssl` (not `host`) is what makes TLS **mandatory** — a non-TLS connection is
rejected at the HBA layer rather than merely discouraged by the client's
`sslmode`. During migration a temporary `host ... scram-sha-256` line exists with
a declared, expiring exception (§6.25); its removal is the completion criterion.

`clientcert=verify-ca` — not `verify-full` — because Postgres's `verify-full`
requires the certificate CN to equal the **database username**, and our CNs are
SPIFFE URIs. Optional client certificates therefore add "the peer is in the mesh"
on top of SCRAM, which is exactly the "costs nothing extra" case in D6. If CN
matching is later wanted, a `pg_ident.conf` map handles it `[Phase 2+]`.

## 6.11.4 Client configuration

| Client | Target DSN |
|---|---|
| `api` | `postgres://api@postgres:5432/netops?sslmode=verify-full&sslrootcert=/data/tls/ca.pem&sslcert=/data/tls/api/api.crt&sslkey=/data/tls/api/api.key` |
| `correlation` | same shape with the `correlation` role and its own pair — replaces `docker-compose.yml:977` |
| `keycloak` | JDBC `?ssl=true&sslmode=verify-full&sslrootcert=...` |

**`verify-full`, never `require`.** `require` encrypts and verifies nothing — it
is MITM-able. The runbook already says exactly this
(`docs/runbooks/tls-mtls.md:84-85`: *"`verify-full` checks BOTH the chain and the
hostname — do not use `require`"*). pgx honors the DSN, so this is configuration.

## 6.11.5 Per-service roles

| Role | Used by | Grants | RLS |
|---|---|---|---|
| `api` | `api` | `SELECT/INSERT/UPDATE/DELETE` on app tables; `USAGE` on sequences | **subject to RLS** — never `BYPASSRLS`, never superuser (enforced at `db.go:186-207`) |
| `correlation` | `correlation` | `SELECT` on the tables it reads; `INSERT` on what it writes | subject to RLS |
| `migrator` | migration runner | `CREATE`/`ALTER` DDL | used only by the migration path (`db.go:172`), never by request handlers |
| `keycloak` | `keycloak` | owner of the `keycloak` database only | separate database (`docker-compose.yml:169`) — no access to `netops` |
| `backup` | backup job | `SELECT` on all; `pg_read_all_data` | subject to RLS `[UNKNOWN]` — a role with RLS applied cannot take a complete logical backup. §6.19.11 resolves this by backing up at the **physical** layer, where RLS does not apply, and encrypting the artifact |
| `netbox` | `netbox` | separate server entirely (`netbox-postgres`, `docker-compose.yml:1755`) | n/a |

Splitting the single `DB_USER` (`docker-compose.yml:60,1088`) into `api` +
`correlation` + `migrator` is a v1 item and is the only part of this section that
touches the schema (role creation + grants in a migration).

**`STORE_PG_ALLOW_RLS_BYPASS`** (`docker-compose.yml:1396`, honored at
`db.go:199-203`) is a documented escape hatch for deliberate single-tenant
deploys. v1 adds one rule: **the production profile validator refuses it.** A
production stack that has turned off its own tenancy enforcement must not boot
silently.

## 6.11.6 Migration sequencing

1. Generate the server pair; set `ssl = on`; **keep** `host` lines. Restart
   Postgres (brief; `depends_on: service_healthy` at `docker-compose.yml:1518`
   makes dependents wait).
2. Move `api` to `sslmode=verify-full`. Verify.
3. Move `correlation`, then `keycloak`.
4. Create the per-service roles and grants; switch each client's user.
5. Remove the `host` lines from `pg_hba.conf`, leaving only `hostssl`. Reload
   (`SIGHUP`).
6. Re-run the RLS isolation tests (`org_isolation_test.go`,
   `maintenance_pg_isolation_test.go`, `processors_pg_isolation_test.go`,
   `svc_catalog_isolation_pg_test.go`) against the TLS deployment.

Rollback at any step: restore the previous `pg_hba.conf` and reload. No data
migration is involved, which is what makes this the lowest-risk datastore.

## 6.11.7 Backup encryption

`[Phase 2+]` in full (§6.19.11), but the v1 minimum: `pg_basebackup`/`pg_dump`
output is written to a directory that is **not** world-readable, and the backup
runbook (`docs/runbooks/backup-restore.md`) gains an explicit statement that
backups are **not** encrypted at rest today — HLD T20 rates backup theft HIGH
with no control. An honest gap beats an assumed control.

---

# 6.12 Valkey LLD `[v1]`

## 6.12.1 Current state — no password at all

```yaml
command: ["valkey-server", "--save", "60", "1", "--maxmemory", "${REDIS_MAXMEMORY:-96mb}"]   # :100
healthcheck: ["CMD", "valkey-cli", "ping"]                                                    # :104
```

`docker-compose.yml:87-109` sets **no `--requirepass`, no ACL file, no TLS**.
Anything on the compose network has full, unauthenticated command access —
including `FLUSHALL`, `CONFIG SET` and `DEBUG`. Clients: `api`
(`docker-compose.yml:1091-1092`), `prober` (`:1568-1569`), and `netbox`, which
even documents empty passwords explicitly (`:1787`, `:1791`).

The service key stays `redis` (`docker-compose.yml:92-94` explains why:
`REDIS_HOST` consumers are untouched) even though the image is Valkey 8 (`:95`).

## 6.12.2 TLS

```
--tls-port 6380 --port 6379            # dual during migration; --port 0 at cutover
--tls-cert-file /tls/server.crt
--tls-key-file  /tls/server.key
--tls-ca-cert-file /tls/ca.pem
--tls-auth-clients yes                 # mTLS — client cert REQUIRED
--tls-protocols "TLSv1.2 TLSv1.3"
```

`--tls-auth-clients yes` is the default in Valkey/Redis 6+ and is kept: our only
clients are ours, and the CA mints their certificates anyway (D6).

## 6.12.3 ACL users

Disable the default user's nopass access — this is the single most important line:

```
user default off
```

Then one user per client, each restricted by **command category**, **key
prefix** and **channel**:

```
user api on >__from_env__ ~netops:* &netops:* +@read +@write +@keyspace +@string +@hash +@list +@set +@sortedset +@transaction -@admin -@dangerous
user prober on >__from_env__ ~netops:probe:* ~netops:topology:* &netops:probe:* +@read +@write +@string +@hash -@admin -@dangerous
user netbox on >__from_env__ ~netbox:* +@read +@write +@string +@hash +@list +@set +@sortedset -@admin -@dangerous
user health on >__from_env__ ~ +ping +info
user opsadmin on >__from_env__ ~* &* +@all
```

| Aspect | Rule |
|---|---|
| **Key prefixes** | `api` → `netops:*`; `prober` → `netops:probe:*`, `netops:topology:*` (it publishes traceroute topology the API reads — `docker-compose.yml:1526-1529`); `netbox` → `netbox:*` on databases 9 and 10 (`:1788`, `:1792`) |
| **Channels** | `&<prefix>` restricts pub/sub. Default deny |
| **Admin denial** | `-@admin -@dangerous` removes `FLUSHALL`, `FLUSHDB`, `CONFIG`, `SHUTDOWN`, `DEBUG`, `KEYS`, `MONITOR`, `REPLICAOF`, `MIGRATE` from every service user. Only `opsadmin` has them, and it is not wired into any service |
| **Health** | `health` can do exactly `PING` and `INFO` — the health check (`:104`) must not need a privileged user |
| **`CONFIG SET`** | needed by the reload sidecar (§6.6) — granted to `opsadmin` only |

`[UNKNOWN]` Valkey 8 supports both inline `user` directives and an external
`aclfile`. An `aclfile` is preferable (passwords are not visible in `ps` or in
the compose file) but requires `ACL LOAD` on rotation. Confirm and prefer the
`aclfile`.

Passwords are generated by `install.py` alongside the existing secrets
(`install.py:305-324`) and carry rotation classifications, which
`tests/test_secret_rotation.py` already enforces (`install.py:296-303`).

## 6.12.4 Client migration

pgx-style DSNs do not apply here; each client needs `--tls` plus user/password.
`[UNKNOWN]` the Go Redis client in use — the backend is stdlib-only, so it is
either a hand-rolled RESP client or the protocol is spoken directly. It must be
read before Phase 4 to confirm it can (a) do TLS and (b) send `AUTH <user>
<pass>` (RESP `AUTH` with two arguments, i.e. ACL-style). If it cannot, adding
either is small stdlib work — `crypto/tls` and one extra command — and needs no
dependency.

Order: `health` → `prober` → `api` → `netbox`, each verified before the next,
then `--port 0` to remove the plaintext listener.

## 6.12.5 Rotation

Valkey ACL passwords rotate with `ACL SETUSER <name> >newpass <oldpass-removed>`,
which supports **two** passwords transiently — the same accept-set idea. The
sequence is: add the new password → roll clients → remove the old → `ACL SAVE`.
Certificates rotate on the §6.6 schedule via `CONFIG SET`.

**Blast-radius note:** Valkey holds TTL'd collector caches and the WAN-circuit
mesh (`docker-compose.yml:93-94`, `:1239-1241`), not durable state — the compose
comment is explicit that a lost RDB is acceptable. That makes Valkey the safest
datastore to migrate first and the right place to prove the whole
TLS-plus-native-auth pattern before touching Kafka or OpenSearch.

---

# 6.13 nginx + API LLD `[v1]`

## 6.13.1 Browser TLS — already shipped

`deployment/docker/nginx/tls.conf.example` is a complete, hardened front:

| Control | Evidence |
|---|---|
| Listener | `tls.conf.example:93` `listen 8443 ssl;`, `:94` `http2 on;` (host-published as 443 — `:46`, since nginx-unprivileged cannot bind <1024, `:51-53`) |
| Versions | `:104` `ssl_protocols TLSv1.2 TLSv1.3;` — rationale `:100-103` ("No CBC, no RSA key transport, no SHA-1. TLS 1.0/1.1 are not offered.") |
| Ciphers | `:106` ECDHE-only AEAD (AES-GCM + ChaCha20-Poly1305); `:105` `ssl_prefer_server_ciphers on;`; `:107` `ssl_ecdh_curve X25519:prime256v1:secp384r1;` |
| Session tickets | `:110` `ssl_session_tickets off;` — "tickets without rotation weaken forward secrecy" |
| HSTS | `:122` `max-age=63072000; includeSubDomains` (2 years; `preload` deliberately not set, `:118-121`) |
| OCSP stapling | `:112-116`, commented out |
| Certificates | `:97-98` `/etc/nginx/certs/{fullchain,privkey}.pem`; key-permission trap documented `:54-58` |

It is enabled on the lab host through the gitignored override
(`docker-compose.override.yml:4-11`) and is **not** in the tracked compose,
because mounting `tls.conf` without certificates would stop nginx booting on a
fresh install (`docker-compose.yml:1726-1733`).

**v1 change:** promote it from `tls.conf.example` to a first-class, profile-gated
file. `production` requires it; `lab` may use `gen-dev-cert.sh` output. The
"copy it verbatim" warning at `:27-31` becomes unnecessary because the gated
paths live in a real included file rather than an example.

`tls.conf.example:3-31` carries the most important operational warning in the
repo and must survive the promotion verbatim:

> `:11-14` — *"Grafana runs with **ANONYMOUS Viewer access enabled** … OpenSearch
> Dashboards runs with its **SECURITY PLUGIN DISABLED** (no tenant isolation at
> all)"*
> `:18-20` — *"A TLS server block that proxies those paths WITHOUT the
> auth_request gates publishes all of the above to whoever can reach port 443. An
> earlier version of this example did exactly that — do not reintroduce it."*

## 6.13.2 Public vs internal port exposure

Published host ports today, enumerated from compose:

| Port | Service | Line | v1 disposition |
|---|---|---|---|
| `${BASE_PORT:-8000}` → 8080 | nginx (**plaintext**) | `:1722` | **retire** after cutover — HLD T17 |
| `443` → 8443 | nginx TLS | `docker-compose.override.yml:6` | **keep — becomes the only web port** |
| `514/udp`, `514/tcp` | syslog-ng | `:296-297` | keep (device lane, Phase 2) but bind to a declared interface (§6.15.6) |
| `${SYSLOG_PORT:-5514}/udp`, `/tcp` | syslog-ng | `:294-295` | keep, same treatment |
| `${NETFLOW_PORT:-2055}/udp` | goflow2 | `:399` | keep, telemetry interface only (§6.18) |
| `${IPFIX_PORT:-4739}/udp` | goflow2 | `:400` | keep, same |
| `${SFLOW_PORT:-6343}/udp` | goflow2 | `:401` | keep, same |
| `${SNMP_TRAP_PORT:-162}/udp` → 1162 | api | `:1516` | keep, same |
| `127.0.0.1:8099` → 8090 | mock-servicenow | `:1632` | **must not exist in production** — profile refused (§6.21.9) |
| `127.0.0.1:8098` → 8091 | mock-nms | `:1660` | same |

**Nothing else is published** — Kafka, OpenSearch, ClickHouse, VictoriaMetrics,
Postgres, Valkey, Grafana, OSD, Keycloak and NetBox are all compose-network-only.
That is already correct and must be preserved as a validator rule (§6.21.3).

The two mocks bind `127.0.0.1` explicitly (`:1629-1632`, `:1657-1660`), which is
the right pattern and worth copying if any other debug port is ever added.

## 6.13.3 Existing headers, cookies and normalization

**`$fwd_proto`** — already shipped and correct (`default.conf:26-29`):

```nginx
map $http_x_forwarded_proto $fwd_proto {
    https   https;
    default $scheme;
}
```

Only the literal `https` is trusted; anything else falls back to the actual
scheme (`default.conf:18-25`). Consumed at `:141` (`/api/`), `:254` (`/netbox/`),
`:315` (`/search/`), `:383` (`/auth/`).

**Gap:** several locations set no `X-Forwarded-Proto` at all — `/` (`:40-67`),
`/docs/` (`:79-95`), `= /api/events` (`:100-111`), the SSH WebSocket regex
(`:119-130`), `/admin/` (`:146-151`), `= /metrics` (`:158-164`). For `/api/events`
and the SSH socket this matters, because `cookieSecure(r)`
(`auth.go:979-987`) consults `r.TLS != nil` (`:983`) then
`X-Forwarded-Proto` (`:986`) — behind nginx, `r.TLS` is nil, so without the
header a cookie set on those paths is **not** marked Secure. **v1: set
`X-Forwarded-Proto $fwd_proto` on every proxied location.**

**Cookies** — `auth.go:970-972` (`secureCookies()` reads `SECURE_COOKIES`),
`auth.go:979-987` (`cookieSecure(r)`: env force → `r.TLS != nil` → forwarded
header). Call sites `auth.go:1005`, `:1018`, `oidc.go:97`, `:138`. Gate cookie
`osdCookieName = "netops_osd"` (`auth.go:966`), path `/` deliberately
(`auth.go:989-994`) so it covers `/search` and `/netbox/`; HttpOnly + SameSite=Lax.
Locked by `security_lows_test.go:26-34` and `oidc_state_cookie_test.go:24-25,
91-93, 116-119, 169-170`. **v1: the production profile sets
`SECURE_COOKIES=true`** — belt and braces once TLS is mandatory.

**CSP** — `default.conf:63` for the SPA:
`default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'`,
with `X-Frame-Options: DENY` (`:55`), `nosniff` (`:56`), `Referrer-Policy:
no-referrer` (`:57`). The docs portal gets a looser policy (`:94`,
`script-src 'self' 'unsafe-inline'`, `frame-ancestors 'self'`) so the in-app Help
panel can iframe it. Header non-inheritance is documented at `:52-54`.

`[UNKNOWN]` No CSP is set on `/grafana/` or `/search/`, which embed third-party
UIs. Those are gated by `auth_request`, so the exposure is authenticated-only,
but a per-location CSP for them is cheap and should be evaluated.

**Log redaction** — `nginx.conf:49-58` maps strip capability tokens from the
access log, applied in `log_format main` (`:60-62`), rationale at `:31-48`
("capability tokens must never enter the log store"). `server_tokens off`
(`nginx.conf:16`). Both preserved.

## 6.13.4 nginx → API mTLS

Today every upstream is plaintext: `default.conf:102`, `:121`, `:135`, `:148`,
`:163`, `:326`, `:342` — all `proxy_pass http://$up_api:8080;`.

The target block is already written in the runbook
(`docs/runbooks/tls-mtls.md:44-52`) and needs only to be applied:

```nginx
proxy_ssl_certificate         /etc/nginx/tls/nginx/nginx.crt;
proxy_ssl_certificate_key     /etc/nginx/tls/nginx/nginx.key;
proxy_ssl_trusted_certificate /etc/nginx/tls/ca.pem;
proxy_ssl_verify              on;
proxy_ssl_verify_depth        2;
proxy_ssl_name                api;
proxy_ssl_server_name         on;
proxy_ssl_protocols           TLSv1.2 TLSv1.3;
proxy_ssl_session_reuse       on;      # handshake cost — HLD §11 standing risk
```

Kept in an included file (`nginx/api-mtls.conf`) that the profile swaps in, so
the plaintext default remains the lab fallback
(`docs/runbooks/tls-mtls.md:53-54`).

API side (already implemented, dormant):

```
TLS_CERT_FILE=/data/tls/api/api.crt
TLS_KEY_FILE=/data/tls/api/api.key
TLS_CLIENT_CA_FILE=/data/tls/ca.pem
TLS_CLIENT_ALLOWED_URIS=spiffe://correlix.workload/ns/ingress/sa/nginx
TLS_RELOAD_INTERVAL=30s
```

`TLS_CLIENT_ALLOWED_URIS` (`docker-compose.yml:1459`) is the least-privilege
half and is **mandatory**, per §6.4.2: leaving it unset makes `PeerPolicy` return
`nil` for any mesh certificate (`tlsconfig/verify.go:62-64`). URI matching is
exact and case-sensitive (`verify.go:78`), so the string must match the minted
SPIFFE ID byte for byte.

The API rejects a non-mTLS client (`tls_server.go` builds
`RequireAndVerifyClientCert` via `tlsconfig/config.go:37-38`) and counts the
rejection (`netops_tls_identity_rejected_total`, `tls_server.go:155-157`, hooked
at `:97-100`). Verification steps are in the runbook (`tls-mtls.md:57-64`).

**Ordering hazard, found while verifying** — `initBackendTransport()` runs inside
`newServer()` at `main.go:284`, but `bootstrapInternalCA()` (which *writes*
`ca.pem`) runs much later at `main.go:1331`. On a **first** boot with
`TLS_INTERNAL_CA=true` and `TLS_BACKEND_CA_FILE` pointing at the not-yet-written
bundle, `initBackendTransport` will fail to load it and `log.Fatalf`
(`main.go:285`). v1 must either move the CA bootstrap before
`initBackendTransport` or make the backend transport lazily initialised. This is
a real first-boot foot-gun in existing code, not a new design concern.

## 6.13.5 API HSTS

`hsts()` (`tls_server.go:130-135`) sets `max-age=63072000; includeSubDomains` and
is applied **only when the API is actually serving TLS** (`main.go:1347`). Since
nginx terminates browser TLS, nginx's HSTS (`tls.conf.example:122`) is the one
browsers see; the API's applies to direct-TLS deployments. Both are correct;
neither sets `preload`, deliberately.

## 6.13.6 Forwarded-header trust

nginx is the only entity permitted to set forwarded headers, and it **overwrites**
client-supplied copies. Two places already do this and are the pattern to follow:
`proxy_set_header X-WEBAUTH-USER $grafana_user` (`default.conf:194`, value
captured from the gate's response at `:185`) and NetBox's `X-Remote-User`
(`docker-compose.yml:1800-1809`).

`[UNKNOWN]` `GF_AUTH_PROXY_WHITELIST` is left open on the internal bridge
(`docker-compose.yml:851-852` — "set `GF_AUTH_PROXY_WHITELIST` to the nginx
IP/CIDR in prod"). With `GF_AUTH_ANONYMOUS_ENABLED: "true"` (`:864`) and
`GF_USERS_AUTO_ASSIGN_ORG_ROLE: "Admin"` (`:860`), anything on the compose
network that can reach Grafana directly can assert an arbitrary admin username.
**v1: set the whitelist in the production profile, and rely on §6.22 to make
Grafana unreachable except from nginx.**

## 6.13.7 Admin-endpoint restrictions

Four locations are gated by `auth_request` against the API's own
`/api/auth/osd-gate` (`default.conf:322-331`, `:338-347`):

| Location | Line | Gate | Why |
|---|---|---|---|
| `= /metrics` | `:158-164` | `/__osd_auth` | "exposes internal hostnames/cardinality that can reveal tenants/devices" (`:153-157`) |
| `/grafana/` | `:180-205` | `/__osd_auth` | Grafana runs anonymous-Viewer (`:173-179`) |
| `/netbox/` | `:244-…` | `/__osd_auth` | privileged superuser |
| `/search/` | `:302-318` | `/__osd_auth_search` | OSD security plugin off (`:303-306`) |

These gates stay exactly as they are. Once §6.8 turns on the OpenSearch security
plugin, the gate becomes defence in depth rather than the only control — but it
is not removed, because removing a working control while adding a new one is how
gaps appear.

`/admin/` (`:146-151`) is **not** `auth_request`-gated; it is protected by the
API's own authz. `[UNKNOWN]` worth confirming which `/admin/*` routes are
public — `/admin/healthz` and `/admin/readyz` must stay reachable for probes
(`main.go:1828`), while `/admin/version` (`docker-compose.yml:1073-1075`) reveals
build provenance and should not be.

## 6.13.8 Rate limiting

**There is none.** `limit_req` and `limit_conn` appear only inside comments in
`tls.conf.example:159,164,166`; there is no `limit_req_zone` anywhere in
`nginx.conf` or `default.conf`. The API enforces per-account lockout
(`tls.conf.example:168-170`) and per-API-key limits
(`APIKEY_RATE_LIMIT_PER_MIN`, `docker-compose.yml:1406`), so credential
stuffing is bounded — but an **unauthenticated** flood, and TLS-handshake flood
in particular, is not.

v1 adds, at the edge:

```nginx
limit_req_zone $binary_remote_addr zone=auth:10m  rate=10r/m;   # login/token endpoints
limit_req_zone $binary_remote_addr zone=api:10m   rate=60r/s;   # general API
limit_conn_zone $binary_remote_addr zone=conn:10m;
```

applied with a `burst`+`nodelay` on `/api/auth/*` and a generous limit on
`/api/`. Deliberately **not** applied to `= /api/events` (SSE, long-lived) or the
SSH WebSocket (`default.conf:119-130`), where a connection limit
(`limit_conn conn 20;`) is the right control instead. `[ASSUMPTION]` — the rates
are starting points and must be tuned against a real deployment before the
production profile enforces them.

## 6.13.9 The sealing-key hop — the sharpest single fix

`deployment/docker/vector-router/cx-secret-backend.sh`:

```sh
API="${SEALING_API_URL:-http://api:8080}"                              # :24
body="$(curl -fsS --max-time 10 \                                       # :55
  -u "${INGEST_USER}:${INGEST_TOKEN}" \                                 # :56
  "${API}/internal/sealing/edge-keys?tenant=${tenant}" 2>/dev/null || true)"   # :57
```

Per-tenant **sealing and MAC keys** (`seal_key`/`mac_key`, extracted at `:60-61`
and `:69-70`) cross the network in cleartext, authenticated by the **same shared
`INGEST_TOKEN`** that gates telemetry ingest. Compose wires it at
`docker-compose.yml:485-487`. A holder of that one token gets **every tenant's**
sealing keys — which undoes the sealed-fields feature's entire guarantee.

The script itself is well built: `set -eu` (`:22`), fail-closed when the token is
missing (`:30-36`), fail-closed when a key cannot be resolved (`:79`), and strict
character-class extraction so nothing from stdin reaches the shell (`:44-47`).
The defect is purely the transport and the credential.

**v1 fix, in three parts:**

1. `SEALING_API_URL` becomes `https://api:8443` and `curl` presents the
   **vector-router's own client certificate**:
   `--cacert /tls/ca.pem --cert /tls/vector-router/tls.crt --key /tls/vector-router/tls.key`.
2. The API authorizes `/internal/sealing/edge-keys` on the **certificate
   identity** (`spiffe://correlix.workload/ns/ingestion/sa/vector-router`), not
   on the ingest token. `TLS_CLIENT_ALLOWED_URIS` becomes a **two**-entry
   allowlist (nginx + vector-router), and the handler additionally checks the
   peer identity for this specific path — an authenticated peer is not
   automatically authorized for key retrieval (F-04).
3. Every fetch is **audited** with the tenant and the caller identity, and
   counted (`netops_sealing_key_fetch_total{identity,outcome}`).

`--cacert`/`--cert`/`--key` are curl flags, not new dependencies, and the script
remains under `scripts`-grade rules (CLAUDE.md §16): no new `|| true` on the
authenticated path, and a non-zero exit must stay non-zero.

## 6.13.10 Ingest lanes — retiring the one shared token

Four `http_server` sources, one shared credential:

| Lane | Address | Auth |
|---|---|---|
| `trap_in` | `0.0.0.0:8688` (`vector/vector.yaml:127`) | `auth: &ingest_auth` (`:128`), user `:129`, password `:130` |
| `probe_in` | `0.0.0.0:8689` (`:139`) | `auth: *ingest_auth` (`:140`) |
| `metrics_in` | `0.0.0.0:8690` (`:152`) | `*ingest_auth` (`:153`) |
| `bus_in` | `0.0.0.0:8692` (`:167`) | `*ingest_auth` (`:166-167`) |

`vector/vector.yaml:108-110` states the rationale plainly ("one shared ingest
secret … every client here is a stack-internal component"), and `:117` documents
that an empty `INGEST_TOKEN` **disables auth entirely**. Clients holding it:
`gnmic` (`docker-compose.yml:341`), `vector-router` (`:487`), `api` (`:1109`),
`prober` (`:1565`), and — override-only — `cloud-ingest`
(`docker-compose.override.yml:37`). The aggregator itself is the verifier
(`:438`, the only `:?`-required one).

Go side: `collectors/ingest_auth.go:39-45` reads the credential once
(`sync.OnceValue`, `:47`), and `SetIngestAuth` (`:72-78`) **sends no header at
all** when the token is empty (`:74-76`) — deliberate, documented at `:65-71`,
with the fail-closed half living in Vector's config, not in Go.

**v1 target:**

- Each lane gets `tls:` with `verify_certificate: true` and a per-lane
  `client_identity` allowlist. Vector's `http_server` source supports
  `tls.ca_file` + `tls.verify_certificate`; `[UNKNOWN]` whether Vector 0.40 can
  express a **per-source client-identity allowlist** (as opposed to "any client
  with a cert from this CA"). If it cannot, the allowlist moves one layer out —
  each lane binds a **distinct port on a distinct internal network** (§6.22), and
  the identity check happens at the network policy. Decide before Phase 5.
- Basic auth is retained *underneath* mTLS during migration, then dropped.
- `IngestAuthConfigured()` (`ingest_auth.go:83`) is extended to report
  `unencrypted` as well as `unauthenticated`, exactly as
  `docs/design/transport-encryption-2026-08-04.md:201` proposes, and both are
  surfaced in the posture view (§6.24).
- **The `bus_in` lane is separated first**, because it is the topic-injection
  path (§6.7.6).

## 6.13.11 Remote vantage

`handleProbePathsPush` (`probe_paths_ingest.go:27-55`) requires
`infrastructure:write` (`:28`) — but the **vantage identity comes from the request
body**: `vantage, clean, err := pathgraph.ValidatePushedPaths(in)` (`:41`), then
`s.remotePaths.Put(vantage, clean, ...)` (`:50`). So any holder of an
`infrastructure:write` API key can publish paths **as any vantage**, and those
paths become RCA evidence.

The handler is otherwise careful — bounded body (`:31`), bounded count (`:37`),
validated content (`:41`), and the package doc is explicit that "the prober is an
input, not a trusted peer" (`:25-26`).

- **v1:** bind the vantage id to the **API key**, not the payload. A key carries
  a `vantage_id` claim; a mismatch is a 403, not a silent accept. No new
  transport needed.
- `[Phase 2+]` per-vantage certificate under `correlix.device`, replacing the
  shared key entirely.

---

# 6.14 Correlation service LLD `[v1]`

## 6.14.1 Current state — unauthenticated **and** cross-tenant

The service is FastAPI at `src/correlation/main.py`. It has **zero**
authentication: `Depends`, `Security`, `OAuth2`, `APIKeyHeader`, `HTTPBearer`
and `add_middleware` appear **nowhere** in the file; the import line is
`from fastapi import FastAPI, HTTPException` (`main.py:41`), and the app is built
with no dependencies (`main.py:3319`).

Six routes, none gated:

| Route | Line |
|---|---|
| `GET /deadletters` | `main.py:3334` |
| `GET /metrics` | `:3349` |
| `GET /healthz` | `:3435` |
| `GET /correlations/{id}/replay` | `:3534` |
| `GET /findings` | `:3548` |
| `POST /analyze` | `:3573` |

The compensating control is architectural and is documented in the code itself —
`main.py:3338-3339` and `:3536-3537` both say *"Internal surface (the Go API
fronts it with authz)"*. The Go front door is
`proxyCorrelationReplay` (`correlations.go:759-780`), reaching
`CORRELATION_URL` (default `http://correlation:8000`, `correlations.go:763`,
`docker-compose.yml:1144`) — **plain HTTP**.

**Worse than the HLD states.** `CH.query()` issues every read at
`tenant_scope=__all__`:

```python
r = await self.client.post(
    self.base, params={"default_format": "JSON", "tenant_scope": "__all__"},   # main.py:1837
    content=sql, auth=self.auth,
)
```

So `/findings` (`main.py:3548-3570`) runs `SELECT ... FROM netops.findings` with
**no tenant predicate** through a **row-policy-bypassing** scope, on an
**unauthenticated** endpoint. `/deadletters` returns raw quarantined event bodies
from every tenant (`main.py:3345`). Anything on the compose network can read
cross-tenant correlation data today. See §7.

## 6.14.2 API → correlation authn

```
CORRELATION_URL=https://correlation:8443
```

- Correlation serves TLS with its own SVID
  (`spiffe://correlix.workload/ns/app/sa/correlation`) and **requires a client
  certificate**.
- The **only** accepted client identity is
  `spiffe://correlix.workload/ns/app/sa/api`.
- The Go side needs no new code: `backendHTTPClient` already presents
  `TLS_BACKEND_CERT_FILE`/`KEY_FILE` (`backend_client.go:66-71`) and verifies
  against the mesh bundle (`:34,47`), and `correlations.go:770` already uses it.
  Turning this on is configuration.
- Uvicorn serves TLS with `--ssl-certfile`, `--ssl-keyfile`, `--ssl-ca-certs`
  and `--ssl-cert-reqs=2` (`CERT_REQUIRED`). Peer-identity checking is a short
  ASGI middleware reading the peer certificate from the transport — stdlib
  `ssl`, no new dependency.

**No plaintext fallback.** The plaintext port is removed at cutover; during
migration both exist with a declared, expiring exception (§6.25). The Go client
fails closed already: a configured-but-unloadable bundle is fatal
(`backend_client.go:30-32`, `main.go:284-286`).

## 6.14.3 Correlation's own credentials

| Dependency | Today | v1 |
|---|---|---|
| Kafka | `KAFKA_BOOTSTRAP` plaintext (`docker-compose.yml:972`), group `netops-correlation` (`main.py:2233`) | mTLS via `aiokafka` `ssl_context`; ACLs = **consume only**, on the 12 topics at `main.py:137-141`, in that one group (§6.7.7) |
| ClickHouse | shared `netops` user, Basic over HTTP (`:975-976`, `main.py:1757`) | client cert as the `correlation` user; `INSERT` on `corr_*`/`findings`, `SELECT` on `corr_*` (§6.9.4) |
| Postgres | inline DSN, no TLS (`:977`) | `sslmode=verify-full` + the `correlation` role (§6.11.4) |
| OpenSearch | `OPENSEARCH_URL` set (`:973`) | `[UNKNOWN]` — appears unused. If unused, **delete the variable**; a credential that exists for no reason is a credential to steal |

## 6.14.4 Tenant propagation

The service already re-derives tenancy rather than trusting the bus:
`verified_tenant()` (`main.py:353`) is applied on the syslog, flows, metrics,
probes, traps and wireless lanes (`main.py:2442`, `:2644`, `:2709`, `:2803`,
`:2873`, `:3073`, `:3190`). The cloud/app-identity/app-edge lanes deliberately do
not (`main.py:2942-2950`) because a cloud account has no device identity to check
against — and they instead **drop** an untenanted event (`main.py:2952-2955`).
That reasoning is sound and stays.

Write-side scope is derived from the rows, never from a default
(`insert_scope`, `main.py:1728-1751`), with an honest note that row policies are
`FOR SELECT` only (`:1735-1743`) and a cross-tenant insert counter
(`corr_cross_tenant_inserts_total`, `main.py:3414`).

**v1 changes, in priority order:**

1. **`/findings` must be tenant-scoped.** It takes a tenant parameter supplied by
   the Go API from the authenticated principal, and the query runs at
   `tenant_scope=<tenant>` — not `__all__`. The Go API never forwards a
   client-supplied tenant; it forwards `principalTenant(claims)`
   (`tenancy.go:63`). This is a **CLAUDE.md §3a rule 1** fix and is the highest
   priority item in this section.
2. **`CH.query()` must take an explicit scope**, exactly as the Go side already
   requires (`clickhouse_client.go:110-117` — "the scope was hardcoded `__all__`
   until the 2026-07-27 audit"). `__all__` becomes a **visible choice at each
   call site**, not a client default.
3. **`/deadletters` becomes platform-admin-only** through the Go front door, and
   redacts event bodies unless the caller is cross-tenant.
4. An `org_isolation`-shaped test for the correlation HTTP surface, per §3a rule 5.

## 6.14.5 Container posture

Already good and worth keeping: `security_opt: ["no-new-privileges:true"]`
(`docker-compose.yml:960`), `cap_drop: [ALL]` (`:961`), non-root `appuser`
(`Dockerfile.correlation:27`), and a real `/metrics`-based health check with the
reasoning recorded (`docker-compose.yml:1029-1040`). §6.21 adds `read_only` +
`tmpfs`.

---

# 6.15 Syslog LLD

**Phase note.** Per decision **D1**, the customer-facing device leg stays as it
is in v1 — we cannot force customer hardware onto RFC 5425. What **is** v1:
(a) the syslog-ng → Vector hop inside our own stack goes TLS (§6.15.5),
(b) the legacy lane gets its honest label, source allowlist and interface binding
(§6.15.4, §6.15.6), and (c) the secure lane is fully designed below so Phase 2 is
build, not design.

## 6.15.1 Lane A — secure `[Phase 2+]`

| Property | Value |
|---|---|
| Port | **6514/tcp** (RFC 5425, syslog-over-TLS) |
| Transport | TLS 1.2+, mutual |
| Client identity | device certificate under `correlix.device` |
| SPIFFE ID | `spiffe://correlix.device/tenant/<tenant_id>/kind/device/id/<device_id>` (HLD §6.2) |
| Trust anchor | **device intermediate only** — a workload certificate must not open a device lane, and vice versa (F-11, enforced by `FederationTrust`, `tlsconfig/federation.go:179`) |
| Hostname verification | server side: the device verifies our collector cert. Our side: the *client* has no DNS name we can verify, so authorization is by **URI SAN**, not hostname |
| Cert TTL | 90d, renew at 21d (§6.3.3) |

syslog-ng configuration shape:

```
source s_secure {
    syslog(ip(0.0.0.0) port(6514) transport("tls")
        tls( key-file("/tls/syslog-ng/tls.key")
             cert-file("/tls/syslog-ng/tls.crt")
             ca-file("/tls/device-ca.pem")
             peer-verify(required-trusted)     # mutual, chain-verified
             ssl-options(no-sslv2, no-sslv3, no-tlsv1, no-tlsv11) )
        flags(syslog-protocol) );
};
```

`peer-verify(required-trusted)` is the whole control. `optional-untrusted` is
forbidden (F-02 class).

## 6.15.2 cert → device → tenant mapping `[Phase 2+]`

The certificate carries a tenant claim. **The claim is checked, never trusted.**

```mermaid
sequenceDiagram
  participant D as Device
  participant SNG as syslog-ng :6514
  participant VEC as vector-aggregator
  participant API as api (device registry)

  D->>SNG: TLS ClientHello + device certificate
  SNG->>SNG: verify chain against DEVICE intermediate ONLY
  alt chain invalid / wrong trust domain
    SNG-->>D: handshake refused · netops_device_tls_rejected_total{reason}
  end
  SNG->>SNG: extract URI SAN → (tenant_claim, device_id)
  SNG->>VEC: event + peer identity (structured field, NOT a log field)
  VEC->>API: registry lookup device_id  (cached, TTL-bounded)
  alt device unknown
    VEC-->>VEC: DROP + netops_device_identity_unmapped_total. NEVER auto-create
  else registered tenant != tenant_claim
    VEC-->>VEC: DROP + netops_device_identity_conflict_total + AUDIT
  else device revoked in registry
    VEC-->>VEC: DROP + netops_device_revoked_total    (revocation in seconds, §6.3.7)
  else match
    VEC->>VEC: stamp tenant_id = registry tenant (NOT the claim)
    VEC->>VEC: stamp transport_authenticated = true
  end
```

Three rules, all non-negotiable:

1. **Never auto-create a device from a certificate.** An unregistered
   certificate is a rejection, not an enrolment.
2. **The registry wins.** `tenant_id` is stamped from the **registered** record.
   The certificate's tenant claim is only ever compared, never copied.
3. **A conflict is an alert, not a warning.** A valid certificate asserting the
   wrong tenant is either a mis-issuance or an attack; both are incidents.

This preserves CLAUDE.md §3a: transport identity narrows *who may connect*; the
tenant boundary stays in the data layer.

## 6.15.3 Lane B — legacy `[v1, hardened]`

Today, verified:

```
source s_network {                                   # syslog-ng.conf:83
    udp(ip(0.0.0.0) port(514));                      # :84
    tcp(ip(0.0.0.0) port(514) max-connections(64));  # :85
};
keep_hostname(yes);                                  # :67
```

No `tls()` block exists anywhere in the file. Published on the host on **both**
`${SYSLOG_PORT:-5514}` and the hard-coded privileged `514`
(`docker-compose.yml:294-297`).

The config file is already brutally honest about what this means
(`syslog-ng.conf:42-44`):

> *"But this source listens on UDP+TCP/514 with NO ACL and NO authentication: the
> hostname is an UNVERIFIED CLAIM by whoever sent the packet. Anything that can
> route to this port can write any hostname it likes."*

and states the residual risk plainly (`:59-66`): a sender that reaches the port
and knows a real hostname lands in that tenant's lane; *"No app-layer check can
close that — it needs transport authentication."* Existing compensations are
listed at `:47-57` (aggregator re-derives tenancy from `device_tenant.csv`; log
content may not set tenancy; `verified_tenant` quarantines unreproducible
claims — `main.py:353`).

**v1 hardening, none of which requires touching a customer device:**

| Control | Implementation |
|---|---|
| Explicit enablement | `ENABLE_LEGACY_SYSLOG` (default **false** in the production profile). The lane exists because it is switched on, not because it always was |
| Declared exception | a `TransportPolicy` with a mandatory `exception` block (V-09), owner + expiry (V-10/V-12), surfaced in the posture view |
| Source allowlist | `source s_network { ... }` gains an explicit accept list of exporter CIDRs, generated from the device registry; everything else dropped at the listener |
| Dedicated interface | the published ports bind a **declared telemetry interface**, not `0.0.0.0` (§6.15.6) |
| Rate limit | syslog-ng `log { ... flags(...) }` plus a per-source message-rate cap; a single spoofing source must not be able to fill the lane |
| Honest label | `transport_authenticated=false` on every event (§6.15.4) |
| Deadline | the exception expires; §6.25 |

## 6.15.4 `transport_authenticated` — a new field `[v1]`

**It does not exist today.** An exhaustive grep across `src/` and
`deployment/` returns zero hits; the only occurrence in the repo is the HLD's own
proposal (`CORRELIX_CLOUD_NATIVE_SECURITY_HLD.md:413`). See §7.

What *does* exist is narrower: the SNMP trap lane has a boolean
`Authenticated bool \`json:"authenticated"\`` (`collectors/snmptrap.go:60`,
comment *"v3 auth verified (v1/v2c are spoofable → false)"*), set true in exactly
one place (`:692`) and otherwise left at Go's zero value. Syslog and flow events
carry **no** authenticity marker at all.

**v1 defines the field once, for every ingest lane:**

```
transport_authenticated : bool     # was the PEER cryptographically authenticated?
transport_mode          : enum     # plaintext | tls | mtls | protocol_native
transport_identity      : string   # the peer identity, or "" — never a hostname
```

Rules:

- Stamped by the **collector**, from the connection — never from the payload.
- Defaults to `false`/`plaintext`/`""`. A missing field is treated as
  unauthenticated by every consumer.
- The existing `authenticated` field on traps is **kept** for compatibility and
  `transport_authenticated` is set alongside it from the same source.
- **Never displayed as "verified" in the UI, in RCA evidence, or in a report
  unless it is `true`.** This is HLD §6.6's honesty clause made mechanical, and
  validator rule F-12 refuses a policy that claims otherwise.

## 6.15.5 syslog-ng → Vector `[v1]`

The internal hop is ours on both ends, so it moves in v1:

```
destination d_vector {          # syslog-ng.conf:109
    syslog("vector-aggregator"  # :110
        transport("tcp")        # :111  → becomes transport("tls") + tls(...) block
        port(6601)              # :112  → 6601 stays; TLS on the same port at cutover
        flags(syslog-protocol)  # :113
        ...disk buffer :114-119 );
};
```

Vector side: `syslog_in` at `0.0.0.0:6601` (`vector/vector.yaml:88`) with no
`tls:` block — gains `tls: { enabled: true, ca_file, crt_file, key_file,
verify_certificate: true }` and accepts only
`spiffe://correlix.workload/ns/ingestion/sa/syslog-ng`.

**Continuity:** the F-48 reliable disk buffer (`syslog-ng.conf:114-119`, mem
10 MiB / disk 256 MiB / `reliable(yes)`, spool at `docker-compose.yml:286-288`)
absorbs the restart window — which is exactly why that buffer was added
(*"without this ... a vector-aggregator restart silently DROPS device syslog"*).
Cutover is: enable TLS on the Vector source alongside plaintext → switch
syslog-ng → verify → remove the plaintext acceptance.

## 6.15.6 Interface binding `[v1]`

`0.0.0.0` on a privileged host port is the widest possible surface. v1 makes the
bind address explicit and declared:

```yaml
ports:
  - "${TELEMETRY_BIND_ADDR:-0.0.0.0}:${SYSLOG_PORT:-5514}:514/udp"
  - "${TELEMETRY_BIND_ADDR:-0.0.0.0}:${SYSLOG_PORT:-5514}:514/tcp"
  - "${TELEMETRY_BIND_ADDR:-0.0.0.0}:514:514/udp"
  - "${TELEMETRY_BIND_ADDR:-0.0.0.0}:514:514/tcp"
```

The default preserves today's behavior exactly (no change for existing installs);
the **production profile requires `TELEMETRY_BIND_ADDR` to be set to a specific
address** and refuses `0.0.0.0`. Same treatment for goflow2 (§6.18) and the trap
listener (§6.16).

---

# 6.16 SNMP LLD

**Phase note.** Rolling customer devices to v3 `authPriv` is **Phase 2** (D1).
But three items in this section are **v1**, because they are Correlix-side code
defects that need no customer action: the trap fail-open (§6.16.6), the
priv-algorithm mismatch (§6.16.3), and the silent auth-protocol downgrade
(§6.16.3).

## 6.16.1 Generic TLS does not secure SNMPv3 — stated explicitly

SNMPv3 security is **USM**: HMAC authentication plus CFB-mode privacy over UDP,
negotiated per message with per-engine localized keys. There is no TLS layer, no
certificate, and no handshake. Wrapping the stack in TLS does **nothing** for
SNMP.

This is why the policy schema has `outbound.mode: protocol_native` with a
`min_level` (§6.2.3): so an SNMP peer's security posture is expressible and
enforceable **without** the dishonest claim that "everything is TLS". Any report
or UI that lists SNMP as "TLS ✓" is wrong; the correct rendering is
"SNMPv3 authPriv ✓" (§6.24.4).

## 6.16.2 Current state

- Credential store enums (`internal/snmpcred/store.go:26-31`):
  `Versions = v1|v2c|v3`, `SecurityLevels = noAuthNoPriv|authNoPriv|authPriv`,
  `AuthProtocols = MD5|SHA|SHA224|SHA256|SHA384|SHA512`,
  `PrivProtocols = DES|3DES|AES128|AES192|AES256`.
- Validation (`store.go:95-143`): v3 requires a security name (`:118-120`) and a
  valid level (`:121-123`); `authNoPriv`/`authPriv` require a listed auth
  protocol + key (`:126-131`); `authPriv` additionally a listed priv protocol +
  key (`:134-139`). **`noAuthNoPriv` is accepted with no keys at all.**
- Credentials are sealed per-tenant, per-field: `snmp.community`,
  `snmp.auth_key`, `snmp.priv_key` (`store.go:176-180`), encrypted at
  `store.go:259,262,265` and decrypted at `:274,277,280`. Load **fails closed** on
  an undecryptable file (`store.go:192-195` → `NewStore` `:169-171`).
- Redaction: `Public` exposes only `HasCommunity`/`HasAuthKey`/`HasPrivKey`
  booleans (`store.go:75,79,81`); `List()`/`Get()` return `Public` (`:286`,
  `:299`), only `Resolve()`/`ResolveAll()` return plaintext (`:312`, `:329`).
- **The poller has no security-level gate.** `Target.creds()`
  (`poller.go:77-93`) passes `V3Level` straight through; `byProtocolVersion`
  (`poller.go:125-140`) partitions v2c/v3 for *metrics accounting only*
  (`:121-124`). Nothing refuses a `noAuthNoPriv` target.
- **v2c falls back to `"public"`** — `poller.go:85-92`:
  `t.Community` → `os.Getenv("SNMP_COMMUNITY")` → `"public"` (`:89-91`).

## 6.16.3 Algorithms — what is advertised vs what works `[v1 fix]`

| Protocol | Store accepts (`store.go:29-30`) | Collector implements | Result |
|---|---|---|---|
| MD5, SHA(1), SHA224, SHA256, SHA384, SHA512 | ✅ | ✅ `authHash()` (`snmpv3.go:74-91`) | correct |
| **an unrecognized auth name** | rejected by the store | **silently falls back to SHA-1/12** (`snmpv3.go:88-89`, the `default:` branch) | **silent downgrade** |
| DES | ✅ | ✅ `HasPrefix("DES")` (`snmpv3.go:258,305`) | correct |
| AES128 | ✅ | ✅ `HasPrefix("AES")` → `aes.NewCipher(key[:16])` (`snmpv3.go:242`) | correct |
| **AES192, AES256** | ✅ | matches `HasPrefix("AES")` → **also `key[:16]`, i.e. AES-128** (`snmpv3.go:242,300`) | **silently weaker than advertised** |
| **3DES** | ✅ (`store.go:30`) | matches **neither** prefix → `default:` → `"snmpv3: unknown priv protocol"` (`snmpv3.go:284,322`) | **a credential the store calls valid fails at runtime** |

Three v1 fixes, all small and all Correlix-side:

1. **Remove `3DES`, `AES192`, `AES256` from `PrivProtocols`** (`store.go:30`)
   until they are actually implemented, *or* implement them. Advertising a
   strength that is silently not delivered is worse than not offering it.
2. **Make the auth-protocol `default:` branch an error** (`snmpv3.go:88-89`),
   matching the priv path which already fails closed (`:284`, `:322`). A typo in
   a credential must not silently downgrade to SHA-1.
3. **Prefer exact matching over `HasPrefix`** for priv protocols, so `AES256`
   cannot quietly mean AES-128.

Validator rule **V-15** enforces the invariant going forward: a policy's
`priv_algorithms` must be a subset of what the collector implements.

The deliberate weak-primitive suppressions are correctly annotated and stay —
`snmpv3.go:14` (`#nosec G502`, DES), `:16` (`G501`, MD5), `:18` (`G505`, SHA-1),
`:263,306` (`G405`) — with the rationale at `:4-6` that these are
protocol-mandated. The AES-CFB IV is constructed per RFC 3826 §3.1 from
engineBoots‖engineTime‖salt, not a fixed nonce (`snmpv3.go:246-250`).

## 6.16.4 Per-device vs per-group credentials

HLD §10 rejects tenant-wide shared SNMP credentials: blast radius = every device
in the tenant. The store already supports the right granularity — credentials are
tenant-scoped records (`store.go:TenantID`) referenced per device.

| Model | When | Rule |
|---|---|---|
| **Per-device** | high-value / core devices | preferred |
| **Per-group** | a homogeneous access-layer fleet | allowed, with the group declared in the policy |
| **Tenant-wide** | — | **forbidden** in the production profile |
| **Platform-wide** | — | **forbidden always** |

`SNMP_COMMUNITY` and the `"public"` fallback (`poller.go:85-92`) are exactly the
platform-wide shape and are **refused by the production validator** in v1.

## 6.16.5 Engine ID, replay, and the `min_level` gate `[Phase 2+ for enforcement]`

Replay protection is USM's own: the authoritative engineID plus engineBoots and
engineTime, discovered per exchange (`snmpv3.go:30-36`), with keys localized as
`Kul = hash(Ku || engineID || Ku)` (`:34-35`). That machinery is present and
correct; nothing needs inventing.

The **enforcement point** is `poller.go` target build. Per
`docs/design/transport-encryption-2026-08-04.md:195`, a device whose credential
is below `min_level` must surface as **`policy_blocked`**, not **`down`** — a
misleading down-state is its own incident, and it would fire
`DeviceUnreachable` (`src/config/rules.yaml:37`) for a policy decision.

`[Phase 2+]` because turning this on stops collection from devices customers have
not yet migrated. v1 ships the **observation** half: the poller records the
achieved level per device and the posture view shows it, so the customer can see
exactly which devices would break before anything is enforced. That is the
"observation before enforcement" rule from
`docs/design/transport-encryption-2026-08-04.md:221-227`.

## 6.16.6 Traps — closing the fail-open `[v1 — required]`

Verified, `collectors/snmptrap.go:665-681`:

```go
var creds snmpCreds                                        // :665
if resolve != nil {                                        // :666
    if tg, ok := resolve(ev.Host); ok { creds = tg.creds() }
}
// noAuthNoPriv (or unknown sender): decode the cleartext scopedPDU directly.   // :671
if !creds.isV3() || !creds.wantsAuth() {                   // :672
    priv, msgData, err := v3MsgData(pkt)                   // :673
    ...
    if priv { return nil, fmt.Errorf("...encrypted v3 trap from %s but no priv creds", ev.Host) }  // :677-679
    return finishV3(ev, msgData)                           // :680
}
```

An **unknown sender** yields the zero `snmpCreds`, whose `Version` is 0, so
`!creds.isV3()` is true and control falls into the cleartext branch. **A v3 trap
from any IP that can reach the listener is accepted, decoded and published to the
bus with no cryptographic verification whatsoever.** Only an *encrypted* trap
from an unknown sender is refused (`:677-679`).

The doc comment above the function (`:655-657`) says *"A trap whose auth can't be
verified (when the creds want auth) is refused"* — the parenthetical is doing all
the work.

**v1 fix:**

```
resolve(ev.Host) miss  → drop + trap_policy_rejected{reason="unknown_sender"} + audit
creds below min_level  → drop + trap_policy_rejected{reason="below_min_level"}
auth verification fail → drop + trap_policy_rejected{reason="auth_failed"}   (already :689-691)
```

with the accept-set giving a safe rollout: `accept: [plaintext, protocol_native]`
during migration (count and mark, do not drop) → observe → `accept:
[protocol_native]`. The metric is what makes the narrowing safe, and it does not
exist today.

`ev.Authenticated` (`snmptrap.go:60`, set only at `:692`) gains the companion
`transport_authenticated` from §6.15.4. Note the trap decoder already documents
the threat model correctly (`:64-69`: *"A trap is an UNAUTHENTICATED UDP datagram
from an untrusted source"*) and already bounds varbind counts and value lengths
with explicit truncation provenance (`:70-72`) — the surrounding code is careful;
this one branch is the gap.

**Source restrictions** apply to the listener too: host UDP 162 maps to the
in-container 1162 (`docker-compose.yml:1511-1516`), and the same
`TELEMETRY_BIND_ADDR` rule as §6.15.6 applies.

## 6.16.7 v2c legacy handling

v2c has no authentication — the community string is cleartext on the wire and is
kept in trap events *for audit only*, explicitly not treated as a secret
(`snmptrap.go:56`). Treatment:

- Allowed only with a declared, expiring exception (§6.2.2).
- `transport_authenticated=false` always.
- Community strings are still sealed at rest (`store.go:259`) — they are
  credentials even if they are weak ones.
- The `"public"` fallback (`poller.go:89-91`) is refused in production.
- Never described as authenticated anywhere in the product.

---

# 6.17 gNMI LLD

**Phase note.** The northbound leg (gnmic → VictoriaMetrics) is **v1** (§6.10).
The southbound device leg is **Phase 2** — but the two production refusals below
are v1 validator rules, because they are configuration we own.

## 6.17.1 Current state — verified, and bad

`deployment/docker/gnmic/gnmic.yaml`:

| Finding | Evidence |
|---|---|
| `skip-verify: true` — **global**, applies to every TLS target | `gnmic.yaml:13` |
| `insecure: true` — **five occurrences**, one per Arista cEOS target on :6030 | `:30`, `:35`, `:40`, `:45`, `:50` |
| **No `tls-ca`, no `tls-cert`, no `tls-key` anywhere** | grep for `tls` matches only the comment at `:16` |
| One hardcoded global username | `:11` `username: admin` |
| Two shared passwords across seven devices | `:19`, `:23` (`${SRL_GNMI_PASS}`); `:29`, `:34`, `:39`, `:44`, `:49` (`${EOS_GNMI_PASS}`) |
| Outputs plaintext, unauthenticated | `:134-137` and `:154-156` — both `http://victoria:8428/api/v1/write` |

`insecure: true` in gNMI means **no TLS at all** — the gRPC channel is plaintext,
so those five devices' credentials cross the wire in the clear.
`skip-verify: true` means the remaining two targets encrypt but authenticate
nothing, so they are MITM-able. Lab defaults are acknowledged in compose
(`docker-compose.yml:342-346`), which is honest — but the file is what ships.

## 6.17.2 Production refusals `[v1 validator rules]`

The production profile **refuses to start** if any gnmic target has
`insecure: true` or if `skip-verify: true` is set at any scope. Error message
names the file, the line and the target (D9). Lab may set either **only** with a
declared exception carrying an owner and an expiry (§6.2.2).

This is enforceable today because the config is a repo file that
`scripts/preflight-security.sh` can parse — no device cooperation required. It is
the cheapest high-value control in the whole device plane.

## 6.17.3 Target state `[Phase 2+]`

```yaml
# global
skip-verify: false
tls-ca: /tls/device-ca.pem
tls-min-version: "1.2"

targets:
  172.40.40.11:57400:
    insecure: false
    tls-ca: /tls/device-ca.pem
    tls-cert: /tls/gnmic/tls.crt        # mTLS where the device supports it
    tls-key:  /tls/gnmic/tls.key
    tls-server-name: spine1.lab.example  # SAN validation — see below
    username: gnmi-spine1                # per-device, not one global admin
    password: ${SPINE1_GNMI_PASS}
```

| Control | Rule |
|---|---|
| TLS | mandatory. `insecure` is refused |
| mTLS | preferred; used wherever the device can verify a client certificate |
| CA bundle | the **device** CA (`correlix.device`), or a customer-supplied bundle per target — never the system pool, never the workload CA (F-11) |
| SAN validation | `tls-server-name` must be set per target. Devices commonly present certificates with an IP SAN or a name that is not the dialled address; the field makes the expectation explicit instead of disabling verification |
| Credentials | **per-device** username/password, not one global `admin` (`gnmic.yaml:11`). Sourced from the sealed credential store, not from two shared env vars |

## 6.17.4 Devices without certificates `[Phase 2+]`

Reality: much field gear cannot present a client certificate, and some cannot
present a *verifiable server* certificate either.

Ladder, most to least preferred:

1. **mTLS** — device presents a cert from the device CA.
2. **TLS + pinned CA** — device presents a cert from a customer CA we trust
   explicitly for that target; gNMI username/password inside the tunnel.
3. **TLS + pinned leaf fingerprint** — self-signed device cert, pinned by
   SHA-256. Not `skip-verify`: pinning is verification, just of a different
   anchor. `[UNKNOWN]` gnmic support for leaf pinning must be checked; if absent,
   the fallback is a per-target CA file containing the self-signed certificate,
   which is equivalent.
4. **Declared exception** — plaintext or skip-verify, owner + expiry +
   compensating controls (management VRF, ACL). Refused in production.

## 6.17.5 Config generation and per-target status

`gnmic.yaml` is hand-maintained today. Target state: it is **generated** from the
device registry + the resolved `TransportPolicy` per target, exactly as
`docs/design/transport-encryption-2026-08-04.md:199` proposes — so
`skip-verify: true` becomes a *declared exception* that a generator emits, rather
than a global default nobody re-examines.

Per-target status is exported and shown in the posture view (§6.24):
`netops_gnmi_target_tls{target,mode}` where `mode ∈ {insecure, tls,
tls_skip_verify, mtls}`. `[UNKNOWN]` whether gnmic exposes per-target TLS mode in
its own metrics; if not, the value is derived from the generated config, which is
authoritative anyway.

## 6.17.6 Rotation

Device certificates rotate on the 90d schedule (§6.3.3); gnmic has no hot-reload
path (§6.6) so rotation is a restart, scheduled off-peak. gNMI subscriptions
re-establish automatically; the gap is reconnect time, and it is visible as a
sample gap in VictoriaMetrics rather than as silent loss.

---

# 6.18 Flow LLD `[v1 hardening; the protocol itself is unfixable]`

## 6.18.1 What cannot be done, stated plainly

NetFlow v5/v9, IPFIX and sFlow are **UDP, unauthenticated, unencrypted by
protocol design**. There is no handshake, no identity and no integrity check.
`sampler_address` — the field tenancy is derived from — is trivially spoofable.

The repo already says this in the right places:
`vector-router/vector.yaml:350-354` — *"still unauthenticated (spoofable UDP), so
this bounds the damage to … is not a substitute for authenticated flow export."*

**Therefore: no claim of cryptographic authenticity is made for flow data
anywhere — not in the UI, not in reports, not in RCA evidence chains.** HLD §6.6.

## 6.18.2 Current state

```yaml
command:
  - "-listen"
  - "netflow://:2055,sflow://:6343,netflow://:4739"     # docker-compose.yml:386-387
  - "-transport" ; "kafka"                               # :390-391
  - "-transport.kafka.topic" ; "netops.flows"            # :394-395
ports:
  - "${NETFLOW_PORT:-2055}:2055/udp"                     # :399
  - "${IPFIX_PORT:-4739}:4739/udp"                       # :400
  - "${SFLOW_PORT:-6343}:6343/udp"                       # :401
```

The mounted `goflow2/goflow2.yaml` is **inert** — it is not mounted into the
container (`goflow2/goflow2.yaml:3-5`), so the compose `command:` is the only
authoritative configuration. Worth knowing before anyone "fixes" the YAML.

Tenant attribution happens downstream in `vector-router` from `sampler_address`
via the `device_tenant` enrichment table (`vector-router/vector.yaml:366`).

## 6.18.3 Controls that do work `[v1]`

| Control | Implementation |
|---|---|
| **Dedicated telemetry interface** | `TELEMETRY_BIND_ADDR` on all three ports (§6.15.6). Production refuses `0.0.0.0` |
| **Telemetry VLAN / segment** | deployment guidance: flow exporters live on a management VLAN with no route to the app subnet. Documented in the install guide, asserted by the network matrix (§6.22) |
| **Exporter allowlist** | `sampler_address` must be a **registered** device. An unknown exporter's flows are dropped, not stored, and counted: `netops_flow_unknown_exporter_total{addr}` — bounded cardinality by capping distinct addresses reported (§6.23.1) |
| **Anti-spoofing** | uRPF / ingress ACLs at the network layer — outside our code, inside our deployment guidance. Plus: an exporter address that appears from an unexpected L3 path is an alert |
| **Rate limiting** | per-source-IP packet-rate cap; a single spoofing source must not be able to fill the lane or the ClickHouse `flows` table |
| **Malformed packets** | goflow2 drops undecodable datagrams; v1 adds a counter so a decode-failure spike (a scanner, or a version mismatch) is visible rather than silent |
| **Honest labelling** | `transport_authenticated=false`, `transport_mode=plaintext`, `transport_identity=""` on every flow event (§6.15.4) |
| **Tenant mapping** | unchanged — registry lookup on `sampler_address`; an unmapped exporter yields `tenant_seg = "untagged"` (`vector-router/vector.yaml:184`) and lands in the untagged index, never in another tenant's |

## 6.18.4 Options that add real cryptographic protection `[Phase 2+]`

| Option | What it buys | Cost |
|---|---|---|
| **IPsec transport mode** exporter→collector | authenticity + confidentiality for the UDP datagrams | per-device IPsec config; many platforms support it for management traffic |
| **MACsec** on the collector's access link | L2 confidentiality/integrity on that hop only | switch support; protects the link, not the path |
| **Remote flow gateway** | a Correlix-owned collector at the customer site receives flows locally, then forwards to Correlix over **mTLS** | a new deployable; this is the only option that makes the *Correlix-facing* leg authenticated |

The gateway is the one worth building when the device plane is taken on: it
converts an unauthenticable protocol into an authenticated one by moving the
trust boundary to a component we control. Its identity would be
`spiffe://correlix.device/tenant/<t>/kind/gateway/id/<id>` (§6.4.4).

## 6.18.5 Device-ingestion security overview

```mermaid
flowchart TB
  subgraph UNTRUSTED["CUSTOMER ESTATE — untrusted"]
    R1["Router / switch / firewall / WLC"]
  end
  subgraph LANES["INGESTION — Correlix-controlled"]
    S1["syslog-ng :6514 RFC5425 mTLS<br/>Phase 2 — device CA"]
    S2["syslog-ng :514 UDP/TCP<br/>v1 — allowlist + iface + rate limit<br/>transport_authenticated=false"]
    G1["goflow2 :2055/:4739/:6343 UDP<br/>UNAUTHENTICABLE — exporter allowlist only<br/>transport_authenticated=false"]
    N1["SNMP poll — USM authPriv<br/>protocol_native, NOT TLS"]
    N2["SNMP trap :162 — v3 authPriv<br/>v1: unknown senders REJECTED"]
    M1["gNMI — TLS+CA, mTLS preferred<br/>v1: prod refuses insecure/skip-verify"]
  end
  R1 -->|"cert → device → tenant"| S1
  R1 -->|"hostname = UNVERIFIED CLAIM<br/>syslog-ng.conf:42-44"| S2
  R1 -->|"sampler_address spoofable"| G1
  R1 --> N1 & N2 & M1
  S1 -->|"authenticated=TRUE"| VEC["vector-aggregator"]
  S2 & G1 & N1 & N2 -->|"authenticated=FALSE — declared exception, expiring"| VEC
  M1 --> VM["VictoriaMetrics via vmauth"]
  VEC -->|"registry lookup — NEVER auto-create"| REG["device registry<br/>device→tenant"]
  REG -->|"tenant_id stamped from the REGISTRY,<br/>never from the payload"| BUS["Kafka (mTLS + ACLs)"]
  VEC -.->|"unknown device / tenant conflict"| DROP["DROP + metric + audit"]
```

---

# 6.19 Secrets management `[v1]`

## 6.19.1 What already exists — reviewed

`src/backend/internal/vault/` is a complete envelope-encryption layer and is
better than most of what it would be replaced with.

| Property | Evidence |
|---|---|
| AES-256 KEK and DEKs | `secrets.go:41-42` (`kekLen = 32`, `dekLen = 32`) |
| AES-256-**GCM** | `newGCM` (`secrets.go:355-361`); seal `gcmSeal` (`:330-340`), open `gcmOpen` (`:343-353`) |
| Random nonce, `nonce‖ciphertext` | `secrets.go:335-339` |
| Versioned, self-describing ciphertext | `VersionPrefix = "v1:"` (`:40`), emitted `:158` |
| **AAD = `tenant|fieldID`** | `aad()` (`secrets.go:327`); rationale `:325-326` — defeats cross-tenant and cross-field copy-paste |
| Wrapped-DEK AAD = `dek|tenant` (`|vN` for v>1) | `secrets.go:217,246`; `tenantkeys.go:63-68` |
| Per-tenant DEK, platform DEK for globals | `secrets.go:69-70,187-230`; rollback on persist failure `:224-228` |
| KEK memory-only | `secrets.go:68` |
| `SealingProvider` abstraction | `secrets.go:54-59`; swtpm impl `secrets_swtpm.go`; TPM2/KMS/HSM drop in with no caller change (`secret-custody.md:58-62`) |
| Sidecar keeps `go.mod` clean | `secrets_swtpm.go:15-26`; sidecar at `docker-compose.yml:1686-1699`, profile `seal` |
| **Wrapped-store integrity (HMAC)** | `secrets.go:267-275`; refusal `:306-308` — "tampered or truncated — refusing to start" |
| Boot-fatal on vault error | `main.go:268-272` (`log.Fatalf("secret custody: %v", err)`) |
| `REQUIRE_SEAL` | `secrets.go:98-100` |
| Dormant warning naming every exposed secret **including the CA key** | `secrets.go:101` |
| Redaction at the API | write-only `*_set` pattern — e.g. `admin.tsx:2336`, `:2459`, `:2650`, `:3087` |
| Rotation classification enforced by tests | `install.py:296-303`, `tests/test_secret_rotation.py` |

This is a well-built layer. The work below is **wiring and gating**, not
rebuilding.

## 6.19.2 Comparison of options

| Option | Verdict |
|---|---|
| **Existing `internal/vault` + swtpm** | **CHOSEN for Compose (v1).** Already built, tested, dependency-free, per-tenant, integrity-checked. The only thing wrong with it is that it is off |
| HashiCorp Vault | **Rejected for v1.** Real option where a customer already runs it; adds a hard operational dependency an air-gapped appliance may not have. The `SealingProvider` seam accepts a `vaultProvider` later with no caller change |
| Cloud KMS (AWS/Azure/GCP) | **Rejected for v1**, adopt per-deployment later. Correct for a cloud-hosted Correlix; wrong for an on-prem appliance. Same seam |
| k8s Secrets + encryption-at-rest | **Insufficient alone.** etcd-level encryption protects the etcd blob, not the pod's view; any pod with the right RBAC reads plaintext, and there is no per-tenant separation. Complements our envelope layer, does not replace it |
| External Secrets Operator | **Phase 2+, k8s only.** ESO syncs from a real backend into k8s Secrets — useful *after* a Vault/KMS decision, not instead of one |

**Recommendation, matching D3's mandatory-sealing rule:**
**Compose now** = the existing Vault with `SEAL_PROVIDER` **required** in
production, swtpm for lab, real TPM/HSM/KMS for production-grade assurance
through the same interface.
**k8s later** = the identical Go Vault (it is substrate-agnostic), with the KEK
sealed by cloud KMS via a `kmsProvider`, and ESO only if a customer's existing
secret backend needs to feed the `.env`-equivalent.

## 6.19.3 Envelope encryption and per-tenant DEKs

Unchanged from `secret-custody.md:66-98`. Restated because it is the thing that
makes an OpenSearch or ClickHouse read-bug leak **ciphertext** rather than
secrets: the crypto complement to RLS (`secret-custody.md:41-43`).

## 6.19.4 Production boot failure on unseal failure — and a defect found

`REQUIRE_SEAL=true` already refuses to start with no provider
(`secrets.go:98-100`). Two hardening items:

1. **`REQUIRE_SEAL` parsing is strict-equality.** `os.Getenv("REQUIRE_SEAL") ==
   "true"` (`secrets.go:98`) means `TRUE`, `True` and `" true"` **do not**
   activate the guard. Compare `assertRLSCapable`, which does
   `strings.EqualFold(strings.TrimSpace(...))` (`internal/platformdb/db.go:199`).
   **v1: normalize it.** A security guard that silently does not engage because
   of capitalization is the worst kind of guard.

2. **An unseal failure is treated as a first run.** `NewWithProvider`
   (`secrets.go:113-127`):

   ```go
   kek, err := p.Unseal(ctx)                                    // :115
   if err != nil || len(kek) != kekLen {                        // :116
       // First run: no sealed KEK yet → generate one and seal it.   // :117
       if kek, err = v.firstRunKEK(ctx); err != nil { ... }     // :118-120
   ```

   A **transient** sidecar error, or a short/corrupt KEK, therefore causes a
   **brand-new KEK to be minted and sealed over the old one** (`firstRunKEK`,
   `:129-138`). Every existing wrapped DEK then becomes unrecoverable. The
   wrapped-store HMAC check (`:306-308`) makes the failure loud on the next
   step — but the sealed root may already have been overwritten.

   **v1 fix:** distinguish "no sealed object exists" from "unseal failed".
   First-run generation happens **only** when the provider reports absence; any
   other error aborts boot. This matches the documented intent
   (`secrets_swtpm.go:25-26`, `secret-custody.md:165-167`) which the current code
   does not quite implement.

3. **Legacy wrapped-store format bypasses the MAC.** `secrets.go:292-301`:
   a store whose JSON lacks a `keys` field is parsed as a bare map and accepted
   **with no MAC check** ("Legacy plain-map format (pre-SR-027): accept once,
   migrate to a MAC'd store on the next write"). An attacker who can write the
   custody file can strip the envelope to downgrade to the unauthenticated
   format. **v1:** gate the legacy path behind an explicit, expiring
   `VAULT_ALLOW_LEGACY_STORE=true`, refused by the production profile.

## 6.19.5 Versioning and rotation

- Ciphertext is versioned (`v1:`, `secrets.go:40`).
- DEK versions exist: `MaxKeyVersion = 1000` (`tenantkeys.go:45`),
  `RotateTenantKey` (`:123`), version-bound AAD (`:63-68`) so "a key can never be
  unwrapped as a different version of itself".
- **KEK rotation** re-wraps every DEK (`docs/runbooks/tls-mtls.md:95-96`).
- Cadence `[ASSUMPTION]`, to be confirmed by the owner: DEK annually or on
  suspicion; KEK annually; TLS leaves every 24h (automatic); DB/ACL passwords
  every 90 days via the existing `rotate_secrets()` machinery
  (`install.py:751-913`), which already sequences live-catalog credentials before
  `.env` edits (`:822-838`) with rollback (`:866`, `:880`).

## 6.19.6 Audit

Every secret operation is auditable and none logs a secret value:

| Event | Metric |
|---|---|
| Unseal at boot | `netops_vault_unseal_total{outcome}` |
| DEK mint | `netops_vault_dek_created_total{scope}` — `scope ∈ {platform, tenant}`, **not** the tenant id (§6.23.1) |
| Decrypt failure (AAD mismatch / tamper) | `netops_vault_decrypt_failures_total{reason}` |
| Rotation | `netops_vault_rotation_total{kind,outcome}` |
| Sealing-key fetch by vector-router | `netops_sealing_key_fetch_total{identity,outcome}` (§6.13.9) |
| Reveal of a sealed field | **already exists** — `netops_unmask_requests_total{outcome}` (`pipeline_processors.go:578-583`) |

## 6.19.7 The CA-key boot refusal `[v1 — required]`

The verified defect, in the code's own words (`tls_ca.go:23-24`):

> *"Dormant unless `TLS_INTERNAL_CA=true`. When the Vault is also dormant the CA
> key is stored plaintext (passthrough) — turning on `SEAL_PROVIDER=swtpm` seals
> it."*

`bootstrapInternalCA` (`tls_ca.go:118-133`) never checks. And the Vault's own
dormant warning already lists "internal-CA key" among what sits in cleartext
(`secrets.go:101`) — the system knows, and says so, and proceeds anyway.

**Design:**

```
at bootstrapInternalCA, before loadOrCreateCA:

  if TLS_INTERNAL_CA == "true" && !vault.Active():
      return error:
        "TLS_INTERNAL_CA=true requires key custody: the CA private key would be
         stored in PLAINTEXT. Set SEAL_PROVIDER=swtpm and start the sealing
         sidecar (docker compose --profile seal up -d secrets-seal), or unset
         TLS_INTERNAL_CA. See docs/runbooks/tls-mtls.md §1."
```

- `main.go:1331-1334` already turns the returned error into `log.Fatalf`, so the
  fail-closed wiring exists — only the check is missing.
- `vault.Active()` is a one-line export of the existing unexported
  `active()` (`secrets.go:141`).
- **Profile behavior:** production and staging refuse. Lab may proceed **only**
  with an explicit `TLS_ALLOW_UNSEALED_CA=true` plus a declared, expiring
  exception, and it logs at ERROR every boot so it cannot become invisible.
- Test (§6.26.1): boot with `TLS_INTERNAL_CA=true` and no provider → error
  containing "PLAINTEXT"; with a provider → success. This is the kind of guard
  `vault_testdeps_test.go` and `tls_ca_test.go` already make easy to write.

## 6.19.8 Break-glass

Retain today's shape: `ADMIN_RESET_PASSWORD` (`docker-compose.yml:1482`, honored
in `main.go`) is time-boxed and audited, and the operator-restriction model
already exists (`docs/security/operator-visibility.md`). Additions:

- Break-glass **secret** access (reading a decrypted value) requires step-up
  auth, is audited with the actor, and pages.
- The KEK is **not** exportable through any API. Recovery from a lost KEK is
  restore-from-backup of the sealed object, not an export path — an export path
  is a permanent backdoor.
- `[Phase 2+]` operator certificates from the `correlix.operator` intermediate,
  8h TTL.

## 6.19.9 Redaction

Already strong and unchanged: write-only fields with `*_set` booleans across the
admin UI (`admin.tsx:2336`, `:2459`, `:2650`, `:3040`, `:3047`, `:3087`,
`:3212`), status-only badges (`:2513-2519`, `:2535-2536`), and the stated
contract "secrets are write-only" (`:3350`, `:2974`, `:2987`). SNMP credentials
expose only presence booleans (`snmpcred/store.go:75,79,81`).

Two additions:

- ClickHouse insert failures already avoid logging response bodies
  (`main.py:1826` — *"r.text deliberately absent — it can contain customer
  rows"*). Apply the same rule to every new error path added by this design.
- OpenSearch audit config **must** set `exclude_sensitive_headers: true` and
  `resolve_bulk_requests: false` (§6.8.7), or the audit log becomes the leak.

## 6.19.10 Backup and restore of custody

The wrapped-DEK store and the sealed KEK are the only things whose loss is
unrecoverable.

| Artifact | Where | Backup rule |
|---|---|---|
| Sealed KEK | swtpm state, `data/swtpm` (`docker-compose.yml:1697`) | backed up **with** the wrapped store, never separately — a mismatched pair is useless |
| Wrapped DEKs | kv store / `app_kv` (`secret-custody.md:159`) | same |
| Ciphertext secrets | in the app stores | ordinary backup |

Restore must be **atomic across the pair**. A restore of the wrapped store
against a newer KEK fails the HMAC check (`secrets.go:306-308`) and refuses to
start — loud, which is right, but the runbook must say what to do about it.
`docs/runbooks/backup-restore.md` gains a custody section.

## 6.19.11 Backup encryption `[Phase 2+]` and DR

HLD T20 rates backup theft **HIGH** with no control, and HLD §11 decision 6 asks
whether to build it now. Design:

- A **separate backup-encryption authority** (HLD §6.1) whose keys are not any
  live service credential — so a full stack compromise does not decrypt the
  archives.
- Artifacts: OpenSearch snapshots (`data/opensearch-snapshots`,
  `docker-compose.yml:554`), ClickHouse backups, `pg_basebackup` output, the
  custody pair above.
- Physical-layer Postgres backup avoids the RLS-vs-logical-backup problem noted
  in §6.11.5.
- DR test: restore into a clean host with **only** the backup keys, and prove the
  stack comes up. Untested backups are not backups — the F-59 finding
  (`docker-compose.yml:540-544`: *"there was no backup of any search index,
  ever"*) is the precedent.

**v1 minimum:** state honestly in the runbook that backups are unencrypted, and
put the artifacts on a filesystem with restricted permissions. An honest gap
beats an assumed control.

## 6.19.12 Dev-only softTPM behavior

swtpm is a **software emulator whose state is a file** — it is not a hardware
root of trust and its attestation is meaningless against a compromised host
(`secret-custody.md:52-57`). It is correct for lab and for building the
integration.

- Lab/dev: `SEAL_PROVIDER=swtpm` — encourage it; it exercises the real path.
- Staging: swtpm acceptable, or a real TPM.
- **Production: `SEAL_PROVIDER` must be set and `REQUIRE_SEAL=true`.** The
  profile records whether the provider is hardware-backed, and the posture view
  shows "software TPM (lab-grade)" rather than a green tick when it is not.
  Overstating custody assurance is the same class of dishonesty as claiming an
  unauthenticated lane is authenticated.

## 6.19.13 Production startup validation sequence

```mermaid
sequenceDiagram
  autonumber
  participant OS as Container start
  participant V as validateSecurityProfile()
  participant VA as vault.New()
  participant BT as initBackendTransport()
  participant CA as bootstrapInternalCA()
  participant TS as buildTLSServer()
  participant CH as assertCHPoliciesConverged()
  participant PG as assertRLSCapable()
  participant SRV as Serve

  OS->>V: load security/profiles/production.yaml + policies
  V->>V: F-01..F-12 forbidden combinations
  V->>V: V-01..V-20 validation rules
  V->>V: exception expiry check
  V-->>OS: FATAL with rule id + file + field + fix   (D9)
  OS->>VA: SEAL_PROVIDER set?
  VA-->>OS: FATAL — REQUIRE_SEAL=true, provider unset (secrets.go:98-100)
  VA->>VA: Unseal KEK — absence ⇒ first run; ERROR ⇒ FATAL (§6.19.4)
  VA->>VA: wrapped-store HMAC (secrets.go:306-308) — mismatch ⇒ FATAL
  OS->>CA: TLS_INTERNAL_CA=true?
  CA->>CA: vault.Active()? — NO ⇒ FATAL "CA key would be PLAINTEXT" (§6.19.7)
  CA->>CA: issue every SVID in identities.yaml; write bundle (writeFileAtomic)
  OS->>BT: load mesh CA (AFTER the CA bootstrap — §6.13.4 ordering fix)
  BT-->>OS: FATAL on unloadable bundle (backend_client.go:30-32)
  OS->>TS: build mTLS listener
  TS-->>OS: FATAL on broken cert/CA (main.go:1338-1341)
  OS->>PG: role bypasses RLS? (db.go:186-207)
  PG-->>OS: FATAL unless STORE_PG_ALLOW_RLS_BYPASS — refused in production
  OS->>CH: converge + read back system.row_policies (§6.9.5.2)
  CH-->>OS: FATAL on CHP-01..CHP-06 in production
  OS->>SRV: listen — every fail-closed gate passed
```

---

# 6.20 Kubernetes future-state LLD `[Design-only]`

No Kubernetes manifests exist in this repo (HLD §1.3 verified this; #114 confirms
k8s packaging is unstarted). Nothing here is v1 work, and **no migration is
forced**. The point is that the identity strings chosen in §6.4 are already the
ones k8s would use, so the move is packaging, not redesign.

## 6.20.1 Namespaces and ServiceAccounts

The §6.4 table's last column *is* the mapping: namespace = the SPIFFE `ns`
segment, ServiceAccount = the `sa` segment. `spiffe://correlix.workload/ns/app/sa/api`
becomes ServiceAccount `api` in namespace `app`. Nothing changes but the
substrate.

## 6.20.2 Certificates

| Option | Role |
|---|---|
| **cert-manager** | issues `Certificate` resources from an `Issuer` backed by the same CA. Identity strings unchanged (HLD §8) |
| **SPIRE** | the drop-in for the workload API. `tlsconfig` already speaks SPIFFE IDs and trust-domain binding (`federation.go:179`), so SPIRE replaces the *source* of SVIDs, not the verifier |

Neither is v1 (D2).

## 6.20.3 NetworkPolicies

Generated directly from §6.22. Default-deny ingress and egress per namespace,
then one allow rule per row. Because §6.22 is already a source→destination table
with ports and directions, this is a mechanical transform.

## 6.20.4 Pod Security Standards and runtime hardening

| Control | Setting |
|---|---|
| Pod Security Standard | `restricted` for `app`, `ingestion`, `ops`; `baseline` only where a datastore image genuinely needs it, with a recorded reason |
| `runAsNonRoot` | `true` everywhere except the prober (which needs `NET_RAW`; today `user: "0:0"` + `cap_drop: ALL` + one capability — `docker-compose.yml:1546-1559`) |
| `allowPrivilegeEscalation` | `false` — the k8s form of `no-new-privileges:true`, already set on 7 services |
| `readOnlyRootFilesystem` | `true` + `emptyDir` for writable paths (§6.21.5) |
| `capabilities.drop` | `["ALL"]`; `add: ["NET_RAW"]` only for the prober |
| `seccompProfile` | `RuntimeDefault` everywhere; a custom profile only with a measured reason |
| Resource limits | already parameterised throughout compose; become requests/limits (`docker-compose.yml:28-34` says exactly this) |

## 6.20.5 Secrets

- The Go Vault is substrate-agnostic and stays — it is what gives per-tenant
  separation, which k8s Secrets do not provide.
- The **KEK** moves to a cloud KMS `SealingProvider`, or to the Secrets Store CSI
  driver.
- External Secrets Operator only if a customer's existing backend must feed
  bootstrap values.
- k8s encryption-at-rest for etcd is assumed, and is **not** counted as a
  control for tenant secrets (§6.19.2).

## 6.20.6 RBAC, admission, images, egress, ingress, storage, audit

| Area | Design |
|---|---|
| RBAC | least privilege per ServiceAccount. **No** ServiceAccount gets `secrets` `list`/`watch` cluster-wide. `automountServiceAccountToken: false` unless the pod calls the API server |
| Admission | Kyverno or Gatekeeper enforcing: PSS `restricted`, digest-pinned images, required labels, no `hostPath`, no `hostNetwork`, no privileged |
| Image verification | images are already **digest-pinned** in compose (every `image:` line carries `@sha256:`) — the k8s form is a cosign/Notation verification policy. `secret-custody.md:60-62` already anticipates reusing the sealing root for a future SBOM/SLSA/cosign pipeline |
| Egress | default-deny. Explicit allows: OIDC issuer/JWKS, ITSM, notification providers, LLM provider (only when `FEATURE_COPILOT`/`FEATURE_AI` is on), NetBox, cloud provider APIs. Complements the existing SSRF guard (`SSRF_ALLOWED_HOSTS`/`SSRF_ALLOW_PRIVATE`, `docker-compose.yml:1355-1361`) |
| Ingress | one Ingress terminating TLS with the public chain, re-encrypting to the api Service with mTLS — the k8s form of §6.13.4 |
| Storage | encrypted StorageClass; PVCs for `data/*`; snapshots encrypted by §6.19.11's authority |
| Audit | API-server audit policy at `Metadata` for reads, `RequestResponse` for `secrets` and RBAC changes, shipped into the platform's own log store |

## 6.20.7 What must not change in the move

The tenant boundary. ClickHouse row policies, Postgres FORCE-RLS, per-tenant
OpenSearch indices and `principalTenant` filtering are **application and
database** controls; NetworkPolicies and a mesh do not implement them and must
never be described as doing so.

---

# 6.21 Docker Compose LLD `[v1]`

## 6.21.1 Networks — one flat bridge today

```yaml
networks:
  netops:
    driver: bridge      # docker-compose.yml:1824-1826
```

**Every one of the 32 services sits on the same flat bridge.** Every service can
reach every other service's every port. That is the substrate on which "Kafka has
no auth" and "OpenSearch has no auth" become "anyone with a foothold anywhere
reads every tenant's data".

Target: five networks, so that even before authentication lands, reachability is
bounded.

```yaml
networks:
  edge:        { driver: bridge }                      # nginx ↔ frontend/api/consoles
  app:         { driver: bridge }                      # api ↔ correlation ↔ netbox ↔ keycloak
  ingestion:   { driver: bridge }                      # collectors ↔ vector ↔ bus
  storage:     { driver: bridge, internal: true }      # datastores — NO EGRESS AT ALL
  ops:         { driver: bridge }                      # grafana, osd, vmalert, exporters
```

`internal: true` on `storage` is the single highest-value line in this section:
it removes the default gateway, so a compromised datastore container **cannot
reach the internet** — no exfiltration, no callback, no package fetch. Postgres,
ClickHouse, OpenSearch, VictoriaMetrics and Valkey need no egress.

Multi-homing (a service on more than one network) is how the tiers connect; §6.22
is the authoritative membership table.

`[UNKNOWN]` Two things must be verified before this lands: (a) `internal: true`
and healthchecks that use `wget`/`curl` to `127.0.0.1` are fine, but image pulls
happen at build time so `internal` is safe; (b) the API multi-homes onto
`storage`, `app`, `ingestion` and `edge`, which is unavoidable — it is the hub.

## 6.21.2 The untracked override

`docker-compose.override.yml` is gitignored and, on the lab host, adds the TLS
front (`:4-11`) and the **`cloud-ingest` Kafka producer** (`:27-70`) — including
host mounts of `~/.aws` (`:65`) and a GCP service-account JSON (`:66`), plus
`INGEST_TOKEN` (`:37`). It also carries a comment recording that it was once
**accidentally overwritten** and had to be reconstructed from a running container
(`:21-25`).

Consequences for this design:

1. **Any inventory or validator that reads only the tracked compose is wrong.**
   `docker compose config` (which merges overrides) is the only correct input —
   V-17 and the §6.22 matrix must be evaluated against the merged output.
2. `cloud-ingest` is a real, credential-holding, Kafka-producing service that
   exists in no tracked file and has no `security_opt`, no `cap_drop` and no
   identity. **v1: promote it into the tracked compose** behind a profile, with
   the secrets staying in `.env`. A production service reconstructed from
   `docker inspect` is not a supply chain.

## 6.21.3 Published ports

Enumerated in §6.13.2. Rules for v1:

| Rule | Enforcement |
|---|---|
| The plaintext `:8000` listener is **retired** after ingress cutover (`docker-compose.yml:1722`) | validator: production refuses a plaintext nginx port |
| No datastore, broker or console port is ever published | validator: the merged compose must publish nothing on the storage/ops networks |
| The mock fixtures must not run in production | validator: `mock-snow`/`mock-nms`/`legacy` profiles refused |
| Every telemetry port binds a **declared** address | `TELEMETRY_BIND_ADDR`; production refuses `0.0.0.0` (§6.15.6) |
| Debug ports bind `127.0.0.1` | already the pattern (`:1632`, `:1660`) |

## 6.21.4 Profile hygiene

| Profile | Services | Production |
|---|---|---|
| *(none)* | postgres, redis, syslog-ng, gnmic, goflow2, vector×2, opensearch(+init), victoria, vmalert, clickhouse, correlation, api, frontend, nginx, secrets-seal(build) | required |
| `embedded-bus` | kafka, kafka-init | required unless external Kafka |
| `seal` | secrets-seal | **required in production** (§6.19.12) |
| `sso` | keycloak | optional |
| `osd` | opensearch-dashboards | optional |
| `self-monitoring` | grafana, cadvisor, node-exporter, kafka-exporter | optional |
| `prober`, `pdf`, `netbox` | prober, gotenberg, netbox(+pg) | optional |
| `legacy` | telegraf | **refused** — the compose comment is explicit that running it "would imply a second, non-canonical SNMP metric path that does not exist" (`:302-312`) |
| `mock-snow`, `mock-nms` | mock fixtures | **refused** |

Profiles are set in `.env` via `COMPOSE_PROFILES` (`install.py:50-52`, written at
`:669`, read at `:770`), never as a CLI flag (`install.py:1101-1105`) — so the
validator can read them from one place.

## 6.21.5 Container hardening — the gap

`security_opt: ["no-new-privileges:true"]` + `cap_drop: [ALL]` are set on
**7 of 32** services: `correlation` (`:960-961`), `api` (`:1063-1064`),
`prober` (`:1548-1550`), `mock-servicenow` (`:1621-1622`), `mock-nms`
(`:1651-1652`), `frontend` (`:1703-1704`), `nginx` (`:1715-1716`).

**Not set on:** postgres, redis, keycloak, kafka, kafka-init, syslog-ng,
telegraf, gnmic, goflow2, vector-aggregator, vector-router, opensearch,
opensearch-init, opensearch-dashboards, victoria, vmalert, kafka-exporter,
cadvisor, node-exporter, grafana, clickhouse, gotenberg, secrets-seal,
netbox, netbox-postgres — **and** cloud-ingest.

**`read_only:` and `tmpfs:` appear nowhere in the file.**

v1 target:

| Control | Rule |
|---|---|
| `security_opt: ["no-new-privileges:true"]` | **every** service. Zero legitimate exceptions |
| `cap_drop: [ALL]` | every service. `cap_add` only for the prober (`NET_RAW`) and syslog-ng if it must bind :514 as non-root (`NET_BIND_SERVICE`) — each with a comment saying why |
| `read_only: true` | every service that can. Datastores cannot (they write their data dirs); `nginx`, `frontend`, `api`, `correlation`, the exporters and the one-shots can |
| `tmpfs` | `/tmp` and nginx's cache/pid paths (`Dockerfile.nginx:7` already prepares "a writable pid path and cache dirs") |
| `user:` pinned | currently pinned only on `api` (`:1062`), `grafana` (`:839`) and `prober` (`:1559`). Pin the rest, so §6.5.3's key ownership is deterministic |
| `cadvisor` | the deliberate exception: it needs broad read-only host mounts (`:802-810`) and `/dev/kmsg` (`:809-810`). It stays profile-gated and its rationale (`:765-796`) stays with it |

`no-new-privileges` on the remaining 25 services is a one-line-per-service change
with no behavioral risk, and it is the cheapest hardening in this document.

## 6.21.6 Read-only certificate mounts

Per §6.5.4. Concretely, each service gains:

```yaml
volumes:
  - ../../data/api/tls/ca.pem:/tls/ca.pem:ro
  - ../../data/api/tls/<svc>:/tls/<svc>:ro
```

and only `api` mounts the TLS root read-write, because it is the issuer.

## 6.21.7 Secret files over environment variables

Environment variables are visible in `docker inspect`, in `/proc/<pid>/environ`,
in `docker compose config` output and in crash dumps. The repo already leans this
way for some things (the sealing socket is a file, `docker-compose.yml:1508-1510`)
and against it for others (`CLICKHOUSE_PASSWORD`, `DB_PASSWORD`, `JWT_SECRET`,
`INGEST_TOKEN`, `GRAFANA_ADMIN_PASSWORD`, `NETBOX_TOKEN` — all env).

**v1 target: `*_FILE` variants** for every credential, following the convention
the Postgres and Keycloak images already support natively:

```yaml
environment:
  DB_PASSWORD_FILE: /run/secrets/db_password
  CLICKHOUSE_PASSWORD_FILE: /run/secrets/clickhouse_password
```

Go side: a small `envOrFile(name)` helper that prefers `<NAME>_FILE` and falls
back to `<NAME>` — backwards compatible, stdlib, ~15 lines. `install.py` writes
the files alongside the `.env` it already generates (`install.py:328-375`) with
mode `0600`.

`[ASSUMPTION]` `.env` continues to exist for non-secret configuration. Compose
`secrets:` (the top-level stanza) is the more idiomatic mechanism but has awkward
semantics outside Swarm; plain read-only file mounts are simpler and achieve the
same thing.

## 6.21.8 Health checks over TLS

Every current health check probes plaintext and will report **healthy while every
real client is being rejected**:

| Service | Current | Line | v1 |
|---|---|---|---|
| kafka | `nc -z 127.0.0.1 9092` | `:232` | `kafka-broker-api-versions.sh` with a client cert (§6.7.11) |
| opensearch | `curl -sf http://localhost:9200/_cluster/health` | `:556` | `curl --cacert --cert --key https://…` |
| clickhouse | `wget -qO- http://127.0.0.1:8123/ping` | `:946` | `https://…:8443/ping` with the CA |
| victoria | `wget -qO- http://127.0.0.1:8428/health` | `:643` | via vmauth over TLS |
| vector×2 | `wget -qO- http://127.0.0.1:8686/health` | `:450`, `:501` | unchanged — the Vector admin API stays loopback-only |
| valkey | `valkey-cli ping` | `:104` | `valkey-cli --tls --user health …` |
| postgres | `pg_isready -U ${DB_USER}` | `:80` | `pg_isready` + `sslmode=require` |
| correlation | python urllib to `127.0.0.1:8000/metrics` | `:1036` | `https://127.0.0.1:8443/metrics` with the CA |
| api (via nginx) | — | — | unchanged |

The correlation health check's design rationale (`:1029-1034` — `/metrics` is
served by the same FastAPI app so it fails if the event loop wedges) is good and
survives the change.

## 6.21.9 Production validation

`validateSecurityProfile()` runs at install (`scripts/preflight-security.sh`), at
API boot, and in CI. In the production profile it **refuses** on:

| Id | Condition |
|---|---|
| PV-01 | any `TLS_*` required var unset while `environment: production` |
| PV-02 | `SEAL_PROVIDER` unset, or `REQUIRE_SEAL != true` |
| PV-03 | `TLS_INTERNAL_CA=true` without an active vault (§6.19.7) |
| PV-04 | `DISABLE_SECURITY_PLUGIN` present on `opensearch` |
| PV-05 | Kafka `LISTENER_SECURITY_PROTOCOL_MAP` contains `PLAINTEXT` for `CLIENT`/`CONTROLLER`, or the migration listener has no unexpired exception |
| PV-06 | `sslmode` missing or not `verify-full` in any Postgres DSN |
| PV-07 | Valkey has no ACL file and no `--requirepass`, or `user default` is not `off` |
| PV-08 | any plaintext host port published by nginx |
| PV-09 | `COMPOSE_PROFILES` contains `legacy`, `mock-snow` or `mock-nms` |
| PV-10 | `gnmic.yaml` has `insecure: true` or `skip-verify: true` without an unexpired exception (§6.17.2) |
| PV-11 | any exception in `policies/exceptions/register.yaml` is expired |
| PV-12 | `STORE_PG_ALLOW_RLS_BYPASS=true` |
| PV-13 | `INGEST_TOKEN` empty (which disables ingest auth entirely — `vector/vector.yaml:117`) |
| PV-14 | `TELEMETRY_BIND_ADDR` is `0.0.0.0` |
| PV-15 | a service is missing `no-new-privileges` or `cap_drop: ALL` |
| PV-16 | `TLS_CLIENT_ALLOWED_URIS` empty while mTLS is on (§6.4.2) |
| PV-17 | `VAULT_ALLOW_LEGACY_STORE=true` (§6.19.4) |
| PV-18 | `GF_AUTH_ANONYMOUS_ENABLED=true` without `GF_AUTH_PROXY_WHITELIST` set |

Every message names **what** failed, **where** (file:line where possible) and
**how to fix it** — D7. A validator that says "configuration invalid" is a
validator people disable.

## 6.21.10 Dependency ordering, cert init and restart safety

- A new one-shot `cert-init` runs after `api` has bootstrapped the CA and before
  any TLS-consuming service starts. `[UNKNOWN]` — this creates a circular
  dependency (`api` issues the certs, but `api` also needs `postgres` which needs
  a cert). Resolution: **Postgres, Valkey and Kafka start with certificates from
  the *previous* boot** (they persist on the volume), and only a genuinely first
  boot needs a two-phase start. `install.py` already performs multi-phase
  bring-up (`install.py:751-913` shows the pattern), so the first-boot sequence
  is: start `api` with TLS off → CA bootstrap issues everything → restart the
  stack with TLS on. Documented in the install flow, not left to chance.
- Existing ordering stays: `postgres: service_healthy` (`:1518`), `redis:
  service_healthy` (`:1519`), `kafka: service_healthy` for `kafka-init` (`:263`),
  `opensearch: service_healthy` for `opensearch-init` (`:587`). The deliberate
  *absence* of a broker dependency on the Vector services (`:455-457`, `:506-507`)
  stays — external-broker mode depends on it.
- **Restart safety:** the reissue loop rewrites cert/key files, and `main.go`
  already tracks it as a named worker rather than a bare goroutine precisely so a
  shutdown cannot truncate a key (`main.go:1350-1352`). Preserve that property in
  the table-driven rewrite (§6.4.5).

## 6.21.11 Plaintext-listener removal

Each temporary plaintext listener is tracked as a row in
`policies/exceptions/register.yaml` with an expiry, is alerted on while it exists
(§6.23), and its removal is a phase completion criterion:

| Listener | Where | Removed at |
|---|---|---|
| nginx `:8000` | `:1722` | Phase 1 |
| Kafka `MIGRATION:9094` | new | Phase 3 |
| OpenSearch http (plugin off) | `:538` | Phase 4 |
| ClickHouse `:8123` | image default | Phase 4 |
| Postgres `host` HBA lines | new | Phase 4 |
| Valkey `--port 6379` | `:100` | Phase 4 |
| correlation `:8000` plaintext | `:1036` | Phase 4 |
| Vector ingest lanes without `tls:` | `vector/vector.yaml:127,139,152,167` | Phase 5 |
| syslog-ng → Vector `:6601` plaintext | `syslog-ng.conf:111` | Phase 5 |

---

# 6.22 Network-policy matrix `[v1]`

Complete enough to **generate** compose network membership, host firewall rules
and k8s NetworkPolicies. Networks: `edge`, `app`, `ingestion`, `storage`
(`internal: true`), `ops`.

Legend — **Pub?** = published to the host · **Ten?** = tenant-aware (carries or
filters tenant data) · **Lab / Prod** = allowed in that profile.

## 6.22.1 External → platform

| Source | Destination | Port | Proto | Dir | Purpose | Identity required | Pub? | Ten? | Lab | Prod |
|---|---|---|---|---|---|---|---|---|---|---|
| Browser | nginx | 443→8443 | HTTPS | in | UI + API | JWT/API key after TLS | ✅ | ✅ | ✅ | ✅ |
| Browser | nginx | 8000→8080 | HTTP | in | legacy plaintext UI | none | ✅ | ✅ | ✅ | ❌ **retire** |
| API client | nginx | 443 | HTTPS | in | REST | API key | ✅ | ✅ | ✅ | ✅ |
| Device | syslog-ng | 514, 5514 | UDP/TCP | in | syslog legacy | **none — unauthenticable** | ✅ | ⚠ derived | ✅ | ⚠ exception |
| Device | syslog-ng | 6514 | TCP/TLS | in | syslog secure `[Phase 2+]` | device cert | ✅ | ✅ | ✅ | ✅ |
| Device | goflow2 | 2055, 4739, 6343 | UDP | in | NetFlow/IPFIX/sFlow | **none — unauthenticable** | ✅ | ⚠ derived | ✅ | ⚠ exception |
| Device | api | 162→1162 | UDP | in | SNMP traps | USM (v3) | ✅ | ⚠ derived | ✅ | ⚠ exception (v2c) |
| Remote vantage | nginx | 443 | HTTPS | in | path push | API key + vantage claim (§6.13.11) | ✅ | ✅ | ✅ | ✅ |

## 6.22.2 Platform → external (egress)

| Source | Destination | Port | Proto | Purpose | Prod |
|---|---|---|---|---|---|
| api | device SNMP | 161 | UDP | polling | ✅ |
| api | device SSH | 22 | TCP | `FEATURE_DEVICE_SSH` / verification | ⚠ opt-in |
| gnmic | device gNMI | 57400, 6030 | gRPC/TLS | telemetry | ✅ |
| prober | targets | ICMP / any | — | active measurement | ⚠ opt-in |
| api | OIDC issuer / JWKS | 443 | HTTPS | SSO | ✅ |
| api | ITSM / Slack / PagerDuty / SMTP / ntfy | 443, 587 | HTTPS/SMTPS | notifications | ⚠ per feature flag |
| api | LLM provider | 443 | HTTPS | copilot | ⚠ only when `FEATURE_AI`/`FEATURE_COPILOT` |
| cloud-ingest | AWS / Azure / GCP APIs | 443 | HTTPS | cloud telemetry | ⚠ opt-in |
| **storage network** | **anything** | — | — | — | ❌ **`internal: true` — no egress at all** |

Egress is default-deny and complements the existing SSRF guard
(`SSRF_ALLOWED_HOSTS`, `SSRF_ALLOW_PRIVATE`, `docker-compose.yml:1355-1361`).

## 6.22.3 Intra-platform

| Source | Destination | Port | Proto | Dir | Purpose | Identity | Net | Ten? | Lab | Prod |
|---|---|---|---|---|---|---|---|---|---|---|
| nginx | frontend | 8080 | HTTP | → | SPA assets | none | edge | ❌ | ✅ | ✅ |
| nginx | api | 8080/8443 | **mTLS** | → | API | `ns/ingress/sa/nginx` | edge | ✅ | ✅ | ✅ |
| nginx | grafana | 3000 | HTTP/TLS | → | console (gated `default.conf:181`) | gate cookie | ops | ❌ | ✅ | ✅ |
| nginx | opensearch-dashboards | 5601 | HTTP/TLS | → | console (gated `:307`) | gate cookie | ops | ✅ | ✅ | ✅ |
| nginx | netbox | 8080 | HTTP/TLS | → | SoT (gated `:245`) | gate cookie | app | ❌ | ✅ | ✅ |
| nginx | keycloak | 8080/8443 | HTTP/TLS | → | SSO (`:378`) | none | app | ❌ | ✅ | ✅ |
| api | correlation | 8443 | **mTLS** | → | RCA replay/findings | `ns/app/sa/api` | app | ✅ | ✅ | ✅ |
| api | postgres | 5432 | **TLS verify-full** | → | app state | role `api` + cert | storage | ✅ | ✅ | ✅ |
| api | valkey | 6380 | **TLS** | → | cache | ACL user `api` | storage | ✅ | ✅ | ✅ |
| api | clickhouse | 8443 | **TLS + client cert** | → | telemetry | user `api` | storage | ✅ | ✅ | ✅ |
| api | opensearch | 9200 | **HTTPS + mTLS** | → | logs | `correlix_reader` | storage | ✅ | ✅ | ✅ |
| api | vmauth | 8427 | **TLS** | → | metrics | `ns/app/sa/api` | storage | ✅ | ✅ | ✅ |
| api | vector-aggregator | 8692 | **mTLS** | → | bus bridge | `ns/app/sa/api` | ingestion | ✅ | ✅ | ✅ |
| api | kafka | 9092 | TLS | → | **health probe only** (`:1093-1096`) | `ns/app/sa/api` | ingestion | ❌ | ✅ | ✅ |
| api | gotenberg | 3000 | HTTP | → | PDF render | none | ops | ⚠ report content | ✅ | ⚠ |
| api | netbox | 8080 | HTTPS | → | SoT sync | token | app | ✅ | ✅ | ✅ |
| api | keycloak | 8080/8443 | HTTPS | → | token validation | none | app | ✅ | ✅ | ✅ |
| correlation | kafka | 9092 | **mTLS** | → | consume | `ns/app/sa/correlation` | ingestion | ✅ | ✅ | ✅ |
| correlation | clickhouse | 8443 | **TLS + cert** | → | write findings | user `correlation` | storage | ✅ | ✅ | ✅ |
| correlation | postgres | 5432 | **TLS verify-full** | → | read state | role `correlation` | storage | ✅ | ✅ | ✅ |
| vector-aggregator | kafka | 9092 | **mTLS** | → | produce | `ns/ingestion/sa/vector-aggregator` | ingestion | ✅ | ✅ | ✅ |
| vector-aggregator | vmauth | 8427 | **TLS** | → | cloud metrics (`vector.yaml:1114`) | identity | storage | ✅ | ✅ | ✅ |
| vector-aggregator | opensearch | 9200 | **HTTPS** | → | stats only (`vector.yaml:203,225`) | `correlix_stats` | storage | ❌ | ✅ | ✅ |
| vector-router | kafka | 9092 | **mTLS** | → | consume | `ns/ingestion/sa/vector-router` | ingestion | ✅ | ✅ | ✅ |
| vector-router | opensearch | 9200 | **HTTPS + mTLS** | → | index | `correlix_writer` | storage | ✅ | ✅ | ✅ |
| vector-router | clickhouse | 8443 | **TLS + cert** | → | insert flows/costs | user `ingest` | storage | ✅ | ✅ | ✅ |
| vector-router | api | 8443 | **mTLS** | → | **sealing keys** (§6.13.9) | `ns/ingestion/sa/vector-router` | app | ✅ | ✅ | ✅ |
| syslog-ng | vector-aggregator | 6601 | **TLS** | → | syslog forward | `ns/ingestion/sa/syslog-ng` | ingestion | ✅ | ✅ | ✅ |
| goflow2 | kafka | 9092 | **mTLS** | → | produce `netops.flows` | `ns/ingestion/sa/goflow2` | ingestion | ✅ | ✅ | ✅ |
| gnmic | vector-aggregator | 8690 | **mTLS** | → | metrics lane | `ns/ingestion/sa/gnmic` | ingestion | ✅ | ✅ | ✅ |
| gnmic | vmauth | 8427 | **TLS** | → | remote_write | `ns/ingestion/sa/gnmic` | storage | ✅ | ✅ | ✅ |
| prober | vector-aggregator | 8689 | **mTLS** | → | probe events | `ns/ingestion/sa/prober` | ingestion | ✅ | ✅ | ✅ |
| prober | valkey | 6380 | **TLS** | → | topology publish | ACL user `prober` | storage | ✅ | ✅ | ✅ |
| prober | vmauth | 8427 | **TLS** | → | metrics | identity | storage | ✅ | ✅ | ✅ |
| cloud-ingest | kafka | 9092 | **mTLS** | → | produce costs/logs | `ns/ingestion/sa/cloud-ingest` | ingestion | ✅ | ✅ | ⚠ opt-in |
| kafka-init | kafka | 9092 | **mTLS** | → | topic creation | `ns/streaming/sa/kafka-admin` | ingestion | ❌ | ✅ | ✅ |
| kafka-exporter | kafka | 9092 | **mTLS** | → | lag metrics (Describe only) | `ns/ops/sa/kafka-exporter` | ❌ | ingestion | ✅ | ⚠ profile |
| opensearch-init | opensearch | 9200 | **HTTPS + admin cert** | → | ISM + securityadmin | `ns/ops/sa/opensearch-admin` | storage | ❌ | ✅ | ✅ |
| opensearch-dashboards | opensearch | 9200 | **HTTPS** | → | console backend | `correlix_osd` | storage | ✅ | ✅ | ⚠ profile |
| grafana | clickhouse | 8443 | **TLS** | → | datasource | user `grafana_ro` | storage | ⚠ platform rows only | ✅ | ⚠ profile |
| grafana | vmauth | 8427 | **TLS** | → | datasource | `ns/ops/sa/grafana` | storage | ✅ | ✅ | ⚠ profile |
| vmalert | vmauth | 8427 | **TLS** | → | rules + remoteWrite | `ns/ops/sa/vmalert` | storage | ✅ | ✅ | ✅ |
| victoria (scraper) | api, clickhouse, vector, correlation, kafka-exporter, cadvisor, node-exporter, grafana, cloud-ingest | various | **TLS** | → | self-monitoring (`src/config/vmscrape.yml:22-96`) | `ns/storage/sa/victoria` | ops | ❌ | ✅ | ✅ |
| keycloak | postgres | 5432 | **TLS verify-full** | → | its own DB | role `keycloak` | storage | ❌ | ✅ | ✅ |
| netbox | netbox-postgres | 5432 | **TLS** | → | its own DB | role `netbox` | storage | ❌ | ✅ | ⚠ profile |
| netbox | valkey | 6380 | **TLS** | → | cache DBs 9/10 (`:1788,1792`) | ACL user `netbox` | storage | ❌ | ✅ | ⚠ profile |
| api | secrets-seal | unix socket | — | → | KEK seal/unseal | filesystem perms | *(no network)* | ✅ | ✅ | ✅ |
| **anything** | **anything not listed** | — | — | — | — | — | — | — | ❌ | ❌ |

## 6.22.4 Generation targets

| Artifact | Derived from |
|---|---|
| compose `networks:` membership per service | the **Net** column |
| host firewall (nftables/ufw) | §6.22.1 rows with **Pub? = ✅**, restricted to `TELEMETRY_BIND_ADDR` |
| k8s NetworkPolicy | §6.22.3, one `ingress`/`egress` rule per row, default-deny per namespace |
| the posture view (§6.24) | every row, joined with the observed transport |

**Two invariants the matrix must never violate:** the `storage` network has no
egress, and no row grants a source a destination it does not appear in the §6.7
ACL / §6.8 role / §6.9 grant tables for. The validator cross-checks both (V-16,
V-17).

---

# 6.23 Observability and operational security `[v1]`

## 6.23.1 The bounded-cardinality rule

The repo has a documented rule and this design obeys it:

> `docs/design/correlation-data-contract.md:40-44` — *"Metrics carry only the
> top-K noisiest tenants (`corr_tenant_writes_window`, K=`CORR_WA_TOPK`) —
> **never one series per tenant**."*
> `docs/design/telemetry-baseline-research.md:82` — *"Labels = identity
> dimensions only … **Never** put unbounded values … in labels — flow-level
> cardinality belongs in the OLAP store (ClickHouse), not the TSDB."*
> `docs/design/sso-saml-oidc-design-2026-08-03.md:646-648` — security metrics
> carry *"no emails, hostnames, tokens, state/nonce, assertion IDs, or tenant
> names in labels"*.

**Applied to every metric below:**

| Allowed as a label | Forbidden as a label |
|---|---|
| `service` (bounded — §6.4's 32 rows) | `tenant_id`, tenant name |
| `identity` (bounded — the same set) | device id, hostname, IP |
| `outcome`, `reason`, `rule` (small enums) | certificate serial or fingerprint |
| `topic`, `index_base`, `table` (bounded sets) | full URL path, query |
| `mode` ∈ {plaintext,tls,mtls,protocol_native} | any free-form string |

Where per-tenant or per-device detail is genuinely needed, it goes to **ClickHouse
or the audit log**, and the metric carries a **top-K** or a **count of distinct**
instead. `netops_flow_unknown_exporter_total` (§6.18.3) is capped at K distinct
addresses with an overflow bucket, for exactly this reason.

Validator rule **V-18** enforces `telemetry.metrics_label` shape at policy level.

## 6.23.2 What already exists

| Metric | Where | Note |
|---|---|---|
| `netops_tls_cert_expiry_seconds` | `tls_server.go:148-150` | gauge, computed at scrape (`:147`), can go negative |
| `netops_tls_handshake_errors_total` | `tls_server.go:152-154` | counted from net/http's error log via `handshakeErrLog.Write` (`:49-57`), wired at `main.go:1349` |
| `netops_tls_identity_rejected_total` | `tls_server.go:155-157` | from `PeerPolicy.OnReject` (`:97-100`) |
| `netops_unmask_requests_total{outcome}` | `pipeline_processors.go:578-583` | sealed-field reveal attempts |
| `netops_integration_webhook_rejected_total` | `integration_metrics.go:59` | bad token/signature |
| `netops_login_throttle_*` | `main.go:2139-2147` | includes `evictions_total` = "a username spray in progress" |
| `collector_ingest_rejected{lane}` | `collectors/ingest_auth.go:121-122` | per-lane 401/403 |
| `corr_cross_tenant_inserts_total{table}` | `main.py:3414` | cross-tenant writes, by table |
| `netops_cloud_ingest_exchange_total{provider,outcome}` | `deployment/docker/cloud-ingest/ingest_metrics.py:129-135` | includes `auth_success`/`auth_fail` |

**A defect in the existing TLS metrics.** `writeTLSMetrics`
(`tls_server.go:139-159`) emits **only when `t.reloader != nil` AND
`leaf != nil`** (`:140-146`). So when no certificate is loaded — the exact
incident state — all three series **vanish from the scrape** rather than
reporting a problem. Alerts that key on a value never fire; only an `absent()`
alert would. **v1: emit `netops_tls_configured{service} 0/1` unconditionally, and
emit the counters even with no leaf.** A metric that disappears when things break
is not a monitoring control.

Also note `netops_tls_cert_expiry_seconds` covers **only the API listener** and
is dormant today (no `TLS_CERT_FILE` set). Nothing observes the nginx front's
certificate at all.

## 6.23.3 New metrics

### Certificates and PKI

| Metric | Type | Labels | Alert |
|---|---|---|---|
| `netops_tls_configured` | gauge | `service` | `== 0` in production → page |
| `netops_tls_cert_expiry_seconds` | gauge | `service`, `usage` (server/client) | `< 4h` warn, `< 1h` page. **Extend beyond the API** to every service, reported by the issuer |
| `netops_tls_cert_issued_total` | counter | `service`, `outcome` | issuance failures |
| `netops_tls_reload_total` | counter | `service`, `outcome` | `outcome="error"` twice consecutively → page (§6.6.2) |
| `netops_tls_trust_bundle_version` | gauge | `service` | divergence across services → warn (drift, HLD T19) |
| `netops_tls_trust_bundle_age_seconds` | gauge | `service` | `> 2 × rotation interval` → warn |
| `netops_tls_handshake_errors_total` | counter | `service`, `reason` | rate spike → warn |
| `netops_tls_identity_rejected_total` | counter | `service`, `reason` ∈ {wrong_san, unknown_ca, expired, no_cert, federation_mismatch} | **any** in production → investigate |
| `netops_tls_plaintext_connections_total` | counter | `service` | **any** in production → page |

`reason` on identity rejection is the one that answers "wrong SAN vs unknown CA
vs expired" — the HLD §6.23 requirement — and the data is already available at
the `OnReject` call site (`tls_server.go:97-100`, which today logs
`rerr.Error()` but does not classify it).

### Per-datastore authorization denials

| Metric | Source |
|---|---|
| `netops_kafka_authz_denied_total{principal,operation}` | broker authorizer log → exporter, or the broker's own `kafka.server:type=...,name=...` JMX `[UNKNOWN]` |
| `netops_opensearch_authz_denied_total{role}` | security-plugin audit index |
| `netops_ch_authz_denied_total{user}` | ClickHouse `system.query_log` exception codes |
| `netops_pg_auth_failures_total{role}` | Postgres log scrape |
| `netops_valkey_acl_denied_total{user}` | Valkey `INFO errorstats` / `ACL LOG` |
| `netops_vmauth_rejected_total{identity,code}` | vmauth's own metrics |

### Tenant / device integrity

| Metric | Meaning |
|---|---|
| `netops_ch_row_policies_expected` / `_present` | §6.9.5.2 — `present < expected` for 5m is a **page** |
| `netops_ch_row_policy_violations_total{rule}` | CHP-01..CHP-06 |
| `netops_ch_queries_total{scope}` | `scope="all"` visibility for cross-tenant reads (§6.9.6) |
| `netops_device_identity_unmapped_total` | cert → no registered device |
| `netops_device_identity_conflict_total` | cert tenant ≠ registry tenant — **page** |
| `netops_flow_unknown_exporter_total` | top-K bounded (§6.18.3) |
| `netops_trap_policy_rejected_total{reason}` | §6.16.6 |
| `netops_snmp_security_level{level}` | count of devices at each level — the migration progress signal |

### Secrets and custody

`netops_vault_unseal_total{outcome}` (failure → **page**),
`netops_vault_dek_created_total{scope}`,
`netops_vault_decrypt_failures_total{reason}`,
`netops_vault_rotation_total{kind,outcome}`,
`netops_sealing_key_fetch_total{identity,outcome}`.

### Policy and exceptions

| Metric | Alert |
|---|---|
| `netops_transport_policy_total{mode}` | the posture summary |
| `netops_transport_policy_drift_total` | declared ≠ observed |
| `netops_transport_policy_changed_total{action}` | `action="widen"` → notify |
| **`netops_security_exception_expiry_seconds{id}`** | `< 0` → **page**. `id` is the exception id, a bounded set |
| `netops_security_exceptions_active` | trend; a rising count is a programme-health signal |
| `netops_legacy_protocol_events_total{protocol}` | `protocol ∈ {syslog_udp, snmp_v2c, flow_udp}` — the migration burndown |

**Expired migration exceptions are a paging alert.** That is what stops a
"temporary" bypass becoming permanent, and it is the mechanical half of HLD
constraint 18.

## 6.23.4 Where the alerts live

`src/config/rules.yaml` already holds ~113 alert rules evaluated by **both**
`vmalert` (external, `docker-compose.yml:683-713`) and the in-API engine — one
file, two evaluators (`docker-compose.yml:666-672`). Security rules go in the
same file, in a new `security` group, so they inherit both evaluators and the
existing `ALERTS`-series notification path (`:674-679`) that
`scripts/stack-watchdog.sh` turns into a phone push.

`src/config/vmscrape.yml` gains no new job for TLS metrics — they ride the
existing `netops-api` job (`:22`) and each service's existing exporter.

## 6.23.5 Audit events

| Event | Fields (no secrets, no PII) |
|---|---|
| Security-config change | actor, object, `config_version`, before/after **mode only** |
| Exception created / extended | actor, id, reason, expiry, ticket |
| Certificate issued / rotated | service, identity, not-after |
| CA rotation step | step, bundle version |
| Break-glass secret access | actor, secret id, justification |
| `securityadmin` invocation | actor, window |
| Device identity conflict | device id, claimed tenant, registered tenant |
| Sealing-key fetch | caller identity, tenant, outcome |

Audit rides the existing `withAudit` middleware (`main.go:1326`) and the existing
audit store. Log sanitisation stays as it is: nginx strips capability tokens
(`nginx.conf:49-58`), ClickHouse errors deliberately omit response bodies
(`main.py:1826`), and OpenSearch audit excludes sensitive headers (§6.8.7).

## 6.23.6 The customer-facing report `[D10]`

A single exportable artifact answering *"is Correlix secure?"* with evidence:

- One row per §6.22 path: source, destination, **mode**, **TLS version**, **peer
  identity**, **certificate expiry**, **authorization mechanism**, **last
  verified**.
- A summary: *N of M paths encrypted and mutually authenticated; K declared
  exceptions with owners and expiry dates.*
- Certificate inventory: identity, issuer, not-before/not-after, days remaining.
- Datastore authorization posture: which stores require authentication, which
  roles exist.
- Tenant-isolation statement: row policies present/expected, RLS asserted, index
  isolation in force — **explicitly labelled as independent of transport
  security**, so nobody reads "TLS ✓" as "tenant-isolated ✓".
- Every unauthenticable lane listed **honestly**, with its compensating controls.

Generated from live state (metrics + the policy store), never hand-maintained,
and delivered through the existing report pipeline
(`ENABLE_REPORT_SCHEDULER`, `docker-compose.yml:1490-1493`) so it can be
scheduled and emailed like any other report.

---

# 6.24 Security UI design `[v1 — read-only]`

## 6.24.1 Placement

The repo's admin IA is a two-level pattern:

- **Level 1**, `src/frontend/src/nav.tsx` — the Administration section is
  `nav.tsx:292-345` (`id: "admin"` at `:293`, `footer: true` at `:296`), whose
  leaves carry `{ id, label, group?, platformOnly?, render }`. A `Security` group
  already exists (`nav.tsx:320`, Authentication). `platformOnly` (`:101`) hides a
  leaf from non-platform users, and the comment at `:326-329` is explicit that
  **the backend enforces it independently** — the flag is presentation only.
- **Level 2**, `src/frontend/src/tabs/admin.tsx` — in-page tab arrays
  (`IA_TABS` at `:1045-1051`, provider/org variants at `:1054`, `:1060-1062`),
  dispatched from `IdentityAccess()` (`:1697-1742`).
- Pages are `React.lazy` route-split and `tabs/admin` exports get a default-shim
  wrapper (`nav.tsx:55-65`).

**Placement: Administration → Security**, a new leaf in the existing `Security`
group, `platformOnly: true`, with seven in-page tabs following the `IA_TABS`
shape exactly.

## 6.24.2 Tabs and columns

| Tab | Columns | Source |
|---|---|---|
| **Transport Policies** | name · channel · peer · outbound mode · accept set · min TLS · **declared vs observed** · drift · exception? · owner · expires · version | policy store + `status.*` |
| **Certificates** | identity · service · issuer · not-before · **not-after** · days left · SANs · usage · **status** (OK / Renewing / Degraded / Expiring / Expired) | issuer + `netops_tls_cert_expiry_seconds` |
| **Trust Domains** | domain · root subject · fingerprint (short) · valid until · **bundle version** · services converged (n/m) · rotation state | trust bundle + `netops_tls_trust_bundle_version` |
| **Legacy Exceptions** | id · channel · peer · reason · owner · accepted by · accepted at · **expires** · days remaining · ticket · compensating controls · **age badge** | exception register |
| **Rotation Status** | scope (leaf / bundle / credential) · last rotation · next due · last outcome · failures (24h) | `netops_tls_reload_total`, `netops_vault_rotation_total` |
| **Service Identities** | service · SPIFFE ID · namespace · cert status · peers allowed to call it · peers it may call · authz summary (Kafka topics / OS role / CH user) | identities.yaml + policies |
| **Device Identities** `[Phase 2+]` | device · tenant · kind · cert serial (short) · not-after · last seen · **mapping status** (mapped / unmapped / **conflict**) · transport mode | device registry |

## 6.24.3 Read-only in phase 1

No create, edit, rotate or revoke controls ship in phase 1 — per the brief and
per HLD §9 Phase 8. Rationale: a UI that can widen an accept-set is a UI that can
disable transport security, and it must not exist before the audit trail,
step-up authentication and the ageing report are proven. Phase 1 answers "what is
our posture?"; editing comes later.

The **only** action in phase 1 is **Export** (§6.23.6), which is read-only.

## 6.24.4 Display rules

These are the rules that keep the UI honest — the same discipline the codebase
already applies to secrets.

| Rule | Why |
|---|---|
| **Never render a private key, a full certificate, or a fingerprint in full.** Status and metadata only, in the established status-only style (`admin.tsx:2513-2519`, badge computation `:2535-2536`) | the write-only/`*_set` convention (`admin.tsx:3350` — "secrets are write-only") |
| **Never show "Secure ✓" for an unauthenticated lane.** syslog-UDP, flow-UDP and SNMPv2c render as **"Unauthenticated — declared exception"** with the owner and expiry inline | HLD §6.6 honesty clause; validator F-12 |
| **SNMPv3 renders as "SNMPv3 authPriv", never "TLS"** | §6.16.1 |
| **swtpm renders as "Software TPM (lab-grade)"**, not a green tick | §6.19.12 |
| **Expired exception → red row, sorted to the top, with the owner named** | ageing must be unavoidable |
| **Transport identity and tenant are shown in separate columns, never merged** | design law: an mTLS peer is authenticated, not tenant-authorized |
| **Drift (declared ≠ observed) is a first-class state**, not a footnote | the posture view's whole value is catching drift |
| Empty state is "not configured", never a silent blank | matches the existing configured/not-configured badge pattern |

## 6.24.5 Authorization

The page is **platform-global plumbing**, not per-tenant data — so per
CLAUDE.md §3a rule 3 it is gated by `requirePlatformAdmin` /
`requireCrossTenant`, **not** by a scope-blind `requireAdmin`. A tenant admin
holds full `administration:admin` within their tenant, and transport policy is
not theirs to see.

`platformOnly: true` on the nav leaf hides it; the backend refuses it
independently — exactly the pattern documented at `nav.tsx:326-329`.

`[Phase 2+]` Device Identities is per-tenant data and is therefore
tenant-scoped with the standard filters, and ships with an
`org_isolation_test.go`-shaped test (§3a rule 5).

---

# 6.25 Migration strategy `[v1]`

## 6.25.1 The state machine every channel follows

```mermaid
stateDiagram-v2
  [*] --> Insecure: as-built
  Insecure --> Declared: TransportPolicy written<br/>accept:[plaintext] + EXCEPTION (owner, expiry)
  Declared --> Observed: posture view shows declared vs observed<br/>NO enforcement yet
  Observed --> DualMode: secure listener added ALONGSIDE plaintext<br/>accept:[plaintext, mtls]
  DualMode --> Migrating: clients cut over ONE at a time,<br/>in the declared order
  Migrating --> DualMode: rollback — revert one client
  Migrating --> Verified: 100% of clients on the secure path<br/>for >= narrow_soak (24h)<br/>netops_tls_plaintext_connections_total == 0
  Verified --> SecureOnly: plaintext listener REMOVED<br/>accept:[mtls] · exception deleted
  SecureOnly --> [*]
  Declared --> Expired: exception passes its expiry
  DualMode --> Expired: exception passes its expiry
  Migrating --> Expired: exception passes its expiry
  Expired --> Declared: extended (audited, step-up, new expiry)
  note right of Expired
    PRODUCTION: validator FAILS, boot refused.
    STAGING: readyz not-ready.
    LAB: warn.
    An expiry is a deadline, not a suggestion.
  end note
```

Two rules make this safe and are non-negotiable:

1. **Never leave `DualMode` without evidence.** The gate from `Migrating` to
   `Verified` is a metric reading zero for a soak period, not a person's opinion.
2. **Never enter `DualMode` without `Observed`.** Shipping observation before
   enforcement is what keeps the rollout from blinding the platform
   (`docs/design/transport-encryption-2026-08-04.md:221-227`).

## 6.25.2 Per-component plan

Ordered by (risk removed ÷ blast radius). Each row: current → dual-mode
mechanism → client order → what to watch → rollback → final state → deadline
(days from phase start).

| # | Component | Current | Dual-mode | Client order | Watch during | Rollback | Final | Deadline |
|---|---|---|---|---|---|---|---|---|
| 1 | **Valkey** | no password, no TLS (`:87-109`) | `--tls-port 6380` beside `--port 6379`; `user default off` last | health → prober → api → netbox | `netops_valkey_acl_denied_total`; cache hit rate | drop the ACL file, restart | `--port 0` | 14d |
| 2 | **nginx→api** | plaintext (`default.conf:135`) | API accepts both; nginx swaps to `api-mtls.conf` | nginx (single client) | `netops_tls_identity_rejected_total`; 5xx rate | revert the include | mTLS only | 14d |
| 3 | **Public ingress** | `:8000` + `:443` both published (`:1722`, override `:6`) | both listeners | browsers, API clients | 4xx/5xx; HSTS | re-publish `:8000` | `:443` only | 30d |
| 4 | **Postgres** | `sslmode=disable` | `ssl=on`, `host` + `hostssl` HBA lines | api → correlation → keycloak | `netops_pg_auth_failures_total`; connection errors | restore `pg_hba.conf`, `SIGHUP` | `hostssl` only | 21d |
| 5 | **ClickHouse** | Basic over `:8123` (`vector-router/vector.yaml:618`) | `:8443` beside `:8123` | vector-router → correlation → api → grafana | `netops_ch_authz_denied_total`; **insert failure rate**; `netops_ch_row_policies_present` | revert URLs | `:8443` only | 21d |
| 6 | **VictoriaMetrics** | anonymous `:8428` | vmauth on `:8427`, VM still reachable | vmalert → grafana → api → prober → gnmic → vector-aggregator | `netops_vmauth_rejected_total`; ingest rate per source | remove vmauth | VM on loopback | 21d |
| 7 | **correlation** | unauthenticated HTTP (`main.py:3319`) | TLS on `:8443` beside `:8000` | api (single client) | replay/findings error rate | revert `CORRELATION_URL` | `:8443` mTLS only | 21d |
| 8 | **Kafka** | PLAINTEXT, no auth (`:207-210`) | `MIGRATION:9094` beside `CLIENT:9092` SSL | kafka-exporter → kafka-init → vector-router → correlation → vector-aggregator → goflow2 → cloud-ingest | **consumer lag per group**; `netops_kafka_authz_denied_total`; `netops_kafka_plaintext_connections_total`; end-to-end event count | move one client back to `:9094` | `:9094` removed, `allow.everyone.if.no.acl.found=false` | 45d |
| 9 | **OpenSearch** | security plugin off (`:538`) | **not possible** — see §6.8.9 | freeze router → restart → securityadmin → repoint clients | indexing rate; consumer lag on `netops-router-*`; anonymous request must now fail | re-set `DISABLE_SECURITY_PLUGIN` | plugin on, roles enforced | 45d |
| 10 | **Ingest lanes** | one shared token (`vector/vector.yaml:128-130`) | `tls:` added; Basic retained beneath | **bus_in first** → traps → probes → metrics | `collector_ingest_rejected{lane}`; per-lane event counts | drop the `tls:` block | per-client identity, Basic removed | 45d |
| 11 | **Sealing keys** | plaintext + shared token (`cx-secret-backend.sh:24,55-57`) | API accepts both auth modes | vector-router (single client) | `netops_sealing_key_fetch_total{outcome}`; Vector must not exit 78 | revert `SEALING_API_URL` | mTLS + dedicated identity | 30d |
| 12 | **syslog-ng→Vector** | plaintext `:6601` (`syslog-ng.conf:111`) | Vector accepts both on `:6601` | syslog-ng (single client) | syslog event rate; disk-buffer depth | revert `transport("tcp")` | TLS only | 30d |
| 13 | **SNMP traps** | v3 fail-open (`snmptrap.go:671-681`) | `accept:[plaintext, protocol_native]` — count, do not drop | n/a (server-side) | `netops_trap_policy_rejected_total{reason}` — **must be understood before narrowing** | widen the accept set | unknown senders rejected | 30d |
| 14 | **gNMI** | `insecure`×5, global `skip-verify` (`gnmic.yaml:13,30,35,40,45,50`) | per-target policy | per device | per-target status; sample gaps | per-target revert | TLS+CA, mTLS where possible | `[Phase 2+]` |
| 15 | **Device syslog** | 514 unauth (`syslog-ng.conf:83-85`) | 6514 beside 514 | per device | per-device event continuity | keep 514 | 6514 only, per device | `[Phase 2+]` |
| 16 | **Flows** | UDP unauth | — | — | — | — | **remains unauthenticated by protocol** — segmentation + honest label only | n/a |

## 6.25.3 Rules for every temporary insecure listener

1. **Explicitly enabled.** It exists only because a variable was set
   (`KAFKA_MIGRATION_LISTENER`, `ENABLE_LEGACY_SYSLOG`, …). The default is off.
2. **It alerts.** `netops_*_plaintext_connections_total` non-zero after the
   cutover milestone pages.
3. **It expires.** The exception has a date; the validator enforces it (V-10,
   PV-11).
4. **It is network-confined.** Never published to the host; §6.22 restricts which
   sources may reach it.
5. **Its removal is a completion criterion**, not a follow-up ticket.

## 6.25.4 Telemetry continuity

This is the thing most likely to go wrong, and the platform is unusually
well-equipped for it:

| Buffer | Where | Covers |
|---|---|---|
| Kafka retention 3 days | `docker-compose.yml:221` | any consumer restart |
| Vector aggregator disk buffer | `docker-compose.yml:441-444` (F-04) | aggregator restart |
| syslog-ng reliable disk buffer, 256 MiB | `syslog-ng.conf:114-119` (F-48) | Vector restart — added precisely because a restart *"silently DROPS device syslog"* |
| Correlation DLQ | `docker-compose.yml:968-971` (F-38) | ClickHouse write rejection |
| Consumer-group offsets | Kafka | no re-processing, no loss |

Continuity assertion for each cutover: **event count in == event count out**
across the window, no duplicates, no reordering within a partition. Measured, not
assumed.

## 6.25.5 Rollback

Every step is reversible by configuration alone. Nothing in this plan performs an
irreversible data migration. The two steps with a real one-way component are:

- **OpenSearch security bootstrap** — the security index is created. Rollback is
  disabling the plugin, which leaves the index harmlessly present.
- **Postgres role split** — new roles are created. Rollback is repointing DSNs;
  the roles can stay.

The snapshot taken before step 9 (§6.8.9) is the floor for the whole programme.

---

# 6.26 Test strategy `[v1]`

Mapped onto this repo's actual conventions: `*_test.go` beside the code in the
owning package (263 test files in `src/backend` today), the isolation-test
template `org_isolation_test.go`, the ratchet guards
(`route_isolation_coverage_test.go`, `package_growth_guard_test.go`), the Python
contract tests under `tests/`, and the shell suites (`tests/auth.sh`,
`tests/smoke.sh`).

## 6.26.1 Unit tests

| Area | Where | Asserts |
|---|---|---|
| Policy schema | `src/backend/security/policy_test.go` (new package) | V-01..V-20 each pass and fail; F-01..F-12 each rejected; unknown `apiVersion` refused; unknown field refused |
| Exception rules | same | expiry parsing, banned-reason list, `max_exception_days`, distinct owner/accepted_by |
| Profile resolution | same | most-specific-wins; missing record ⇒ inherit, never allow; intra-stack default `accept: []` |
| **CA-key boot refusal** | `src/backend/tls_ca_test.go` (extends the existing file) | `TLS_INTERNAL_CA=true` + no provider ⇒ error containing `PLAINTEXT`; with provider ⇒ success; lab override honored and logged |
| Vault first-run vs unseal-error | `src/backend/internal/vault/secrets_test.go` | provider **absence** ⇒ first-run KEK; provider **error** ⇒ boot abort (the §6.19.4 fix) |
| `REQUIRE_SEAL` normalization | same | `TRUE`, `True`, `" true"` all engage the guard |
| Legacy wrapped-store gate | same | legacy format refused unless `VAULT_ALLOW_LEGACY_STORE=true` |
| **CH policy safety check** | `src/backend/clickhouse_policies_test.go` (extends) | table-driven `system.row_policies` fixtures → each of CHP-01..CHP-06 detected; a correct set passes |
| SPIFFE namespace issuance | `src/backend/tls_ca_test.go` | `spiffeID(ns, svc)` emits the §6.4 format for every identity in `identities.yaml` |
| Peer allowlist non-empty | `src/backend/tlsconfig/verify_test.go` | an empty allowlist is rejected by the production validator (the `verify.go:62-64` gap) |
| SNMP priv/auth algorithms | `src/backend/collectors/snmpv3_test.go` | unknown auth proto ⇒ **error**, not SHA-1 fallback; `AES256` either works or is rejected — never silently AES-128; `3DES` is not advertised unless implemented |
| Trap fail-open closed | `src/backend/collectors/snmptrap_test.go` | unknown sender v3 ⇒ dropped + counted; known sender below level ⇒ dropped; valid ⇒ `Authenticated=true` and `transport_authenticated=true` |
| `transport_authenticated` stamping | per collector | defaults false; set true only from the connection, never from the payload |
| Kafka principal mapping | `src/backend/security/kafka_acl_test.go` | the mapping rule turns each §6.4 CN into the expected principal; a non-SPIFFE CN maps to something that matches no ACL |
| Bus-bridge topic allowlist | Vector VRL unit fixture + `tests/test_ingest_contract.py` | a topic outside the allowlist aborts |

## 6.26.2 Integration tests

| Scenario | Where |
|---|---|
| mTLS handshake succeeds with the right identity, fails with the wrong SAN, fails with no cert, fails with a cert from another trust domain | `src/backend/tls_server_test.go`, `tls_phase4_test.go` (both exist) |
| Federation binding rejects a cross-domain identity | `tlsconfig/federation_test.go` (exists) |
| Kafka ACL denial per identity; consumer-group scoping; `allow.everyone.if.no.acl.found=false` | new compose-based integration suite, gated like `DATABASE_URL_TEST` |
| OpenSearch role enforcement; **anonymous request fails** | same |
| ClickHouse client-cert auth; row policies still enforced under the new user | same, plus the existing `ch_convergence_test.go` |
| Postgres `verify-full`; `hostssl`-only rejects a non-TLS client; RLS still enforced | extends `maintenance_pg_isolation_test.go` etc. |
| Valkey ACL: `api` cannot `FLUSHALL`; `prober` cannot read `netops:` keys outside its prefix | new |
| Sealing-key fetch requires the vector-router identity; the api identity alone is refused | new |
| End-to-end: device → syslog-ng → Vector → Kafka → router → OpenSearch with TLS at every internal hop | extends `tests/smoke.sh` |

## 6.26.3 Tenant-isolation tests (CLAUDE.md §3a rule 5 — required)

Every new data-returning surface ships one. Concretely:

| Surface | Test |
|---|---|
| Transport-policy API | `security_policy_isolation_test.go` — modelled on `org_isolation_test.go:34-174`: own-only list, cross-tenant get/put/delete ⇒ **404**, `as_tenant` into another org ignored, `reachesTenant` false |
| Device Identities `[Phase 2+]` | same shape |
| **Correlation `/findings`** | new — proves a tenant-scoped caller cannot read another tenant's findings (the §6.14.1 defect) |
| Re-prove existing isolation **under TLS** | run the full existing isolation suite against the secured stack — HLD §9 Phase 4 requires it |

`org_isolation_test.go` is the template because it exercises the **real router
and auth middleware** (`:3-9`) across three orgs and asserts all eight properties
(`:115-173`).

## 6.26.4 Fault injection

| Fault | Expected behavior |
|---|---|
| Certificate expires mid-flight | new handshakes fail; existing connections survive; `netops_tls_cert_expiry_seconds ≤ 0`; alert fires |
| Issuer unavailable at renewal | last good cert kept (`tlsconfig/reload.go:41`); `netops_tls_reload_total{outcome="error"}`; **no crash** |
| Truncated / corrupt cert file | reload rejected, old cert retained |
| CA rotated with one service left on the old bundle | that service's connections rejected with `reason="unknown_ca"`; drift metric diverges |
| Seal sidecar down at boot | boot refused (`docs/runbooks/tls-mtls.md:100-102`) |
| Seal sidecar dies at runtime | in-flight decrypts continue; new DEK creation blocks and logs; **no plaintext fallback** (`secret-custody.md:168-170`) |
| ClickHouse access storage wiped | CHP-01/CHP-06 detected within one check interval; production refuses to serve |
| Kafka ACL misconfigured for one producer | that lane stops and **alerts**; other lanes unaffected; DLQ/buffers absorb |
| Wrong SAN presented | rejected + counted, not accepted-with-warning |
| Expired exception | validator fails in production |
| Clock skew ±10 minutes | leaves carry a 1-minute backdate (`internalca/ca.go:176`); larger skew must fail **loudly**, not silently accept |

## 6.26.5 Ratchet guards

The codebase already uses shrink-only baselines
(`route_isolation_coverage_test.go:15-21` — *"The baseline only shrinks … Do NOT
add to it"*; `package_growth_guard_test.go:315` — *"THIS NUMBER MUST ONLY EVER
DECREASE"*). Three new ones, same shape:

| Guard | Locks |
|---|---|
| `plaintext_path_ratchet_test.go` | a baseline list of known-plaintext paths. A **new** plaintext path fails the build; removing one requires lowering the count in the same commit |
| `security_exception_ratchet_test.go` | the count of active exceptions may not increase without an accompanying policy file |
| `insecure_config_guard_test.go` | greps the tracked configs for `skip-verify: true`, `insecure: true`, `DISABLE_SECURITY_PLUGIN`, `sslmode=disable`, `InsecureSkipVerify`, `--tls-auth-clients no`, `allow.everyone.if.no.acl.found=true` — each occurrence must be in the baseline |

## 6.26.6 Continuity tests

| Test | Assertion |
|---|---|
| Rotation continuity | events in == events out across a full leaf rotation, per lane |
| Kafka cutover continuity | no loss, no duplicates, no intra-partition reordering across the listener migration |
| OpenSearch bootstrap continuity | document count before == after + buffered |
| Nightly | run against a staging stack; a continuity regression blocks the phase |

## 6.26.7 CI

All of the above runs under the existing blocking gate (CLAUDE.md §12: vet, test,
`-race`, staticcheck, gosec, govulncheck). Additions: the security validator runs
against `production.yaml` in CI, and the ratchets are ordinary Go tests so they
need no new infrastructure.

---

# 6.27 Acceptance criteria

Each phrased as a **testable assertion**. "Done" means the assertion passes
mechanically, not that someone believes it.

## 6.27.1 Configuration and enforcement

1. `scripts/preflight-security.sh` **exits non-zero** on a production profile
   containing any of PV-01..PV-18, and the message names the rule id, the file
   and the fix.
2. Every §6.22 intra-platform row has a `TransportPolicy` file; V-17 fails if any
   service or path is unpolicied.
3. No policy in `production.yaml` reaches plaintext without an unexpired
   `exception` (F-01, V-09).
4. `docker compose config` (merged, including overrides) publishes **no**
   datastore, broker or console port.
5. `COMPOSE_PROFILES` in production contains none of `legacy`, `mock-snow`,
   `mock-nms`.

## 6.27.2 Identity and PKI

6. Every service in §6.4 marked v1 has an issued SVID whose URI SAN matches its
   table row exactly.
7. `spiffeID()` emits the per-namespace format; no identity contains
   `/ns/default/` unless `default` is its real namespace.
8. Every mTLS server has a non-empty `allowed_identities`; an empty one fails the
   validator (F-04).
9. A certificate from the device trust domain presenting a workload SPIFFE ID is
   **rejected** (`FederationTrust` test).
10. A full leaf rotation completes with **zero** dropped connections on the api
    and **zero** telemetry loss on every lane.
11. A dual-root CA rotation completes in staging with zero loss, gated on
    `netops_tls_trust_bundle_version` convergence.

## 6.27.3 Datastores and bus

12. An **anonymous** connection to Kafka, OpenSearch, ClickHouse, VictoriaMetrics,
    Postgres and Valkey **fails** — asserted per store by an integration test.
13. Kafka reports `allow.everyone.if.no.acl.found=false` and
    `auto.create.topics.enable=false`; every topic in §6.7.5 exists.
14. Each Kafka principal can produce/consume exactly its §6.7.7 row and nothing
    else — one denial test per principal.
15. `netops_kafka_plaintext_connections_total == 0` for 24h, and the `MIGRATION`
    listener is absent from the config.
16. OpenSearch: `securityadmin` has run, `nodes_dn` is set, the admin certificate
    is mounted into no long-lived service.
17. **ClickHouse row policies: `present == expected`**, no `corr_*`/`path_*`
    policy contains `tenant_id = ''`, and deleting one causes the production API
    to refuse to start (CHP-02, CHP-01).
18. Postgres: `pg_hba.conf` contains **no** non-`hostssl` line; a plaintext
    connection is refused; `assertRLSCapable` passes with
    `STORE_PG_ALLOW_RLS_BYPASS` unset.
19. Valkey: `user default` is `off`; `api` cannot execute `FLUSHALL`.

## 6.27.4 Ingress, app and secrets

20. nginx publishes **only** the TLS port; HSTS present; the SPA CSP unchanged;
    `X-Forwarded-Proto` set on every proxied location.
21. nginx→api is mTLS and an api request presenting any other identity is
    rejected and counted.
22. The correlation service refuses a request without the api client certificate;
    `/findings` returns only the caller's tenant's rows.
23. `vector-router` fetches sealing keys over mTLS with its own identity; the
    shared ingest token no longer authorizes key retrieval.
24. Each ingest lane has its own client identity; `INGEST_TOKEN` is no longer
    shared across five services.
25. Production boot **fails** with `TLS_INTERNAL_CA=true` and no `SEAL_PROVIDER`,
    with an error containing the word `PLAINTEXT`.
26. Production boot **fails** with `REQUIRE_SEAL=true` and no provider, including
    when the value is `TRUE` or `True`.
27. A provider **error** (as opposed to absence) at unseal aborts boot rather than
    minting a fresh KEK.

## 6.27.5 Device plane (honesty in v1, security in Phase 2)

28. Every syslog-UDP, flow and SNMPv2c event carries
    `transport_authenticated=false`; **no** UI surface, report or RCA evidence
    chain describes them as verified.
29. An **unknown sender's cleartext v3 trap is rejected** and counted
    (`netops_trap_policy_rejected_total{reason="unknown_sender"}`).
30. The production validator refuses `insecure: true` or `skip-verify: true` in
    `gnmic.yaml`.
31. `PrivProtocols` advertises only algorithms the collector actually implements;
    an unknown auth protocol is an error, not a SHA-1 downgrade.
32. `[Phase 2+]` A device certificate whose tenant claim disagrees with the
    registry is **rejected**, counted and audited; no device is ever
    auto-created.

## 6.27.6 Tenant isolation (must not regress)

33. The complete existing isolation suite passes **unchanged** against the fully
    secured stack.
34. Every new data-returning surface ships an `org_isolation`-shaped test:
    own-only list, cross-tenant get/put/delete ⇒ 404, `as_tenant` ignored.
35. No transport control is described anywhere — code, docs, UI — as providing
    tenant isolation.

## 6.27.7 Observability and the customer story

36. All §6.23.3 metrics are exported, and `netops_tls_configured` is present even
    when no certificate is loaded (closing the `tls_server.go:140-146` gap).
37. Every metric label is drawn from a bounded set; no label carries a tenant id,
    device id, hostname, IP or fingerprint.
38. An **expired exception pages**.
39. The Transport Security view renders every §6.22 path with mode, identity and
    expiry, and the export produces the §6.23.6 report from live state.
40. The report states, in one line, how many paths are encrypted and mutually
    authenticated, how many are declared exceptions, and who owns each.

---

# 7. Where this LLD found the HLD to be wrong

Reported rather than silently diverged from, per the brief.

**Baseline note.** The HLD was revised while this LLD was being written
(556 → 677 lines; HEAD `804f719f`). Two of the corrections below were **absorbed
into the revised HLD before this document was finished** and are marked
✅ *already fixed upstream* — they are retained because the LLD's design decisions
depend on them, and because the record of *why* the change was made belongs
somewhere. All line citations are against the **current** 677-line HLD.

| # | HLD statement | Reality | Impact |
|---|---|---|---|
| 1 ✅ | §6.2 originally: the SPIFFE format is *"already the format `tls_ca.go:91-93` emits"* | The **shape** matches, but the namespace is the hardcoded literal `default`: `return "spiffe://" + m.trustDomain + "/ns/default/sa/" + svc` (`tls_ca.go:92`). Only the trust domain is configurable. **The revised HLD now states this itself** (`HLD:317-323` — *"That is shape-true but value-false"*) | The per-namespace identity model is a **code change**, not configuration. §6.4.1, §6.4.5 |
| 2 | §6.6 (`HLD:420`): *"`transport_authenticated=false` stamped on every event (the SNMP trap path **already** does this — `snmptrap.go:64`)"* | **`transport_authenticated` does not exist anywhere in the codebase** — zero hits across `src/` and `deployment/`; the only occurrences in the repo are the HLD's own text (`HLD:448`, `HLD:608`). What exists is narrower: `Authenticated bool` at `snmptrap.go:60` (not `:64`), on the trap lane only, set in exactly one place (`:692`). Syslog and flow events carry **no** authenticity marker | **Still open.** The honesty clause needs a **new field on every lane**, not a rollout of an existing one. §6.15.4 |
| 3 | §1.1 (`HLD:62`) and T3 (`HLD:260`): *"one `INGEST_TOKEN` for 6 clients"* | The tracked compose wires it to **five** services — `gnmic:341`, `vector-aggregator:438` (the **verifier**, and the only `:?`-required one), `vector-router:487`, `api:1109`, `prober:1565` — i.e. **four clients + one verifier**. The gitignored `docker-compose.override.yml:37` adds `cloud-ingest`, making five clients | The claim is right in spirit and slightly off in arithmetic; more importantly it under-reports because the sixth is in an **untracked file**. §6.13.10, §6.21.2 |
| 4 | §7: *"correlation … UNAUTHENTICATED surface"* and §3 diagram | True, and **worse than stated**: `CH.query()` runs every read at `tenant_scope=__all__` (`main.py:1837`), and `/findings` (`main.py:3548-3570`) has no tenant predicate. So the unauthenticated surface is also a **cross-tenant read** of `netops.findings`, and `/deadletters` (`:3345`) returns raw cross-tenant event bodies | This is a tenant-isolation finding, not only a transport one. §6.14.1, §6.14.4 |
| 5 | §7 / §3 imply an `api → Kafka` relationship | The Go API has **no Kafka client** (`bus_producer.go:17-23`, stdlib-only per §6 allowlist). It POSTs to `vector-aggregator:8692` and Vector writes to a **templated topic** (`vector/vector.yaml:1188`) guarded only by a `netops.` **prefix** check (`:773`) | The ACL matrix cannot have an `api` row. The subdivision must happen in Vector, not Kafka. §6.7.6 |
| 6 | §3 diagram and §7 omit `cloud-ingest` | It is a real Kafka producer to `netops.cloudcosts`/`netops.cloudlogs`, holds `INGEST_TOKEN`, mounts host cloud credentials — and lives **only** in a gitignored override (`docker-compose.override.yml:27-70`) | Any inventory built from the tracked compose is incomplete. §6.21.2 |
| 7 | §7 goflow2 row: *"mTLS **or SASL_SSL**"* | §11.0 **D5** chose mTLS, and the owner has confirmed it. The row is internally inconsistent with the decision | Standardised on mTLS throughout; goflow2's TLS capability is flagged `[UNKNOWN]` and must be verified. §6.7.9 |
| 8 | §1.1 cites `tls_ca.go:22-24` for the plaintext-CA-key admission | The text is at `tls_ca.go:23-24` | Cosmetic |
| 9 ✅ | §11 originally framed boot refusal as an open question (now settled as **D9**) | Precedent already exists in-repo: `assertRLSCapable` (`internal/platformdb/db.go:186-207`) aborts boot on an RLS-bypassing role, with the reasoning spelled out at `:179-185` | The decision was easier than it looked — the pattern is established and tested in-repo. §6.9.5.2, §6.19.13 |

**Also found, not contradicting the HLD but material:**

- `RowPolicyDDL` uses `IF NOT EXISTS` (`policies.go:10`) while `StrictRowPolicyDDL`
  uses `OR REPLACE` (`ch_sql.go:47`), and **nothing reads back**
  `system.row_policies`. Convergence failure is a `log.Printf` warning
  (`clickhouse_policies.go:46-51`) with no metric and no readiness impact — the
  precise shape of the 1,560-silent-failure incident (`policies.go:20-29`).
- `writeTLSMetrics` emits nothing when no leaf is loaded (`tls_server.go:140-146`)
  — the metrics disappear exactly when they matter.
- `PeerPolicy` with an empty allowlist accepts **any** mesh certificate
  (`tlsconfig/verify.go:62-64`).
- `initBackendTransport()` (`main.go:284`) runs long before
  `bootstrapInternalCA()` (`main.go:1331`) — a first-boot ordering hazard.
- `REQUIRE_SEAL` uses strict `== "true"` (`secrets.go:98`) where the RLS guard
  uses `EqualFold(TrimSpace(...))` (`db.go:199`).
- An unseal **error** is treated as a first run and mints a new KEK
  (`secrets.go:116-120`).
- The legacy wrapped-store format bypasses the integrity MAC
  (`secrets.go:292-301`).
- `snmpcred` advertises `3DES`/`AES192`/`AES256` (`store.go:30`) that the
  collector does not implement or silently downgrades (`snmpv3.go:242,284`), and
  an unknown auth protocol silently becomes SHA-1 (`snmpv3.go:88-89`).
- `poller.go:89-91` falls back to the community string `"public"`.
- `clickhouse/custom-settings.xml:7` references `users.d/tenant-scope.xml`, which
  does not exist.
- Four to ten Kafka topics exist only by auto-creation and are absent from
  `kafka-init` (`docker-compose.yml:255-258`).
- nginx has **no** rate limiting at all (only commented references in
  `tls.conf.example:159,164,166`).
- `read_only:` and `tmpfs:` appear nowhere; `no-new-privileges` + `cap_drop` are
  set on 7 of 32 services.

---

# 8. Assumptions and unknowns

## 8.1 Assumptions (defensible, not derived from evidence)

| # | Assumption | Where | If wrong |
|---|---|---|---|
| A1 | Certificates are distributed via one shared volume mounted read-only per service | §6.4.5, §6.5.2 | switch to a per-service init container; layout is unchanged |
| A2 | Keys are `0640` with a shared `CORRELIX_GID`, not `0600` | §6.5.3 | fall back to per-service `chown` from a privileged init container (worse) |
| A3 | Reload sidecars run in the target's PID namespace rather than holding the Docker socket | §6.6.1 | accept restarts, or accept the socket with a network policy |
| A4 | Device certificates get 90-day TTLs | §6.3.3 | shorten if the enrolment story turns out to be cheap |
| A5 | ClickHouse `verificationMode: relaxed` + per-user `ssl_certificate` gives fail-closed per-user auth without breaking probes | §6.9.3 | use `strict` and give the probe a certificate |
| A6 | The CHP policy re-check runs every 15 minutes | §6.9.5.2 | tune against ClickHouse load |
| A7 | Compose `secrets:`-style file mounts beat env vars for credentials | §6.21.7 | keep env vars; the rest of the design is unaffected |
| A8 | nginx rate limits of 10r/m (auth) and 60r/s (api) are a sane starting point | §6.13.8 | measure and tune before production enforces them |
| A9 | The 24h workload leaf TTL is affordable at our handshake rate | §6.3.3 | lengthen the TTL, or enable session resumption more aggressively |

## 8.2 Unknowns that must be resolved before building

| # | Unknown | Blocks | How to resolve |
|---|---|---|---|
| U1 | Does `apache/kafka:4.1.1` accept `ssl.keystore.type=PEM` end to end? | §6.5.6, §6.7.2 | staging test; else add a PKCS#12 conversion step |
| U2 | Does Kafka reload keystores on file change, or only via a dynamic broker-config update? | §6.6 | staging test |
| U3 | Does **goflow2 v2.2.1** support Kafka TLS + client certificates? | §6.7.9 — a hard Phase-3 dependency | read the release flags; if not, keep it on the migration listener behind a network policy, or interpose Vector |
| U4 | Does Vector 0.40's `http_server` source support a **per-source client-identity allowlist**? | §6.13.10 | Vector docs/source; else enforce at the network layer |
| U5 | Can `vmauth` v1.101.0 verify **client** certificates? | §6.10.2 | test; else per-identity bearer tokens over TLS |
| U6 | Does VictoriaMetrics reload TLS certificates without restart? | §6.6 | test |
| U7 | Does Valkey 8 auto-reload TLS files, and does it prefer `aclfile` over inline `user` lines? | §6.6, §6.12.3 | test |
| U8 | Which Go Redis/RESP client does the backend use, and can it do TLS + ACL `AUTH user pass`? | §6.12.4 | read the code; small stdlib work if not |
| U9 | Does `cloud-ingest`'s `broker_client.py` support TLS? | §6.7.9 | read `deployment/docker/cloud-ingest/broker_client.py` |
| U10 | Does correlation actually use OpenSearch? `OPENSEARCH_URL` is set (`docker-compose.yml:973`) but no use was found | §6.8.5, §6.14.3 | grep; if unused, delete the variable |
| U11 | Does gnmic support leaf-certificate pinning? | §6.17.4 | docs; else per-target CA file |
| U12 | Kafka authorizer denial metrics — JMX only, or exportable? | §6.23.3 | test on 4.1.1 |
| U13 | Can `stack_health.go` do a TLS dial to Kafka without a Kafka client? | §6.7.11 | a bare `tls.Dial` with the API SVID should suffice — verify |
| U14 | `internal: true` on the storage network vs healthchecks and image pulls | §6.21.1 | build-time pulls are unaffected; verify healthchecks |
| U15 | Is `DISABLE_SECURITY_PLUGIN` keyed on presence or on value in the 2.16 entrypoint? | §6.8.2 | remove the variable entirely to be safe |
| U16 | Does the first-boot two-phase start (§6.21.10) interact badly with `install.py`'s existing sequencing? | §6.21.10 | dry-run on a clean host |
| U17 | Which `/admin/*` routes are intentionally unauthenticated? | §6.13.7 | route audit; `/admin/version` should not be public |
| U18 | Postgres container runtime uid (not pinned in compose) | §6.5.3, §6.11.2 | inspect and pin |

## 8.3 Owner decisions already made

HLD §11.0 decisions **D1–D10** are resolved and are restated in **§0.1** using the HLD's own numbering. The remaining item the
owner may still want to weigh in on is **§6.19.11 backup encryption** — designed
here, deferred, and the only HLD §11 item whose answer this document does not
force.

---

*End of LLD. Companion documents to be written next per the HLD header:
`CORRELIX_SECURITY_IMPLEMENTATION_BACKLOG.md` (SEC-001…SEC-024),
`docs/adr/ADR-SEC-*.md`, `docs/runbooks/security/*`.*
