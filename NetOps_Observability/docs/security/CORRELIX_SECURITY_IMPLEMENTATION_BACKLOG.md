# Correlix Security — Implementation Backlog (SEC-001 … SEC-024)

**Status (2026-08-12): the v1 programme was EXECUTED under tracker #151.**
Steps 1–3 are complete as of 2026-08-12 — the enforce wave (`ebadd2af`,
2026-08-09: default-deny bus, plaintext listeners removed), the 13-phase
assurance run (`d2e5cf65`), and the step-3 fixes F-1…F-12 (`4e5e0d00` …
`8124d834`, including the F-11 seal-or-quarantine build) — with step 4
(documentation/claims reconciliation, SEC-024) in flight. The owner steer in
§0a was applied throughout; per-epic outcomes, every deviation, and every
owner-accepted shape are recorded in
`docs/security/TLS_ASSURANCE_REPORT_2026_08.md`, and dated per-row status now
annotates the §"V1 COMPLETION DEFINITION" tables below. This file remains the
**epic-spec record** — the item texts are the specs the work was built
against, not a live to-do list (open work lives in `docs/TRACKER.md`). The
original 2026-08-04 "DRAFT / nothing authorized to start" status and the HLD
§12 do-not-implement boundary are discharged.

**Binding parents:**
`docs/security/CORRELIX_CLOUD_NATIVE_SECURITY_HLD.md` (component matrix §7,
trust domains §6.1, phase roadmap §9, open decisions §11) and
`docs/design/transport-encryption-2026-08-04.md` (the per-peer policy object §4
and enforcement points §5). Where this backlog and the HLD disagree, the HLD
wins and this file is wrong; where this backlog and the *repo* disagree, the
repo wins and both documents are wrong.

**Conventions used here**

- Every "current problem" was re-verified against branch `feat/observability-platform`
  on 2026-08-04. File paths are relative to `NetOps_Observability/` (the project
  dir) **except** `.github/workflows/*`, which live at the **git root**, one
  level up — CI `working-directory:` is `NetOps_Observability/src/backend`.
- **No calendar estimates anywhere.** Complexity is XS/S/M/L/XL only.
- **Approval required = yes** whenever an item (a) sits on an HLD §11 open
  decision, (b) can drop telemetry, (c) touches a customer device, or (d)
  changes production failure behaviour (a listener, credential, cert, or policy).
- Tests follow this repo's conventions: Go `*_test.go` in the **owning package**;
  cross-tenant tests modelled on `src/backend/org_isolation_test.go`; ratchet
  guards modelled on `src/backend/package_growth_guard_test.go`; config
  fresh-load checks in `scripts/preflight-configs.sh`; static install-integrity
  checks in `scripts/preflight-install.py`; Python integration suites under
  `tests/` (`tests/test_ingest_contract.py`, `tests/test_gnmi_fidelity.py`,
  `tests/test_secret_rotation.py`, `tests/test_architecture_contract.py`).
- Tracker cross-references use **real** rows only: **#114** (k8s packaging, open),
  **#148** (install-bundle levers, open), **#129** (Sealed Fields, complete —
  polish only), **#133** (topology polish, open), **#97** (Redpanda removal,
  shipped), **#145** (HTTPS readiness at the nginx edge — **shipped** 2026-08-03,
  row correctly deleted per tracker rule 1; commits `470456e8`, `877ea39a`).
  There is **no open #145 row**; see the closing notes.

---

## 0a. Owner steer (2026-08-04) — decisions applied to this backlog

> *"Pick secure methods, don't add too much overhead, not overkill. I want to
> show customers this is a secure environment where all components are
> transported via TLS securely."* — and: *"we will stick with our design for the
> most part; I am just giving high level direction where you have to make
> decisions for me."*

**The backlog is unchanged in extent.** All **24 epics** and all **54 numbered
items** (plus SEC-022, which is epic-level and has no sub-items — 55 units of
work) keep their full detail. Nothing is deleted, nothing is thinned. What the
steer changes is (a) the **phase** each item lands in, and (b) **which option is
chosen** inside items that previously said "owner-decision".

### Decisions now resolved (HLD §11)

| HLD §11 | Question | **Decision** | Effect on this backlog |
|---|---|---|---|
| 7 | Scope of v1 | **Intra-stack + public ingress only** — every Correlix-owned component talks TLS. Customer-device lanes are Phase 2+. | SEC-014/015/016 → Phase 2+, except their honest-labelling items; SEC-017 → Phase 2+ except labelling + segmentation guidance |
| 2 | Where the internal CA root lives | **v1 = the existing in-process CA** (`tls_ca.go` + `internalca/`), which already auto-issues and auto-rotates. **Mandatory sealing.** Offline root + ceremony is Phase 2+. | SEC-003 drops from **XL → M** for v1; SEC-003.4 kept in full, marked Phase 2+ |
| 1 | Device PKI: certs vs PSK vs both | **Deferred with the device lanes.** No device-credential build in v1. | SEC-003.5 kept in full, marked Phase 2+ |
| 3 | Kafka authn: mTLS vs SASL_SSL | **mTLS with the same internal CA.** SASL/SCRAM is rejected in v1 — it would add a second credential store to operate for no gain in transport security. | SEC-006.1 no longer waits on a decision |
| 4 | How hard production fails | **Boot refusal** on production violations. | SEC-002.3 confirmed for v1 |
| 5 | Legacy lane sunset policy | Deferred with the device lanes (Phase 2+); the *declaration + ageing* mechanism still ships in v1. | SEC-014.3 / SEC-017.2 stay v1 |
| 6 | Backup encryption domain | Not raised in the steer; remains open. See closing note 5. | unchanged |

### Additional standing direction

- **Two trust domains in v1:** public/enterprise (nginx server cert) and
  `correlix.workload`. The `correlix.device` and operator intermediates are
  designed but not built until Phase 2+.
- **No new operational dependencies in v1:** no SPIRE, no Vault PKI, no
  cert-manager, no offline-root ceremony. The SPIFFE *identity strings* stay
  exactly as `tls_ca.go:91-93` already emits them, so every deferred option
  remains a drop-in later (HLD §8 already commits to this).
- **Datastores: simplest sufficient native auth.** One scoped service user per
  store is enough where it is enough; do not build an elaborate per-client role
  matrix for its own sake. **ClickHouse row policies and Postgres FORCE-RLS stay
  exactly as they are** — they are the tenant boundary, they are already strong,
  and each datastore epic's job is *to not break them*, not to redesign them.
- **SEC-021 is promoted to a v1 deliverable.** The customer-visible artefact is a
  **read-only** Transport Security posture view plus an exportable report showing
  every path as TLS ✓ with the peer identity and certificate expiry. Read-only in
  v1; the editing half (SEC-021.2) is Phase 2+.
- **Judgement rule for the whole v1:** prefer the smaller sufficient mechanism.
  Where an item offers a choice, take the one that reaches "all Correlix
  components communicate over TLS" with the fewest moving parts to operate.

### V1 complexity totals (after re-phasing)

| Bucket | Items in scope | Total | Heavy items |
|---|---|---|---|
| **v1** | SEC-001 (3), SEC-002 (3), SEC-003.1/.2/.3 (3), SEC-004 (2), SEC-005 (2), SEC-006 (3), SEC-007 (2), SEC-008 (2), SEC-009 (2), SEC-010 (1), SEC-011 (2), SEC-012 (2), SEC-013.1/.2 (2), SEC-014.1 + .3 (2), SEC-017.2 (1), SEC-018 (2), SEC-019.1 (1), SEC-020 (2), SEC-021.1 (1), SEC-023 (2), SEC-024 (3) | **43 items** | **2 XL** (SEC-006.2 client cutover, SEC-008.1 OpenSearch plugin) · **6 L** (SEC-002.1, SEC-003.3, SEC-006.1, SEC-008.2, SEC-013.1, SEC-023.1) · remainder M or smaller |
| **Phase 2+** | SEC-003.4, SEC-003.5, SEC-013.3, SEC-014.2, SEC-015 (2), SEC-016 (2), SEC-017.1, SEC-019.2, SEC-021.2, SEC-022 (epic-level) | **11 items + 1 epic** | **1 XL** (SEC-014.2 RFC 5425 lane) · **5 L** (SEC-003.4, SEC-003.5, SEC-019.2, SEC-021.2, SEC-022) · remainder M or smaller |

Two **XL** items remain in v1 and both are irreducible: **SEC-008.1**
(OpenSearch Security plugin — the bootstrap is invasive by nature and this is
the largest unauthenticated surface in the product) and **SEC-006.2** (the
per-client Kafka cutover — heterogeneous clients including goflow2 and Python,
each needing its own verified change window). Neither can be simplified away
without leaving an anonymous datastore or an anonymous bus, which would falsify
the v1 claim outright.

**SEC-003 falls from XL to M** — the largest single saving from the steer —
because `.4` (offline ceremony) and `.5` (device domain) move out, leaving only
the seal gate, one compose variable, and extending the *existing* issuance loop
from two SVIDs to every service. **SEC-014 drops from XL to M for v1** (only the
internal `.1` and the labelling `.3` remain in scope).

---

## 0. Summary table

Phase = HLD §9 roadmap phase. **V1** = in the narrowed v1 scope set by the owner
steer (§0a); **P2+** = written in full, executed later. "Blocks" lists what cannot
start until this epic lands; "Blocked by" lists this epic's hard prerequisites.

| Epic | Title | Phase | V1? | Complexity | Approval | Blocked by | Blocks |
|---|---|---|---|---|---|---|---|
| **SEC-001** | As-built inventory + documentation reconciliation | 0 | **V1** | M | no | — | 002, 017, 024 |
| **SEC-002** | Production fail-closed configuration validator | 0 | **V1** | L | .3 yes | 001 | 004, 008–018, 020 |
| **SEC-004** | Public ingress TLS (promote + retire plaintext) | 1 | **V1** | M | .2 yes | 002 | 005, 021 |
| **SEC-005** | nginx → API mTLS | 1 | **V1** | M | yes | 003.1, 003.2, 003.3 | 004.2 |
| **SEC-003** | PKI custody + workload identity fabric | 2 | **V1** = .1/.2/.3 (**M**); .4/.5 P2+ | M (v1) · XL (full) | .1 yes; .4/.5 yes | 001 | 005–019, 022 |
| **SEC-006** | Kafka transport encryption + authentication (**mTLS, same CA — decided**) | 3 | **V1** | XL | yes | 003.3 | 007, 023 |
| **SEC-007** | Kafka topic + consumer-group ACLs | 3 | **V1** | L | yes | 006 | 023 |
| **SEC-008** | OpenSearch Security plugin (authn + roles) | 4 | **V1** | XL | yes | 003.3, 002 | 020, 023 |
| **SEC-009** | ClickHouse TLS + row-policy safety under new auth | 4 | **V1** | L | yes | 003.3 | 023 |
| **SEC-010** | VictoriaMetrics behind vmauth | 4 | **V1** | M | yes | 003.3 | — |
| **SEC-011** | Postgres TLS (`verify-full`) + per-service roles | 4 | **V1** | M | yes | 003.3 | — |
| **SEC-012** | Valkey authentication + TLS | 4 | **V1** | M | yes | 003.3 | — |
| **SEC-018** | Secret-sealing transport + `REQUIRE_SEAL` enforcement | 4 | **V1** | L | yes | 003.3, 013.1 | 019 |
| **SEC-013** | Secure Vector ingestion (per-client identity + TLS) | 5 | **V1** = .1/.2; .3 P2+ | XL | yes | 003.3 | 018.1, 014.1 |
| **SEC-014** | Secure syslog (RFC 5425 mTLS lane + legacy marking) | 5 → **P2+** | **V1** = .1 (internal hop) + .3 (labelling); .2 P2+ | XL | yes | 003.5, 013.2 | 023 |
| **SEC-015** | SNMPv3 hardening (close the trap fail-open) | 5 → **P2+** | no | L | yes | 002 | 020 |
| **SEC-016** | gNMI TLS enforcement (kill global `skip-verify`) | 5 → **P2+** | no | M | yes | 002, 003.5 | — |
| **SEC-017** | Flow-lane segmentation + honest declaration | 5 → **P2+** | .2 only (labelling) | M | yes | 001 | 020 |
| **SEC-019** | Certificate + credential rotation | 6 | **V1** = .1; .2 P2+ | L | yes | 003, 018 | 023 |
| **SEC-022** | Kubernetes security future-state (design only) | 7 → **P2+** | no | L | no | #114, 003 | — |
| **SEC-020** | Security observability (metrics, audit, alerts) | 8 → **v1** | **V1** | M | no | 002, and each enforcement epic | 021, 023 |
| **SEC-021** | Security status UI + exportable posture report | 8 → **v1** (read-only) | **V1** = .1; .2 P2+ | L | .2 yes | 020 | — |
| **SEC-023** | Fault injection + continuous security validation | 8 | **V1** | L | no | 006, 008, 019 | — |
| **SEC-024** | Documentation + runbooks | 0 → 8 | **V1** | M | no | 001 | — |

**Re-phasing note.** SEC-020 and SEC-021.1 move *earlier* than HLD §9 places them
(Phase 8), because the steer makes the posture view and its exportable report a
**customer-visible v1 deliverable** — "show customers this is a secure
environment". They still depend on the enforcement epics for content, so they
land last within v1, not first; what changes is that they are no longer optional
tail-end work.

**Dependency-graph shape:** a single-rooted DAG. `SEC-001` is the only node with
no prerequisites. It feeds `SEC-002` (the validator) and `SEC-003` (the PKI
spine); those two are the *only* fan-out points. Everything in Phases 3–5 hangs
off `SEC-003.3` (the workload-identity registry) and/or `SEC-002` (the rule
vocabulary), runs in parallel, and re-converges on `SEC-020` → `SEC-021` /
`SEC-023`. Maximum depth is 6 (`001 → 002 → 003.1 → 003.3 → 013.1 → 018.1`).
**No cycles**; the one near-cycle (`SEC-004.2` "drop :8000" needs `SEC-005`
mTLS, and `SEC-005` is filed in the same phase) is broken by making `004.2` a
*separate item* that depends on `005`, not on the whole of `004`.

---

# PHASE 0 — Inventory and validation framework

*HLD §9: Deps none · Risk low · Rollback n/a (additive) · Telemetry none ·
Tenant none. This is the only phase permitted before approval.*

---

## SEC-001 — As-built inventory + documentation reconciliation

**Phase 0 · V1 · Complexity M · Owner: platform eng · Approval: no (additive, no
runtime behaviour change).**

Objective: produce one committed, machine-readable statement of what every
network hop in the stack *actually* does today, and correct the docs that
currently contradict the code, so every later epic can be validated against a
fixed baseline instead of against re-derived guesswork.

### SEC-001.1 — Committed as-built transport inventory

- **Title:** Machine-readable as-built transport inventory
- **Objective:** One checked-in file enumerating every source→destination hop
  with its current protocol, transport, authentication, authorization, and the
  file:line that proves each claim — the executable input to SEC-002's validator
  and the data source for SEC-021's UI.
- **Current problem:** The posture is only knowable by reading six config files
  per hop (HLD §1.4). The evidence is scattered across
  `deployment/docker/docker-compose.yml` (Kafka `KAFKA_LISTENERS:
  "PLAINTEXT://0.0.0.0:9092"` at :207-210; `DISABLE_SECURITY_PLUGIN: "true"` at
  :538; `OPENSEARCH_URL: "http://opensearch:9200"` and `CLICKHOUSE_URL:
  "http://clickhouse:8123"` and `POSTGRES_DSN: postgresql://…@postgres:5432` on
  the correlation service at :972-977), `deployment/docker/nginx/default.conf`
  (every `proxy_pass http://$up_api:8080`, :102/121/135/148/163/326/342),
  `deployment/docker/vector/vector.yaml` (four `http_server` lanes at
  :125-172 sharing one `&ingest_auth` anchor), and
  `deployment/docker/gnmic/gnmic.yaml` (`skip-verify: true` at :13).
  Nothing aggregates them, so no test can assert on them.
- **Affected paths:** all 22 rows of HLD §7 (inventory only — it reads, it does
  not change any hop).
- **Prerequisites:** none.
- **Implementation steps:**
  1. Define the inventory schema as the HLD §7 column set plus an `evidence`
     field (`path:line`) per assertion, using the
     `docs/design/transport-encryption-2026-08-04.md` §4 policy-object field
     names so the two never diverge.
  2. Write the inventory to `docs/security/transport-inventory.yaml` (data) with
     a short prose companion in `docs/security/` (already-existing dir).
  3. Extend `scripts/preflight-install.py` (static, stdlib-only, already parses
     `docker-compose.yml`) with an inventory-coverage check: every compose
     service that publishes or dials a port must appear in the inventory.
  4. Add an evidence-liveness check: every `path:line` in the inventory must
     resolve to an existing file (line drift tolerated, file absence is a fail).
- **Files likely affected:** `docs/security/transport-inventory.yaml` (new),
  `scripts/preflight-install.py`, `.github/workflows/fresh-install-integrity.yml`.
- **Tests:** extend `scripts/preflight-install.py`'s own assertions (it is the
  static gate and is already wired into `fresh-install-integrity.yml:44`);
  add a case to `tests/test_architecture_contract.py` asserting the inventory
  enumerates every compose service with a published/dialled port.
- **Acceptance criteria:** (a) adding a new compose service with a port and no
  inventory row **fails** `fresh-install-integrity`; (b) every inventory
  `evidence` path exists; (c) the inventory's Kafka/OpenSearch/Valkey/VM/PG rows
  state `plaintext` + `none` for authn, matching the verified facts above.
- **Rollout:** additive commit; no stack change; no restart.
- **Rollback:** revert the commit; nothing depends on it at runtime.
- **Security impact:** none directly; makes the exposure auditable and is the
  precondition for every fail-closed rule.
- **Telemetry impact:** none — no data path is touched.
- **Tenant impact:** none, and the existing isolation tests must still pass.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** none ·
  **Approval:** no.

### SEC-001.2 — Documentation drift correction (verified drift only)

- **Title:** Correct the docs that contradict the code
- **Objective:** Remove the specific false statements a reader would act on.
- **Current problem (verified):**
  - `docs/ARCHITECTURE.md:14,56-58,78` presents **Telegraf** as the SNMP
    collector and the `netops.metrics` producer. `deployment/docker/docker-compose.yml:313-315`
    puts telegraf under `profiles: [legacy]` — it does not run. The real
    collector is Go: `src/backend/collectors/poller.go`, `snmpmetrics.go`,
    `snmpv3.go`.
  - `scripts/preflight-configs.sh:18` says it is used by
    `.github/workflows/config-preflight.yml`. **That workflow does not exist**;
    the real caller is `.github/workflows/fresh-install-integrity.yml:44` (via
    `scripts/preflight.sh:28`). A reader looking for the gate finds nothing.
  - `docs/design/tls-architecture.md` marks phases 1–5 ✅ "done". True in code,
    but `deployment/docker/.env` contains **no `TLS_*` and no `SEAL_*`
    variable** (231 lines; only `INGEST_TOKEN` matches the security grep). The
    doc must distinguish **built** from **enabled**.
  - **HLD correction:** the HLD §3 drift table also lists `docs/UPGRADE.md` and
    `docs/STREAMING.md` as Redpanda drift. Re-verified: `UPGRADE.md:61-70` is a
    legitimate *migration note* ("Redpanda → Apache Kafka (2026-07)") and
    `STREAMING.md:8` explicitly states Redpanda "was removed from the product
    entirely". These are correct history, **not drift** — do not rewrite them.
- **Affected paths:** none (documentation only).
- **Prerequisites:** SEC-001.1 (the inventory is the corrected source of truth).
- **Implementation steps:** (1) rewrite the `ARCHITECTURE.md` SNMP/metrics
  sections around the Go collector, noting telegraf is `profiles: [legacy]`;
  (2) fix the `preflight-configs.sh` header comment to name
  `fresh-install-integrity.yml`; (3) add a "built ≠ enabled" banner to
  `docs/design/tls-architecture.md` and `docs/runbooks/tls-mtls.md` stating the
  dormancy plainly; (4) leave `UPGRADE.md`/`STREAMING.md` alone and record why
  in this backlog's closing notes.
- **Files likely affected:** `docs/ARCHITECTURE.md`,
  `scripts/preflight-configs.sh` (comment only),
  `docs/design/tls-architecture.md`, `docs/runbooks/tls-mtls.md`.
- **Tests:** a doc-drift guard in `tests/test_architecture_contract.py`: if
  `docker-compose.yml` marks a service `profiles: [legacy]`, `ARCHITECTURE.md`
  must not present it as an active component.
- **Acceptance criteria:** the guard fails on a reintroduced legacy-service
  claim; grep for "Telegraf" in `ARCHITECTURE.md` returns only text that names
  it as legacy/not-running.
- **Rollout / rollback:** docs commit; revert.
- **Security impact:** removes a misleading map that would send an incident
  responder to the wrong collector.
- **Telemetry impact:** none. · **Tenant impact:** none.
- **Complexity:** S · **Owner:** platform eng · **Dependencies:** SEC-001.1 ·
  **Approval:** no.

### SEC-001.3 — Register the transport posture as an INVARIANT with an enforcement tier

- **Title:** Add transport posture to the invariants register
- **Objective:** Make "no unauthenticated datastore endpoint exists" a *tracked
  invariant with a tier*, not a preference.
- **Current problem:** `docs/audit/INVARIANTS.md` (enforcement ladder
  BUILD/GATE/RUNTIME/PROSE/NONE) has no transport-security section at all, so
  the entire gap sits at tier **NONE** — invisible to the mechanism the repo
  built specifically to catch this class ("an invariant that no gate enforces is
  a preference").
- **Affected paths:** n/a (register).
- **Prerequisites:** SEC-001.1.
- **Implementation steps:** add an "Transport security" section with one row per
  HLD §7 hop, each at tier **NONE** today, and each naming the SEC item that
  will raise it to **GATE** (validator) or **BUILD** (test). Add a tracker row
  in `docs/TRACKER.md` (4-column shape `# | Item | Pri | Status`, numeric id, so
  `scripts/tracker_staleness.py` stays live) pointing at this backlog.
- **Files likely affected:** `docs/audit/INVARIANTS.md`, `docs/TRACKER.md`.
- **Tests:** none beyond `tracker-ci`'s existing shape check.
- **Acceptance criteria:** every HLD §7 row has an INVARIANTS row with a named
  target tier and an owning SEC item.
- **Rollout / rollback:** docs commit; revert. **Security/telemetry/tenant
  impact:** none.
- **Complexity:** XS · **Owner:** platform eng · **Dependencies:** SEC-001.1 ·
  **Approval:** no.

---

## SEC-002 — Production fail-closed configuration validator

**Phase 0 · V1 · Complexity L · Owner: platform eng + security eng · Approval:
`.3` yes (changes production failure behaviour — HLD §11 decision 4).**

Objective: replace prose security requirements with an executable check that
runs at install, at API boot, and in CI, per HLD §6.4.

### SEC-002.1 — Validator core + rule set (warn-only)

- **Title:** Deployment-profile validator, warn-only
- **Objective:** One function that takes (profile, environment) and the resolved
  configuration and returns a list of violations, with the HLD §6.5 profile
  matrix as its rule table. Warn-only in this item — it must not be able to stop
  a boot yet.
- **Current problem:** Boot-time validation exists in the API and
  `scripts/preflight-install.py`/`preflight-configs.sh` exist, but nothing
  encodes the security matrix. `deployment/docker/.env` can (and does) omit
  every `TLS_*`/`SEAL_*` variable with no complaint, and
  `src/backend/tls_ca.go:20-22` documents that `TLS_INTERNAL_CA=true` without a
  seal provider stores the CA private key in plaintext — a foot-gun nothing
  currently detects.
- **Affected paths:** none at runtime (read-only evaluation).
- **Prerequisites:** SEC-001.1 (rules are expressed against inventory rows).
- **Implementation steps:**
  1. New Go package `src/backend/secpolicy/` (stdlib only; §6 dependency rules
     unchanged) exporting `Evaluate(profile, env) []Violation`, each violation
     carrying `{rule_id, severity, hop, evidence, remediation}`.
  2. Encode the HLD §6.5 matrix: plaintext transports, cert validation, secret
     sealing, legacy protocols, enforcement severity, per profile
     (`lab|development|staging|production`), profile read from a single
     `CORRELIX_PROFILE` env var defaulting to `lab` (never to `production` —
     defaulting to the strictest profile would break every existing lab install
     the moment this ships).
  3. Rules v1 (all derived from verified facts): Kafka listener must not be
     PLAINTEXT in production; OpenSearch `DISABLE_SECURITY_PLUGIN` must not be
     true; `sslmode=disable` prohibited; `TLS_INTERNAL_CA=true` requires
     `SEAL_PROVIDER`; `INGEST_TOKEN` must not be shared across more than one
     client identity; `gnmic` global `skip-verify` prohibited; `snmptrap`
     unknown-sender acceptance prohibited; any `accept ⊇ plaintext` requires an
     `exception` block with owner + expiry (HLD §6.3).
  4. Wire a **warn-only** call at API boot in `src/backend/main.go` (log
     structured warnings; return no error) and into `scripts/install.py`
     (print, exit 0).
- **Files likely affected:** `src/backend/secpolicy/` (new),
  `src/backend/main.go`, `scripts/install.py`.
- **Tests:** `src/backend/secpolicy/secpolicy_test.go` — one table case per
  rule, both directions (violating config produces exactly one violation with
  the right `rule_id`; compliant config produces none); a fixture for each of
  the four profiles; a **ratchet guard** (`secpolicy_rules_test.go`, modelled on
  `package_growth_guard_test.go`) asserting the rule count never *decreases*
  without an explicit fixture update, so a rule cannot be quietly deleted.
- **Acceptance criteria:** running the validator against the **current**
  `deployment/docker/.env` under `profile=production` emits violations for at
  minimum: Kafka plaintext, OpenSearch security disabled, Postgres
  `sslmode=disable`, Valkey unauthenticated, VM unauthenticated, shared
  `INGEST_TOKEN`, gnmic `skip-verify`. Under `profile=lab` it emits the same
  list as **warnings with declared-exception prompts**, not errors.
- **Rollout:** ships dormant-by-severity (warn). No stack behaviour changes.
- **Rollback:** revert; the boot call is a single line.
- **Security impact:** none yet — it only observes. Its value is that it makes
  the later fail-closed flip a one-line severity change rather than a rewrite.
- **Telemetry impact:** none. · **Tenant impact:** none; isolation tests unchanged.
- **Complexity:** L · **Owner:** platform eng · **Dependencies:** SEC-001.1 ·
  **Approval:** no (warn-only, explicitly permitted by HLD §12).

### SEC-002.2 — CI wiring + fixture corpus

- **Title:** Run the validator in CI against committed fixtures
- **Objective:** A pull request that regresses the security posture fails a
  merge-blocking job.
- **Current problem:** `.github/workflows/backend-ci.yml` gates build/vet/test/
  race/govulncheck/staticcheck/gosec/golangci-lint;
  `fresh-install-integrity.yml` gates install/config integrity. Neither knows
  anything about transport security.
- **Affected paths:** none.
- **Prerequisites:** SEC-002.1.
- **Implementation steps:** (1) commit `src/backend/secpolicy/testdata/`
  fixtures — one per profile, plus a "current lab reality" fixture derived from
  the real compose file; (2) add a `secpolicy` job to
  `.github/workflows/backend-ci.yml` running `go test ./secpolicy/...` plus a
  CLI evaluation of the production fixture that must produce **zero**
  violations; (3) add a compose-derived evaluation to
  `fresh-install-integrity.yml` so a compose change that reintroduces a
  plaintext listener is caught where compose is already parsed.
- **Files likely affected:** `.github/workflows/backend-ci.yml`,
  `.github/workflows/fresh-install-integrity.yml`,
  `src/backend/secpolicy/testdata/`, `scripts/preflight-install.py`.
- **Tests:** the job itself; plus a negative test that deliberately breaks the
  production fixture and asserts the job would fail (kept as a unit test, not a
  CI experiment).
- **Acceptance criteria:** an insecure production config **fails** in CI (this is
  the HLD §9 Phase 0 completion criterion).
- **Rollout / rollback:** CI-only; remove the job to roll back.
- **Security impact:** converts the posture from PROSE to **GATE** tier in
  `docs/audit/INVARIANTS.md`.
- **Telemetry impact:** none. · **Tenant impact:** none.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-002.1 ·
  **Approval:** no.

### SEC-002.3 — Flip production to fail-closed at boot and install

- **Title:** Boot refusal on production violations
- **Objective:** In `profile=production`, any severity-`error` violation refuses
  the boot and refuses the install.
- **Current problem:** Today a misconfigured production stack comes up happily
  and silently insecure. HLD §11 decision 4 recommends boot refusal and states
  the availability tradeoff explicitly.
- **Affected paths:** all — this is the enforcement switch for every hop.
- **Prerequisites:** SEC-002.2, and **owner sign-off on HLD §11 decision 4**.
- **Implementation steps:** (1) change the boot call in `src/backend/main.go`
  from warn to fatal when `CORRELIX_PROFILE=production`; (2) same in
  `scripts/install.py` (non-zero exit before `docker compose up`); (3) implement
  the lab bypass as an explicit profile value plus per-rule declared exceptions
  with owner + expiry (never a `--force` flag — an anonymous bypass is exactly
  what HLD §6.3 forbids); (4) emit an expiring-exception report so a bypass
  ages visibly.
- **Files likely affected:** `src/backend/main.go`, `src/backend/secpolicy/`,
  `scripts/install.py`, `docs/runbooks/` (new security runbook, SEC-024.2).
- **Tests:** `secpolicy_test.go` cases for fatal-vs-warn per profile; a boot
  test in `src/backend` asserting `newServer()` returns an error (not a panic,
  not a silent continue) on a production violation; an `install.py` test path in
  `scripts/tests/`.
- **Acceptance criteria:** a production stack with **any** `error` violation does
  not start, logs the `rule_id` + remediation, and the exit code is
  distinguishable from a crash.
- **Rollout:** staging first with the production profile; only then production.
  Requires that Phases 1–5 have actually closed the violations, or the stack
  will refuse to start — so this item **lands last within its dependency
  chain**, not when it is merely codeable.
- **Rollback:** set `CORRELIX_PROFILE=staging` (fail on new violations only) or
  revert the severity change; both are single-variable operations.
- **Security impact:** the single highest-leverage control in the programme.
- **Telemetry impact:** **indirect but real** — a refused boot stops all
  ingestion. That is the intended tradeoff and the reason for approval.
- **Tenant impact:** none; isolation tests must still pass.
- **Complexity:** M · **Owner:** owner-decision + platform eng ·
  **Dependencies:** SEC-002.2 · **Approval:** **yes** — HLD §11 decision 4 and
  it changes production failure behaviour.

---

# PHASE 1 — Public ingress + nginx→API mTLS

*HLD §9: Deps 0 · Risk med (edge) · Rollback revert the compose override, keep
:8000 until cutover · Telemetry none · Tenant none.*

---

## SEC-004 — Public ingress TLS

**Phase 1 · V1 · Complexity M · Owner: SRE + platform eng · Approval: `.2` yes.**

### SEC-004.1 — Promote the TLS front from lab override to a supported profile

- **Title:** Make the shipped TLS front a first-class, validated deployment mode
- **Objective:** The HTTPS edge that shipped 2026-08-03 (#145, commits
  `470456e8`, `877ea39a`) becomes a supported, tested configuration rather than
  an example file.
- **Current problem:** the TLS front exists as
  `deployment/docker/nginx/tls.conf.example` alongside
  `deployment/docker/nginx/certs/`, applied through a compose override; the
  primary `deployment/docker/nginx/default.conf:32` still `listen 8080` behind
  the published plaintext `:8000`. Nothing validates the TLS parameters on a
  fresh install.
- **Affected paths:** HLD §7 row 1 — Browser → nginx (HTTPS).
- **Prerequisites:** SEC-002.1.
- **Implementation steps:** (1) fold the example into a supported
  `deployment/docker/docker-compose.override.yml` profile (or a named compose
  profile) with cert paths from the installer `.env` contract; (2) teach
  `scripts/install.py` to provision or accept a cert (self-signed via
  `scripts/gen-dev-cert.sh` for lab; operator-supplied or ACME for production);
  (3) add TLS-parameter rules to `secpolicy` (TLS ≥1.2, HSTS present, no session
  tickets, PFS ciphers) validated against the rendered nginx config; (4) add the
  nginx config to `scripts/preflight-configs.sh` fresh-load checks (nginx is
  already an image pin there: `NGINX_IMG="nginx:1.27-alpine"`).
- **Files likely affected:** `deployment/docker/nginx/tls.conf.example`,
  `deployment/docker/nginx/default.conf`,
  `deployment/docker/docker-compose.override.yml`, `scripts/install.py`,
  `scripts/preflight-configs.sh`, `src/backend/secpolicy/`.
- **Tests:** `preflight-configs.sh` nginx fresh-load case; `secpolicy` unit
  cases for the TLS parameter rules; a `tests/smoke.sh` addition asserting the
  HTTPS front answers and presents the expected protocol/cipher floor.
- **Acceptance criteria:** a fresh `install.py` run produces a working HTTPS
  edge without manual file copying; the validator fails a config with TLS < 1.2,
  missing HSTS, or session tickets enabled.
- **Rollout:** lab → staging → production; the plaintext listener stays up
  throughout this item.
- **Rollback:** drop the override; `:8000` is still serving.
- **Security impact:** removes "the secure mode is an example file" — the class
  of gap where a control exists but no supported path reaches it (same class as
  `TLS_FEDERATED_BUNDLES`, SEC-003.2).
- **Telemetry impact:** none — the edge carries UI/API traffic, not ingestion.
- **Tenant impact:** none; isolation tests unchanged.
- **Complexity:** M · **Owner:** SRE · **Dependencies:** SEC-002.1 ·
  **Approval:** no (additive; the plaintext path is untouched).

### SEC-004.2 — Retire the plaintext `:8000` listener

- **Title:** Remove the plaintext edge after cutover
- **Objective:** Close T17 (insecure fallback / downgrade) by deleting the
  parallel plaintext front.
- **Current problem:** HLD §5 T17 rates this **HIGH**: `:8000` is published
  beside `:443`, so any client (or any misconfigured integration) can silently
  keep using the unencrypted path, and HSTS on the TLS front does not help a
  non-browser client.
- **Affected paths:** HLD §7 row 1.
- **Prerequisites:** SEC-004.1 **and** SEC-005.2 (nginx→api must already be
  mTLS, or removing the plaintext front just moves the plaintext one hop in).
- **Implementation steps:** (1) inventory every internal caller of `:8000`
  (`scripts/*.sh` health probes, `scripts/stack-watchdog.sh`, `tests/smoke.sh`,
  `tests/auth.sh`, the Postman collection, docs); (2) migrate them to the TLS
  front with the correct trust anchor; (3) add a `secpolicy` production rule
  prohibiting a plaintext published edge; (4) remove the port publication.
- **Files likely affected:** `deployment/docker/docker-compose.yml` (nginx
  ports), `scripts/stack-watchdog.sh`, `tests/smoke.sh`, `tests/auth.sh`,
  `tests/netops.postman_collection.json`, `README.md`, `docs/ARCHITECTURE.md`.
- **Tests:** `tests/smoke.sh` must pass with only the TLS front reachable; a
  `secpolicy` rule test; a watchdog dry-run (`scripts/stack-watchdog.sh --test`)
  proving the monitor still detects up/down after the port change — a watchdog
  that silently probes a dead port is worse than no watchdog (§16).
- **Acceptance criteria:** `:8000` is not published; every in-repo caller uses
  HTTPS; the watchdog still transitions correctly; the validator fails if the
  port is reintroduced.
- **Rollout:** publish a removal date first (HLD §9 Phase 1 completion criterion
  is "the plaintext listener has a removal date"), announce, then remove.
- **Rollback:** re-publish the port in compose (single line, no data migration).
- **Security impact:** removes the downgrade path entirely.
- **Telemetry impact:** none for device telemetry; **the watchdog and any
  operator scripts pointed at `:8000` will break if step (1) is incomplete** —
  that is an observability outage, so it is called out here explicitly.
- **Tenant impact:** none.
- **Complexity:** S · **Owner:** SRE · **Dependencies:** SEC-004.1, SEC-005.2 ·
  **Approval:** **yes** — changes a published listener and can break monitoring.

---

## SEC-005 — nginx → API mTLS

**Phase 1 · V1 · Complexity M · Owner: platform eng · Approval: yes (changes a
listener and a credential on the request path for every user).**

### SEC-005.1 — Enable the API mTLS listener with a migration accept-set

- **Title:** Turn on the built mTLS listener alongside plaintext
- **Objective:** nginx authenticates to the API with its SVID; the API accepts
  both plaintext and mTLS during the window (HLD §6.3 `accept` set).
- **Current problem:** every `proxy_pass` in
  `deployment/docker/nginx/default.conf` (:102, :121, :135, :148, :163, :326,
  :342) is `http://$up_api:8080` — plaintext, with **no authentication** of
  nginx to the API. The machinery to fix it is already written and dormant:
  `src/backend/tls_server.go` (mTLS listener, expiry/handshake/identity-reject
  metrics `netops_tls_cert_expiry_seconds`,
  `netops_tls_handshake_errors_total`, `netops_tls_identity_rejected_total` at
  :148-157), `src/backend/tls_ca.go` (mints the nginx client SVID on boot),
  `src/backend/tlsconfig/` (policy floor, `PeerPolicy` allowlist), and the
  enable sequence is documented in `docs/runbooks/tls-mtls.md`. It is off
  because `.env` sets no `TLS_*`.
- **Affected paths:** HLD §7 row 2 — nginx → api (**P0**).
- **Prerequisites:** SEC-003.1 (never enable `TLS_INTERNAL_CA` without the seal
  gate), SEC-003.2 (federation bundles reachable), SEC-003.3 (identity registry).
- **Implementation steps:** (1) set the `TLS_*` variables through
  `scripts/install.py` so they are part of the generated `.env` contract, not a
  manual edit; (2) add the `proxy_ssl_*` block from `docs/runbooks/tls-mtls.md`
  to `deployment/docker/nginx/default.conf` with the nginx SVID and the CA
  bundle mounted; (3) run the API with **both** listeners (plaintext + mTLS)
  during the window; (4) confirm the SAN allowlist rejects a wrong identity via
  `tlsconfig.PeerPolicy`.
- **Files likely affected:** `src/backend/main.go` (listener wiring),
  `src/backend/tls_server.go`, `deployment/docker/nginx/default.conf`,
  `deployment/docker/docker-compose.yml`, `scripts/install.py`.
- **Tests:** `src/backend/tls_server_test.go` — handshake success, wrong-SAN
  rejection increments `netops_tls_identity_rejected_total`, expired-cert
  rejection, hot reload via `tlsconfig/reload.go`; `tests/smoke.sh` browser-path
  smoke through nginx; an `org_isolation_test.go`-style run **unchanged** to
  prove authentication did not become authorization.
- **Acceptance criteria:** nginx→api handshakes succeed with the minted SVID; a
  client presenting a valid chain but a non-allowlisted SPIFFE ID is rejected
  and counted; every existing API test still passes over the plaintext listener.
- **Rollout:** lab → staging → production, plaintext listener retained.
- **Rollback:** unset the `TLS_*` variables and revert the nginx block; the
  plaintext listener is still bound, so rollback is a restart.
- **Security impact:** closes T12 (service impersonation) for the highest-traffic
  internal hop and puts the first real consumer on the PKI.
- **Telemetry impact:** none — this hop carries UI/API traffic only. Device
  telemetry does not traverse nginx→api.
- **Tenant impact:** none. **Design law (HLD §4): an mTLS peer is authenticated,
  not authorized for a tenant** — the isolation tests must pass unchanged, and
  no tenant decision may be derived from the peer certificate on this hop.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-003.1/.2/.3
  · **Approval:** **yes** — changes a listener and a credential.

### SEC-005.2 — Narrow the accept-set to mTLS only

- **Title:** Remove the plaintext API listener
- **Objective:** `accept: [mtls]`, no fallback.
- **Current problem:** while both listeners are bound, anything on the compose
  network can still reach the API unauthenticated — the migration lever must
  expire (HLD §10, "permanent plaintext migration listeners" is a rejected
  alternative).
- **Affected paths:** HLD §7 row 2.
- **Prerequisites:** SEC-005.1 running clean in staging; every internal caller
  of `http://api:8080` migrated. Verified callers today:
  `deployment/docker/vector-router/cx-secret-backend.sh:24` (`SEALING_API_URL`
  default `http://api:8080`) — so **SEC-018.1 must land first or this item
  breaks the sealing-key fetch and the router will refuse to start (exit 78).**
- **Implementation steps:** (1) confirm SEC-018.1 shipped; (2) drop the
  plaintext listener; (3) add a `secpolicy` production rule prohibiting it.
- **Files likely affected:** `src/backend/main.go`,
  `deployment/docker/docker-compose.yml`, `src/backend/secpolicy/`.
- **Tests:** an integration test asserting a plaintext dial to the API is
  refused; re-run `tests/smoke.sh` and the sealed-fields path from
  `tests/test_secret_rotation.py`.
- **Acceptance criteria:** no plaintext dial to the API succeeds from anywhere
  on the compose network; the router still starts and still fetches keys.
- **Rollout:** after a full staging soak.
- **Rollback:** re-bind the plaintext listener (restart).
- **Security impact:** closes the internal anonymous-API surface.
- **Telemetry impact:** **at risk** — if any ingest or sealing caller was
  missed, that lane fails closed. `cx-secret-backend.sh` fails the whole router,
  which stops **all** routed telemetry. Ordering behind SEC-018.1 is mandatory.
- **Tenant impact:** none.
- **Complexity:** S · **Owner:** platform eng · **Dependencies:** SEC-005.1,
  SEC-018.1 · **Approval:** **yes** — removes a listener and can drop telemetry.

---

# PHASE 2 — PKI + workload identity foundation

*HLD §9: Deps 0 · Risk med (CA custody) · Rollback dual-root window · Telemetry
none · Tenant none. Done when every service has an SVID and a trust bundle, the
root is offline, and `TLS_FEDERATED_BUNDLES` is reachable from compose.*

---

## SEC-003 — PKI custody + workload identity fabric

**Phase 2 · V1 = `.1`/`.2`/`.3` only · Complexity M (v1) / XL (full) · Owner:
security eng + platform eng · Approval: `.1`, `.4`, `.5` yes.**

> **Owner steer applied (§0a, HLD §11 decisions 1 and 2).** V1 uses the
> **existing in-process internal CA** — `src/backend/tls_ca.go` +
> `src/backend/internalca/` already auto-issue SPIFFE-SAN leaves and already run
> a TTL/2 re-issue loop, so v1 adds **no new PKI component and no new
> operational dependency**: no SPIRE, no Vault PKI, no cert-manager, no offline
> ceremony. **Two trust domains in v1** — public/enterprise (the nginx server
> cert) and `correlix.workload`. The mandatory v1 work is exactly `.1` (refuse
> to boot the CA unsealed) and `.2` (make `TLS_FEDERATED_BUNDLES` reachable),
> plus `.3` (extend issuance from two SVIDs to every service). `.4` (offline
> root) and `.5` (device domain) are written in full below and execute in
> **Phase 2+**; the SPIFFE identity strings are unchanged by that deferral, so
> both remain drop-in later.

### SEC-003.1 — Refuse to boot the internal CA unsealed

- **Title:** `TLS_INTERNAL_CA` requires `SEAL_PROVIDER`
- **Objective:** Make the documented foot-gun impossible.
- **Current problem:** `src/backend/tls_ca.go:20-22` states it plainly — "When
  the Vault is also dormant the CA key is stored plaintext (passthrough) —
  turning on `SEAL_PROVIDER=swtpm` seals it." Nothing enforces that pairing, so
  the first operator who follows `docs/runbooks/tls-mtls.md` and sets
  `TLS_INTERNAL_CA=true` writes a **plaintext CA private key** to the kv store.
  HLD §5 T11 rates CA compromise **MED-HIGH** for exactly this reason. The seal
  sidecar exists (`deployment/docker/swtpm-sidecar/`, compose service
  `secrets-seal` under `profiles: ["seal"]` at docker-compose.yml:1686-1699) but
  is not required.
- **Affected paths:** key management (HLD §4 boundary ⑨); indirectly every
  workload hop.
- **Prerequisites:** SEC-001.1.
- **Implementation steps:** (1) in `src/backend/tls_ca.go`, return an error at
  bootstrap when `TLS_INTERNAL_CA=true` and the vault is in passthrough mode —
  in `production`/`staging` profiles this is fatal, in `lab` it is a loud warning
  plus a declared exception (SEC-002.1 vocabulary); (2) add the matching
  `secpolicy` rule so the refusal is also caught **before** boot, at install and
  in CI; (3) make `scripts/install.py` enable the `seal` compose profile
  whenever it seeds `TLS_INTERNAL_CA`.
- **Files likely affected:** `src/backend/tls_ca.go`,
  `src/backend/internal/vault/`, `src/backend/secpolicy/`, `scripts/install.py`,
  `deployment/docker/docker-compose.yml` (profile activation).
- **Tests:** `src/backend/tls_ca_test.go` — CA bootstrap with a passthrough
  vault returns an error under production/staging and succeeds with a warning
  under lab; a test asserting no plaintext CA key file is written on the refusal
  path (the failure mode is a key on disk, so assert on the *artifact*, not just
  the error); `secpolicy` rule test.
- **Acceptance criteria:** it is impossible to end up with a plaintext CA key in
  any profile other than `lab`, and in `lab` the exception is recorded with an
  owner and expiry.
- **Rollout:** ship with the refusal active before anyone enables the CA — this
  must precede SEC-005.1.
- **Rollback:** revert; but note that rolling back re-opens the foot-gun, so the
  rollback is "disable `TLS_INTERNAL_CA`", not "allow unsealed".
- **Security impact:** closes T11 at its root cause.
- **Telemetry impact:** none. · **Tenant impact:** none.
- **Complexity:** M · **Owner:** security eng · **Dependencies:** SEC-001.1 ·
  **Approval:** **yes** — changes production failure behaviour (a boot refusal).

### SEC-003.2 — Make `TLS_FEDERATED_BUNDLES` reachable from compose

- **Title:** Close the unreachable-config defect
- **Objective:** A shipped Go capability must have a supported configuration
  surface.
- **Current problem:** `TLS_FEDERATED_BUNDLES` is parsed and enforced in Go —
  `src/backend/tls_server.go:81,181,196` and
  `src/backend/backend_client.go:42`, documented at
  `docs/design/tls-architecture.md:144` — and appears **nowhere** in
  `deployment/docker/docker-compose.yml`. Verified by repo-wide grep: the only
  non-Go hits are documentation. The federation-impersonation control it
  implements is therefore unreachable through the supported surface.
- **Affected paths:** every mTLS hop's trust anchoring (multi-region / partner).
- **Prerequisites:** SEC-001.1.
- **Implementation steps:** (1) add `TLS_FEDERATED_BUNDLES: ${TLS_FEDERATED_BUNDLES:-}`
  to the `api` service environment; (2) have `scripts/install.py` write the (empty)
  variable into the `.env` template so `preflight-install.py`'s "every required
  compose var is provisioned" check covers it; (3) add a `secpolicy` rule that
  a non-empty value must reference files that exist and parse.
- **Files likely affected:** `deployment/docker/docker-compose.yml`,
  `scripts/install.py`, `src/backend/secpolicy/`.
- **Tests:** `preflight-install.py` coverage (automatic once declared);
  `src/backend/tls_server_test.go` already covers `parseFederationBundles` —
  extend with a malformed-entry case asserting the boot fails rather than
  silently ignoring the bundle.
- **Acceptance criteria:** setting a federated bundle in `.env` takes effect
  without editing compose; a malformed value fails loudly.
- **Rollout / rollback:** additive compose change; revert is one line.
- **Security impact:** restores an implemented control to reachability. Low
  effort, and it is the exemplar of the "built but unreachable" class the
  inventory exists to find.
- **Telemetry impact:** none. · **Tenant impact:** none.
- **Complexity:** XS · **Owner:** platform eng · **Dependencies:** SEC-001.1 ·
  **Approval:** no (declaring an empty variable changes nothing at runtime).

### SEC-003.3 — Workload identity registry (SVID for every service)

- **Title:** Stable SPIFFE identities and issuance for all workloads
- **Objective:** Every service in HLD §7 has a distinct, non-wildcard SVID, a
  trust bundle, and a documented Compose↔k8s identity mapping (HLD §6.2), so
  later epics can reference identities instead of inventing them.
- **Current problem:** `src/backend/tls_ca.go` mints exactly **two** SVIDs today
  (api server, nginx client — the `tls_ca.go` bootstrap comment describes
  precisely that scope). Kafka, OpenSearch, ClickHouse, VictoriaMetrics,
  Postgres, Valkey, vector-aggregator, vector-router, goflow2, gnmic,
  correlation, and prober have **no identity at all**; the only thing resembling
  a service credential is one shared `INGEST_TOKEN` (compose lines 341, 438,
  487, 1109, 1565 across `gnmic`, `vector-aggregator`, `vector-router`, `api`,
  `prober`, plus the Python producers in
  `deployment/docker/cloud-ingest/ingest_auth.py`).
- **Affected paths:** every workload row in HLD §7.
- **Prerequisites:** SEC-003.1, SEC-003.2.
- **Implementation steps:**
  1. Define the identity table in the LLD and encode it as data:
     `spiffe://correlix.workload/ns/<ingress|app|ingestion|streaming|storage|identity|ops>/sa/<service>`,
     one row per compose service, with the cert file path it mounts.
  2. Extend `src/backend/tls_ca.go` issuance from two hardcoded SVIDs to the
     table, keeping the existing TTL/2 re-issue loop.
  3. Write the material to a per-service mount path and add the mounts to
     `deployment/docker/docker-compose.yml`; issue on the API's boot (the
     existing bootstrap point) so no new service is required.
  4. Add the identity table to `secpolicy`: no wildcards, no shared identity
     across two services, every service in compose must have a row.
  5. Document the future k8s ServiceAccount mapping (input to SEC-022) without
     building it.
- **Files likely affected:** `src/backend/tls_ca.go`,
  `src/backend/internalca/ca.go`, `src/backend/tlsconfig/policy.go`,
  `deployment/docker/docker-compose.yml`, `scripts/install.py`,
  `src/backend/secpolicy/`.
- **Tests:** `src/backend/tls_ca_test.go` — issuance for every table row, SAN
  contents (URI SAN + the DNS names actually dialled), TTL/2 renewal,
  no-wildcard assertion; `internalca/ca_test.go` extension; a **ratchet guard**
  asserting the identity table covers every compose service (fails when a
  service is added without an identity).
- **Acceptance criteria:** every compose service has exactly one SVID; no two
  services share one; a new service without a row fails CI.
- **Rollout:** issuance is additive — certs are written and unused until each
  consuming epic switches over. This decoupling is what makes Phases 3–5
  parallelisable.
- **Rollback:** stop issuing (revert); no consumer breaks because consumers are
  switched on per-epic.
- **Security impact:** closes T3/T9/T12 structurally by making per-service
  attribution possible at all.
- **Telemetry impact:** none in this item (issuance only, no enforcement).
- **Tenant impact:** none. Workload identity is **not** a tenant boundary
  (HLD §4 design law).
- **Complexity:** L · **Owner:** platform eng + security eng ·
  **Dependencies:** SEC-003.1, SEC-003.2 · **Approval:** no (issuance is
  additive and enforces nothing until a consuming epic is approved).

### SEC-003.4 — Offline root + online intermediates — **PHASE 2+ (deferred by owner steer)**

> Kept in full. HLD §11 decision 2 is resolved **for v1** as "keep the existing
> in-process CA, sealed" (§0a). This item executes in Phase 2+, when a customer
> or compliance requirement demands an offline root. Nothing in v1 blocks it:
> the identity strings and the trust-bundle mechanism are unchanged, so this is
> an additive migration rather than a rework.

- **Title:** Move the root out of the process
- **Objective:** Implement HLD §6.1 — an air-gapped root signing a Workload
  Intermediate, a Device Intermediate, and an Operator Intermediate.
- **Current problem:** `src/backend/tls_ca.go` load-or-creates a **single
  in-process root** with a 10-year validity (`caValidity = 10 * 365 * 24 * time.Hour`)
  and mints leaves directly from it. A compromise of the API process is a
  compromise of the root. HLD §11 decision 2 flags this and recommends offline
  root + online intermediates, at the cost of a manual ceremony.
- **Affected paths:** key management (⑨); all workload and device hops.
- **Prerequisites:** SEC-003.3, and **owner sign-off on HLD §11 decision 2**.
- **Implementation steps:** (1) support an *imported* intermediate — the API
  loads a signing intermediate + chain rather than creating a root; (2) keep
  self-created-root mode for `lab` only, gated by profile; (3) document the
  offline ceremony (SEC-024.2) including HSM/offline media handling; (4) add a
  `secpolicy` rule that production must not run a self-created root.
- **Files likely affected:** `src/backend/tls_ca.go`,
  `src/backend/internalca/ca.go`, `src/backend/tlsconfig/trust.go`,
  `docs/runbooks/` (new ceremony runbook), `src/backend/secpolicy/`.
- **Tests:** `internalca/ca_test.go` — issue from an imported intermediate,
  chain verification to the offline root, refusal to issue when the chain is
  incomplete; `tls_ca_test.go` profile-gating test.
- **Acceptance criteria:** production can run with no root private key present
  anywhere in the running system; leaves still verify.
- **Rollout:** dual-trust window — both roots in the bundle while leaves migrate
  (this is the same mechanism SEC-019.2 uses for rotation).
- **Rollback:** the dual-trust window is the rollback; revert to the previous
  anchor before narrowing.
- **Security impact:** converts T11 from "process compromise = CA compromise" to
  "process compromise = one intermediate, revocable by expiry".
- **Telemetry impact:** none if the dual-trust window is respected; **loss of
  every mTLS hop** if the bundle is narrowed early.
- **Tenant impact:** none.
- **Complexity:** L · **Owner:** owner-decision + security eng ·
  **Dependencies:** SEC-003.3 · **Approval:** **yes** — HLD §11 decision 2.

### SEC-003.5 — Device trust domain (`correlix.device`) — **PHASE 2+ (deferred by owner steer)**

> Kept in full. HLD §11 decision 1 (certs vs PSK vs both) is **deferred with the
> device lanes**: v1 scope is intra-stack + ingress, so no device credential is
> built. The design below stands unchanged and is the entry point to Phase 2+
> (it is the hard prerequisite for SEC-013.3, SEC-014.2 and SEC-016.2).

- **Title:** Separate device intermediate and device identity format
- **Objective:** Issue `spiffe://correlix.device/tenant/<tenant_id>/kind/<device|vantage|gateway>/id/<device_id>`
  from a **separate** intermediate, so a device compromise cannot mint a
  workload identity (HLD §6.1 rationale, ADR-SEC-002).
- **Current problem:** no device identity exists in any form. Device tenancy is
  re-derived server-side from `device_tenant.csv` (see the enrichment comment in
  `src/correlation/main.py:301-307`, which states that a party who can reach the
  unauthenticated syslog port and knows a victim's real device hostname "still
  lands in that tenant" and that closing it "needs transport authentication").
- **Affected paths:** HLD §7 device rows — syslog, gNMI, SNMP, remote vantage.
- **Prerequisites:** SEC-003.4, and **owner sign-off on HLD §11 decision 1**
  (certs vs PSK vs both) and decision 7 (whether device lanes are in v1 scope).
- **Implementation steps:** (1) add the device intermediate + issuance API;
  (2) implement the **binding rule**: the tenant inside a device SVID is
  *checked against* the registered device record and a mismatch is rejected —
  never trusted, never auto-created (HLD §6.2); (3) define per-device PSK as the
  parallel credential for peers that cannot do mTLS, reusing the existing
  envelope custody (`src/backend/internal/vault/`) and the per-connector webhook
  HMAC pattern named in `docs/design/transport-encryption-2026-08-04.md` §2.3.
- **Files likely affected:** `src/backend/internalca/ca.go`,
  `src/backend/tls_ca.go`, a new device-credential store under
  `src/backend/`, `src/backend/internal/vault/`.
- **Tests:** issuance tests; **a cross-tenant test modelled on
  `src/backend/org_isolation_test.go`** proving a device cert carrying tenant A
  cannot register, publish, or read as tenant B, and that an unknown device_id
  is rejected rather than auto-created; a test that a device-domain cert is
  refused by a workload-domain `PeerPolicy` and vice versa.
- **Acceptance criteria:** device and workload intermediates cannot sign for
  each other's trust domain; a tenant mismatch is a rejection with an audit
  event; no auto-provisioning path exists.
- **Rollout:** issuance only; consumed by SEC-014/016/013.3.
- **Rollback:** stop issuing; device lanes stay legacy.
- **Security impact:** closes T2 (device impersonation) and is the only
  mechanism that can bind tenancy to transport for syslog.
- **Telemetry impact:** none in this item (issuance only).
- **Tenant impact:** **this is the one item that deliberately touches tenancy.**
  The cert carries a tenant claim; it must remain a *checked claim*, never an
  authorization grant. Isolation tests must be extended, not merely preserved.
- **Complexity:** L · **Owner:** owner-decision + security eng ·
  **Dependencies:** SEC-003.4 · **Approval:** **yes** — HLD §11 decisions 1 and 7.

---

# PHASE 3 — Kafka TLS + authn + ACLs

*HLD §9: Deps 2 · Risk **high** (the bus is the spine) · Rollback dual listener
until the deadline · **Telemetry at risk — this is the phase that can drop
data** · Tenant none directly.*

---

## SEC-006 — Kafka transport encryption + authentication

**Phase 3 · V1 · Complexity XL · Owner: platform eng + SRE · Approval: yes (every
item here can drop telemetry).**

> **Owner steer applied — HLD §11 decision 3 is RESOLVED: mTLS using the same
> internal CA.** SASL_SSL/SCRAM is rejected for v1: it would introduce a second
> credential store to provision, rotate and operate, for no improvement in
> transport security over certificates the CA already issues automatically.
> Every client below therefore uses the SVID it receives from SEC-003.3 — no new
> secret material, no new rotation mechanism.

### SEC-006.1 — Dual listener (PLAINTEXT + SSL) on the broker

- **Title:** Add an authenticated Kafka listener without removing the old one
- **Objective:** Stand up mTLS on the broker while every existing client keeps
  working (the HLD §6.3 accept-set applied to a broker).
- **Current problem:** `deployment/docker/docker-compose.yml:207-210` —
  `KAFKA_LISTENERS: "PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093"`,
  `KAFKA_ADVERTISED_LISTENERS: "PLAINTEXT://kafka:9092"`,
  `KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: "PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT"`.
  Combined with `KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"` (:217), anything that
  can route to the compose network can create topics and produce to any lane.
- **Affected paths:** HLD §7 rows `vector-* → Kafka`, `goflow2 → Kafka`,
  `correlation → Kafka`.
- **Prerequisites:** SEC-003.3 (broker + client SVIDs). HLD §11 decision 3 is
  **resolved — mTLS with the internal CA** (epic header); no SASL work.
- **Implementation steps:** (1) add an `SSL://0.0.0.0:9094` listener with the
  broker SVID and the workload trust bundle; (2) mount the material; (3) keep
  `BROKER_URLS` as the single resolution point for every client (compose already
  routes all clients through `${BROKER_URLS:-kafka:9092}` — :393, :431, :481,
  :739, :972 — which is exactly the seam that makes a staged cutover possible);
  (4) turn **off** `KAFKA_AUTO_CREATE_TOPICS_ENABLE` in the same change, since
  an authenticated bus with auto-create is still an injection surface, and
  ensure `kafka-init` (compose :247) creates every required topic explicitly.
- **Files likely affected:** `deployment/docker/docker-compose.yml`,
  `scripts/install.py` (`.env` contract for the new URL + cert paths),
  `scripts/preflight-configs.sh` (broker config fresh-load check).
- **Tests:** an integration test that both listeners accept a produce/consume
  round-trip; a topic-existence test proving `kafka-init` creates every topic
  the pipeline uses (guards against the auto-create removal silently dropping a
  lane); `secpolicy` rule that production must not expose a PLAINTEXT listener.
- **Acceptance criteria:** both listeners serve; every topic in the pipeline
  exists without auto-create; no client has changed yet.
- **Rollout:** broker-only change, clients untouched.
- **Rollback:** remove the SSL listener; re-enable auto-create if a topic was
  missed.
- **Security impact:** creates the authenticated path; closes nothing yet.
- **Telemetry impact:** **at risk from the auto-create change specifically** — a
  topic that was being auto-created and is not in `kafka-init` will silently
  stop accepting writes. This is the single most likely way to lose data in this
  epic, so the topic-existence test is mandatory, not optional.
- **Tenant impact:** none directly. Note that Kafka carries multi-tenant
  telemetry; transport security here is **not** the tenant boundary (that stays
  at the storage layer).
- **Complexity:** L · **Owner:** platform eng · **Dependencies:** SEC-003.3 ·
  **Approval:** **yes** — changes a listener and can drop telemetry.

### SEC-006.2 — Per-client cutover to the authenticated listener

- **Title:** Move every Kafka client onto mTLS, one at a time
- **Objective:** Each producer/consumer switches to `SSL://kafka:9094` with its
  own SVID, with lag monitored across the switch.
- **Current problem:** the clients are heterogeneous and include two that are
  not Go — `goflow2` (compose command flags, `kafka://` transport per
  `deployment/docker/goflow2/goflow2.yaml:21-27`), Vector (`deployment/docker/vector/vector.yaml`
  kafka sinks at :990-1195), the Python correlation consumer
  (`KAFKA_BOOTSTRAP` at compose :972), and `kafka-exporter` (compose :739).
  HLD §11 decision 3 names this cost explicitly ("every client must handle
  certs, including goflow2 and Python").
- **Affected paths:** HLD §7 Kafka rows.
- **Prerequisites:** SEC-006.1.
- **Implementation steps:** per client, in this order (least → most
  loss-sensitive): `kafka-exporter` (metrics only) → `correlation` consumer →
  `vector-router` consumer → `vector-aggregator` producer → `goflow2` producer.
  For each: configure certs, restart, verify produce/consume, verify **consumer
  lag returns to baseline**, verify no dead-letter growth
  (`CORR_DLQ_DIR` on correlation, `misrouted_flows_deadletter`/`deadletter_encoded`
  in `vector.yaml`), then proceed.
- **Files likely affected:** `deployment/docker/docker-compose.yml`,
  `deployment/docker/vector/vector.yaml`,
  `deployment/docker/vector-router/vector.yaml`, `src/correlation/main.py`
  (consumer config), `deployment/docker/goflow2/` + the goflow2 compose
  `command:` (**note: `goflow2.yaml` is NOT mounted — its own header at :3-11
  says the compose `command:` is authoritative; changing the YAML alone does
  nothing**).
- **Tests:** `tests/test_ingest_contract.py` end-to-end after each cutover;
  a migration-continuity test asserting **no loss, no duplicates, no
  out-of-order** across the switch (HLD §9 Phase 3 test requirement);
  `src/backend/bus_producer_failure_test.go` (already covers producer failure
  surfacing) extended for a TLS handshake failure.
- **Acceptance criteria:** every client authenticated; lag baseline restored;
  zero dead-letter growth attributable to the cutover.
- **Rollout:** one client per change window, never batched.
- **Rollback:** point the client's `BROKER_URLS` back at `kafka:9092`; the
  plaintext listener is still bound until SEC-006.3.
- **Security impact:** closes T5 (unauthorized consumption) once complete.
- **Telemetry impact:** **high risk, per client.** Flows (`goflow2`, UDP source,
  no upstream buffer) are the least recoverable — do them last, and accept that
  a failed cutover loses flow records for the window.
- **Tenant impact:** none; isolation tests must still pass.
- **Complexity:** XL · **Owner:** platform eng + SRE · **Dependencies:**
  SEC-006.1 · **Approval:** **yes** — can drop telemetry.

### SEC-006.3 — Remove the PLAINTEXT listener

- **Title:** Close the bus
- **Objective:** `KAFKA_LISTENERS` carries no PLAINTEXT entry.
- **Current problem:** while it is bound, SEC-006.2 has bought encryption but
  not exclusion.
- **Prerequisites:** SEC-006.2 complete and soaked; SEC-007.1 ACLs authored.
- **Implementation steps:** remove the listener + protocol map entry; add the
  `secpolicy` production rule; publish the deadline first (HLD §10 forbids
  permanent migration listeners).
- **Files likely affected:** `deployment/docker/docker-compose.yml`,
  `src/backend/secpolicy/`.
- **Tests:** a test asserting a plaintext produce attempt is refused; full
  `tests/test_ingest_contract.py` pass.
- **Acceptance criteria:** no plaintext produce or consume succeeds.
- **Rollout:** after the announced deadline. **Rollback:** re-add the listener.
- **Security impact:** completes T4/T5 closure at the transport layer.
- **Telemetry impact:** **any missed client stops producing immediately.**
- **Tenant impact:** none.
- **Complexity:** S · **Owner:** platform eng · **Dependencies:** SEC-006.2 ·
  **Approval:** **yes**.

---

## SEC-007 — Kafka topic + consumer-group ACLs

**Phase 3 · V1 · Complexity L · Owner: platform eng + security eng · Approval:
yes.** *(Same-CA mTLS identities from SEC-006; ACLs name those identities.)*

### SEC-007.1 — Author and apply the ACL matrix (permissive mode)

- **Title:** Per-identity topic ACLs with `allow.everyone.if.no.acl.found=true`
- **Objective:** Encode HLD §7's `authorization` column as real ACLs, observing
  denials before enforcing them.
- **Current problem:** there are **no ACLs**; `allow.everyone.if.no.acl.found`
  is at its permissive default and no authorizer is configured. HLD §5 T4 rates
  topic injection **HIGH**. The application layer's only guard was a topic
  **prefix** check, which `src/backend/collectors/ingest_auth.go:17-24`
  describes as the defect it was written to close: "the bus bridge enforced only
  that the requested topic starts with `netops.` — a topic-prefix check, not an
  identity check".
- **Affected paths:** HLD §7 Kafka rows (`produce`/`consume` sets).
- **Prerequisites:** SEC-006.2 (identities must exist on the wire before ACLs
  can name them).
- **Implementation steps:** (1) configure the standard KRaft authorizer;
  (2) author ACLs from the identity table: `vector-aggregator` produces
  `netops.syslog|snmptrap|probes|metrics|applogs|deadletter|bus`,
  `goflow2` produces **only** `netops.flows`, `vector-router` consumes,
  `correlation` consumes only, `kafka-exporter` describes only; (3) scope
  consumer groups per identity; (4) keep `allow.everyone.if.no.acl.found=true`
  in this item so a missing ACL logs rather than drops.
- **Files likely affected:** `deployment/docker/docker-compose.yml`,
  a new ACL definition file under `deployment/docker/` applied by the existing
  `kafka-init` service, `scripts/install.py`.
- **Tests:** an integration test per identity asserting the allowed operation
  succeeds and the forbidden one is **denied** (e.g. goflow2's identity cannot
  produce to `netops.syslog`); a consumer-group scoping test.
- **Acceptance criteria:** every identity has an ACL; denial tests pass; no
  production traffic is denied (because the fallback is still permissive).
- **Rollout:** apply, then watch denial metrics for a full retention window
  (`BUS_RETENTION_MS` default 259200000 = 3 days) before SEC-007.2.
- **Rollback:** delete the ACLs.
- **Security impact:** builds the matrix; enforces nothing yet.
- **Telemetry impact:** none in permissive mode — that is the point of splitting
  this item.
- **Tenant impact:** none. ACLs are per-**service**, never per-tenant; tenant
  scoping stays in storage.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-006.2 ·
  **Approval:** **yes** — changes broker policy.

### SEC-007.2 — Flip `allow.everyone.if.no.acl.found=false`

- **Title:** Default-deny on the bus
- **Objective:** HLD §9 Phase 3 completion criterion.
- **Prerequisites:** SEC-007.1 with a clean denial window; SEC-006.3.
- **Implementation steps:** flip the setting; add the `secpolicy` production
  rule; keep the denial metric alerting live from SEC-020.
- **Files likely affected:** `deployment/docker/docker-compose.yml`,
  `src/backend/secpolicy/`.
- **Tests:** an unauthorized identity is denied; all authorized lanes still
  round-trip in `tests/test_ingest_contract.py`.
- **Acceptance criteria:** an identity with no ACL can do nothing.
- **Rollout:** after the observation window. **Rollback:** flip back to `true`
  (a single broker setting; a restart).
- **Security impact:** closes T3/T4 fully.
- **Telemetry impact:** **any lane whose ACL was missed stops immediately.** The
  observation window in SEC-007.1 is the mitigation and must not be skipped.
- **Tenant impact:** none.
- **Complexity:** XS · **Owner:** platform eng · **Dependencies:** SEC-007.1 ·
  **Approval:** **yes**.

---

# PHASE 4 — Datastores

*HLD §9: Deps 2 · Risk high (OpenSearch security bootstrap is invasive) ·
Rollback per-store, staged · Telemetry at risk for OS/CH writes · **Tenant: must
re-prove isolation under new auth.** Done when no unauthenticated datastore
endpoint exists anywhere.*

> **Owner steer applied to this whole phase (§0a): TLS + the simplest sufficient
> native authentication per store.** One scoped service user is enough wherever
> it is enough — do **not** build an elaborate per-client role matrix for
> completeness. Where an epic below sketches per-identity roles, the v1
> instruction is: implement the smallest set that (a) removes anonymous access
> and (b) gives per-service attribution. **ClickHouse row policies and Postgres
> FORCE-RLS stay exactly as they are** — they are the tenant boundary, they are
> already the strongest control in the product, and the job of these epics is
> *to not break them* (SEC-009.2 and SEC-011.2 exist for precisely that).

---

## SEC-008 — OpenSearch Security plugin (authentication + roles)

**Phase 4 · V1 · Complexity XL · Owner: platform eng + security eng · Approval:
yes.** *(The one irreducible XL in v1 — the plugin bootstrap is invasive by
nature and this is the largest unauthenticated surface in the product.)*

### SEC-008.1 — Enable the security plugin with TLS and a bootstrapped role model

- **Title:** Turn on OpenSearch authentication
- **Objective:** Remove the single largest unauthenticated surface in the stack.
- **Current problem:** `deployment/docker/docker-compose.yml:538` —
  `DISABLE_SECURITY_PLUGIN: "true"` with the comment "dev default; flip for prod
  and add certs". Every client dials plaintext with no credential:
  `OPENSEARCH_URL: http://opensearch:9200` on `opensearch-init` (:571),
  `OPENSEARCH_HOSTS: '["http://opensearch:9200"]'` on OpenSearch Dashboards
  (:600), `"http://opensearch:9200"` on correlation (:973), and the Go client in
  `src/backend/logs.go:393` via `backendHTTPClient`. HLD §5 T14 rates this
  **CRITICAL**: every tenant's logs are readable by anything on the network.
- **Affected paths:** HLD §7 rows `api → OpenSearch` (**P0**),
  `vector-router → OpenSearch`, plus OSD and `opensearch-init`.
- **Prerequisites:** SEC-003.3, SEC-002.1.
- **Implementation steps:** (1) remove `DISABLE_SECURITY_PLUGIN`, provide node
  and admin certs from the workload intermediate; (2) author `internal_users`,
  `roles`, and `roles_mapping` as committed config. **Owner steer: keep this
  minimal** — one user per client identity (api, vector-router, correlation,
  opensearch-init, OSD) scoped to the index patterns it actually touches, and
  nothing more. Do **not** model per-tenant OpenSearch roles: tenant scoping is
  per-tenant indices + `osTenantFilter` in the application and it stays there;
  (3) run `securityadmin` from
  `opensearch-init` (the service already exists and already runs post-health
  bootstrap); (4) note the slim image (`deployment/docker/opensearch/Dockerfile`,
  flattened for #148) **must retain the security plugin** — verify the trim did
  not remove it before assuming it is available.
- **Files likely affected:** `deployment/docker/docker-compose.yml`,
  `deployment/docker/opensearch/Dockerfile`,
  `deployment/docker/opensearch/` (new security config),
  `scripts/bootstrap-opensearch.sh`, `deployment/docker/opensearch/apply-ism.sh`,
  `scripts/install.py` (credential seeding).
- **Tests:** an integration test that an anonymous request to `:9200` is refused;
  per-role tests that each identity can do exactly its operations;
  `scripts/preflight-configs.sh` addition for the security config;
  `tests/test_ingest_contract.py` full pass.
- **Acceptance criteria:** anonymous access returns 401; every in-stack client
  authenticates; ISM policies and index templates still apply.
- **Rollout:** lab → staging → production, with a full reindex/read smoke at
  each step. This is the most invasive item in Phase 4 (HLD §9 says so).
- **Rollback:** re-set `DISABLE_SECURITY_PLUGIN: "true"` and restart. Data is
  unaffected; only the access path changes.
- **Security impact:** closes T14 and T5 for the log store; also closes T16 for
  OSD (HLD §7 last row wants OSD security on).
- **Telemetry impact:** **high risk.** If `vector-router`'s OpenSearch sink
  credential is wrong, **all** app-log and syslog indexing stops. Note the known
  gotcha class here: OpenSearch indexing failures in this stack have historically
  been silent (the dotted-key `.label` mapping conflict that dropped all app
  logs). Assert on **document counts**, not on "no errors in the log".
- **Tenant impact:** **this is a tenant-critical item.** OpenSearch isolation is
  per-tenant indices + `osTenantFilter`. Adding roles must not become a second,
  competing tenant mechanism — the role model scopes *services*, and the tenant
  filter stays in the application. All existing isolation tests must pass
  unchanged.
- **Complexity:** XL · **Owner:** platform eng · **Dependencies:** SEC-003.3 ·
  **Approval:** **yes** — credentials, listener, and telemetry risk.

### SEC-008.2 — Client cutover and mTLS for the API path

- **Title:** Move every OpenSearch client to authenticated HTTPS
- **Objective:** Per HLD §7, `api → OpenSearch` becomes HTTPS + mTLS mapped to
  an OS role.
- **Current problem:** the Go path already routes through
  `src/backend/backend_client.go` (`backendHTTPClient`, 14 call sites incl.
  `logs.go:393`, `search_unified.go`), which **already supports mTLS** and
  explicit mesh-CA roots — it is dormant only because the env is unset. The
  Python and Vector paths have no such seam.
- **Affected paths:** HLD §7 `api → OpenSearch`, `vector-router → OpenSearch`.
- **Prerequisites:** SEC-008.1.
- **Implementation steps:** (1) set the backend-mTLS variables so
  `backendHTTPClient` picks up the SVID (no Go code change expected — verify,
  do not assume); (2) configure the `vector-router` OpenSearch sink with TLS +
  credential; (3) configure correlation's client; (4) configure OSD.
- **Files likely affected:** `deployment/docker/docker-compose.yml`,
  `deployment/docker/vector-router/vector.yaml`, `src/correlation/main.py`,
  `src/backend/backend_client.go` (only if the verification finds a gap).
- **Tests:** `src/backend/backend_client_test.go` (exists) extended for the
  OpenSearch endpoint; an isolation test run (`org_isolation_test.go` template)
  proving tenant scoping is unchanged under authenticated transport;
  document-count assertions per lane.
- **Acceptance criteria:** every client authenticated; index document counts
  continue to advance across the cutover.
- **Rollout / rollback:** per client, per HLD §9 Phase 4 "per-store, staged".
- **Security impact:** completes the OpenSearch closure.
- **Telemetry impact:** **at risk per client** (see SEC-008.1).
- **Tenant impact:** none if the role model stays service-scoped; isolation
  tests must pass.
- **Complexity:** L · **Owner:** platform eng · **Dependencies:** SEC-008.1 ·
  **Approval:** **yes**.

---

## SEC-009 — ClickHouse TLS + row-policy safety under new auth

**Phase 4 · V1 · Complexity L · Owner: platform eng · Approval: yes.**
*(Row policies are the tenant boundary and do not change — this epic's job is to
not break them.)*

### SEC-009.1 — TLS listener and authenticated clients

- **Title:** Stop sending ClickHouse Basic credentials in the clear
- **Objective:** HLD §7 `api → ClickHouse`: TLS + client cert, Basic replaced or
  wrapped.
- **Current problem:** `deployment/docker/docker-compose.yml:911-914` sets
  `CLICKHOUSE_USER`/`CLICKHOUSE_PASSWORD`; correlation dials
  `CLICKHOUSE_URL: "http://clickhouse:8123"` (:974) and authenticates with
  HTTP Basic (`src/correlation/main.py:1757,1810,1838` — `auth=self.auth`).
  The Go side goes through `src/backend/clickhouse_client.go:46` /
  `src/backend/chhttp/`. Every one of those credentials transits plaintext.
- **Affected paths:** HLD §7 `api → ClickHouse` (**P0**),
  `vector-router → ClickHouse`, `correlation → ClickHouse`.
- **Prerequisites:** SEC-003.3.
- **Implementation steps:** (1) enable the ClickHouse HTTPS/native-TLS port with
  the workload cert (config goes in `deployment/docker/clickhouse/`, which
  already carries `custom-settings.xml`, `memory.xml`, `query-spill.xml`, etc.);
  (2) run both listeners during migration; (3) cut over Go, Python, and the
  Vector sink; (4) remove the plaintext listener.
- **Files likely affected:** `deployment/docker/clickhouse/` (new TLS config),
  `deployment/docker/docker-compose.yml`, `src/backend/clickhouse_client.go`,
  `src/backend/chhttp/`, `src/correlation/main.py`,
  `deployment/docker/vector-router/vector.yaml`.
- **Tests:** `src/backend/chhttp/chhttp_test.go` (already fires real failures —
  21 cases) extended with a TLS-failure case asserting the error is **surfaced,
  not swallowed**; a plaintext-refused test; the correlation suite in
  `src/correlation/`.
- **Acceptance criteria:** no ClickHouse credential transits plaintext; write
  and query paths unaffected.
- **Rollout:** dual listener → cutover → remove plaintext.
- **Rollback:** re-enable the plaintext listener.
- **Security impact:** closes part of T13 (plaintext credential exposure).
- **Telemetry impact:** **at risk** — ClickHouse holds RCA evidence and cloud/
  path data; a failed writer path routes to `CORR_DLQ_DIR` (durable, per F-38)
  which limits loss but will backlog.
- **Tenant impact:** touches the store that holds the strongest tenant control.
  See SEC-009.2 — isolation must be **re-proven**, not assumed.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-003.3 ·
  **Approval:** **yes**.

### SEC-009.2 — Row-policy convergence guard under the new auth model

- **Title:** Prove row policies survive the auth change and any access-storage reset
- **Objective:** Preserve the strongest tenant control in the product.
- **Current problem (this is a strength to protect, not a gap):**
  `src/backend/clickhouse_policies.go` converges `ROW POLICY` objects on every
  API start, idempotently and self-healingly, and
  `src/backend/clickhouse_policies_test.go` fails if any policy on a
  `corr_*`/`path_*` table is written leniently (the guard cited in HLD §1.1).
  The risk is that introducing TLS, new users, or `CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT`
  changes (compose :914) resets or shadows access storage and the policies come
  back absent — a **silent** cross-tenant exposure.
- **Affected paths:** HLD §7 ClickHouse rows, `authz = row policies (keep)`.
- **Prerequisites:** SEC-009.1.
- **Implementation steps:** (1) add a post-convergence **verification** step
  that reads back the policies and refuses to serve if any expected policy is
  missing (convergence today asserts it wrote; make it assert it *exists*);
  (2) add an explicit test for the access-storage-reset scenario; (3) ensure the
  new ClickHouse user used by each service is subject to the policies (a user
  with `default_access_management` or an admin grant would bypass them).
- **Files likely affected:** `src/backend/clickhouse_policies.go`,
  `src/backend/clickhouse_policies_test.go`, `src/backend/ch_convergence_test.go`,
  `deployment/docker/clickhouse/init.sql`,
  `deployment/docker/docker-compose.yml`.
- **Tests:** extend `clickhouse_policies_test.go` (lenient-policy guard already
  at :65-69) with (a) a missing-policy-after-reset case, (b) a case asserting
  the *service* user cannot bypass policies, (c) `cloud_costs_test.go`-style
  per-table coverage; plus a cross-org run of `org_isolation_test.go`.
- **Acceptance criteria:** the API refuses to serve ClickHouse-backed endpoints
  if a required row policy is absent; a service account cannot read another
  tenant's rows even with a valid certificate.
- **Rollout:** ships with SEC-009.1.
- **Rollback:** revert the refusal to a loud alert (never to silence).
- **Security impact:** protects the product's strongest existing control from
  regression during the security migration.
- **Telemetry impact:** a false-positive refusal would block query paths — hence
  the read-back must be exact.
- **Tenant impact:** **directly protects tenant isolation.** No item in this
  backlog may weaken it; this one strengthens the guard.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-009.1 ·
  **Approval:** **yes** — changes production failure behaviour (a serve refusal).

---

## SEC-010 — VictoriaMetrics behind vmauth

**Phase 4 · V1 · Complexity M · Owner: platform eng · Approval: yes.**

### SEC-010.1 — Introduce vmauth with TLS

- **Title:** Put an authenticating proxy in front of VictoriaMetrics
- **Objective:** HLD §7 `api → VictoriaMetrics`: via vmauth, TLS, route + tenant
  scoping.
- **Current problem:** `victoria` (compose :612-640) exposes `:8428` with **no
  authentication**; `vmalert` (:684-694) points at
  `http://victoria:8428` for datasource, remoteWrite and remoteRead; the Go
  side dials `envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))`
  (`src/backend/path_health_api.go:50`, `src/backend/seam_bootstrap.go:247`,
  `src/backend/metrics_query.go`). Anything on the network can read or **write**
  every tenant's metrics.
- **Affected paths:** HLD §7 `api → VictoriaMetrics` (**P0**),
  `gnmic → VictoriaMetrics`.
- **Prerequisites:** SEC-003.3.
- **Implementation steps:** (1) add a `vmauth` service with per-identity routes
  (api read, gnmic write, vmalert read+write) and TLS; (2) repoint every client
  via `VICTORIA_URL`/`METRICS_URL` (the env seam already exists in Go and is
  already used by tests — `topology_metrics_isolation_test.go:41` sets it); (3)
  restrict `victoria`'s own port to the internal network only.
- **Files likely affected:** `deployment/docker/docker-compose.yml`,
  `src/config/` (vmauth config), `scripts/install.py`,
  `scripts/preflight-configs.sh` (a `VM_IMG` pin already exists there).
- **Tests:** an unauthenticated request is refused; each route works for its
  identity and 401s for others; `src/backend/metrics_forecast_isolation_test.go`
  and `topology_metrics_isolation_test.go` must pass unchanged (they already
  drive `VICTORIA_URL`).
- **Acceptance criteria:** no unauthenticated read or write reaches VM;
  dashboards, alerts, forecasts, and path health still work.
- **Rollout:** add vmauth alongside; repoint clients one at a time; then close
  the direct port.
- **Rollback:** repoint clients at `victoria:8428`.
- **Security impact:** closes T14 for the metrics store.
- **Telemetry impact:** **at risk** — `gnmic`'s remote_write is the gNMI metric
  lane; a bad vmauth route silently 401s it (the same failure signature as the
  2026-07-22 `INGEST_TOKEN` incident described in
  `deployment/docker/cloud-ingest/ingest_auth.py`, where the only symptom was a
  rate-limited WARN). Assert on **sample counts**.
- **Tenant impact:** VM tenant scoping is a device/tenant **label filter** in
  the application. vmauth routes are per-service and must not be treated as a
  tenant boundary. Isolation tests must pass unchanged.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-003.3 ·
  **Approval:** **yes**.

---

## SEC-011 — Postgres TLS + per-service roles

**Phase 4 · V1 · Complexity M · Owner: platform eng · Approval: yes.**

### SEC-011.1 — `sslmode` ladder to `verify-full`

- **Title:** Encrypt and verify the Postgres connection
- **Objective:** HLD §7 `api → Postgres`: `verify-full`.
- **Current problem:** correlation's DSN is
  `postgresql://${DB_USER}:${DB_PASSWORD}@postgres:5432/${DB_NAME}` with no TLS
  parameters (compose :976), and the Postgres path is pinned `sslmode=disable`
  per the HLD's verified inventory — the database password crosses the network
  in the clear on every connection.
- **Affected paths:** HLD §7 `api → Postgres` (**P0**),
  `correlation → PG`.
- **Prerequisites:** SEC-003.3.
- **Implementation steps:** (1) issue a Postgres server cert from the workload
  intermediate and enable TLS in the container; (2) walk the documented ladder
  (`disable` → `require` → `verify-ca` → `verify-full`) with the CA mounted in
  every client; (3) update the Go DSN construction and the correlation DSN;
  (4) add the `secpolicy` rule prohibiting `sslmode=disable` in production.
- **Files likely affected:** `deployment/docker/postgres/` (server config +
  `netops-app-role.sql`), `deployment/docker/docker-compose.yml`,
  `src/backend/internal/platformdb/`, `src/correlation/main.py`,
  `scripts/install.py`, `src/backend/secpolicy/`.
- **Tests:** the existing **blocking** `pg-integration` job
  (`.github/workflows/backend-ci.yml:79-125`, `go test -tags=pgintegration -run TestPG`)
  extended to run against a TLS-enabled postgres; `src/backend/saved_pg_rls_test.go`
  and the RLS suite must pass unchanged.
- **Acceptance criteria:** connections are `verify-full`; a wrong-CA connection
  is refused; RLS behaviour is byte-identical.
- **Rollout:** ladder step by step, verifying at each rung.
- **Rollback:** step back down the ladder (a DSN change and a restart).
- **Security impact:** closes T13 for the relational credential.
- **Telemetry impact:** low — PG holds app state, not the telemetry lanes. A
  failure blocks the API, which is loud rather than silent.
- **Tenant impact:** PG isolation is **FORCE-RLS + `withTenant`**. Transport
  changes must not alter the role the queries run as, or RLS can be bypassed —
  see SEC-011.2. Isolation tests must pass unchanged.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-003.3 ·
  **Approval:** **yes**.

### SEC-011.2 — Per-service roles that cannot bypass RLS

- **Title:** Distinct, non-superuser roles per service
- **Objective:** HLD §7 `authz = per-service roles + RLS (keep)`.
- **Current problem:** `deployment/docker/postgres/netops-app-role.sql` exists
  and the CI job explicitly "create[s] the non-superuser app role" — but api and
  correlation share `${DB_USER}` from the same `.env` (compose :60, :976). One
  credential, two services, no attribution; and a role with `BYPASSRLS` or
  ownership silently defeats FORCE-RLS.
- **Prerequisites:** SEC-011.1.
- **Implementation steps:** (1) split into `netops_api` and `netops_correlation`
  roles with least-privilege grants; (2) assert neither is superuser, owner of
  the RLS tables, or `BYPASSRLS`; (3) seed both in `scripts/install.py`.
- **Files likely affected:** `deployment/docker/postgres/netops-app-role.sql`,
  `scripts/install.py`, `deployment/docker/docker-compose.yml`,
  `src/backend/internal/platformdb/`.
- **Tests:** a `pgintegration` test asserting each role's `rolbypassrls` is
  false and that it is not the table owner (the two ways FORCE-RLS is silently
  defeated); re-run `saved_pg_rls_test.go` and `org_isolation_test.go`.
- **Acceptance criteria:** each service has its own role; no role can bypass RLS;
  isolation tests pass.
- **Rollout / rollback:** additive roles first, switch DSNs, drop the shared role
  last; rollback = point back at the shared role.
- **Security impact:** attribution + blast-radius reduction (T3).
- **Telemetry impact:** none. · **Tenant impact:** **protects** isolation.
- **Complexity:** S · **Owner:** platform eng · **Dependencies:** SEC-011.1 ·
  **Approval:** **yes** — changes credentials.

---

## SEC-012 — Valkey authentication + TLS

**Phase 4 · V1 · Complexity M · Owner: platform eng · Approval: yes.**

### SEC-012.1 — Require a Valkey password / ACL user

- **Title:** Authenticate the shared prober↔API channel
- **Objective:** HLD §7 `api → Valkey`: ACL user, command/key-prefix ACL.
- **Current problem:** the compose service is literally named `redis` and runs
  `valkey/valkey:8-alpine` with
  `command: ["valkey-server", "--save", "60", "1", "--maxmemory", …]` (:95-104)
  — **no `--requirepass`, no ACL, no TLS**. The client is the repo's own
  dependency-free RESP client `src/backend/collectors/redis.go`, which *already*
  supports `REDIS_PASSWORD` (`redisDial`, :68-73 — it sends `AUTH` when the env
  var is set) and is used to publish per-vantage probe paths
  (`traceroute.go:173-175`), LLDP/BGP-LS topology (`bgpls.go:1093-1111`,
  `lldp.go:175`) and interface maps (`snmpmetrics.go:212-219`). Anything on the
  network can read or **overwrite** topology and path data that feeds RCA.
- **Affected paths:** HLD §7 `api → Valkey` (**P0**).
- **Prerequisites:** SEC-003.3 (for the credential lifecycle; the password
  itself comes from the installer secret set).
- **Implementation steps:** (1) add `REDIS_PASSWORD` to the installer's generated
  secrets (`scripts/install.py` already generates `INGEST_TOKEN`,
  `CLICKHOUSE_PASSWORD`, etc. at :309-319 — this is a one-line addition to that
  map); (2) pass `--requirepass` (or a Valkey ACL user file) in the compose
  command; (3) set `REDIS_PASSWORD` on every service that dials it (api,
  prober); (4) add the `secpolicy` production rule.
- **Files likely affected:** `deployment/docker/docker-compose.yml`,
  `scripts/install.py`, `src/backend/collectors/redis.go` (verify only — the
  AUTH path exists), `src/backend/secpolicy/`.
- **Tests:** `src/backend/collectors/redis_test.go` (exists; already drives
  `REDIS_HOST`/`REDIS_PORT`) extended with an AUTH-required server asserting an
  unauthenticated dial fails and an authenticated one succeeds, and that the
  failure is **surfaced** rather than swallowed (`traceroute.go:173` currently
  does `_ = redisSetEX(...)` — an ignored error, so a publish failure would be
  invisible; this item must either check it or justify the discard per §5).
- **Acceptance criteria:** unauthenticated Valkey commands are refused; probe
  paths, LLDP and BGP-LS maps still publish and are still read.
- **Rollout:** seed the password, restart Valkey and its two clients together.
- **Rollback:** remove `--requirepass`.
- **Security impact:** closes T14 for the shared state channel and removes an
  RCA-evidence tampering path.
- **Telemetry impact:** **at risk** — path/topology publication degrades
  silently today because the write errors are discarded. If the password is
  wrong, `RedisAddr()` still returns non-empty and callers take the Redis branch
  (`probe_handlers.go:34`, `seam_bootstrap.go:222`, `path_ingest.go:373`), so
  the fallback to file/in-process sharing does **not** trigger. This is a real
  silent-failure risk and the reason the error-surfacing test above is required.
- **Tenant impact:** the Valkey keyspace is **not** tenant-scoped
  (`netops:probe:paths:<vantage>` etc.); tenancy is re-derived downstream. Do not
  introduce a tenant decision here. Isolation tests must pass unchanged.
- **Complexity:** S · **Owner:** platform eng · **Dependencies:** SEC-003.3 ·
  **Approval:** **yes** — introduces a credential on a live data path.

### SEC-012.2 — TLS for the Valkey channel

- **Title:** Encrypt the RESP channel
- **Objective:** HLD §7 target transport `TLS`.
- **Current problem:** `src/backend/collectors/redis.go:57-73` dials with
  `net.Dialer` over plain TCP; there is no TLS path at all. The AUTH password
  from SEC-012.1 would therefore transit in the clear.
- **Prerequisites:** SEC-012.1.
- **Implementation steps:** (1) add a TLS dial path to `redis.go` using
  `src/backend/tlsconfig/` (the only place TLS may be configured — design
  principle P5 of the transport-encryption doc); (2) enable `--tls-port` on the
  Valkey container with the workload cert; (3) run both ports during migration,
  then close the plaintext port.
- **Files likely affected:** `src/backend/collectors/redis.go`,
  `src/backend/tlsconfig/httpclient.go` (or a sibling dialer),
  `deployment/docker/docker-compose.yml`.
- **Tests:** `redis_test.go` round-trip over TLS against a test server;
  hostname-verification-required assertion (never `InsecureSkipVerify` — the
  LDAP client `src/backend/internal/ldap/ldap.go:311-317` is the reference
  pattern that structurally refuses it outside dev).
- **Acceptance criteria:** the password never transits plaintext; plaintext port
  closed.
- **Rollout / rollback:** dual port; revert to the plaintext port.
- **Security impact:** completes T13 closure for this hop.
- **Telemetry impact:** same risk profile as SEC-012.1.
- **Tenant impact:** none.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-012.1 ·
  **Approval:** **yes**.

---

## SEC-018 — Secret-sealing transport + `REQUIRE_SEAL` enforcement

**Phase 4 · V1 · Complexity L · Owner: security eng · Approval: yes.**

> **HLD gap noted:** SEC-018 is not assigned a phase in HLD §9. It is placed in
> Phase 4 here because it is a **P0 credential-exposure fix** whose only hard
> dependency is the PKI (SEC-003.3) plus the per-client ingest identity
> (SEC-013.1), and because SEC-005.2 cannot land before it. If the owner
> disagrees, this is the item to re-phase.

### SEC-018.1 — Fetch per-tenant sealing keys over mTLS with a dedicated identity

- **Title:** Stop shipping tenant key material over plaintext HTTP
- **Objective:** HLD §7 `vector-router → api (sealing keys)`: mTLS, dedicated
  identity, key-fetch scope only. HLD §1.1 calls this "the sharpest one".
- **Current problem:** `deployment/docker/vector-router/cx-secret-backend.sh:24`
  sets `API="${SEALING_API_URL:-http://api:8080}"` and :55-57 fetches
  `${API}/internal/sealing/edge-keys?tenant=${tenant}` with
  `-u "${INGEST_USER}:${INGEST_TOKEN}"`. So the **per-tenant seal and MAC keys**
  — the entire basis of the Sealed Fields feature (#129, complete) — cross the
  network in cleartext, authenticated by the **same shared token** six other
  clients hold. The feature's guarantee is undone by its own key-distribution
  hop. HLD §5 T13 rates this **CRITICAL**.
- **Affected paths:** HLD §7 `vector-router → api (sealing keys)` (**P0**).
- **Prerequisites:** SEC-003.3 (a dedicated `vector-router` SVID),
  SEC-013.1 (per-client identity replacing the shared token).
- **Implementation steps:** (1) issue a distinct identity for the sealing-key
  fetch, separate from the router's ingest identity, scoped to the
  `/internal/sealing/edge-keys` route only; (2) change the script to `https://`
  with client cert + CA (`curl --cert --key --cacert`, no `-k`, ever);
  (3) enforce the scope server-side — the endpoint accepts only that identity;
  (4) audit every key fetch with tenant + identity (never the key material);
  (5) keep the fail-closed behaviour intact — the script's exit-1/`{}` contract
  and the documented "no key ⇒ router will not start, exit 78" property must be
  preserved exactly.
- **Files likely affected:** `deployment/docker/vector-router/cx-secret-backend.sh`,
  `deployment/docker/vector-router/vector.yaml`,
  `deployment/docker/docker-compose.yml`, the sealing endpoint handler in
  `src/backend/` (`/internal/sealing/edge-keys`), `src/backend/sealing/`.
- **Tests:** a Go test that the endpoint rejects any identity other than the
  sealing one (403/404, never a key); a shell test for the script under §16.3
  rules (this file is production software on the customer-data path) covering:
  cert present → success, cert missing → non-zero exit with a well-formed `{}`,
  TLS failure → non-zero (**never** a silent empty key); extend
  `tests/test_secret_rotation.py`.
- **Acceptance criteria:** no key material transits plaintext; a stolen
  `INGEST_TOKEN` can no longer fetch any tenant's sealing key; the router still
  refuses to start without a key.
- **Rollout:** dual-accept on the endpoint (token **or** mTLS) for one window,
  then mTLS only. Must precede SEC-005.2.
- **Rollback:** re-allow the token path (endpoint-side flag), revert the script.
- **Security impact:** the highest-value single fix in the backlog by
  exposure-removed ÷ effort. Closes the credential half of T13.
- **Telemetry impact:** **severe if botched** — a failed key fetch stops
  `vector-router` entirely (by design), which stops **all** routed telemetry.
  Test the failure paths before the success path.
- **Tenant impact:** the keys are **per-tenant**. A scope error here is a
  cross-tenant key disclosure. The endpoint test must include a cross-tenant
  case modelled on `org_isolation_test.go`: identity for tenant A must not be
  able to fetch tenant B's key, and an unknown tenant must 404, not
  auto-provision.
- **Complexity:** M · **Owner:** security eng · **Dependencies:** SEC-003.3,
  SEC-013.1 · **Approval:** **yes** — credential change on a fail-closed
  telemetry path.

### SEC-018.2 — `REQUIRE_SEAL=true` in production

- **Title:** Refuse to boot unsealed in production
- **Objective:** HLD §6.5 profile matrix — production requires `REQUIRE_SEAL=true`.
- **Current problem:** the sealing sidecar exists (`secrets-seal`,
  `profiles: ["seal"]`, docker-compose.yml:1686-1699, backed by
  `deployment/docker/swtpm-sidecar/`) but is **opt-in by profile**, and the live
  `.env` sets no `SEAL_*` variable at all. Production can therefore run with
  passthrough custody for every sealed secret including the internal CA key.
- **Prerequisites:** SEC-003.1, SEC-018.1.
- **Implementation steps:** (1) add the `REQUIRE_SEAL` rule to `secpolicy`;
  (2) make `scripts/install.py` activate the `seal` profile for
  staging/production; (3) fail boot when the profile demands sealing and the
  provider is passthrough.
- **Files likely affected:** `src/backend/internal/vault/`,
  `src/backend/secpolicy/`, `scripts/install.py`,
  `deployment/docker/docker-compose.yml`.
- **Tests:** vault-package tests for the refusal; `secpolicy` rule test; a
  swtpm round-trip (the existing `TestSwtpm` live-validation pattern).
- **Acceptance criteria:** production cannot boot with passthrough custody.
- **Rollout:** staging first. **Rollback:** profile downgrade.
- **Security impact:** closes T11 and the sealed-fields custody gap together.
- **Telemetry impact:** a refused boot stops ingestion (intended).
- **Tenant impact:** per-tenant DEKs — no scoping change; existing sealing tests
  must pass.
- **Complexity:** S · **Owner:** security eng · **Dependencies:** SEC-003.1,
  SEC-018.1 · **Approval:** **yes** — production failure behaviour.

---

# PHASE 5 — Secure device ingestion

*HLD §9: Deps 2, 3 · Risk high (customer devices) · Rollback legacy lane stays
until deadline · Telemetry at risk per device · **Tenant: cert→tenant binding
must never auto-create.***

> **HLD §11 decision 7 is RESOLVED (§0a): v1 is intra-stack + public ingress
> only. Most of this phase moves to PHASE 2+**, with three exceptions that stay
> in v1 — the first because those components are ours, the other two because
> without them the v1 customer claim would be dishonest:
>
> - **SEC-013.1 / SEC-013.2 stay v1** — the Vector ingest lanes are
>   *Correlix-owned components*, not customer devices. "All Correlix components
>   communicate over TLS" is false while six of them share one Basic token over
>   plaintext HTTP.
> - **SEC-014.1 stays v1** — syslog-ng → vector-aggregator is likewise an
>   internal hop with Correlix software at both ends (completion criterion A12).
>   Only the *device-facing* half of SEC-014 defers.
> - **SEC-014.3 and SEC-017.2 stay v1** — the `transport_authenticated=false`
>   stamping. The v1 device-lane deliverable is exactly this: **honest labelling
>   plus segmentation guidance, and no device PKI build.** Without it the posture
>   report (SEC-021.1) would imply device traffic is authenticated when it is not,
>   which is the one thing HLD §6.6 forbids.
>
> Everything else below — SEC-013.3, SEC-014.2, SEC-015, SEC-016, SEC-017.1 — is
> written in full and executes in Phase 2+. **Do not present device telemetry as
> TLS-protected in any v1 customer material.**

---

## SEC-013 — Secure Vector ingestion (per-client identity + TLS)

**Phase 5 · V1 = `.1`/`.2`; `.3` Phase 2+ · Complexity XL · Owner: platform eng ·
Approval: yes.** *(Vector and the collectors are Correlix-owned components, so
this stays in v1 despite sitting in the device phase.)*

### SEC-013.1 — Replace the shared `INGEST_TOKEN` with per-client identities

- **Title:** One identity per ingest client
- **Objective:** HLD §7 `collectors/prober → Vector lanes`: mTLS, per-collector
  identity, lane-scoped authorization. HLD §10 names the shared credential as a
  rejected design ("exactly today's `INGEST_TOKEN` problem").
- **Current problem:** one token, six holders. Verified in
  `deployment/docker/docker-compose.yml`: `gnmic` (:341),
  `vector-aggregator` (:438, the verifier), `vector-router` (:487), `api`
  (:1109), `prober` (:1565), plus the Python producers via
  `deployment/docker/cloud-ingest/ingest_auth.py`. All four aggregator lanes
  share one YAML anchor — `deployment/docker/vector/vector.yaml:128`
  (`auth: &ingest_auth`) reused at :140, :153, :167 — so a single token opens
  `trap_in` (:8688), `probe_in` (:8689), `metrics_in` (:8690) **and** `bus_in`
  (:8692), the bridge onto the bus. `src/backend/collectors/ingest_auth.go`
  reads it once per process (`sync.OnceValue`) with no rotation story. HLD §5
  rates T3 and T9 **HIGH**.
- **Affected paths:** HLD §7 `collectors/prober → Vector lanes` (**P0**).
- **Prerequisites:** SEC-003.3.
- **Implementation steps:** (1) issue per-client SVIDs (already produced by
  SEC-003.3); (2) extend `src/backend/collectors/ingest_auth.go` to present a
  client certificate instead of Basic — keeping its deliberate single-chokepoint
  design (the file's own comment explains why there is exactly one function);
  (3) mirror it in `deployment/docker/cloud-ingest/ingest_auth.py` (the file
  states it "Mirrors collectors/ingest_auth.go exactly" — that parity is a
  documented invariant and must be preserved); (4) configure each Vector lane
  with a **lane-specific** accept list, so a metrics client cannot post to
  `bus_in`; (5) keep the token accepted during the window (`accept` set), then
  narrow.
- **Files likely affected:** `src/backend/collectors/ingest_auth.go`,
  `deployment/docker/cloud-ingest/ingest_auth.py`,
  `deployment/docker/vector/vector.yaml`,
  `deployment/docker/docker-compose.yml`, `scripts/install.py`.
- **Tests:** `src/backend/collectors/ingest_auth_test.go` (the reset helpers
  `resetIngestCredentialForTest`/`ResetIngestCredentialForTest` already exist
  precisely so the rejection path is testable — use them); a lane-scoping test
  proving the metrics identity is refused by `bus_in`;
  `tests/test_ingest_contract.py` full pass; a Go↔Python parity test.
- **Acceptance criteria:** each client has its own credential; a compromised
  collector credential cannot write to another lane; no lane loses events.
- **Rollout:** accept-set (token **or** cert) → per-client cutover → narrow.
- **Rollback:** the token path is still accepted until narrowing.
- **Security impact:** closes T3 (collector compromise → full bus access) and is
  the prerequisite for SEC-018.1.
- **Telemetry impact:** **high risk, historically proven.** The
  `cloud-ingest/ingest_auth.py` header documents the exact incident: when the
  credential was seeded and the aggregator recreated (2026-07-22) "every cloud
  metric and probe event began returning 401 and being dropped — with the only
  symptom a rate-limited WARN in Vector's own log." Repeat that mistake and it
  will again be invisible. Every cutover must assert on **per-lane event
  counts**, not on logs.
- **Tenant impact:** none directly; but note `bus_in` is the lane whose prior
  prefix-only check allowed **forged `tenant_id` injection** (per
  `ingest_auth.go`'s header). Lane scoping must not regress that. Isolation
  tests must pass unchanged.
- **Complexity:** L · **Owner:** platform eng · **Dependencies:** SEC-003.3 ·
  **Approval:** **yes** — credential change that can drop telemetry.

### SEC-013.2 — TLS on the four `http_server` ingest lanes

- **Title:** Encrypt the ingest lanes
- **Objective:** Credentials and telemetry stop crossing the compose network in
  the clear.
- **Current problem:** `vector.yaml`'s four `http_server` sources bind
  `0.0.0.0:8688/8689/8690/8692` with `auth:` but no `tls:` block.
- **Prerequisites:** SEC-013.1.
- **Implementation steps:** add `tls:` (cert, key, CA, `verify_certificate`) to
  each source; mount the aggregator SVID; update every client to https; validate
  the config boots via `scripts/preflight-configs.sh` (Vector is already the
  first check there and the script exists **because** a Vector config that
  passed `vector validate` failed the real topology build — use the real boot
  check, not `validate`).
- **Files likely affected:** `deployment/docker/vector/vector.yaml`,
  `deployment/docker/docker-compose.yml`,
  `src/backend/collectors/ingest_auth.go`,
  `deployment/docker/cloud-ingest/ingest_auth.py`, `scripts/preflight-configs.sh`.
- **Tests:** `preflight-configs.sh` Vector fresh-load; `tests/test_ingest_contract.py`;
  per-lane count assertions.
- **Acceptance criteria:** all four lanes are TLS; a plaintext post is refused;
  lane counts unchanged.
- **Rollout:** per lane. **Rollback:** remove the `tls:` block (restart).
- **Security impact:** closes the ingest half of T13.
- **Telemetry impact:** **at risk per lane** — same silent-401 signature.
- **Tenant impact:** none.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-013.1 ·
  **Approval:** **yes**.

### SEC-013.3 — Per-vantage identity for remote path publication — **PHASE 2+**

> Deferred with the device/collection plane: a remote vantage is a
> customer-deployed peer and this item depends on SEC-003.5. Kept in full. Note
> for v1 honesty: the posture report must show the remote-vantage path as
> **shared-credential**, not as an authenticated identity.

- **Title:** Stop letting any API-key holder publish as any vantage
- **Objective:** HLD §7 `Remote vantage → api`: per-vantage identity,
  vantage-scoped authorization.
- **Current problem:** `src/backend/probe_paths_ingest.go:28` gates
  `POST /api/probe/paths` on `s.requirePerm(w, r, "infrastructure", LevelWrite)`
  and then takes the vantage id from the **payload**
  (`pathgraph.ValidatePushedPaths(in)` → `s.remotePaths.Put(vantage, …)` at
  :41-50). Any holder of an `infrastructure:write` credential can publish paths
  attributed to **any** vantage — and paths are RCA evidence. This is the same
  class as the shared-token problem, one layer up.
- **Affected paths:** HLD §7 `Remote vantage → api`.
- **Prerequisites:** SEC-003.5 (device/vantage trust domain) **or** a per-vantage
  PSK if HLD §11 decision 1 lands on PSK for constrained peers.
- **Implementation steps:** (1) derive the vantage id from the authenticated
  identity, never from the body (the §3a rule "stamp the owner from the token,
  never the request body", applied to vantages); (2) reject a payload whose
  declared vantage disagrees with the identity; (3) audit per-vantage.
- **Files likely affected:** `src/backend/probe_paths_ingest.go`,
  `src/backend/pathgraph/`, `src/backend/collectors/traceroute.go` (publisher
  side), `deployment/docker/docker-compose.yml` (prober credential).
- **Tests:** a handler test asserting a mismatched vantage claim is refused; a
  cross-tenant test (`org_isolation_test.go` template) asserting a vantage bound
  to tenant A cannot publish paths that surface under tenant B; a regression
  test that the legitimate prober still publishes.
- **Acceptance criteria:** vantage attribution is derived from the credential;
  spoofing another vantage is impossible.
- **Rollout:** accept-set — honour the body value only when the identity is the
  legacy shared credential, during the window.
- **Rollback:** re-enable the body-derived vantage.
- **Security impact:** closes an RCA-evidence forgery path (T1/T7 adjacent).
- **Telemetry impact:** **at risk** — a mis-issued prober credential silently
  stops path publication; `traceroute.go:173-175` currently discards the publish
  error (`_ = redisSetEX(...)`), so failure is invisible. Pair with SEC-012.1's
  error-surfacing fix.
- **Tenant impact:** **touches attribution.** Vantage → tenant binding must be
  checked against the registry and never auto-created.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-003.5 ·
  **Approval:** **yes** — touches a customer-deployed component and changes a
  credential.

---

## SEC-014 — Secure syslog

**Phase 2+ (was Phase 5) · V1 = `.1` + `.3`; `.2` Phase 2+ · Complexity XL ·
Owner: platform eng + SRE · Approval: yes (customer devices for `.2`).**

> Split by the v1 boundary:
> - **`.1` stays v1** — syslog-ng → vector-aggregator is an **internal
>   Correlix-owned hop** (both ends are ours), so it is inside "all Correlix
>   components communicate over TLS" and appears as **A12** in the v1 completion
>   definition. It touches no customer device.
> - **`.2` is Phase 2+** — the RFC 5425 device lane needs device PKI (SEC-003.5),
>   which the steer defers.
> - **`.3` stays v1** — marking the legacy 514 lane
>   `transport_authenticated=false` is what keeps the v1 posture claim truthful
>   (completion criterion **C3**).

### SEC-014.1 — TLS on the syslog-ng → Vector hop — **V1 (internal hop, A12)**

- **Title:** Encrypt the internal syslog hand-off
- **Objective:** HLD §7 `syslog-ng → Vector :6601`: TLS.
- **Current problem:** `deployment/docker/syslog-ng/syslog-ng.conf:109-112`
  forwards with `transport("tcp") port(6601)` — no `tls()`; the receiving side
  is `vector.yaml:86-88` `syslog_in` on `0.0.0.0:6601` with no `tls:`.
- **Prerequisites:** SEC-013.2 (the aggregator must already hold a server cert).
- **Implementation steps:** add `tls()` to the syslog-ng destination with the
  syslog-ng SVID and CA; add `tls:` to the Vector source; dual-port during
  migration. **Note the #148 interaction:** tracker item 148 lever (a) proposes
  replacing syslog-ng with Vector's own syslog source entirely. If that lands
  first, this item collapses into SEC-014.2 — check #148 before starting.
- **Files likely affected:** `deployment/docker/syslog-ng/syslog-ng.conf`,
  `deployment/docker/vector/vector.yaml`,
  `deployment/docker/docker-compose.yml`, `scripts/preflight-configs.sh`
  (`SYSLOGNG_IMG` pin already present).
- **Tests:** `preflight-configs.sh` syslog-ng + Vector fresh-load; an end-to-end
  message-count assertion across the hop; the existing disk-buffer behaviour
  (F-48) must be preserved.
- **Acceptance criteria:** the hop is TLS; message counts unchanged; the disk
  buffer still absorbs a downstream stall.
- **Rollout:** dual port. **Rollback:** revert to plain TCP.
- **Security impact:** removes an internal cleartext log path.
- **Telemetry impact:** **at risk** — syslog is the highest-volume lane; a
  handshake failure with the buffer full loses messages.
- **Tenant impact:** none — tenancy is derived downstream from
  `device_tenant.csv`.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-013.2 ·
  **Approval:** **yes** — can drop telemetry.

### SEC-014.2 — RFC 5425 mTLS device lane on :6514 with cert→device→tenant binding — **PHASE 2+**

- **Title:** A secure syslog lane for capable devices
- **Objective:** HLD §7 `Device → syslog-ng`: 6514 RFC 5425 mTLS, tenant derived
  from the device certificate rather than a spoofable hostname.
- **Current problem:** `deployment/docker/syslog-ng/syslog-ng.conf:83-85` —
  `source s_network { udp(ip(0.0.0.0) port(514)); tcp(ip(0.0.0.0) port(514) …); }`.
  The config's own comment (:42-63) states the problem better than any summary:
  the source listens "with NO ACL and NO authentication: the hostname is an
  UNVERIFIED CLAIM by whoever sent the packet", and closing it "needs transport
  authentication". `src/correlation/main.py:301-307` independently confirms the
  consequence: a party who reaches the port and knows a real device hostname
  "still lands in that tenant". HLD §5 rates T1 **HIGH**.
- **Affected paths:** HLD §7 `Device → syslog-ng` (**P0**).
- **Prerequisites:** SEC-003.5 (device trust domain), SEC-014.1.
- **Implementation steps:** (1) add a `syslog(ip(0.0.0.0) port(6514) transport("tls") …)`
  source requiring a client certificate from the **device** intermediate;
  (2) extract the device identity from the cert and stamp
  `transport_authenticated=true` + the certificate-derived device id;
  (3) **check** the cert's tenant claim against the registered device record —
  reject on mismatch, never auto-create (HLD §6.2); (4) leave the tenancy
  re-derivation (`device_tenant.csv`) as the authority for the legacy lane so
  the two lanes cannot disagree silently.
- **Files likely affected:** `deployment/docker/syslog-ng/syslog-ng.conf`,
  `deployment/docker/vector/vector.yaml` (the `syslog_normalized` transform at
  :372), `deployment/docker/docker-compose.yml`, the device registry in
  `src/backend/`.
- **Tests:** an integration test that a valid device cert lands with
  `transport_authenticated=true`; a **cross-tenant test** (org_isolation
  template) that a device cert claiming tenant B while registered to tenant A is
  **rejected** and that an unregistered device is rejected rather than
  auto-created; a VRL test via `scripts/vrl-harness.py` for the new fields.
- **Acceptance criteria:** the secure lane authenticates devices; tenancy is
  bound to the certificate **and** cross-checked; the legacy lane is unchanged.
- **Rollout:** additive lane; devices migrate individually; the 514 lane stays.
- **Rollback:** disable the 6514 source.
- **Security impact:** the only mechanism that closes T1/T2 for syslog.
- **Telemetry impact:** **at risk per device** — a device misconfigured for the
  new lane stops sending. Per-device migration with per-device verification.
- **Tenant impact:** **this item changes how tenancy is derived on one lane.**
  It must be additive and cross-checked; a cert must never be able to *move* a
  device between tenants. Extend, do not replace, the isolation tests.
- **Complexity:** XL · **Owner:** platform eng + SRE · **Dependencies:**
  SEC-003.5, SEC-014.1 · **Approval:** **yes** — customer devices, tenancy
  derivation, telemetry risk.

### SEC-014.3 — Mark and expire the legacy 514 lane — **V1 (honesty, C3)**

> **Ordering note under the v1 split:** this item's prerequisite in the original
> plan was SEC-014.2 (the secure lane), because "legacy" only means something
> next to a secure alternative. Under the deferred-device decision there is no
> secure alternative yet, so in v1 this ships **standalone**: the field is
> stamped, the exception is recorded as `no_secure_lane_yet` with the Phase 2+
> item as its remediation, and the expiry is set against the Phase 2+ schedule
> rather than a device migration deadline.

- **Title:** Declare the plaintext syslog lane
- **Objective:** HLD §6.6 honesty clause — every event on the legacy lane
  carries `transport_authenticated=false`, and the lane has an owner and an
  expiry.
- **Current problem:** events from :514 are indistinguishable, in storage and in
  the UI, from authenticated ones. The SNMP trap path already does this right
  (`snmptrap.go` stamps `Authenticated`), which is the pattern to copy.
- **Prerequisites:** SEC-014.2.
- **Implementation steps:** (1) stamp `transport_authenticated=false` in the
  `syslog_normalized` VRL transform; (2) add the declared-exception record
  (reason/owner/expiry) per HLD §6.3; (3) surface the flag in SEC-021's UI;
  (4) never claim cryptographic authenticity anywhere in UI, docs, or evidence
  chains.
- **Files likely affected:** `deployment/docker/vector/vector.yaml`,
  the index templates in `deployment/docker/opensearch/index-templates.json`,
  `src/backend/` (evidence rendering), `src/frontend/src/`.
- **Tests:** `scripts/vrl-harness.py` case for the new field; an OpenSearch
  mapping test (**beware the known dotted-key gotcha** — use a flat field name,
  not a dotted one, or the mapping conflict will silently drop the lane);
  a UI test that unauthenticated events are visually marked.
- **Acceptance criteria:** every legacy-lane event is marked; the exception has
  an owner and expiry; the ageing report lists it.
- **Rollout / rollback:** additive field; revert the transform.
- **Security impact:** honesty — prevents an unauthenticated log being cited as
  evidence.
- **Telemetry impact:** low, but a mapping mistake would drop the lane entirely
  (documented precedent).
- **Tenant impact:** none.
- **Complexity:** S · **Owner:** platform eng · **Dependencies:** SEC-014.2 ·
  **Approval:** no (additive metadata; no listener, credential or device change).

---

## SEC-015 — SNMPv3 hardening

**Phase 2+ (was Phase 5) · Complexity L · Owner: platform eng · Approval: yes.**

> Deferred with the collection plane. **Flagged for the owner's attention
> anyway:** SEC-015.1 closes a *live fail-open* (`snmptrap.go:671-681` accepts an
> unknown sender's cleartext v3 trap). It is the one Phase 2+ item whose current
> behaviour is a defect rather than a missing feature, and it is cheap (M). If
> any single device item is pulled forward into v1, it should be this one.

### SEC-015.1 — Close the trap fail-open

- **Title:** Reject v3 traps from unknown senders
- **Objective:** HLD §7 `Device → SNMP trap`: unknown rejected. Named in
  `docs/design/transport-encryption-2026-08-04.md` §2.3 as "the single most
  instructive line in the inventory".
- **Current problem (verified, exact):**
  `src/backend/collectors/snmptrap.go:658-681` — `decodeTrapV3` resolves creds
  by source IP, and then:
  ```go
  // noAuthNoPriv (or unknown sender): decode the cleartext scopedPDU directly.
  if !creds.isV3() || !creds.wantsAuth() {
      … return finishV3(ev, msgData)
  }
  ```
  An **unknown sender's** cleartext v3 trap is accepted and processed. The
  authenticated branch below it is correct (`verifyV3Auth` → `ev.Authenticated = true`),
  which makes the fail-open branch the whole defect.
- **Affected paths:** HLD §7 `Device → SNMP trap` (**P0**).
- **Prerequisites:** SEC-002.1 (policy vocabulary: `min_level`, accept-set).
- **Implementation steps:** (1) split "unknown sender" from "known sender
  configured noAuthNoPriv" — they are different decisions merged into one
  branch today; (2) for an unknown sender, drop the trap, emit
  `trap_policy_rejected{reason="unknown_sender"}`, and audit; (3) for a known
  sender below `min_level`, drop with `reason="below_min_level"`; (4) gate
  strictness by profile so lab can still accept with a declared exception.
- **Files likely affected:** `src/backend/collectors/snmptrap.go`,
  `src/backend/collectors/snmpcred/` (or wherever `Credential.SecurityLevel`
  lives), `src/backend/secpolicy/`, the metrics surface.
- **Tests:** `src/backend/collectors/snmptrap_test.go` — unknown sender cleartext
  v3 is **dropped** (currently would be accepted: this is a genuine regression
  test for a live defect); known sender below `min_level` dropped; known sender
  at `authPriv` accepted with `Authenticated=true`; profile gating; metric
  increments.
- **Acceptance criteria:** no trap from an unresolvable source is processed in
  staging/production; every drop is counted and audited with a reason.
- **Rollout:** ship counting-only first (emit the metric, still accept) for one
  observation window, then enforce — the same observe-then-enforce discipline
  the transport-encryption doc §6 Phase 1 recommends.
- **Rollback:** flip the enforcement gate back to counting-only.
- **Security impact:** closes a live fail-open; T1/T2.
- **Telemetry impact:** **at risk** — any device sending traps from an IP not in
  the credential map stops being heard. The observation window exists to size
  that population before enforcing.
- **Tenant impact:** traps from an unknown source currently reach tenant
  attribution downstream; rejecting them **narrows** exposure. Isolation tests
  unchanged.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-002.1 ·
  **Approval:** **yes** — can drop device telemetry.

### SEC-015.2 — Enforce a polling `min_level` with a distinct `policy_blocked` state

- **Title:** Refuse to poll below the configured security level
- **Objective:** HLD §7 `Device → SNMP poll`: v3 authPriv required in
  production; "refuse below `min_level`, mark `policy_blocked` (≠ down)".
- **Current problem:** `Credential.SecurityLevel`
  (`noAuthNoPriv|authNoPriv|authPriv`) is per-peer but is only a *credential
  attribute* — nothing rejects a peer that shows up with less
  (`docs/design/transport-encryption-2026-08-04.md` §2.3). The target build is
  in `src/backend/collectors/poller.go` at the v2c/v3 split.
- **Prerequisites:** SEC-015.1.
- **Implementation steps:** (1) add `min_level` to the per-device policy;
  (2) in `poller.go`, refuse to construct a target below it; (3) introduce
  `policy_blocked` as a **distinct device state** — surfacing it as "down" would
  manufacture a false incident, which is its own outage; (4) expose per-device
  level metrics.
- **Files likely affected:** `src/backend/collectors/poller.go`,
  `src/backend/collectors/snmpv3.go`, the device state model in
  `src/backend/`, `src/frontend/src/pages/DeviceMonitoring.tsx`.
- **Tests:** `poller_test.go` — a v2c-only device under a `authPriv` policy is
  not polled and is marked `policy_blocked`, **not** down; a device at the
  required level polls normally; a UI test that the two states render
  differently.
- **Acceptance criteria:** no poll occurs below `min_level`; `policy_blocked`
  never triggers a down-alert.
- **Rollout:** dry-run diff first ("this policy would block N devices"), then
  enforce per tenant.
- **Rollback:** lower `min_level`.
- **Security impact:** closes the v2c-cleartext exposure for polling.
- **Telemetry impact:** **by design, it stops collection from
  non-compliant devices.** The dry-run diff is mandatory (R1 in the
  transport-encryption doc: "enforcement can blind the platform").
- **Tenant impact:** policy is tenant-scoped; a tenant admin must not be able to
  set policy for another tenant's devices — `requirePerm` + tenant filter, and a
  cross-org test.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-015.1 ·
  **Approval:** **yes** — customer devices; will stop collection.

---

## SEC-016 — gNMI TLS enforcement

**Phase 2+ (was Phase 5) · Complexity M · Owner: platform eng · Approval: yes.**

> Deferred: gNMI target trust is per-customer-device onboarding, which v1
> excludes. The v1 obligation is honesty — the posture report must show gNMI
> targets as **unverified TLS** (`skip-verify: true`) or **plaintext**
> (`insecure: true`), never as secured.

### SEC-016.1 — Remove the global `skip-verify` and move to per-target trust

- **Title:** Verify gNMI device certificates
- **Objective:** HLD §7 `gnmic → Device`: TLS + CA, per-target policy;
  production refuses `insecure`/`skip-verify`.
- **Current problem (verified, exact):** `deployment/docker/gnmic/gnmic.yaml:13`
  sets `skip-verify: true` **globally**, and five targets set `insecure: true`
  (lines 30, 35, 40, 45, 50). So gNMI subscriptions are either unencrypted or
  unauthenticated, and a MITM on the management network can feed arbitrary
  telemetry. `insecure: true` also means the device credentials in that block go
  out in the clear.
- **Affected paths:** HLD §7 `gnmic → Device`.
- **Prerequisites:** SEC-002.1 (the rule), SEC-003.5 (for mTLS to capable
  targets).
- **Implementation steps:** (1) delete the global `skip-verify`; (2) give each
  target an explicit `tls-ca` (pinned device CA) or a declared exception with
  owner + expiry; (3) add the `secpolicy` production rule prohibiting
  `skip-verify`/`insecure` anywhere in the rendered gnmic config; (4) generate
  the target blocks from the policy object rather than hand-editing (the
  enforcement point named in `transport-encryption-2026-08-04.md` §5).
- **Files likely affected:** `deployment/docker/gnmic/gnmic.yaml`,
  `deployment/docker/docker-compose.yml`, `src/backend/secpolicy/`.
- **Tests:** a `secpolicy` rule test that scans the committed gnmic config;
  `tests/test_gnmi_fidelity.py` (exists) must still pass — it is the guard that
  the subscription paths keep producing the expected leaves.
- **Acceptance criteria:** no global skip-verify; every target either verifies a
  CA or carries a dated exception; CI fails on reintroduction.
- **Rollout:** per target, since each needs its device's trust anchor.
- **Rollback:** restore the exception for the specific target (never globally).
- **Security impact:** closes a MITM path and a credential-exposure path on the
  device management network.
- **Telemetry impact:** **at risk per target** — a target whose CA is wrong
  stops subscribing, and gNMI metrics feed VictoriaMetrics
  (`gnmic → VM remote_write`). Pair with SEC-010's sample-count assertions.
- **Tenant impact:** none; gNMI targets map to devices which map to tenants
  downstream, unchanged.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-002.1 ·
  **Approval:** **yes** — changes device-facing configuration.

### SEC-016.2 — mTLS to capable targets

- **Title:** Present a client certificate to gNMI devices that support it
- **Objective:** HLD §7 target authn "device cert or pinned CA", mTLS preferred.
- **Prerequisites:** SEC-016.1, SEC-003.5.
- **Implementation steps:** issue a collector client certificate from the device
  intermediate; configure per-target `tls-cert`/`tls-key`; keep CA-only
  verification for targets that cannot do mTLS, as a declared exception.
- **Files likely affected:** `deployment/docker/gnmic/gnmic.yaml`,
  `deployment/docker/docker-compose.yml`.
- **Tests:** `tests/test_gnmi_fidelity.py`; a config-scan test that every target
  is either mTLS or has an exception with an expiry.
- **Acceptance criteria:** capable targets are mutually authenticated.
- **Rollout / rollback:** per target; revert to CA-only.
- **Security impact:** device-side authentication of the collector.
- **Telemetry impact:** at risk per target.
- **Tenant impact:** none.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-016.1,
  SEC-003.5 · **Approval:** **yes** — customer devices.

---

## SEC-017 — Flow-lane segmentation + honest declaration

**Phase 2+ (was Phase 5) · V1 = `.2` only · Complexity M · Owner: SRE + platform
eng · Approval: yes.**

> `.1` (exporter allowlist) executes in Phase 2+. **`.2` stays v1** — flows can
> never be encrypted, so stamping `transport_authenticated=false` plus writing
> the network-layer segmentation guidance *is* the v1 deliverable for this lane.

> HLD §6.6 is explicit: NetFlow/IPFIX/sFlow **cannot** be secured. This epic
> buys segmentation, allowlisting and honesty — not encryption. No item here may
> imply otherwise in UI, docs, or evidence.

### SEC-017.1 — Exporter allowlist and rate limiting — **PHASE 2+**

- **Title:** Drop flows from unknown exporters
- **Objective:** HLD §7 `Device → goflow2`: "exporter allowlist only", drop
  unknown exporters.
- **Current problem:** goflow2 listens on UDP 2055/4739/6343 and accepts from
  anyone; `sampler_address` is spoofable and is one of the emitted fields
  (`deployment/docker/goflow2/goflow2.yaml:34`). **Critical implementation
  note:** that YAML "is NOT mounted into the container" — its own header (:3-11)
  states the compose `command:` flags are authoritative and the file is
  reference documentation for the field schema. Editing the YAML alone changes
  nothing; this exact trap already cost an audit once (F-49).
- **Affected paths:** HLD §7 `Device → goflow2`.
- **Prerequisites:** SEC-001.1.
- **Implementation steps:** (1) implement the allowlist where it can actually be
  enforced — goflow2 flags if supported, otherwise at the container network /
  host firewall layer, or in the `vector-router` flow transform where the
  existing spoof-bounding lives; (2) rate-limit per exporter; (3) count drops
  by reason; (4) document that the real control is network-layer (management
  VRF/VLAN, ACLs) per HLD §6.6 and R6.
- **Files likely affected:** `deployment/docker/docker-compose.yml` (goflow2
  `command:`), `deployment/docker/vector-router/vector.yaml`,
  `deployment/docker/goflow2/goflow2.yaml` (documentation only — say so in the
  commit), `docs/security/` deployment guidance.
- **Tests:** a VRL/harness test (`scripts/vrl-harness.py`) that a flow from a
  non-allowlisted exporter is dropped and counted; an assertion that allowlisted
  exporters are unaffected.
- **Acceptance criteria:** unknown exporters are dropped and counted; known ones
  are unaffected; the drop reason is queryable.
- **Rollout:** count-only first (the exporter population is not fully known),
  then enforce.
- **Rollback:** empty allowlist = accept all (must be an explicit, declared
  configuration, not the default).
- **Security impact:** bounds T1 for the one lane that can never be
  authenticated.
- **Telemetry impact:** **at risk** — an exporter missing from the allowlist
  disappears entirely, and UDP gives no feedback to the device. Count-only phase
  is mandatory.
- **Tenant impact:** flows carry tenant attribution derived in `vector-router`;
  dropping unknown exporters cannot cross tenants, but the drop counter must be
  tenant-scoped where it is surfaced.
- **Complexity:** M · **Owner:** SRE · **Dependencies:** SEC-001.1 ·
  **Approval:** **yes** — can drop telemetry from customer devices.

### SEC-017.2 — Stamp and declare the unauthenticated flow lane — **V1 (honesty, C3)**

> Same standalone-ordering note as SEC-014.3: in v1 this ships without `.1`,
> because flows can never be encrypted and the labelling is the deliverable. The
> network-layer segmentation guidance (management VRF/VLAN, ACLs) ships as
> documentation with it.

- **Title:** `transport_authenticated=false` on every flow record
- **Objective:** HLD §6.6 — no claim of cryptographic authenticity anywhere.
- **Current problem:** flow records carry no transport-authenticity marker, so a
  spoofed flow is indistinguishable from a real one in RCA evidence.
- **Prerequisites:** SEC-017.1.
- **Implementation steps:** stamp the field in the flow transform; register the
  permanent declared exception (protocol-level, no expiry is achievable — record
  it as `protocol_cannot_encrypt` with the network-layer mitigations named);
  surface it in SEC-021.
- **Files likely affected:** `deployment/docker/vector-router/vector.yaml`,
  `deployment/docker/opensearch/index-templates.json`, ClickHouse flow schema,
  `src/backend/` evidence rendering.
- **Tests:** VRL harness field test; a mapping test (flat field name — dotted-key
  gotcha); an evidence-rendering test that flow-derived evidence is marked
  unauthenticated.
- **Acceptance criteria:** every flow record is marked; RCA never presents a
  flow as cryptographically authentic.
- **Rollout / rollback:** additive field.
- **Security impact:** honesty; prevents overclaim in RCA.
- **Telemetry impact:** low; mapping risk only.
- **Tenant impact:** none.
- **Complexity:** S · **Owner:** platform eng · **Dependencies:** SEC-017.1 ·
  **Approval:** no (additive metadata).

---

# PHASE 6 — Automated rotation

*HLD §9: Deps 2 · Risk med · **Tests: telemetry continuity across rotation is
the acceptance criterion that matters most** · Done when dual-root rotation is
exercised in staging without loss.*

---

## SEC-019 — Certificate and credential rotation

**Phase 6 · V1 = `.1`; `.2` Phase 2+ · Complexity L · Owner: SRE + security eng ·
Approval: yes.** *(The existing CA already auto-rotates — v1's job is to prove it
does so without dropping data, not to build rotation.)*

### SEC-019.1 — Leaf rotation with proven telemetry continuity — **V1 (B6)**

- **Title:** Prove the TTL/2 reissue loop does not drop data
- **Objective:** 24 h leaf TTL with an 8 h renew-before window (HLD §6.3
  `rotation`), with continuity proven, not assumed.
- **Current problem:** the reissue loop exists (`src/backend/tls_ca.go`, ~TTL/2,
  with `tlsconfig/reload.go` hot-swapping) and is unit-tested — but it has
  **never run against a live multi-client stack**, because the whole PKI is
  dormant. HLD §5 T18 notes expired-certificate outage becomes MED once TLS is
  enabled. The riskiest consumers are the ones with no application-level
  retry-and-buffer: goflow2 (UDP in, no upstream buffer) and the Kafka clients.
- **Affected paths:** every mTLS hop.
- **Prerequisites:** SEC-003 complete; the mTLS hops from Phases 1, 3, 4 live.
- **Implementation steps:** (1) shorten TTLs in a staging stack to force
  rotations in minutes; (2) drive load through every lane; (3) assert per-lane
  event counts across ≥3 rotations; (4) add expiry alerting off the existing
  `netops_tls_cert_expiry_seconds` gauge (`tls_server.go:148-150`); (5) add a
  trust-store age/drift metric (T19).
- **Files likely affected:** `src/backend/tls_ca.go`,
  `src/backend/tlsconfig/reload.go`, `src/config/rules.yaml` (alert rules),
  `tests/` (a rotation continuity suite).
- **Tests:** a rotation-continuity integration test (no loss, no duplicates, no
  out-of-order) per lane; a hot-reload unit test in `tlsconfig`; an alert-rule
  test that a cert within `renew_before` fires.
- **Acceptance criteria:** three consecutive rotations with zero event loss on
  every lane; expiry alert fires before, not after.
- **Rollout:** staging only until proven.
- **Rollback:** lengthen TTLs (a configuration change).
- **Security impact:** makes short TTLs (the chosen substitute for revocation)
  operationally safe.
- **Telemetry impact:** **the whole point of the item** — an unproven rotation is
  a scheduled outage.
- **Tenant impact:** none.
- **Complexity:** M · **Owner:** SRE · **Dependencies:** SEC-003 ·
  **Approval:** **yes** — changes certificate lifecycle in production.

### SEC-019.2 — Dual-root CA rotation and emergency procedure — **PHASE 2+**

> Follows SEC-003.4 (offline root), which the steer defers. Kept in full — and
> note the residual v1 risk it leaves open: with the in-process CA, a compromise
> of the API process is a compromise of the CA, and v1 has **no fast remedy**
> beyond re-creating the CA and reissuing every leaf. That is an accepted v1
> tradeoff, and it must be written into the runbook (SEC-024.2) rather than left
> implicit.

- **Title:** Rotate the CA without an outage, and be able to do it fast
- **Objective:** Overlapping trust window (HLD §6.3, 7 d) plus a documented
  emergency rotation for CA compromise (T11).
- **Current problem:** there is no CA-rotation procedure at all; `caValidity` is
  10 years and the only rotation story in `tls_ca.go` is "short TTLs +
  re-issue-on-boot". A compromised CA today has no fast remedy.
- **Prerequisites:** SEC-003.4, SEC-019.1.
- **Implementation steps:** (1) support two trust anchors simultaneously
  (`tlsconfig/trust.go` + the `TLS_FEDERATED_BUNDLES` mechanism made reachable
  in SEC-003.2 is the closest existing primitive — verify whether it can carry a
  second same-domain root or whether a distinct multi-root bundle is needed;
  do **not** assume); (2) reissue all leaves from the new intermediate;
  (3) narrow the bundle; (4) write the emergency runbook; (5) also cover PSK and
  `INGEST_TOKEN`-successor rotation (`scripts/secret_rotation.py` and
  `tests/test_secret_rotation.py` already exist — extend them rather than
  building a parallel mechanism).
- **Files likely affected:** `src/backend/tlsconfig/trust.go`,
  `src/backend/tls_ca.go`, `scripts/secret_rotation.py`,
  `docs/runbooks/secret-rotation.md`, a new CA-rotation runbook.
- **Tests:** a dual-root acceptance test; a narrowing test proving old leaves are
  refused after the window; `tests/test_secret_rotation.py` extension; a staging
  drill.
- **Acceptance criteria:** a full CA rotation completes in staging with zero
  telemetry loss and is documented step-by-step.
- **Rollout:** staging drill before any production rotation.
- **Rollback:** widen the bundle back to both anchors.
- **Security impact:** turns T11 from unrecoverable into a procedure.
- **Telemetry impact:** **at risk if the window is narrowed early** — that is
  the single failure mode, and the drill exists to rehearse it.
- **Tenant impact:** none.
- **Complexity:** L · **Owner:** security eng + SRE · **Dependencies:**
  SEC-003.4, SEC-019.1 · **Approval:** **yes**.

---

# PHASE 7 — Kubernetes security (design only)

---

## SEC-022 — Kubernetes security future-state

**Phase 2+ (was Phase 7) · Complexity L · Owner: platform eng · Approval: no
(design only — producing a design document changes nothing at runtime).**

> Deferred with #114 and with SPIRE/Vault/cert-manager per the steer ("no new
> operational dependencies in v1"). Kept in full because the *identity-string
> stability* requirement it records is what makes the v1 in-process CA a safe
> choice rather than a dead end.

- **Title:** Security design for the future k8s substrate
- **Objective:** Ensure the identity model, ACLs and policies carry over
  unchanged when #114 lands, and record where a mesh (deferred per HLD §8) would
  and would not help.
- **Current problem:** **no Kubernetes manifests exist anywhere in the repo** —
  verified: no Helm chart, no kustomize, no manifests; tracker **#114**
  ("Kubernetes deployment packaging", High, "⏳ not started — confirmed absent
  2026-07-20; a project, not a task") is the owning row. Any mesh-based security
  claim today is vacuous, which is precisely why HLD §8 defers it.
- **Affected paths:** none today.
- **Prerequisites:** #114 for implementation; SEC-003.3 for the identity mapping
  (design can start once the identity table exists).
- **Implementation steps (design deliverables only):** (1) map each SPIFFE
  workload identity to a future ServiceAccount, keeping the **identity string
  stable across substrates** (HLD §6.2 requires this); (2) specify
  NetworkPolicies per trust boundary; (3) specify secret handling
  (`REQUIRE_SEAL` equivalent, external secret stores); (4) specify where
  cert-manager replaces `tls_ca.go` issuance **without changing identities**;
  (5) record the mesh re-evaluation criteria from HLD §8; (6) note that the
  datastore-authorization work (Kafka ACLs, CH row policies, OS roles) is
  substrate-independent and must not be re-litigated as "the mesh will handle
  it" — HLD §8's explicit anti-goal.
- **Files likely affected:** `docs/security/` (new design doc), `docs/adr/`
  (ADR-SEC-004 record), `docs/TRACKER.md` (cross-reference on #114).
- **Tests:** none (no code). The design must state its own acceptance tests for
  when #114 executes.
- **Acceptance criteria:** the identity strings in the k8s design are
  byte-identical to the Compose ones; every HLD §7 authorization control has a
  named k8s equivalent or an explicit "unchanged, application-layer".
- **Rollout / rollback:** documentation.
- **Security impact:** prevents a substrate migration from silently dropping
  controls.
- **Telemetry impact:** none. · **Tenant impact:** none.
- **Complexity:** L · **Owner:** platform eng · **Dependencies:** #114,
  SEC-003.3 · **Approval:** no.

---

# PHASE 8 — Security UI, compliance, fault injection

*HLD §9: Deps 1–6. Read-only UI first. Done when posture is visible, exceptions
age visibly, and fault-injection suites run in CI.*

---

## SEC-020 — Security observability

**Phase 8 → executed in v1 · V1 · Complexity M · Owner: platform eng + SRE ·
Approval: no (additive
metrics/audit; no listener, credential, or policy change).**

### SEC-020.1 — A single security metric and audit vocabulary

- **Title:** Name the security signals once
- **Objective:** Every enforcement point emits a consistently-named,
  tenant-scoped metric and audit event, so posture is queryable.
- **Current problem:** only three security metrics exist, all on one hop:
  `netops_tls_cert_expiry_seconds`, `netops_tls_handshake_errors_total`,
  `netops_tls_identity_rejected_total` (`src/backend/tls_server.go:148-157`).
  There is no metric for ACL denials, ingest rejections, trap policy rejections,
  exporter drops, sealing-key fetches, or declared-exception ageing — so none of
  the enforcement epics above can prove they are working without inventing
  their own vocabulary ad hoc.
- **Affected paths:** all.
- **Prerequisites:** SEC-002.1 (rule ids) and, for each signal, its owning epic.
- **Implementation steps:** (1) define the naming scheme (`netops_sec_*`) and
  the label set (never include secrets, tokens, key material, or PII —
  CLAUDE.md §8); (2) register the metrics each epic will emit; (3) define the
  audit-event types for security-config changes (T22) using the existing
  `src/backend/audit.go` store and its tenant-scoped listing
  (`auditScopedList`); (4) add an ageing counter for declared exceptions.
- **Files likely affected:** `src/backend/audit.go`, the metrics handler,
  `src/backend/secpolicy/`, `scripts/audit_metric_contract.py` (an existing
  metric-contract auditor — extend it rather than adding a parallel one).
- **Tests:** a metric-contract test (via `scripts/audit_metric_contract.py`)
  asserting every declared security metric is emitted and correctly typed; an
  audit test asserting security-config changes are recorded and are
  tenant-scoped; a redaction test asserting no credential appears in a metric
  label or audit payload.
- **Acceptance criteria:** every enforcement point in SEC-005…018 has a
  registered metric and audit event; nothing leaks a secret.
- **Rollout / rollback:** additive.
- **Security impact:** makes enforcement observable — without this, a
  fail-closed control that silently mis-fires is indistinguishable from a quiet
  network (the exact failure mode `docs/audit/INVARIANTS.md` §2 was written
  about).
- **Telemetry impact:** none (adds signals).
- **Tenant impact:** **audit and metric surfaces are data-returning surfaces** —
  they must be scoped by `principalTenant` and default-closed. An
  `org_isolation_test.go`-style test is required for any new security listing
  endpoint.
- **Complexity:** M · **Owner:** platform eng · **Dependencies:** SEC-002.1 ·
  **Approval:** no.

### SEC-020.2 — Alert rules and the exception-ageing report

- **Title:** Alert on posture drift; make declared plaintext age visibly
- **Objective:** HLD §11 standing risk — "declared plaintext degenerating into a
  rubber stamp without the ageing report".
- **Current problem:** `src/config/rules.yaml` has infrastructure alerts (e.g.
  `up{job=~"opensearch|clickhouse|victoria|postgres|redis"} == 0` at :648) but
  nothing about certificates, denials, or exceptions.
- **Prerequisites:** SEC-020.1.
- **Implementation steps:** add rules for cert expiry within `renew_before`,
  handshake-error rate, identity-rejection rate, ACL-denial rate, trap/exporter
  policy rejections, trust-bundle age (T19); generate a periodic
  exception-ageing report ("accepted N months ago, never revisited").
- **Files likely affected:** `src/config/rules.yaml`, `src/backend/reports/`,
  `scripts/verify-critical-alert-channel.sh` (existing channel verifier).
- **Tests:** alert-rule unit tests (promtool is already pinned in
  `preflight-configs.sh` for rules validation); a report test.
- **Acceptance criteria:** each rule fires on a synthetic condition; the ageing
  report lists every declared exception with its owner and age.
- **Rollout / rollback:** additive.
- **Security impact:** keeps the honesty mechanism honest.
- **Telemetry impact:** none. · **Tenant impact:** report must be tenant-scoped.
- **Complexity:** S · **Owner:** SRE · **Dependencies:** SEC-020.1 ·
  **Approval:** no.

---

## SEC-021 — Security status UI + exportable posture report

**Phase 8 → executed in v1 (read-only half) · V1 = `.1`; `.2` Phase 2+ ·
Complexity L · Owner: frontend + platform eng · Approval: `.2` yes.**

> **Promoted by the owner steer.** This is the customer-visible deliverable of
> the whole programme: *"I want to show customers this is a secure environment
> where all components are transported via TLS securely."* A posture the operator
> cannot show is a posture the customer will not believe. `.1` gains an
> **exportable report** requirement (see below) and ships in v1, **read-only**.
> `.2` (policy editing, PSK issuance) is Phase 2+ — editing can change
> enforcement and drop telemetry, which is the opposite of a v1 demo artefact.

### SEC-021.1 — Read-only transport posture view **+ exportable report** (V1)

- **Title:** Show declared vs observed transport per peer, and export it
- **Objective:** `docs/design/transport-encryption-2026-08-04.md` §6 Phase 1/3 —
  ship observation before enforcement; answer "how exposed are we?" without
  reading six config files.
- **Current problem:** there is **no UI for any of this**: no CA/SVID visibility,
  no per-peer transport view, no exception list. The admin surfaces that exist
  are `src/frontend/src/tabs/admin.tsx`, `Settings.tsx`, and
  `ProcessorsAdmin.tsx`; none covers transport security.
- **Affected paths:** none (read-only).
- **Prerequisites:** SEC-020.1 (the data must exist before it can be rendered).
- **Implementation steps:** (1) a backend read endpoint returning the posture
  table (peer, channel, declared policy, observed transport, last verified,
  drift, exception owner/expiry), **tenant-scoped and default-closed**;
  (2) platform-global rows (intra-stack service hops, CA/SVID state) gated by
  `requirePlatformAdmin`/`requireCrossTenant`, **not** `requireAdmin` — a tenant
  admin holds `administration:admin` and a scope-blind gate here is a privilege
  leak (CLAUDE.md §3a.3); (3) a read-only React view under the admin tab;
  (4) **an exportable posture report** (the customer-facing artefact): every
  Correlix-owned path with TLS ✓/✗, negotiated protocol version, the peer's
  SPIFFE identity, and its certificate expiry — plus a clearly separated section
  listing device lanes that are **not** authenticated, with the declared reason.
  Reuse the existing report machinery (`src/backend/reports/`, gotenberg is
  already in compose) rather than building a second export path.
- **Files likely affected:** a new handler in `src/backend/`,
  `src/backend/audit.go` (change trail), `src/frontend/src/tabs/admin.tsx`,
  a new page under `src/frontend/src/pages/`.
- **Tests:** a Go HTTP isolation test on the new endpoint modelled on
  `src/backend/org_isolation_test.go` (own-only list, cross-tenant get → 404,
  `as_tenant` into another org ignored) — **required, per §3a.5, no exceptions**;
  a gate test proving a tenant admin cannot read platform-global rows; frontend
  component tests.
- **Acceptance criteria:** the posture of every hop is visible; a tenant sees
  only its own peers; platform rows require platform admin.
- **Rollout:** read-only, additive.
- **Rollback:** remove the route.
- **Security impact:** turns posture into something an operator can act on;
  also surfaces the unauthenticated-lane markers from SEC-014.3/017.2.
- **Telemetry impact:** none. · **Tenant impact:** **new data-returning
  surface — full §3a treatment mandatory.**
- **Complexity:** M · **Owner:** frontend + platform eng · **Dependencies:**
  SEC-020.1 · **Approval:** no (read-only).

### SEC-021.2 — Policy editing, plaintext-acceptance dialog, and PSK issuance — **PHASE 2+**

> Read-only in v1 per the steer. This item also carries the policy-object store
> that closing note 3 flags as homeless — when it is scheduled, split the store
> out of the UI epic first.

- **Title:** Make the policy object editable with step-up and a required reason
- **Objective:** `transport-encryption-2026-08-04.md` §6 Phase 3.
- **Current problem:** none of the policy object exists yet as storage or API;
  this item is the write half and it can change enforcement, so it is
  deliberately separated from the read half.
- **Prerequisites:** SEC-021.1 and the policy-object storage (which is itself an
  owner decision — see closing note 3: the HLD adopts the policy *model* but
  does not assign an epic to *building the store*).
- **Implementation steps:** (1) tenant-scoped, versioned, audited policy storage
  with the `tenant_iso` FORCE-RLS migration and `withTenant` access (CLAUDE.md
  §3a.4); (2) step-up authentication for narrowing/widening; (3) a
  plaintext-acceptance dialog that **requires** reason + owner + expiry; (4) PSK
  issuance/rotation UI.
- **Files likely affected:** a new policy package + migration under
  `src/backend/`, `src/frontend/src/pages/`, `src/backend/audit.go`.
- **Tests:** RLS migration test; `org_isolation_test.go`-template cross-org test
  (own-only list, cross-tenant put/delete → 404, `as_tenant` ignored); a test
  that saving `accept ⊇ plaintext` without a reason/owner/expiry is **rejected**;
  step-up tests.
- **Acceptance criteria:** no policy can be widened to plaintext without a
  recorded, expiring justification; cross-tenant edits are impossible.
- **Rollout:** behind a feature flag, read-only default.
- **Rollback:** disable the flag.
- **Security impact:** makes the honesty clause enforceable in the product.
- **Telemetry impact:** **indirect but real** — an operator narrowing a policy
  can stop a device's collection. The dry-run diff (SEC-015.2 pattern) must be
  present in the UI.
- **Tenant impact:** new tenant-scoped store — full §3a treatment.
- **Complexity:** L · **Owner:** frontend + platform eng · **Dependencies:**
  SEC-021.1 · **Approval:** **yes** — edits change enforcement and can drop
  telemetry.

---

## SEC-023 — Fault injection + continuous security validation

**Phase 8 · V1 · Complexity L · Owner: platform eng + SRE · Approval: no (CI and
staging only; must never run against production).**

### SEC-023.1 — Negative-path security suite in CI

- **Title:** Prove the controls fail closed
- **Objective:** Every fail-closed claim has a test that breaks it deliberately.
- **Current problem:** the repo's own invariants register makes the case: "285 Go
  test files were green throughout, because every one of them tested the happy
  path", and §2 records that ~60 instances of "an error routed to the same
  branch as a benign empty state" were found in one audit. A security control
  that is only tested on its success path is a preference.
- **Prerequisites:** SEC-006, SEC-008, SEC-019 (there must be controls to break).
- **Implementation steps:** build a suite that, per control, injects: expired
  cert, wrong-SAN cert, revoked/unknown identity, missing trust bundle, wrong
  ACL, disabled auth plugin, unsealed vault, unknown SNMP sender, unknown flow
  exporter — and asserts the system **refuses and counts**, never "logs and
  accepts".
- **Files likely affected:** `tests/` (new suite), `.github/workflows/`
  (a security-fault-injection job, non-blocking first then blocking),
  `src/backend/*_test.go` for the in-process cases.
- **Tests:** the suite is the test. Each case asserts (a) refusal, (b) the
  correct metric increments, (c) an audit event exists.
- **Acceptance criteria:** removing any single enforcement check makes at least
  one case fail.
- **Rollout:** non-blocking CI job first, then blocking (§12).
- **Rollback:** mark the job non-blocking.
- **Security impact:** moves the transport invariants from GATE to **BUILD** tier
  in `docs/audit/INVARIANTS.md` — the strongest tier the repo defines.
- **Telemetry impact:** none — CI and staging only. **The suite must be
  structurally incapable of targeting production** (no production endpoints in
  its configuration).
- **Tenant impact:** includes cross-tenant negative cases; must not create
  real tenant data.
- **Complexity:** L · **Owner:** platform eng · **Dependencies:** SEC-006,
  SEC-008, SEC-019 · **Approval:** no.

### SEC-023.2 — Continuous posture verification against the running stack

- **Title:** Re-verify the deployed posture, not just the committed config
- **Objective:** Catch drift between what is committed and what is running — the
  "landmine" class `scripts/preflight-configs.sh` was written for (a service up
  11 days on an old in-memory config).
- **Current problem:** `preflight-configs.sh` validates **committed** configs on
  a fresh load; nothing probes the **running** stack's actual transport posture.
  A hand-edited container would go unnoticed.
- **Prerequisites:** SEC-023.1, SEC-020.1.
- **Implementation steps:** a probe (extending the existing
  `scripts/stack-watchdog.sh` pattern and obeying `scripts/CLAUDE.md` §16) that
  connects to each declared hop, records the negotiated protocol/cipher/peer
  identity, compares it to the inventory, and alerts on drift. It must never
  swallow an error (§16.1) and must be safe under cron's hostile environment
  (§16.2).
- **Files likely affected:** `scripts/` (new probe), `src/config/rules.yaml`,
  `docs/security/transport-inventory.yaml`.
- **Tests:** a shell test per §16.3; a drift-detection test with a deliberately
  mismatched hop.
- **Acceptance criteria:** a hop whose live transport differs from its declared
  policy raises an alert with the hop name and both values.
- **Rollout:** observe-only first.
- **Rollback:** disable the cron entry.
- **Security impact:** closes the config-vs-reality gap.
- **Telemetry impact:** none — it is a read-only prober. Must not open
  connections aggressive enough to affect the hops it probes (rate-limit).
- **Tenant impact:** none.
- **Complexity:** M · **Owner:** SRE · **Dependencies:** SEC-023.1, SEC-020.1 ·
  **Approval:** no.

---

## SEC-024 — Documentation + runbooks

**Phase 0 → 8 (cross-cutting) · V1 · Complexity M · Owner: platform eng ·
Approval: no.**

### SEC-024.1 — Correct the security-relevant docs (Phase 0)

- **Title:** Make the docs match the code before anyone acts on them
- **Objective:** Ship with SEC-001.2; explicitly permitted before approval.
- **Current problem:** covered in SEC-001.2 (ARCHITECTURE.md Telegraf; the
  `preflight-configs.sh` header naming a non-existent workflow;
  `tls-architecture.md`/`tls-mtls.md` presenting dormant machinery as landed).
- **Prerequisites:** SEC-001.1.
- **Implementation steps / files / tests / acceptance:** as SEC-001.2.
- **Complexity:** S · **Approval:** no.

### SEC-024.2 — Operational runbooks for each new control

- **Title:** One runbook per irreversible operation
- **Objective:** Every operation that can take the stack down has a written,
  rehearsed procedure.
- **Current problem:** `docs/runbooks/` has 12 runbooks (backup-restore,
  secret-rotation, tls-mtls, storage-and-volume-operations, …). A
  `docs/runbooks/security/` directory has since appeared with
  `bootstrap-pki.md` and `rotate-workload-ca.md` (verified 2026-08-04) — those
  two cover SEC-003.1/.3 and SEC-019. Still **missing**: OpenSearch security
  bootstrap/rollback, Kafka listener cutover, "the stack refused to boot — which
  rule and how to fix it", the offline CA ceremony (Phase 2+), and device-lane
  migration (Phase 2+). The two that exist must also be reconciled with §0a —
  `bootstrap-pki.md` must state the v1 in-process-CA path, not an offline
  ceremony.
- **Prerequisites:** the owning epic for each runbook.
- **Implementation steps:** author one runbook per: CA ceremony (SEC-003.4),
  emergency CA rotation (SEC-019.2), OpenSearch security bootstrap + rollback
  (SEC-008), Kafka cutover + rollback (SEC-006), "the stack refused to boot —
  which rule and how to fix it" (SEC-002.3), device secure-lane onboarding
  (SEC-014.2/016), declared-exception process (SEC-021.2). Update
  `docs/runbooks/tls-mtls.md` to the post-enablement reality.
- **Files likely affected:** `docs/runbooks/`,
  `docs/runbooks/first-customer-acceptance.md` (acceptance additions),
  `docs/security/`.
- **Tests:** each destructive runbook must be **rehearsed in staging** and the
  rehearsal recorded — an unrehearsed runbook is a hypothesis, exactly as
  `docs/audit/INVARIANTS.md` says of an untested backup.
- **Acceptance criteria:** every approval-required item in this backlog has a
  runbook, and each has been executed once in staging.
- **Rollout / rollback:** documentation.
- **Security impact:** reduces the chance that an emergency procedure is
  invented under pressure.
- **Telemetry impact:** none. · **Tenant impact:** none.
- **Complexity:** M · **Owner:** SRE + platform eng · **Approval:** no.

### SEC-024.3 — ADRs for the decisions actually made

- **Title:** Record each HLD §11 decision as an ADR
- **Objective:** One ADR per decision actually made, each recording the decision,
  the rejected alternatives from HLD §10, and the cost accepted.
- **Current status (verified 2026-08-04, changed during the writing of this
  backlog):** the ADR set now **exists** — `docs/adr/ADR-SEC-001` … `ADR-SEC-008`
  (transport-policy model, PKI trust domains, workload-identity platform, native
  TLS vs service mesh, Kafka authentication model, device identity model,
  secret-sealing provider, production fail-closed policy), alongside the
  pre-existing `0001-privileged-network-operations-isolation.md`. Two security
  runbooks also landed: `docs/runbooks/security/bootstrap-pki.md` and
  `rotate-workload-ca.md`. **This item therefore changes from "write them" to
  "reconcile them with the §0a owner steer"** — each ADR must record the option
  the owner actually chose (in-process CA for v1, mTLS for Kafka, boot refusal,
  intra-stack-only v1 scope) rather than leaving the choice open.
- **Prerequisites:** the §0a decisions (now made).
- **Implementation steps:** (1) read each existing ADR against §0a and update its
  Decision section to the chosen option, moving the unchosen options into
  "Alternatives considered"; (2) mark ADR-SEC-006 (device identity) as
  **deferred to Phase 2+** with the reason; (3) add the missing ADR for HLD §11
  decision 6 (backup encryption) or record explicitly that it is unresolved;
  (4) cross-link each ADR to the SEC items it governs.
- **Files likely affected:** `docs/adr/ADR-SEC-001`…`ADR-SEC-008`,
  `docs/runbooks/security/`.
- **Tests:** a link-integrity check that every ADR referenced by the HLD/LLD
  exists (the same class of check as SEC-001.1's evidence-liveness rule).
- **Acceptance criteria:** no document references a non-existent ADR.
- **Complexity:** S · **Owner:** owner-decision + platform eng ·
  **Approval:** no (recording a decision is not making one).

---

## V1 COMPLETION DEFINITION

**What must be true before we tell a customer "all Correlix components
communicate over TLS".** Every line is a testable assertion, not a claim. The
sentence is only defensible if all of A, B and C hold — C is what keeps it
honest.

### A. Every Correlix-owned network path is TLS, mutually authenticated, and identified

| # | Path | Must be true | Proven by | Status (2026-08-12; "ph." = assurance-report phase) |
|---|---|---|---|---|
| A1 | Browser → nginx | TLS 1.2+, HSTS, PFS, no session tickets; **no plaintext `:8000` published** | SEC-004.1/.2 | **PARTIAL** — TLS/HSTS live (ph. 5/12); the LAB dropped `:8000` 2026-08-09 (`ports: !override`, 443-only), but the SHIPPED `compose.tls.yml` still publishes `:8000` until `install.py` messaging is TLS-aware (`browser-nginx` inventory row) — the no-plaintext clause is NOT yet held for a fresh install |
| A2 | nginx → api | mTLS, SAN allowlist, plaintext API listener removed | SEC-005.1/.2 | **HELD** (live since 2026-08-04) — no-cert handshake refused; wrong-but-valid identity refused AND counted (ph. 6) |
| A3 | api ↔ correlation | mTLS; no unauthenticated HTTP surface remains | SEC-005 / backend client | **HELD** — correlation serves its SVID on :8443 (ph. 5); peer scoping enforced (monitor SVID: 200 on `/metrics`, 403 on app paths — ph. 6) |
| A4 | every Kafka client ↔ Kafka | mTLS with a per-service SVID; **no PLAINTEXT listener**; `allow.everyone.if.no.acl.found=false`; auto-create off | SEC-006.1/.2/.3, SEC-007.1/.2 | **HELD** — enforce wave 2026-08-09 (`ebadd2af`): 9092 REMOVED, default-deny, auto-create off; declared exception: goflow2 produces TLS-anon on FLOWS:9095, ACL-bounded to Write `netops.flows` (owner option-1; ANONYMOUS sees 1/17 topics — ph. 6) |
| A5 | api / vector-router / correlation ↔ OpenSearch | HTTPS with the Security plugin on; **no anonymous access** | SEC-008.1/.2 | **HELD in the owner-accepted shape** — plugin on; anon 401, write-only-read 403 (ph. 6); clients are per-identity basic-in-TLS, NOT client-cert mTLS (F-3 decision, recorded in the rows' `target.notes`) |
| A6 | api / vector-router / correlation ↔ ClickHouse | TLS; credentials never in the clear | SEC-009.1 | **HELD** — 8443 + 9440 serve the clickhouse SVID (ph. 5) |
| A7 | api / gnmic / vmalert ↔ VictoriaMetrics | via vmauth over TLS; no unauthenticated read or write | SEC-010.1 | **HELD** — per-user scoping proven: write-only users get 400 no-route on query paths, wrong password 401 (ph. 11) |
| A8 | api / correlation ↔ Postgres | `sslmode=verify-full`; distinct non-`BYPASSRLS` roles | SEC-011.1/.2 | **HELD** — plus server-side enforcement: `hostssl` refuses plaintext TCP (F-4 fix 2026-08-10; `TestPostgresRefusesPlaintextTCP`); `TestAppRoleCannotBypassRLS` live 6/6 (F-12). Correlation holds NO postgres DSN at all (SEC-011.2). Adjacent honesty row: keycloak→postgres negotiates TLS without CA/hostname verification (F-5) |
| A9 | api / prober ↔ Valkey | AUTH required **and** TLS | SEC-012.1/.2 | **HELD** — TLS 6380 is the only listener; NOAUTH / WRONGPASS / plaintext-6379-refused all proven (ph. 6) |
| A10 | collectors / prober / cloud-ingest → Vector lanes | per-client identity (no shared `INGEST_TOKEN`) and TLS on all four `http_server` lanes | SEC-013.1/.2 | **HELD** — client cert REQUIRED on all four lanes (ph. 5); per-lane tokens with the shared token opening no lane (4× per-lane 200 / shared 401, proven live 2026-08-09) |
| A11 | vector-router → api (sealing keys) | **mTLS with a dedicated, scope-limited identity** — no tenant key material over plaintext | SEC-018.1 | **HELD, proven feature-ON** — router-SVID 200 / wrong SVID 401 / stolen token 401 / no cert refused / feature-off 404 (ph. 11); end-to-end sealed-fields PASS after F-6/F-7 (2026-08-11) |
| A12 | syslog-ng → vector-aggregator | TLS on :6601 | SEC-014.1 *(the one internal hop that sits in the syslog epic — pull it into v1 with SEC-013.2)* | **HELD, stronger than specified** — F-1 fix 2026-08-11: mesh TLS with a REQUIRED client certificate; `test_syslog_hop_serves_and_requires_mesh_tls`; tlsprobe watches the endpoint |

### B. The claim is enforced, not asserted

| # | Must be true | Proven by | Status (2026-08-12) |
|---|---|---|---|
| B1 | Production **refuses to boot** on any transport-policy violation | SEC-002.3 | **HELD for the ruled surfaces** — `internal/secprofile` 16 rules, prod boot-refusal; live fatal=0 warn=1 (BKP-001 deferred). HONEST GAP: no bus/ingest-lane rule exists — a prod boot with a plaintext bus would not be refused (INVARIANTS §8) |
| B2 | An insecure production config **fails CI** | SEC-002.2 | **BUILT; first execution pending** — preflight gates + the blocking `tls-install-boot` job (F-9 fix, `test_ci_runs_the_tls_install_path`); like all CI on this branch, actual execution awaits the owner's push |
| B3 | `TLS_INTERNAL_CA=true` without a seal provider **cannot** produce a plaintext CA key | SEC-003.1 | **HELD** since 2026-08-04 — `tls_ca.go` seal gate + 4 tests incl. the refusal-message contract |
| B4 | `REQUIRE_SEAL=true` in production; boot fails unsealed | SEC-018.2 | **HELD in substance** — sealing custody live (`SEAL_PROVIDER=swtpm`, installer default) + secprofile sealed-secrets rule (fatal in prod); the literal `REQUIRE_SEAL=true` switch exists and fails closed (`internal/vault/secrets.go`) but is not set by default — enforcement rides the validator rule |
| B5 | Every service has exactly one non-wildcard SVID; a new service without one fails CI | SEC-003.3 | **HELD** — workloadid registry (28 identities + 7 reasoned exemptions); ph. 4: 28/28 minted, exact SPIFFE SANs, zero unregistered dirs; registry membership contract-pinned (`tests/test_assurance_contracts.py`) |
| B6 | Leaf rotation is proven not to drop data (≥3 rotations, per-lane counts) | SEC-019.1 | **HELD with a stated deviation** — three consecutive rotations, distinct serials each round, zero lane interruption (ph. 10); ran at the owner-approved interim TTL=168 h with forced mints, not a literal short-TTL validity-pressure soak |
| B7 | Breaking any single control makes a negative-path test fail | SEC-023.1 | **HELD live; CI legs pending** — the negative matrix ran on the wire (ph. 6/11) and every step-3 finding carries a failed-first regression test; `-race`/staticcheck/gosec/govulncheck have NOT executed on this branch (owner push pending) |
| B8 | The **running** stack's negotiated transport matches the declared inventory | SEC-023.2 | **HELD** — achieved-vs-declared comparison over all inventory edges (ph. 3) + wire identity per endpoint (ph. 5); continuously: tlsprobe (10 endpoints) + posture join + SEC-020.2 drift alerts |

### C. Tenant isolation is untouched, and the unsecurable lanes are labelled honestly

| # | Must be true | Proven by | Status (2026-08-12) |
|---|---|---|---|
| C1 | ClickHouse row policies and Postgres FORCE-RLS behave **identically** to before; the API refuses to serve if a row policy is missing | SEC-009.2, SEC-011.2 | **HELD** — the datastore epics did not touch the tenant boundary (§0a direction); `TestAppRoleCannotBypassRLS` executed live 6/6 with the restored pgintegration suite (F-12); full Go isolation suite PASS (ph. 11) |
| C2 | Every existing isolation test passes unchanged; every new data-returning surface ships its own cross-org test | §3a.5, SEC-021.1 | **HELD** — ph. 11 isolation suite PASS; `TestEveryScopedRouteHasIsolationCoverage` build guard; the F-11 quarantine surface shipped its own guards (`TestQuarantineIndexUnreachableFromTenantPaths`, `TestQuarantineRoutesArePlatformOnly`) |
| C3 | Device lanes (syslog 514, SNMP v2c/traps, NetFlow/sFlow, gNMI `skip-verify`) carry `transport_authenticated=false` and are shown as **not authenticated** in the UI and the report | SEC-014.3, SEC-017.2 | **PARTIAL — not fully held.** The posture view lists device lanes as unauthenticated (`secobs.DeviceLaneRows`, SEC-021.1) and device-lane events carry `tenant_attribution`/`tenant_registry` stamps (F-11) plus the trap lane's `authenticated` field — but the stack-wide per-event `transport_authenticated` stamp named here does NOT exist (errata E7). Claim C8 in the claims doc stays partial accordingly |
| C4 | No UI, doc, report, or evidence chain claims cryptographic authenticity for a device lane | HLD §6.6, SEC-021.1 | **HELD (prose-level)** — claims doc §5 limitations table + the anchor sentence + posture labeling; no mechanical guard scans for such claims |
| C5 | An operator can **export** the posture report: every Correlix path TLS ✓ with peer identity and cert expiry, and device lanes listed separately as unauthenticated with the declared reason | SEC-021.1 | **HELD** — shipped `3c4c41ea` (SEC-020.1/021.1: posture visible and exportable); wire truth fed by tlsprobe |

**The exact sentence v1 earns:** *"All Correlix platform components communicate
over mutually-authenticated TLS with short-lived, per-service certificates, and
the platform refuses to start if that is not true. Telemetry arriving from your
network devices uses the protocols those devices speak — where those protocols
cannot authenticate (syslog, NetFlow/sFlow, SNMPv2c), Correlix labels the data as
unauthenticated rather than implying otherwise, and secure device lanes are the
next phase."* Anything stronger than that is not supported by v1.

**Earned? (2026-08-12):** almost, with three dated qualifiers that must
accompany the sentence until they close — (1) a fresh shipped install still
publishes plaintext `:8000` (A1); (2) "refuses to start" holds for the ruled
surfaces but no validator rule yet covers the bus/ingest lanes (B1); (3) the
"labels the data" clause is posture-view/lane-level, not a per-event
`transport_authenticated` stamp (C3). The per-claim customer wording lives in
`CORRELIX_SECURITY_CLAIMS.md` §2a, which states the same three exceptions.

---

## First three items to execute (narrowed v1)

Unchanged in *kind* by the steer — HLD §12 still permits only the inventory, the
drift corrections, the validator **in warn-only mode**, and test scaffolding
before approval — but now scoped and ordered for the v1 target. All three are
additive, reversible by `git revert`, and change **no** runtime behaviour:

1. **SEC-001.1 — Committed as-built transport inventory, scoped to the v1 path
   set (A1–A12) first.** Nothing else can be validated until one artifact states
   what each hop does. It is the only item with no prerequisites, so it is the
   unique entry point to the dependency graph. Narrowing it to the Correlix-owned
   hops first means it is useful immediately, and the device rows can be appended
   as declarations (`protocol_cannot_encrypt`) rather than blocking it.
2. **SEC-002.1 — Validator core in warn-only mode, with the v1 rule set.** The
   rules can be written and tested immediately against the current `.env` and
   `docker-compose.yml`. **Its first run is the deliverable that matters**: it
   prints the exact, non-theoretical list of what stands between today and the
   completion definition above — the honest baseline for the customer claim, and
   the input to sequencing everything else. It also proves the rule set is right
   *before* anyone approves the fail-closed flip (SEC-002.3).
3. **SEC-003.2 + SEC-003.1 — Make `TLS_FEDERATED_BUNDLES` reachable, then make
   the CA refuse to boot unsealed.** Promoted ahead of the doc work because the
   steer's "use the existing CA" decision makes these two the *entire* v1 PKI
   prerequisite, and they gate SEC-005 (the first real mTLS hop). `.2` is XS and
   purely additive (declaring an empty compose variable). `.1` is the one item
   that must land **before** anyone follows `docs/runbooks/tls-mtls.md` and
   enables `TLS_INTERNAL_CA` — otherwise the first person to turn on the mesh
   writes a plaintext CA private key to disk.

**SEC-001.2 / SEC-024.1 (documentation drift) rides along with item 1** — it is
cheap and removes active misinformation: `ARCHITECTURE.md` sends a reader to
Telegraf (a `profiles: [legacy]` service that does not run) for SNMP,
`tls-architecture.md` presents dormant machinery as enforced, and the
`preflight-configs.sh` header names a workflow that does not exist. **Do not**
rewrite `UPGRADE.md`/`STREAMING.md` — their Redpanda mentions are correct
migration history, not drift.

Everything beyond these waits on the HLD §12 review.

---

## Notes on where the HLD is thin or wrong (for the review)

> Five of these were raised against the HLD before the owner steer of §0a.
> Decisions 1, 2, 3, 4 and 7 are now **resolved** and recorded in §0a. Notes 1, 3,
> 5 and 6 below remain open; note 4 is a factual correction to the HLD.

1. **HLD §9 assigns no phase to SEC-018** (secret sealing), despite §1.1 calling
   the plaintext sealing-key fetch "the sharpest one" and §7 marking it **P0
   ⚠⚠**. Placed here in Phase 4 and confirmed **in v1** — the steer's "all
   Correlix components over TLS" claim is directly falsified by shipping
   per-tenant key material over plaintext HTTP, so this is arguably the single
   item v1 cannot omit. Still needs the phase written back into the HLD.
2. **HLD §9 Phase 1 claims "Deps: 0"** for nginx→API mTLS. That cannot hold:
   enabling that hop means enabling `TLS_INTERNAL_CA`, which per the HLD's own
   §1.1 stores the CA key in plaintext without a seal provider. SEC-005 is
   therefore filed as depending on SEC-003.1/.2/.3 — a real Phase 2 dependency
   inside Phase 1.
3. **No epic owns building the policy object store.** The HLD adopts the policy
   model (§6.3) and `transport-encryption-2026-08-04.md` §4 specifies its
   schema, but the 24 epics contain no "build the policy storage + resolution +
   API" item. It is currently smuggled into SEC-021.2 (the UI epic), which is
   the wrong home for a tenant-scoped, RLS-backed store.
4. **HLD §3 drift table is partly wrong about Redpanda.** `UPGRADE.md:61-70` is a
   legitimate migration note and `STREAMING.md:8` explicitly records the removal.
   Only the ARCHITECTURE.md/Telegraf row is genuine drift.
5. **HLD §11 decision 6 (backup encryption) has no epic** among SEC-001…024,
   although §2 puts backup encryption in scope and T20 rates backup theft
   **HIGH**. Either an epic is missing or the scope statement is too broad. The
   owner steer did not address it, so it stays open. Note it is **outside** the
   v1 completion definition — v1 claims transport security, not backup-at-rest
   security, and the customer-facing wording in §"V1 COMPLETION DEFINITION"
   deliberately does not imply otherwise.
6. **The HLD's `api → Valkey` row understates the surface.** Valkey carries
   probe paths, LLDP/BGP-LS topology and interface maps — RCA *evidence*, not
   just cache — and the publishing call sites discard their errors
   (`_ = redisSetEX(...)`), so tampering or auth failure would be silent.
