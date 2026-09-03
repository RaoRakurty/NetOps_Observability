# Project 3 — Security CTEM  🟠

**Goal:** a **network-first security section** (CTEM: Scope → Discover →
Prioritize → **Validate** → Mobilize) that grounds into the **correlation
engine** as a fourth evidence class — an exposure is a seam-owned *story with an
owner*, not a scanner row. NOT a SIEM; integrates/exports to partner SIEMs.

**Model rule:** Fable owns the design + the storage-architecture decision; Opus
builds every package/UI.

## Design — ✅ COMPLETE (approved, merged from owner + Fable research)
HLD (`SECURITY_OBSERVABILITY_HLD`), compliance model, scenarios, GTM, build plan
(`SECURITY_BUILD_PLAN`), CVE/vendor-extensibility, config-backup/drift/capture.
**Frontend design mockup:** https://claude.ai/code/artifact/4b3b450f-5177-4d8a-a1a0-12f3697bf84f
(CTEM funnel · Exposure Story hero · four evidence lanes · seam map) — **owner
approved the page 2026-08-27**. This is the T8 build target.

## Foundation — ✅ BUILT + gate-clean
`internal/secfindings` (T1) · `advisory` (T3) · `compliancemodel` (T4) ·
`hardening` (T5, seam-aware) · `threatlane` (T6, MITRE) · `secbus` (T2).

**P3-EMIT (2026-09-02): the producers now EMIT.** `internal/seclane` runs a
per-tenant, bounded, jittered scan (hardening + offline vendor advisory +
threatlane device-log/flow detections) → `secbus.FromFinding` → `netops.security`
keyed by tenant, behind `FEATURE_SECURITY_LANE` (default false). Ops surface:
`GET /api/security/lane/status`, `POST /api/security/scan`,
`netops_security_*` metrics. **Superseded 2026-09-02:** the engine now grounds
them (T2b, `ecda0d1e`) and the UI exists (T8, `317c6dec`) — see the Build list
below. Still true: the flag has never been switched on outside tests.

**Honest coverage caveat (carry into T8):** with config capture (T-config) not
built, every hardening rule emits `Unknown` ("running-config unavailable —
control not assessed"), and a device with no parsed vendor/version emits an
`advisory-unassessed` finding. That is deliberate (§5g never false-clear) — the
UI must render `Unknown` as *unassessed*, never as green.

**Updated 2026-09-02 — capture and hardening are now REAL for the lab fabric.**
Both capture dialects were established on the devices themselves, over the same
single non-interactive read-only SSH exec the gateway performs:

| Platform | Capture command | Verified on |
|---|---|---|
| Nokia SR Linux | `info from running flat` | spine1 `172.40.40.11`, SR Linux v26.3.2 |
| Arista EOS | `show running-config` | leaf1 `172.40.40.21`, cEOSLab 4.36.0.1F |

Three findings from that verification are now encoded rather than assumed.
(1) SR Linux is a **sibling capture dialect** of the `nokia` family, not a member
of it — `admin display-config` does not exist on that OS, and before this the
label "Nokia SR Linux" resolved to the SR OS family because it contains "nokia".
(2) `info` with a *path* argument returns nothing over a non-interactive exec, so
the command is the root form with an explicit `from running`; the flat rendering
is what makes a line-oriented diff meaningful. (3) EOS answers `show
running-config` **only at privilege 15** — a level-1 account gets
`% Invalid input (privileged mode required)` with a ZERO exit status, so the
capture account must be authorized into privileged exec, and `internal/configstore`
now refuses a capture whose first line is a CLI refusal instead of hashing it as
a configuration version.

**Hardening coverage per platform** (dialects `arista` and `srlinux`, bound
through `hardening.binding` in the profiles; detections + reasoning in
`internal/hardening/dialect_fabric.go`, scored in tests against the real
redacted captures):

- **Arista EOS** — `telnet-vty-enabled`, `http-server-nontls` (eAPI transport),
  `snmp-v1v2c-community`, `snmp-default-community`, `snmp-no-source-acl`,
  `weak-enable-password`, `no-central-logging`, `ntp-no-authentication`, plus the
  new `mgmt-api-unencrypted`, `local-user-weak-secret`, `no-remote-aaa`,
  `no-ntp-server`. `ssh-not-v2` and `no-service-password-encryption` report
  **NotApplicable with a stated reason** (EOS ships no SSHv1 and has no global
  password-encryption switch).
- **Nokia SR Linux** — `http-server-nontls` (JSON-RPC HTTP listener),
  `snmp-v1v2c-community`, `snmp-default-community`, `no-central-logging`, plus
  the new `mgmt-api-unencrypted` (gRPC instance with no TLS profile),
  `tls-no-client-auth`, `local-user-weak-secret`, `no-remote-aaa`,
  `no-ntp-server`. `telnet-vty-enabled`, `ssh-not-v2`, `weak-enable-password`
  and `snmp-no-source-acl` report **NotApplicable with a stated reason** — SR
  Linux implements no telnet server, no SSHv1, no enable password and no
  per-community source ACL.

Two honesty notes carried deliberately. **No default-admin-password rule** exists
for either platform: neither writes anything to the running configuration that
distinguishes a shipped default credential from a rotated one, and a rule that
cannot observe its condition can only guess. **Control-catalogue provenance is
asymmetric**: Arista publishes a CIS EOS Benchmark, Nokia SR Linux has none, so
SR Linux verdicts map to NIST 800-53 controls only — a statement about the
industry, not a gap in the rule set. Advisory coverage is unchanged and still
`advisory-unassessed`, for one reason that applies to *every* platform: the CVE
feed is operator-provisioned and air-gapped by design (`VULN_FEED_PATH`), so none
ships in the repo. Both profiles already declare the product ids NVD uses
(`arista:eos`, `nokia:sr_linux` → `srlinux`), and a test installs a feed to prove
both platforms become assessed the moment one is provisioned.

## Execution order (build)
### Blocking decision (Fable) — ✅ DECIDED 2026-08-28
`docs/design/SECURITY_FINDINGS_STORE_DECISION_2026-08-28.md`. **Findings store =
per-tenant OpenSearch index `netops-secfindings-<seg>-*`** (written from
`netops.security` via vector-router, exactly like syslog/flows; read via
`TenantIndexPattern`+`TenantFilter`). **PG FORCE-RLS** holds only the small
mutable control-plane state (feed/rule enablement, saved views). ClickHouse
unchanged (flow detections ground into `corr_*` Exposure Stories). Rationale:
`Finding` is immutable, time-stamped, append-heavy with full-text/facet/trend
access + consumer-side dedup — the telemetry-to-OpenSearch precedent, not
mutable PG rows. Unblocks T8.

### Build
- [x] **Persist the lane (L1)** — `370ea65d`: vector-router route
  `netops.security` → per-tenant `netops-secfindings-<seg>-*`, deterministic doc
  identity (`cx_finding_id = sha256(native_id|attrs.scan_id)`; a missing part
  quarantines, never a random id — executed on the real Vector 0.40 image),
  index template `dynamic:false` + shared ISM retention, router principal
  Read+Describe on `netops.security`, dotted keys guarded by the shared
  `log_lane` anchor (`del(.label)`). Generator-owned lane entry follow-up:
  `3badb3b3`.
- [x] **Findings read API** — `b386d44e`: list / get / facets / trend / posture /
  exposure-stories / rules / views over the per-tenant OpenSearch index; typed
  fail-closed filters, byte-pinned query bodies, current-view collapse on
  `native_id`, opaque typed cursors, bounded paging; 12 routes classified +
  OpenAPI; 9 §3a isolation tests.
- [x] **PG control-plane state** — `b386d44e`: migration 0037
  `security_rule_state` + `security_saved_views` with the `tenant_iso` FORCE-RLS
  policy, `withTenant` PG store + FileStore fallback, per-tenant `requirePerm`
  (never platform-global); a cross-tenant rule write is refused, PG RLS test
  included.
- [x] **T2b — engine grounding** — `ecda0d1e`: security evidence grounds as a
  **fourth modality with zero security-specific engine code** (generic
  evidence-event intake mapped by field names only, `EVIDENCE_CLASSES` registry,
  `uuid5` identity idempotent on redelivery, malformed → DeadLetter). A
  security-only object is **at most `suspected`** until an independent modality
  corroborates (§10a). Removable-module proof: an AST scan finds no
  security-named import and `CORR_EVIDENCE_TOPICS=''` unsubscribes. V1 objects
  are blob-identical (`FIXTURE_GOLDEN` re-frozen). ACL follow-up `8c65801d` —
  one ungranted topic fails the whole subscription under mTLS.
- [x] **EMIT (P3-EMIT)** — `47d0df00`: `internal/seclane` per-tenant bounded,
  jittered scan → `secfindings` → `secbus` → `netops.security` behind
  `FEATURE_SECURITY_LANE`; two-pass store isolation so one store's outage cannot
  silence the other, per-tenant rule enablement fail-closed, the 189-style
  ladder (bus retry → dead-letter → spool; `lost` moves only when every sink
  fails), `GET /api/security/lane/status`, `POST /api/security/scan`.
- [x] **T7 — Exposure Story** output class — reached via T2b's Exposure Story
  templates (`sig.ent.security.{exposure-story,hardening-drift-story,threat-signal-story}`,
  `ecda0d1e`), the read API's `exposure-stories` route over the correlations SQL
  filtered to security evidence (`b386d44e`), and the RCA UI treating security
  evidence as its own independent source class with seam / internet-facing /
  provider chips (`73c2c196`). **Empty until a scan grounds** — see below.
- [x] **T8 — Security UI** — `317c6dec`: Overview (funnel, coverage honesty,
  trend), Exposures (facets, current/history, cursor, Inspector), Exposure
  Stories (RCA workspace reuse), Threat Detection, Compliance, Rules, Saved
  views — built against the fixed contract, no endpoint invented. Where the
  approved mockup asks for data the contract cannot supply (exposure score, CVE
  lane, control-level detail, action CTAs, owner contact) the UI shows honest
  coverage cards or omits, **never fake values**; `Unknown` is never rendered as
  clear (tested).
- [x] **T9 — Vendor Profile registry** — `ff068f7d`: 20 embedded declarative
  profiles (detection, dialect, capture commands, advisory binding, hardening
  binding, threat tags) behind an immutable registry with `Load(fs.FS)` for the
  air-gap path; `collectors`, `netconcepts`, `hardening`, `advisory` and
  `threatlane` resolve through it with **byte-identical goldens**; unknown vendor
  is unassessed, never a silent default. **The tracker-216 residual is CLOSED:**
  `internal/verify`'s two command tables are now the vendor-level
  `verify.commands` block (read-only shape enforced at load, all 25 rows pinned
  byte-identically), `protocoldiag.VendorFromPlatform`/`DisplayVendor` resolve
  through the new per-profile `cli.dialect`/`cli.display` binding (a SEPARATE
  axis from `hardening.binding`: Arista EOS speaks the Cisco IOS-XE show grammar
  but — as of 2026-09-02 — binds its OWN hardening dialect `arista`, because it
  does not speak IOS' *configuration* grammar), `showparse.DialectFromPlatform`'s Arista/Huawei
  fallback token map is deleted now that both profiles declare their own
  `platform_contains`/`platform_rank`, and `secfindings.Resource` carries the
  registry-resolved `ProfileID` beside the free-form label so no consumer
  re-parses it. `TestNoVendorVocabularyOutsideTheRegistry` (an AST scan of every
  non-test Go file) is what keeps them gone; the six sites it found elsewhere are
  allowlisted with reasons and carried on tracker 221.

### Infra modules (owner order, after the core lanes)
- [x] **Config Backup (sealed store) · Config Sync/Drift (in-sync badge)** —
  `a7afbb27` (backend) + `fc5b08be` (UI). Capture rides the existing
  `x/crypto/ssh` gateway (TOFU host-key pin, no PTY, a single exec from a
  **closed per-vendor command table**, 4 MiB cap, ctx deadline) → per-vendor
  normalize → sha256 → `vault.Encrypt` per tenant → `0600` blob under `0700`;
  migration 0038 (`tenant_iso` FORCE-RLS) holds **metadata only**, unsealed
  blobs are refused at `Put`, and a dormant vault refuses construction. A named
  redaction rule list is applied to every API/diff read while the sealed copy
  keeps the original. `configdrift` runs `in_sync|changed|drifted|unknown` per
  device against a golden and emits a drift finding
  (posture / `CFG-DRIFT-001`, **diff summary only** — a test serializes the wire
  event and fails on any config line) through the existing secbus producer onto
  `netops.security`, so it persists and grounds via T2b; it also provides the
  `hardening.ConfigSource`. 81 tests; gosec 133. UI: device Configuration tab
  with honest never-captured / failed states, back up now, versions with
  view/diff/golden, and an Infrastructure → Config Drift fleet list; config text
  and diffs render as escaped text only. Wiring (`main.go` / seclane / route ledger)
  landed in `1378ca26`; nothing here has run on the stack yet — the hardening
  `Unknown` posture below is unlocked by a real capture, not by the code
  existing.
- [x] **Packet Capture** — `1378ca26`: `internal/pcap` — bounded on-device
  capture over the same SSH gateway (closed BPF grammar, one capture per device,
  sealed blobs, audited `sensitive` download) under `/api/devices/{id}/pcap*`;
  the Config Backup `main.go` / seclane / route-ledger wiring landed in the same
  commit, and `042b8e62` put configdrift on the removability allowlist and moved
  the capture templates onto the registry-backed CommandTable.

### Later-flagged (non-blocking)
- PSIRT/CSAF API credentials (vault) · CIS-CAT licensing · framework crosswalk
  data (NIST OSCAL / PCI SSC).

### Finish
- [ ] Owner runs **`/code-review ultra`** — **PENDING.** It has not been
  launched for this project; I cannot launch it. Everything above is
  gate-clean but unreviewed at that depth.

## Live attestation on the lab stack (2026-09-03 03:2x UTC) — FIRST FINDINGS FLOWING

Tenant `lab` created via API (`POST /api/tenants`), spine1/spine2 added with
`tenant_id` (`POST /api/devices`). Scan → 64 findings per pass → `netops.security`
→ vector-router → `netops-secfindings-<tenant>-2026.09.03` (template applied,
`dynamic:false`, keyword facets) → `/api/security/findings` 200 with facets
critical 2 · high 26 · medium 16 · low 18 · info 2 → the engine grounded
security_posture signals on both spines (class=security, 256 grounded). Config
capture stored both running configs (728 lines each, sealed). Two upgrade-path
defects fixed live and filed for the repo: the router's OpenSearch role lacked
`netops-secfindings-*` (403 on every bulk write) and `bootstrap-opensearch.sh`
is blind on TLS installs (no template → dynamic text mappings → dashboard 400/502).

## Live state on the lab stack (2026-09-03 01:10 UTC)

- `FEATURE_SECURITY_LANE=true` and `FEATURE_CONFIG_BACKUP=true` are ON (read-only
  SSH credential staged in the gitignored `.env`; capture dialects for SR Linux and
  EOS device-verified in `4c6ee238`). The `netops.security` topic exists, the
  correlation principal holds Read+Describe on it, the router indexes it, the
  findings index template is applied, and the engine's consumer is active on the
  lane with lag 0 (engine tolerance for absent optional lanes shipped in
  `ee218028` after the 2026-09-02 outage).
- **Both lanes have NOTHING in scope:** the lab has one tenant (`global`) and
  spine1/spine2 are platform-owned; the lane scans tenant-owned devices only, by
  design. The first finding flows the moment a tenant owns the spines — an owner
  action (Administration → Tenants, assign devices). Expected first verdicts from
  the real captures: leaf/spine `mgmt-api-unencrypted`, `no-remote-aaa`,
  `no-ntp-server`, `snmp-v1v2c-community` (see `4c6ee238`).
- Alert delivery is PROVEN on this TLS install: vmalert → api webhook over mTLS →
  ntfy (synthetic page-tier alert dispatched and sent, 2026-09-03 00:58 UTC).

## Not live-attested — what is BUILT but UNPROVEN on a running stack

Honest counterpart to the ticks above. Nothing in this project has been
deployed; the api, frontend, correlation, vector-router and vector-aggregator
images are all unbuilt at HEAD. Until they are:

- **No scan has ever run on the stack.** `FEATURE_SECURITY_LANE` has never been
  true outside tests, so no finding has reached `netops.security`, no document
  has reached a `netops-secfindings-*` index, and the engine has never grounded
  a security evidence event outside its fixtures. Tracker row **217**.
- **Hardening posture is 100 % `Unknown` until config capture runs *on the
  stack*.** Every hardening rule evaluates over a nil config source and emits
  `Unknown` ("running-config unavailable — control not assessed") by design (§5g
  never false-clear). `a7afbb27` provides the `hardening.ConfigSource` that
  unlocks it, but posture stays Unknown until a **real capture runs against a
  real device through the running stack** — code existing is not a captured
  config. *Narrowed 2026-09-02:* the rules themselves are no longer unproven.
  Both fabric dialects are now scored in tests against configurations the lab
  devices actually returned (`internal/hardening/testdata/{arista_leaf1,
  srlinux_spine1}_running.txt`, redacted), and they produce real FAILs —
  cleartext gNMI/gRPC on both, an HTTP JSON-RPC listener and
  `authenticate-client false` on SR Linux, v1/v2c communities, no remote AAA and
  no NTP source on both. What is still unproven is the *stack path*: no capture
  has run through `main.go` against these devices, so nothing has reached
  `netops.security`. A device with no parsed vendor/version emits
  `advisory-unassessed`.
- **Exposure Stories are empty until a scan grounds one.** The templates, the
  route and the UI all exist; the corpus does not. The read API's
  exposure-stories query returns an empty set today, and that is the correct
  answer, not a defect.
- **The T2b removability proof is structural, not operational** — the AST scan
  and the `CORR_EVIDENCE_TOPICS=''` unsubscribe are tested; no one has yet
  removed the module from a running stack.
- **An absent `netops.security` topic is now tolerated, not fatal** (2026-09-02).
  It used to be: with the lane off and broker auto-create disabled the topic did
  not exist, `consumer.start()` → `_wait_topics()` raised
  `UnknownTopicOrPartitionError` over the whole 13-topic subscription, and the
  correlation supervisor restarted every 60 s — ONE optional evidence lane held
  all twelve required lanes dead for ~3 h while `/healthz` still said `"ok"`
  (same shape as 2026-08-16, where the missing Read ACL raised
  `TopicAuthorizationFailedError` instead). The engine now partitions its
  subscription into REQUIRED lanes (fail-loud, and the log line names the topic
  and the reason) and OPTIONAL `CORR_EVIDENCE_TOPICS` lanes, which are resolved
  against cluster metadata AFTER start: absent/unauthorized ones are dropped
  with one structured error line each (`evidence lane NOT grounded`), surfaced
  on `/healthz` (`ingest.evidence_subscription`,
  `consumer.subscription.optional_dropped`) and as
  `corr_evidence_topic_dropped{topic,reason}`, then re-probed every ~90 s and
  re-subscribed without a restart when the lane is switched on. `/healthz`
  `status` is no longer a literal — it reads `degraded` while the required
  subscription is not live (the sidecar still answers HTTP 200, so tracker 174's
  no-flap contract is intact). **This changes nothing about grounding**: until a
  scan actually produces onto `netops.security`, the lane is still ungrounded —
  it is now merely visible as such instead of taking the engine down.
- **No compliance claim is measured.** The Compliance view renders control
  EVIDENCE for the frameworks a tenant has opted into; with hardening
  unassessed, none of it is evidence of a control passing. Every scorecard
  carries the §5d caption saying so, and a framework with no assessed control
  reports a null score and a sentence, never 0 % or 100 %.

---

## Compliance frameworks are per-tenant and opt-in (2026-09-03)

Owner direction: *"we shouldn't be checking all compliances by default;
compliance is analyzed per customer requirement."*

**Frameworks (`GET|PUT /api/security/frameworks`).** A closed, VERSIONED
vocabulary in `internal/compliancemodel/registry.go`:

| id | framework | version | source | default |
|----|-----------|---------|--------|---------|
| `nist-800-53-r5` | NIST SP 800-53 Rev5 | Rev 5 (Release 5.2.0) | base | **on** |
| `cis-controls-v8` | CIS Controls v8.1 | 8.1 | projection-of-800-53 | **on** |
| `nist-csf-2.0` | NIST CSF 2.0 | 2.0 | projection-of-800-53 | off |
| `hipaa-security-rule` | HIPAA Security Rule | 45 CFR 164.312 | projection-of-800-53 | off |
| `pci-dss-v4` | PCI DSS v4.0.1 | 4.0.1 | projection-of-800-53 | off |

The default set is deliberately small: the 800-53 base is the catalogue the
platform already models (no crosswalk hop), CIS Controls is the vendor-neutral
baseline a network team is expected to speak to, and the three regulatory
frameworks describe a position a customer either has or does not — rendering a
HIPAA scorecard for an organisation that handles no PHI is an implied compliance
claim. Selection is per-tenant state (migration `0042_security_framework_state`,
`tenant_iso` FORCE-RLS + `withTenant`, file-store fallback), gated
`requirePerm(administration, LevelWrite)` — **not** a platform gate: a tenant's
compliance scope is that tenant's configuration. A save writes a row for every
known framework so "has not chosen" (→ defaults) stays distinguishable from
"deliberately chose nothing".

**Scoring (`GET /api/security/compliance`).** One INDEPENDENT scorecard per
enabled framework, computed by projecting the tenant's CURRENT findings:

    finding → canonical 800-53 control → framework requirement

The control comes from the owned check→control mapping when there is one, else
from the control the producer stamped. `secapi.ComplianceCatalog()` composes the
hardening catalogue's rule→control mapping onto `compliancemodel.DefaultCatalog()`
(`Catalog.With`), so `internal/compliancemodel` still imports no producer.
Because the projection is the mechanism, **HIPAA and PCI report even though no
finding ever carries a HIPAA or PCI tag** — which is exactly why they could not
appear before.

**Benchmark sections are NOT frameworks.** The hardening rules used to carry
tags like `CIS-NET-5.1` … `CIS-NET-9.3` in `Rule.Controls`; the Compliance page
built its framework list from the distinct `standards` tags on findings, so every
one of those rendered as its own "framework". They were invented — the CIS Cisco
IOS / IOS-XE benchmark taxonomy is three planes (1 Management Plane, 2 Control
Plane, 3 Data Plane) and never exceeds top-level 3, so there is no §5.1 or §9.3
to be truncated from. They are gone: `Rule.Controls` now carries canonical
800-53 control ids ONLY (`TestControlTagsAreCanonical800_53Only` guards it), and
benchmark provenance lives in `internal/hardening/benchmark.go` as an explicit
citation — benchmark id, published title, pinned version, section heading —
rendered inside a control row as
`CIS Cisco IOS XE 17.x Benchmark v2.2.1 §1.2 Access Rules`.

Benchmarks pinned 2026-09-03 from the CIS catalogue (`cisecurity.org`):

| benchmark | version | sections verified |
|-----------|---------|-------------------|
| CIS Cisco IOS XE 17.x Benchmark | v2.2.1 | ✅ (TOC read) |
| CIS Cisco IOS 17.x Benchmark | v2.0.0 | ✅ (same three-plane taxonomy) |
| CIS Cisco NX-OS Benchmark | v1.2.0 | ❌ unverified — cites nothing |
| CIS Arista EOS Benchmark | v1.0.0 | ❌ unverified — cites nothing |
| CIS Juniper OS Benchmark | v2.1.0 | ❌ unverified — cites nothing; CIS announced (Aug 2025) an intent to archive the Juniper benchmarks |

There is no current CIS Cisco IOS 15 benchmark (v4.1.0, 2021, archived), so
nothing references one. A benchmark whose section taxonomy could not be read from
a published document is LISTED (so the coverage gap is visible) but cites no
section — an unverified section number is the same invention the `CIS-NET` tags
were. `TestBenchmarkCitationsResolve` enforces both halves.
