# Changelog

All notable changes to Correlix (NetOps_Observability).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from its first tag.

> **No release has ever been tagged.** The repository's only tag,
> `correlation-v2-p3a-probe-authority-verified`, is an engineering marker, not a release. This file
> therefore starts from **2026-07-01**, the point at which the product became recognisably the thing
> it is now — the month the offline appliance installer, the Apache Kafka / Valkey licensing swap and
> the RCA document rebuild all landed. Work before that date is in the git history and in
> `docs/archive/`; it is not summarised here.
>
> **1 511 non-merge commits** are covered (814 in July, 589 in August, 108 in September through the
> 3rd). Entries are grouped by month and then by area. Within each month the most consequential
> changes come first, not the most numerous.
>
> Proposed first tag: **`v0.9.0-rc1`** — see [`docs/RELEASE_NOTES_v0.9.0-rc1.md`](docs/RELEASE_NOTES_v0.9.0-rc1.md)
> for the reasoning and the customer-facing narrative.

---

## [0.9.0-rc1] — unreleased

### ⚠ Breaking / operator action required

Anyone upgrading across this window needs each of these. Ordered oldest first; see
[`docs/UPGRADE.md`](docs/UPGRADE.md) and [`docs/runbooks/upgrade-bootstraps.md`](docs/runbooks/upgrade-bootstraps.md).

| Date | Change | What you must do |
|---|---|---|
| 07-03 | **Redpanda → Apache Kafka 4.1 (KRaft)** and **Redis → Valkey 8** (licensing, #97) | Broker addressing moves to `BROKER_URLS`; the old services are gone |
| 07-03 | **Prometheus removed** — VictoriaMetrics self-scrapes | Repoint anything scraping Prometheus; optional tiers became add-on packs |
| 07-04 | Offline installs can no longer use digest-pinned images | A tag-pin override is required; images are `docker save`d by tag |
| 07-04 | First run no longer seeds lab devices or scans the network unasked | Nothing — but a fresh install now genuinely starts empty |
| 07-17 / 07-18 | DB migrations 0026, 0028 (service catalogue `owner`, `runbook_url`) | Applied automatically by the API at boot |
| 08-04 → 08-09 | **The TLS/mTLS mesh.** nginx→API mTLS; Postgres `sslmode=verify-full` then plaintext refused (`hostssl`); ClickHouse TLS; Valkey authenticated then TLS; **OpenSearch security plugin ENABLED**; new `vmauth` service fronting VictoriaMetrics; Kafka dual secure listeners with auto-create OFF and an enforced ACL matrix; KRaft controller on mTLS | `install.py --tls=yes` brings up the whole mesh. **After the enforce wave, an un-TLS'd client cannot connect and an unlisted Kafka principal is denied.** |
| 08-06 / 08-07 | Per-lane ingest credentials replace the shared `INGEST_TOKEN` | New per-lane `.env` credentials; the shared token now opens no lane |
| 08-07 | `OS_*` and DB password families mint URL-safe | Existing installs holding non-URL-safe secrets should rotate |
| 08-12 / 08-13 | The API owns its data tree and follows its runtime UID (`CORRELIX_UID`) | Existing bind-mount ownership may need correcting |
| 08-15 | Device SSH uses a one-time WebSocket ticket instead of a session JWT in the URL | Any client relying on the old URL scheme breaks |
| 08-16 | `install.py` applies the Kafka ACL matrix during install | Required — fresh installs previously booted auth-dead |
| 08-16 | **Kafka tenant-keyed co-partitioning**; OpenSearch document IDs move to Kafka coordinates | Coordinated restart; index identity changes |
| 08-24 | **Healthchecks move to port `:8094`** (correlation health sidecar) | Repoint any external probe |
| 08-29 | ClickHouse hypotheses to `CODEC(ZSTD(3))`, daily TTL partitions, resumable repartition; `merge_tree` thresholds rescaled to a 12-slot pool | `CORR_REPARTITION` defaults to `check`. Without the rescale **the server refuses to start** |
| 08-30 | **`CORR_AGGREGATION_PLANE` now defaults ON** | Behaviour change under load; `compose.agg-off.yml` is the off arm |
| 09-02 | New per-tenant OpenSearch findings index + template + ISM; correlation needs Read/Describe on `netops.security` and `netops.syslog.control` | **One ungranted topic fails the whole subscription under mTLS.** Run `scripts/deploy-qualify.sh` |
| 09-02 | ClickHouse source enum gains `'bgp'=15`; `seam_type` projected onto `corr_current` | Boot-time converging `ALTER` |
| 09-02 | New bind mounts `data/config-backups` and `data/pcap` (0700, api-owned); new `.env` stubs | `scripts/update.sh` reconciles `.env`; the directories must exist |
| 09-02 | Teams/SNS notification channels | One-time env-seed migration moves env-configured webhooks into managed channel config |
| 09-02 | **Go toolchain 1.25.13 → 1.26.8** | Build-environment requirement only |
| 09-03 | On stacks already running TLS, the findings lane was unwritable | `bootstrap-opensearch.sh` is now TLS-aware and the sole owner of index templates — re-run it |

### Security

- **Full TLS/mTLS transport mesh**, enabled by a single question in the installer: ingress TLS,
  nginx→API mTLS, every store hop, Kafka mTLS with an enforced ACL matrix, Vector lanes, and sealed
  CA custody. A workload-identity registry issues an SVID per service, with served-certificate expiry
  watched on the wire rather than on disk, and a jittered daily rotation sweep with a dead-man alert.
- **Sealed Fields** — reversible field-level masking with per-tenant data-encryption keys, a `seal`
  pipeline action, an RBAC'd reveal API, audit, metrics and key rotation.
- **Seal-or-quarantine** — quarantined data is sealed, keeps its attribution, and is isolated at
  every boundary, with an operator workflow and a passing acceptance battery.
- Vulnerabilities found and fixed by review, not by a scanner: stored XSS in ECharts tooltip
  formatters (critical); a session JWT carried in a WebSocket URL; SNMPv3 poll responses trusted
  before HMAC verification; SNMP trap forgery; a cross-tenant tombstone in `find_merges`; an OIDC
  bearer platform-owner self-elevation; an `/api/graphql` RBAC bypass where the query was ignored
  entirely; and a legacy import that clobbered live RLS tables on every boot.
- Tenant isolation tightened across topology metric bundles, correlation intel in the AI data path,
  scheduled-report renderers and flow attribution — and made structural: a new scoped route now
  requires a real isolation test to merge.
- **Advisory response** during the window: Go 1.25.11→1.25.12 (GO-2026-5856), `x/text` v0.39.0
  (GO-2026-5970), Go 1.25.12→1.25.13 (net/http batch), echarts 6.1 (GHSA-fgmj-fm8m-jvvx),
  `x/crypto` v0.55.0 + `x/net` v0.57.0 (CVE-2026-56854, CVE-2026-46600), and Go 1.26.8 +
  `x/crypto` v0.56.0 (GO-2026-6354/6355).
- A production security validator that **fails closed with no global bypass**, a machine-readable
  as-built transport inventory, and posture-drift alerts.

### Removed

- **Redpanda, Redis and Prometheus** — removed entirely for licensing (#97) and replaced by Apache
  Kafka 4.1 (KRaft), Valkey 8 and VictoriaMetrics self-scraping. They will not be reintroduced.
- The legacy raw-incident → ITSM lane (flag-gated and deprecated) and its phantom state.
- Seeded lab devices, unasked network scanning, shipped sourcemaps and vendor names from the UI on
  first run.
- The topbar theme toggle — appearance is chosen at login and changed from account settings.

---

### 2026-09 (1–3) · 108 commits

#### Security & CTEM
- **Security became a product section**: Overview with a funnel, coverage honesty and trend;
  Exposures with facets and an Inspector; Exposure Stories reusing the RCA workspace; Threat
  Detection; Compliance; Rules and saved views.
- The **findings lane went live end to end** — `netops.security` → a per-tenant OpenSearch index via
  vector-router with deterministic document identity, index template, ISM policy and router ACL —
  behind a read API (list / get / facets / trend / posture / exposure-stories / rules / views) with
  Postgres FORCE-RLS control-plane state.
- **Config Backup** — sealed, captured over the SSH gateway, per-vendor normalisation and redaction,
  content-addressed versions, a golden config and a bounded diff — plus **Config Sync/Drift** raising
  findings, a device Configuration tab and a fleet-wide Config Drift list.
- **Packet Capture** — bounded on-device capture over the SSH gateway with a closed BPF grammar,
  sealed blobs, one capture per device and an audited download. The UI enforces 60 s / 10 000-packet
  caps and refuses BPF injection.
- A **vendor-profile registry**: one embedded declarative profile per vendor/platform (detection,
  dialect, capture commands, advisory binding, hardening binding, threat tags) that the collector,
  hardening, advisory and threat lanes all resolve through, with byte-identical goldens.
- Microsoft Teams and Amazon SNS as managed notification channels (sealed webhooks, severity floors,
  platform-owner gate).

#### Troubleshooting & Iris
- A **symptom-first Investigation surface** — verdict header, honest evidence lanes, an Iris lane and
  seam-owned handoff.
- **Iris gained a skills layer**: troubleshooting method expressed as data, server-planned read-only
  gathering, bounded skill chaining, a show-first live-state battery with a deterministic parser
  library, read-only BGP tools, and tenant-scoped investigation memory with feedback IDs.
- **Operator verdict feedback** — a "Was this verdict right?" control on the RCA header, a feedback
  API, a tenant summary with false-positive rate, a 30-day tile on the NOC scorecard, and the verdict
  line in the PDF export.
- **Security evidence became a fourth correlation modality** with no security-specific engine code:
  generic evidence-event intake, Exposure Story templates, and a removable-module proof.
- The telemetry catalogue is now the parser's executor — 38 catalogue rules in a guard/extract/emit
  DSL compiled into a generated interpreter, replacing branch code. Every signal carries
  parser-rule provenance.
- Live SSH collection for protocol diagnostics, with multi-line PEM private keys redacted by a
  stateful, fail-closed block scanner.

#### BGP & routing
- **BGP depth**: RPKI, honest ASPA, geofeed, an AS-path graph, a near-live feed, an RFC 7854 **BMP
  receiver**, and per-device interfaces grouped by routing instance.
- **BGP alerting** on route leaks, hijacks and outages with a single classifier, a Peers tab and
  bogon detection.
- **IGP depth**: IS-IS LSDB / area / SPF / hold-time over gNMI (lab-verified on SR Linux) and
  OSPF-MIB LSDB / area / SPF / timers over SNMP.
- A protocol-diagnostics panel: a BGP/OSPF/IS-IS issue matrix from the catalogue, a device picker,
  Collect (with an honest 503 when not wired), Analyze with matched-signature and no-match states,
  and a redacted TAC bundle download.

#### Scale & performance
- **Release qualification became one command** — `release-qualify` with a three-valued verdict, a
  machine-readable `storm-s11` baseline and a preflight disk/quiet gate.
- A ground-truth **time-to-useful-RCA** instrument with a formal definition of "useful", and tail
  classification across 15 dimensions.
- OpenSearch flood-stage blocking now degrades to **DELAYED, never LOST**: partial-bulk retry, a
  bounded 43-minute envelope, block-on-full router sinks and three alerts. *(Built 09-02; deployment
  pending owner approval — tracker 209.)*

#### Ops & reliability
- **The engine-down class was closed**: an optional evidence lane can never block the engine, alerts
  are delivered over mTLS on TLS installs, liveness rules are tiered, the watchdog gained
  consumer-group probes, and a deploy-qualification step was added.
- Platform alerts now page the host-monitoring channel, so Correlix's own health goes where the
  watchdog already pages.
- A pilot support bundle with two-pass secret redaction, plus an install-timing instrument.

---

### 2026-08 · 589 commits

#### Security & CTEM — the month's dominant theme (100 commits)
- The TLS/mTLS mesh, store by store (see *Breaking* above): Postgres, ClickHouse, VictoriaMetrics
  behind `vmauth`, Valkey, OpenSearch with its security plugin enabled and a minimal five-identity
  role model, and Kafka from anonymous to authenticated-and-authorised.
- A second-pass security review wave that found and fixed real vulnerabilities rather than lint.
- **CTEM foundations**: an owned normalised security-finding model, a security-as-producer bus seam,
  a vendor-advisory provider seam (offline / mock / Cisco), a compliance lane, a network-device
  hardening rule engine and a MITRE-tagged threat-detection lane.
- SSO/Keycloak: GUI-configurable identity providers, PKCE S256 with nonce and single-use login
  transactions, and IdP-initiated/Okta-bookmark login repaired without reopening the login-CSRF hole.

#### Troubleshooting & Iris
- **Correlation-engine boundedness** was the month's engineering spine: a bounded-cohort scheduler,
  an open-object cap with defined at-bound behaviour, ingest-priority scheduling, storm-mode
  hysteresis, sub-linear continuation indexing, capacity-driven evidence shedding separated from age
  pruning, and per-tenant retention running on stream time with an RCA horizon derived from scoring
  rather than declared.
- **Explicit storm mode** — dedup / prioritise / aggregate / preserve.
- The memory programme: a cross-epoch rank memo (content-addressed, proven-sound key), compact
  ~1.2 KiB entries (22× smaller) so all storm keys fit, and an async Evidence plane with cross-version
  write batching (28.8× fewer inserts).
- **Incident identity now survives partition handoff** — durable continuation seeding on assignment,
  flush-and-release on revoke, ownership guards at persist and admission, and a flush before
  `LeaveGroup` on graceful shutdown.
- A structural role-grounding gate suppresses RCA verdicts the topology cannot support.
- A rejected ClickHouse write is retried rather than silently lost; deterministic RCA report
  regeneration finally reproduces.
- **Protocol diagnostics** began: a collect→analyze backend for BGP/OSPF/IS-IS and its HTTP API.

#### Scale & performance
- ClickHouse sized to its cgroup and made merge-safe by construction: a 6-slot merge pool, per-table
  merge caps, a 1.5 GiB soft limit, vertical merges and bounded system logs.
- Hypotheses storage moved to ZSTD(3) — 89.7× compression versus 13.9× with LZ4 — with a size-gated
  resumable repartition migration.
- Time-intelligence backfill became watermarked and budgeted, degrading and resuming instead of
  stalling.
- A self-judging nightly **scale mini-ladder** regression harness, 5k/10k ladder profiles, and an
  unattended resumable A/B leg driver.
- Discovery persistence went from an O(N²) whole-fleet rewrite to O(1) per-device writes.
- Per-event work in the engine's `handle()` cut so throughput went 1 261 → 1 785 ev/s; window
  eviction 770 ms → 60 ms.

#### BGP & routing
- **Consolidated BGP operations**: a tenant watchlist, a RIPEstat/RDAP data spine and a one-screen
  outage page.
- A VRF/routing-instance vendor-dialect abstraction so routing concepts are expressed once across
  vendors.

#### Ops & reliability
- **The stack watchdog shipped as a product feature** with enterprise notification channels and an
  installer-GUI handover; it probes every replica of scaled services, checks TLS rotation heartbeats,
  separates ClickHouse health from container-runtime health and guards against PID-cgroup saturation.
- A loop-independent health/metrics sidecar for the correlation service.
- Ratified workload profiles for the qualification harness, a realistic six-kind event mix,
  tenant-keyed injection and a 72-hour soak profile.
- GA gate suites: cost-budget, failure-accounting, counter-exposure and error-swallow guards, plus a
  guard against a vacuous PASS (promtool reports zero resolved rules as SUCCESS).
- Snapshot policy control plane with a full-backup run report in the Backup & DR page.

#### Productization
- Installer robustness on real hosts: the API owns its data tree and follows `CORRELIX_UID`, root
  installs can mint again, cold-boot seal ordering with honest mint-timeout evidence, and
  reset/reinstall hardening learned from a clean-slate rebuild.
- **Fresh installs no longer boot auth-dead** — the Kafka ACL matrix is applied during install.
- The customer bundle got slimmer (OpenSearch image 920 MB → 385 MB) and moved off a daily cron to
  event-driven rebuilds.

#### Platform & UI
- A **network digital twin**: scenario DSL, fault stories with ground truth, an accuracy scorer,
  snmpsim agents, trap and NetFlow emitters and a gNMI target mode.
- **Navigation redesign** to an 8-section information architecture, a frontend performance wave, and
  a copy pass stripping instructional chrome from operator surfaces.

---

### 2026-07 · 814 commits

#### Productization
- **The offline appliance installer**, end to end: a one-command installer with licensing guards,
  hardened host preparation behind a hard preflight gate, a setup console, an `install-correlix` PATH
  alias and a full install transcript.
- **VM appliance images** (qcow2 / vmdk / vhdx) with nightly lockstep, a bundle staleness gate and
  forbidden-image guards.
- A **graphical installer wizard** (`correlix-setup`) for the customer bundle, a post-install
  admin-credential self-test and password-recovery docs.
- **Correlix brand identity** across the shell, and the in-app assistant renamed to **Iris AI**.
- An in-app documentation portal behind a "?" Help drawer; a cloud-connector onboarding wizard with
  resume; org-level multi-account cloud onboarding.
- **Build provenance**, so "deployed ≠ committed" is detectable.

#### Troubleshooting & Iris — 153 commits
- **The RCA document was rebuilt around honesty.** "Incident at a glance" leads the report — where,
  what possibly happened, possible owners, and the causality path with the broken hop in red. Causes
  read "possibly because of X" with an evidence state instead of a bare "not identified", and every
  "observed / not observed" render was removed.
- **Seam ownership replaced the hardcoded "NOC"** — a per-tenant registry maps owner class to the
  actually responsible party, and every case carries engine-derived attribution.
- RCA documents are produced only for **promoted real outages**; candidates stay a separate tier.
- Report immutability: an integrity block, a tenant-scoped revision register, deterministic PDF
  attestation and a 12-section SRE-postmortem layout.
- **Path causality**: a segment/device classifier, path discovery fusing multiple sources into typed
  causal paths, on-path restriction of RCA candidates, and a report that draws the path.
- **Active verification**: a closed read-only command allowlist, a bounded parallel command battery,
  per-tenant opt-in, and an `active_verification` evidence modality with corroborate/refute scoring.
- The v1 NOC **failure-signature catalogue** — 32 owner-specified fault families with a voice contract
  and specificity ranking, then two further waves, with golden-wire fixtures and a live-fire drill
  proving every enabled signature triggers on the deployed engine.
- **Iris AI**: a product-knowledge retriever giving accurate key-free answers, per-tenant BYO provider
  keys sealed with the tenant DEK, Gemini as a first-class provider, a bounded governed agent loop
  (dormant), and a golden-set eval harness with retrieval floors, citation correctness and
  prompt-injection evals.
- **Port Intelligence**: 23 physical-layer signatures, a universal DOM/DDM optics collector,
  per-vendor adapters, a port-health scorer and an Interfaces/Ports/Optics workbench.

#### Ops & reliability
- **Alert episodes** — Active Alerts grouped by episode with a triage panel, a fold/close/flap store
  and notification-suppression seams.
- **Maintenance windows** — planned work stops paging and stops polluting MTBF.
- **ITSM and notification lanes**: ServiceNow, Jira, PagerDuty and Slack as tenant-scoped RCA policy
  destinations, with human display IDs, a "notified via" column, and alert-resolution propagation
  that auto-closes PagerDuty incidents.
- **Disaster recovery**: a restore drill that proves a backup is actually restored and
  content-verified, ClickHouse and OpenSearch restore legs, and a Data Protection UI.
- Self-healing: an appliance self-health guard that recovers ingest after disk pressure,
  threshold-driven host hygiene with OpenSearch block healing, and an orphaned-open sweep.
- The watchdog learned to detect **telemetry silence**, not just container liveness.

#### Scale & performance
- Capacity planning became a product surface: a resource planner with a 26-scenario suite and golden
  plans, installer flags, and installs that size themselves to the detected host.
- **Pipeline Processors** — registries, managed rules, versioning and metrics — with a per-tenant
  processor editor.
- A free **Sensitive Data Scanner** with 16 managed detectors and hash/tag/key-scoped actions.
- The ClickHouse write path hardened with insert dedup tokens, bounded retry with jitter and
  per-outcome write metrics — because an HTTP 200 can still be a write failure.
- Silent log loss closed: timestamps normalised across all log lanes, a dead-letter path added, and
  clock skew flagged per device and lane.
- Correlation read-path storms behind Command Center 502s fixed with a `corr_current` hot projection,
  per-endpoint read budgets and a per-query memory cap.

#### BGP & routing
- **Service Path Graph contract v1** — a measured, end-to-end RCA spine.
- A dying path now states its drop point, with a ladder fold, a terminal statement and a history seam
  hint.
- A canonical segment taxonomy and a discovery-driven device-role classifier with NOC-facing labels.

#### Platform & UI
- **Cloud observability** built out in waves: API discovery and route-table egress topology on AWS,
  Azure and GCP; multi-source S3 and Azure blob log ingestion; a service map from observed traffic;
  per-tenant SLOs and error budgets; monitor authoring; cost ingestion (with an honest GCP gap); and
  console deep-links on every cloud row.
- **Wireless** phases 1–8: canonical model, Catalyst 9800 read-only ingestion, correlation
  integration, sessions and onboarding episodes, a multi-vendor architecture proof, the Iris wireless
  module, the Wireless UI, and guarded remediation with five gates that fail closed.
- A **WCAG AA accessibility pass** across shell, forms, tables, dialogs, dashboards and the RCA
  workspace.
- A shared frontend time authority with a Local/UTC contract, and pipeline timezone pinning.
- Eighty commits of internal Go package decomposition (`internal/rca`, `internal/tenant`,
  `internal/rbac`, `internal/vault`, `internal/platformdb` and more) with no user-visible change.

---

[0.9.0-rc1]: https://github.com/RaoRakurty/NetOps_Observability/commits/main
