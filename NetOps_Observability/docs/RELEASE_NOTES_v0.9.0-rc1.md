# Correlix v0.9.0-rc1 — release notes

**Status:** release candidate · **Proposed tag:** `v0.9.0-rc1` · **Prepared:** 2026-09-03

This is the first tagged build of Correlix. Everything before it was a branch.

---

## Why this version number

**`0.9.0`, not `1.0.0`.** Under semantic versioning, `0.y.z` says the public surface may still
change — and it will. A dozen capabilities ship behind flags that default off, the API-key scopes do
not yet cover administrative onboarding, and there is no Kubernetes packaging. Calling this `1.0`
would assert a stability we have not earned. `0.9` says what is true: this is feature-complete for a
design-partner pilot, and one validated deployment away from `1.0`.

**`-rc1`, not final.** The release-qualification gate — `scripts/release-qualify.py`, graded against
the frozen `CORRELIX_REFERENCE_CAPACITY_V1` profile — is **built but has never been executed** against
a candidate build. Until it returns a PASS on the rig, no build can honestly be called final. `rc1` is
the accurate label for *built, gated by CI, not yet qualified on hardware*. Dropping `-rc1` is a
decision the qualification run earns, not a decision the calendar makes.

---

## What Correlix is

A single-host observability and root-cause platform for network operations. Device discovery →
multi-protocol telemetry ingestion (SNMP, syslog, traps, flow, gNMI) → an event bus → search,
time-series and OLAP storage → anomaly correlation → API → dashboard. One `docker compose` stack
behind nginx on one port.

The thing it does that a dashboard does not: when something breaks, it produces an **RCA document** —
where the fault is, what possibly happened, which team owns the seam, and the causality path with the
broken hop drawn in red.

---

## What's new

Everything, in the sense that this is the first release. The highlights a new operator will notice:

### Install and run
- **One-command offline installer.** `python3 scripts/install.py` builds the environment file, sizes
  itself to the detected host, and brings the stack up on `:8000`. There is also a graphical wizard
  (`correlix-setup`) and a fully offline appliance bundle with pre-loaded images for air-gapped sites.
- **VM appliance images** — qcow2, vmdk and vhdx.
- **Capacity planning is built in.** The installer derives container limits from the host rather than
  shipping one static guess (`--plan-resources`, `--sizing-file`, `--replan`, `--rollback-plan`).

### Root cause
- **Honest RCA documents.** "Incident at a glance" leads: where, what possibly happened, possible
  owners, and the causality path. Causes read *"possibly because of X"* with an evidence state — never
  a confident guess dressed as a finding, and never a bare "not identified".
- **Seam ownership.** Every case names the actually responsible party from a per-tenant registry
  instead of routing everything to a generic "NOC".
- **Active verification.** Correlix can run a bounded battery of read-only commands against a device
  to corroborate or refute its own hypothesis — opt-in per tenant, from a closed allowlist.
- **RCA documents are produced only for promoted real outages.** Candidates stay a separate tier, so
  the report library is not full of noise.
- **Reports are immutable and reproducible** — an integrity block, a tenant-scoped revision register
  and deterministic PDF attestation.
- **Verdict feedback.** A "Was this verdict right?" control on every case, with a per-tenant
  false-positive rate on the NOC scorecard.

### Iris AI
- A product-knowledge assistant that answers accurately **without any API key**, and — when you supply
  your own provider key (sealed with your tenant's encryption key) — a troubleshooting assistant with
  a skills layer: server-planned read-only gathering, bounded skill chaining and a live-state battery
  with deterministic parsing.

### Protocols
- **BGP operations**: watchlist, RPKI, ASPA, geofeed, AS-path graph, a live feed, a BMP receiver, and
  alerting on route leaks, hijacks and outages.
- **IGP depth**: IS-IS over gNMI, OSPF over SNMP — LSDB, areas, SPF and timers.
- **Port intelligence**: optics/DOM collection, 23 physical-layer signatures, a port-health scorer,
  and an Interfaces/Ports/Optics workbench.
- **Wireless**: Catalyst 9800 ingestion, sessions and onboarding episodes, correlation integration.
- **Protocol diagnostics**: a BGP/OSPF/IS-IS issue matrix, collect-and-analyze over the SSH gateway,
  and a redacted TAC bundle.

### Security
- **A full TLS/mTLS transport mesh**, enabled by answering one question during install. Ingress TLS,
  nginx→API mTLS, every store hop verified, Kafka mTLS with an enforced ACL matrix, per-service
  workload identities (SVIDs) with automatic rotation.
- **Sealed Fields** — reversible field-level masking with per-tenant keys, an audited reveal, and key
  rotation.
- **A security module** (CTEM): exposures with an inspector, exposure stories that reuse the RCA
  workspace, compliance, threat detection, **config backup with drift detection**, and **bounded
  on-device packet capture**.
- **Tenant isolation is structural**, not incidental: every scoped route requires a passing isolation
  test to merge.

### Operations
- **Alert episodes** and **maintenance windows** — grouped triage, and planned work that neither pages
  anyone nor pollutes your MTBF.
- **ITSM and chat integration**: ServiceNow, Jira, PagerDuty, Slack, Teams and SNS as tenant-scoped
  destinations, with resolution propagation that closes tickets when the condition clears.
- **Backup and disaster recovery** with a restore drill that actually restores and content-verifies —
  a backup that has never been restored is a hypothesis, not a backup.
- **A watchdog that survives the stack dying.** External, cron-driven, checks that the engines are
  *consuming* rather than merely *running*, and pages your phone independently of the product's own
  notifiers — because a notifier cannot report its own death.

### Licensing and third-party components
- **Correlix is open core.** Correlix core is licensed under the Apache License, Version 2.0.
  Commercial add-on modules are licensed under the Correlix Enterprise License
  (LicenseRef-Correlix-Enterprise) — see LICENSING.md. The default is open: a file with no SPDX
  header, in a directory with no Enterprise notice file, is Apache-2.0, so nothing becomes
  commercial by omission. `LICENSE`, `LICENSING.md` and `LICENSES/` ship at both repository roots
  and in the offline bundle.
- **Every third-party licence obligation is inventoried, and the inventory is generated from the
  tree** rather than remembered. The running product serves it at `/licenses/` (account menu →
  *Third-party licences*), the offline bundle ships it as `LICENSES.md`, and
  `scripts/license-audit.py` fails the build if a component arrives whose licence nobody reviewed.
- **The GPL source we owe now ships with the binaries.** syslog-ng OSE is GPL-2.0-or-later for its
  modules and LGPL-2.1-or-later for its core. Rather than rely on a three-year written offer, every
  bundle carries `source-offer/syslog-ng-4.7.1.tar.gz` — the complete unmodified upstream release,
  checksummed in `SHA256SUMS`. The build fails rather than ship a bundle without it.
- **Grafana is optional and unmodified.** Grafana is AGPL-3.0-only and reaches a deployment only
  through the optional `self-monitoring` add-on. It runs as the stock upstream image, configured
  only through Grafana's own settings. The proxy no longer rewrites the pages Grafana serves, so
  the "unmodified" claim is one you can check rather than one you have to take. Correlix's own
  source carries no AGPL obligation.
- **Keycloak ships on a Red Hat Universal Base Image**, which is governed by the Red Hat UBI EULA
  rather than an open-source licence. Correlix accepts that agreement and redistributes the image
  unmodified; installing Correlix means you receive it on the same terms. Read the agreement at
  <https://www.redhat.com/licenses/EULA_Red_Hat_Universal_Base_Image_English_20190422.pdf>. The
  terms and the acceptance are also stated in `NOTICE`, in the generated notices, and in the
  customer documentation. If the EULA is not acceptable in your environment, run Correlix against
  an external identity provider instead.
- **No vendor trademark files ship any more.** The AWS, Azure and Google Cloud marks that used to be
  embedded in the API binary and the web interface are replaced by original Correlix cloud glyphs.
  Cloud nodes still read as AWS, Azure or GCP; the artwork is ours.
- **Nothing source-available is present.** No SSPL, BUSL, Elastic or RSAL-licensed software appears
  anywhere in the product, and nothing under a copyleft licence is linked into any binary Correlix
  builds.

Full detail: [`docs/THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) and the customer-facing
summary at **Deploy → Third-party components and licences** in the documentation portal.

---

## Upgrading

There is nothing to upgrade *from* — this is the first tag. If you are running a build from the
`feat/observability-platform` branch, treat this as an upgrade and read
[`docs/UPGRADE.md`](UPGRADE.md) and [`docs/runbooks/upgrade-bootstraps.md`](runbooks/upgrade-bootstraps.md)
in full. The condensed path:

```bash
cd /path/to/NetOps_Observability
scripts/update.sh                 # backup → .env reconcile → pull → build → up -d
scripts/deploy-qualify.sh         # bootstraps + proof that the engines are consuming
echo "exit=$?"                    # 0 = qualified. 1 = failed. 2 = INCOMPLETE, which is NOT a pass.
```

### The bootstraps are not optional

`scripts/update.sh` runs **only** the OpenSearch template bootstrap. It does **not** create Kafka
topics, apply the Kafka ACL matrix, or apply the OpenSearch ISM policy. On a TLS/mTLS stack this
matters more than it sounds: **one ungranted topic fails the entire consumer subscription**, not just
that lane. `scripts/deploy-qualify.sh` is what runs those four bootstraps and then proves the result —
correlation joined its consumer group, every router lane has a live member, lag is draining, both
Vector tiers are emitting, the API answers, OpenSearch is not red.

`docker compose up` exiting 0 is not evidence of anything. Run the qualification step.

### Changes that need your attention

Full detail in [`CHANGELOG.md`](../CHANGELOG.md) under *Breaking / operator action required*. The ones
most likely to bite:

| | |
|---|---|
| **Healthchecks moved to `:8094`** | Repoint any external probe |
| **Kafka topic auto-create is OFF and ACLs are enforced** | An unlisted principal is denied. New lanes need an ACL — `deploy-qualify.sh` applies the matrix |
| **Postgres refuses plaintext TCP** on TLS installs | Any external DB client must present TLS |
| **`CORR_AGGREGATION_PLANE` now defaults ON** | Different behaviour under load; `compose.agg-off.yml` is the off arm |
| **New bind mounts** `data/config-backups`, `data/pcap` | Must exist, mode 0700, owned by the API user |
| **Per-lane ingest credentials** replaced the shared `INGEST_TOKEN` | The shared token now opens no lane |
| **ClickHouse `merge_tree` thresholds rescaled** | Without this the server refuses to start |
| **Redpanda, Redis and Prometheus are gone** | Replaced by Apache Kafka 4.1, Valkey 8 and VictoriaMetrics self-scraping. They will not return |

---

## Known limitations

Read this section. It is the honest state of the product, and none of it is hidden in a footnote.

### Not yet qualified on hardware
- **The reference-capacity regression has never been run against a candidate build.** The harness
  (`scripts/release-qualify.py`), the frozen profile and the `storm-s11` baseline all exist; the run
  does not. This is the single reason this build is `-rc1`.
- **Performance claims are "proven on a named run", not "cannot regress".** Eleven invariants —
  completion time, losslessness, memory caps, accuracy ≥ 93 %, SLO under overload — were measured on
  specific rig legs. No pull request can be blocked by them today. Treat them as evidence about a
  build, not a guarantee about all builds.
- **Storage sizing is derived, never measured.** Every bytes/day, retention and capacity figure in the
  documentation is a calculation. Validate against your own traffic before committing to disk.
- **The headline time-to-root-cause number does not exist.** In the qualification corpus,
  `time_to_useful` is censored on all 345 cases. We are not quoting a number we have not measured.
- **The storm benchmark has no flap or recovery dynamics** — zero state transitions, one vantage
  point, one modality. It exercises volume, not instability.
- Three evidence classes (`contradiction`, `new_vantage`, `new_modality`) have **never fired on any
  run**. They are unexercised, not proven; no configuration should lean on them.

### Backend and storage
- **The default application-state backend is file-based**, and it is not equivalent to the relational
  one. On a file-backed install the **cloud-connector store returns nothing and the NMS integration
  refuses credential writes** — you cannot store cloud or NMS credentials at all. If you intend to use
  the cloud connectors or NMS integration, deploy with Postgres app-state:
  [`docs/DEPLOY_POSTGRES_APPSTATE.md`](DEPLOY_POSTGRES_APPSTATE.md).
- **The newest OpenSearch snapshot is PARTIAL** and the snapshot API returns 401 for two service
  roles. Until that is fixed, the disaster-recovery claim for the search tier is not true. Backup and
  restore for Postgres and ClickHouse are drilled and verified; OpenSearch is not.

### Security posture depends on the TLS choice
- **A plaintext install is a scaffold, not a production posture.** With `--tls=no`, the **OpenSearch
  security plugin is disabled**, the bus is unauthenticated, and stores accept plaintext. With
  `--tls=yes` you get the full mesh, the security plugin enabled with a five-identity role model, and
  an enforced Kafka ACL matrix. **Use `--tls=yes` for anything real.**
- Even on a TLS install, **the shipped ingress still publishes plaintext `:8000` alongside `:443`**.
  Restrict it at the network layer if that matters to you.
- The ingress certificate is **self-signed** by default. Your browser will warn.
- **SNMP discovery is off by default** and, when enabled without `--snmp-discovery`, defaults to
  `10.0.0.0/8`. Narrow it before pointing Correlix at a real network.
- The **gnmic → Kafka hop remains plaintext**, a declared exception that has not been ratified for
  production use.
- **The gNMI correlation lane has never been live-attested** — no gnmic workload identity, no produce
  ACL, and partition-key parity unverified.
- The **security findings lane is live but currently reports nothing**, because the only devices in
  scope are platform-owned rather than tenant-owned. It works; it has not yet had anything to find.

### Capabilities that ship switched off
These are complete and tested but default to disabled. Each is a deliberate choice, not an oversight:
`FEATURE_COPILOT` (needs your provider key), `FEATURE_AI_TOOLS`, `FEATURE_DEVICE_SSH`,
`FEATURE_TRACEROUTE` (needs `CAP_NET_RAW`), `FEATURE_WIRELESS_ACTIONS`, `FEATURE_SECURITY_LANE`,
`ENABLE_GNMI_COLLECTION`, `ENABLE_GNMI_CORRELATION`, `ENABLE_NETCONF_COLLECTION`,
`ENABLE_SNMP_DISCOVERY`, the router-side syslog admission split, and `CORR_FIDELITY_WEIGHTING`.

One of those deserves calling out: **with `CORR_FIDELITY_WEIGHTING` off (the default), documentation-
claimed evidence can still *confirm* a verdict.** The rule that a claim from documentation may support
but never confirm is implemented and ready — it is not enforced until you enable the flag.

### Deployment shape
- **Single host only. There is no Kubernetes packaging** — no Helm chart, no air-gapped k8s image
  bundle. Customers get single-host artifacts.
- **No SAML.** SSO is available through Keycloak/OIDC; a native SAML service provider is deferred.
- **The API-key UI cannot mint an administrative key.** Available scopes cover reads plus
  `write:incidents`, so fully scripted onboarding is not possible yet.
- **Sealed Fields has no operator key-rotation control** and no sensitive-data-access audit page,
  though rotation exists underneath.
- **Restore is runbook-driven**, not a button. The backup side has a UI; the restore side does not.
- The bundled **documentation portal's build chain carries 26 npm advisories** (12 high). They are
  build-time only, in Docusaurus's webpack toolchain, running against our own markdown — they are not
  in the product runtime. Clearing them requires a Docusaurus major upgrade, tracked.

---

## Support and evidence

- **Install guide:** [`docs/DEPLOY_LINUX.md`](DEPLOY_LINUX.md)
- **Sizing:** [`docs/HOSTING_SIZING_GUIDE.md`](HOSTING_SIZING_GUIDE.md), [`docs/RESOURCE_SIZING.md`](RESOURCE_SIZING.md)
- **First-customer acceptance:** [`docs/runbooks/first-customer-acceptance.md`](runbooks/first-customer-acceptance.md)
- **When something is wrong:** [`docs/runbooks/engine-not-consuming.md`](runbooks/engine-not-consuming.md)
- **What is proven versus merely built:** [`docs/audit/INVARIANTS.md`](audit/INVARIANTS.md) — the
  enforcement ladder is explicit, and its own maxim is worth quoting: *an invariant that no gate
  enforces is a preference.*
- **Bill of materials:** [`docs/sbom/`](sbom/) — CycloneDX for every dependency class.
- **Support bundle:** `scripts/support-bundle.sh` (two-pass secret redaction) or
  `./install-correlix.sh support-bundle` from a bundle install.
