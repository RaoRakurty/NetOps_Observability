# Project 5 — Ship readiness (owner asks of 2026-09-03)  🟠

Owner, 2026-09-03: "test the BGP page with the available data; once good close the
topic and move ahead with security and test all security elements; then run
`/code-review ultra`; identify when documentation was last updated, update it with
the diff up to today and humanize the entire documentation website (Fortinet / Palo
Alto / CrowdStrike as the bar); is the package ready to ship with release docs; ensure
no open-source licensing obligations; plan how to automate patching every package;
create a tracker and show status by tomorrow."

Statuses: ✅ done · 🔧 in flight (agent) · ⏳ queued · 👤 owner action · ❌ not started.
Dates are 2026-09-03 unless stated. Rows are DELETED when shipped (tracker rule).

## A. Close out today's build (Projects 3 + 4)

| # | Item | Status | Evidence / next step |
|---|---|---|---|
| A1 | BGP page tested with available data | 🔧 | One-page outage view SHIPPED (e8e85f85: no tabs, verdict pinned, 3× fewer DOM nodes). Watchlist file store + immediate bogon sightings in final gate; then deploy and prove: watch 1.1.1.0/24 + RIPE RPKI test prefixes → transit/RPKI/geofeed/feed; re-run `scripts/bmp-synthetic-session.py` → "bogons seen". Receiver→store→tenant proof already done. |
| A2 | Security: Unknown verdicts → real FAIL/PASS | ✅ code / ⏳ live proof | Root causes fixed: engine gated on config BEFORE dialect binding (so the whole IOS catalogue was emitted Unknown for SR Linux); security lane was constructed before the config-backup source existed (nil → "running-config unavailable"); no reason on the wire (`attrs.status_detail` now carried, UI shows "Why unassessed"). Fixture test asserts the exact SR Linux FAIL set (http-server-nontls, mgmt-api-unencrypted, tls-no-client-auth, snmp-v1v2c-community, no-remote-aaa, no-ntp-server). Next: commit with A3, deploy, rescan `lab`, expect 15 findings/spine with 6 FAILs + Exposure Stories. |
| A3 | Security: compliance frameworks per tenant, HIPAA visible, CIS sections not "versions" | ✅ code / ⏳ live proof | Closed catalogue of 5 frameworks (800-53 R5 + CIS Controls v8.1 default ON; NIST CSF 2.0, HIPAA Security Rule, PCI DSS v4.0.1 opt-in) with per-tenant selection (migration 0042 FORCE-RLS + file fallback, isolation test). Invented `CIS-NET-x.y`/`PCI-*` tags deleted; rules cite real CIS Cisco IOS/IOS-XE benchmark sections (verified on cisecurity.org 2026-09-03); NX-OS/EOS/Junos benchmarks listed but cite nothing (taxonomy unverified). CSF ids corrected from 1.1 to 2.0. Next: deploy and check the page. |
| A4 | Test ALL security elements on the lab | ✅ run / 🔧 defects | `docs/qa/scenarios/security-ops-2026-09-03.md` (7 scenarios, 16 defects). PROVEN: syslog line → finding (T1136.001/T1098) → engine grounded (class=security) → correlated exposure story in **73 s**; config drift capture→seal→golden→recapture `in_sync` (sealed blob, 34 masks, zero plaintext); rule toggles + saved views + every isolation assertion. FAILED: exposure-stories LIST always empty (engine stamps zero-UUID signal_id on edge rows), findings detail 404 for every id, SR Linux threat-log phrasing unmatched, SR Linux never advisory-assessed, vmalert password visible in `docker inspect`. Fix agent running. Packet capture untestable (flag off, no Nokia pcap family, data/pcap root-owned). |
| A5 | Tenant-isolation audit of everything built today | ✅ | `docs/security/TENANT_ISOLATION_AUDIT_2026-09-03.md`: 61 PASS, 0 leaks; 1 CRITICAL (customer per-device alerts pushed as platform) fixed d32f0c0f and deployed. Both scenario runs re-asserted isolation on every troubleshooting + security surface (404s byte-identical to absent, `as_tenant` escalation ignored). |
| A6 | Local `/code-review` (high) on the branch, fix findings | ⏳ | After the three defect agents land and the gate is green. |
| A7 | `/code-review ultra` | 👤 | Owner-triggered, billed. Command: `/code-review ultra` on `feat/observability-platform`. I cannot launch it. |
| A8 | Hardening dialects: NX-OS, IOS-XR, Junos, Huawei VRP, FortiOS, PAN-OS (owner ask) | ⏳ | Queued behind A2 (same package). Detections per control from documented config grammar, fixtures `doc_claimed` until a real capture; CIS benchmarks pinned where they exist (NX-OS, Junos, FortiGate, PAN-OS). Today: Cisco IOS/IOS-XE (26), Arista EOS, Nokia SR Linux (device-verified). |
| A9 | Alert noise + ntfy rate-limit | ✅ code / ⏳ live | 0c9eb816: warning digest (one push / 30 m window), per-topic push budget 30/h with 10 reserved for pages, page-tier retry with backoff honouring Retry-After, typed ntfy errors. Drill evidence (before): the ONE engine-down page fired on time and died on 429 behind 18/18 failed warning pushes; resolutions never pushed (D-12, fixing). Deploying now. |
| A10 | Troubleshooting scenarios (Project 4) | ✅ run / 🔧 defects | `docs/qa/scenarios/troubleshooting-2026-09-03.md` (7 scenarios, 12 defects). PASS: IGP adjacency, VRF views, investigation API, Iris audit trail, error boundary, IS-IS depth series agree with the device. **P0 found + fixed + redeployed:** Iris feedback store constructor left a nil map → every rating panicked (502) → Phase-B memory loop was dead (500acabb; proven live afterwards: memory stamped "(operator confirmed)", invisible to a foreign tenant). HIGH open: SR Linux profile hands out SR OS commands (20/20 failed) — fixing with A4's agent. Others (status phrasings reach no skill, total-collect failure mis-reported, `?device=` ignored, gnmic ownership gate starves the lab of interface/CPU series, audit trail not persisted) — fix agent running. |
| A11 | Host disk (found 94 %, OpenSearch read-only at 95 %) | 🔧 | Reclaimed 8 GB tonight (stale Go build temp dirs, scratch, build cache) → 85 %. Causes being fixed: only 8/37 compose services had a log size bound (OpenSearch json log 1.1 GB); ClickHouse writes 1.8 GB of logs inside its container layer (no mount, no rotation). Not touched: `data/` 6.3 GB, images 13.5 GB. |

## B. Documentation

| # | Item | Status | Evidence / next step |
|---|---|---|---|
| B1 | When was the documentation last updated? | ✅ | docs-portal (71 pages): last change 2026-08-12; **56 of 71 pages last edited 2026-07-01**; README.md 2026-07-27. Engineering docs under `docs/` are current (today). The customer-facing site is ~2 months behind the code. |
| B2 | Update the website with the diff to today | 🔧 | Agent: per-page gap analysis vs `git log 2026-07-01..HEAD` (Projects 1–4: scale, productization, CTEM, troubleshooting, Iris, BGP depth, alerting), rewrite/extend pages, add new ones. |
| B3 | Humanize the site (Fortinet / Palo Alto / CrowdStrike bar) | 🔧 | Agent studies the three vendors' doc conventions (task-first titles, one procedure per page, prerequisites, "what you will see", screenshots/captures, plain verbs, no AI-tells), writes `docs-portal/STYLE.md`, applies to every page, adds a denylist guard for AI-tell phrasing like the frontend copy guard. |

## C. Package, licensing, patching

| # | Item | Status | Evidence / next step |
|---|---|---|---|
| C1 | Is the package ready to ship? | ✅ answered | d6f1e036: `docs/RELEASE_CHECKLIST.md`, `CHANGELOG.md`, `docs/RELEASE_NOTES_v0.9.0-rc1.md`, CycloneDX 1.6 SBOMs (`scripts/sbom.py`, 6 docs, 1 382 components). **Verdict: not ready for a final tag; ready for `v0.9.0-rc1`** once: branch protection stops naming a phantom job, `release-bundle.yml` labels the core bundle honestly, work lands on main. Final blocked on: tracker 203 (reference-capacity regression never run), no bundle signing in CI (`CORRELIX_SIGNING_KEY` unset), no cosign, **no `LICENSE` file at either root** (owner: pick the licence). Tag + GHCR publish are yours; note `publish-images.yml` has no test gate. |
| C2 | Open-source licence obligations | ✅ audit / 🔧 attribution | `docs/security/LICENSE_AUDIT_2026-09-03.md` (commit bc052002): 1,428 components, 127 distributed; **no copyleft linked into anything we build, zero SSPL/BUSL/Elastic**. Reproducible offline `scripts/license-audit.py` + `license-gate` CI job. Five attribution gaps being fixed now (tracker 228: elkjs EPL notice, OFL fonts, Feather/Lucide icons, certifi, bundle LICENSES.md). Six owner decisions filed as tracker 227 (Grafana AGPL keep/drop, syslog-ng source offer, Cisco/Arista MIB extracts, cloud marks, Keycloak UBI EULA / Gotenberg never ships, brand glyph is Feather's `activity`). |
| C3 | Automate patching all packages (plan) | ✅ plan / 👤 enable | d6f1e036: `docs/design/PATCH_AUTOMATION_PLAN_2026-09-03.md`, `.github/renovate.json` (validated), self-hosted `renovate.yml` (fails loudly without `RENOVATE_TOKEN`), blocking offline-vendor-build CI job, `docs/runbooks/patch-train.md`. Why Renovate over Dependabot: Dependabot cannot see the 47 compose image refs or the toolchain pins in env blocks, has no automerge, breaks the hash-locked requirements. Owner: create `RENOVATE_TOKEN`, delete `dependabot.yml` in the same commit, extend required checks. Drift found (nothing bumped): 8 image tags 2+ yrs old, docs-portal 26 npm advisories (Docusaurus chain), uvicorn/aiokafka far behind, 5 unpinned Actions. |

## C2. Commercial tiering

| # | Item | Status | Evidence / next step |
|---|---|---|---|
| C4 | Free tier vs licensed tiers — which parts of the whole solution go where (owner ask) | 👤 decide | Fable design: `docs/design/TIERING_PLAN_2026-09-03.md` — aligned with the capacity/pricing model (price per device, retention upsell, burst = SLO not billing; security findings as a per-tenant paid service). Owner decision needed on the cut lines. |

## D. Owner-visible status (updated each day)

**2026-09-03 end of day:** A1–A3, A5, B2–B3, C1–C3 in flight; A4, A6 queued behind them; A7 and the release tag/publish are yours. Owner 2026-09-03 night: **commit + push + CI green authorized at end of work**; running autonomously overnight; scenario tests (docs/qa/scenarios/) gate every closure. First status report due 2026-09-04.
