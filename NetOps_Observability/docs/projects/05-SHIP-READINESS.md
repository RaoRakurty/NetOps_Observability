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
| A1 | BGP page tested with available data | 🔧 | One-page outage view (research §(b)) being built; watchlist file store + immediate bogon sightings in flight; then: watch 1.1.1.0/24 → transit/RPKI/geofeed/feed proof; re-run `scripts/bmp-synthetic-session.py` → "bogons seen" proof. Receiver→store→tenant proof already done (3 updates stored, 2nd tenant sees nothing). |
| A2 | Security: Unknown verdicts → real FAIL/PASS | 🔧 | Root causes found (IOS rules bound to SR Linux; config source empty; no reason on the wire); fix in flight; then rescan `lab` and verify the fixture-predicted FAILs + Exposure Stories. |
| A3 | Security: compliance frameworks per tenant, HIPAA visible, CIS sections not "versions" | 🔧 | Frameworks API + per-tenant enablement (default 800-53 + CIS v8) + benchmark pinning in flight. |
| A4 | Test ALL security elements on the lab | ⏳ | After A2/A3: threat detection (log + flow rules), config drift (golden → drift finding), packet capture on spine1 (bounded), advisory with a provisioned CVE feed, rules toggles, saved views, exposure stories in the RCA workspace, engine grounding as 4th class (done: 320 events). |
| A5 | Tenant-isolation audit of everything built today | 🔧 | Structural: 26 routes classified (19 scoped w/ cross-org tests, 6 globalRef, 1 token) ✅. Behavioural audit with a 2nd tenant against every surface in flight → `docs/security/TENANT_ISOLATION_AUDIT_2026-09-03.md`. |
| A6 | Local `/code-review` (high) on the branch, fix findings | ⏳ | After A1–A5 commit. |
| A7 | `/code-review ultra` | 👤 | Owner-triggered, billed. Command: `/code-review ultra` on `feat/observability-platform`. I cannot launch it. |
| A8 | Hardening dialects: NX-OS, IOS-XR, Junos, Huawei VRP, FortiOS, PAN-OS (owner ask) | ⏳ | Queued behind A2 (same package). Detections per control from documented config grammar, fixtures `doc_claimed` until a real capture; CIS benchmarks pinned where they exist (NX-OS, Junos, FortiGate, PAN-OS). Today: Cisco IOS/IOS-XE (26), Arista EOS, Nokia SR Linux (device-verified). |

## B. Documentation

| # | Item | Status | Evidence / next step |
|---|---|---|---|
| B1 | When was the documentation last updated? | ✅ | docs-portal (71 pages): last change 2026-08-12; **56 of 71 pages last edited 2026-07-01**; README.md 2026-07-27. Engineering docs under `docs/` are current (today). The customer-facing site is ~2 months behind the code. |
| B2 | Update the website with the diff to today | 🔧 | Agent: per-page gap analysis vs `git log 2026-07-01..HEAD` (Projects 1–4: scale, productization, CTEM, troubleshooting, Iris, BGP depth, alerting), rewrite/extend pages, add new ones. |
| B3 | Humanize the site (Fortinet / Palo Alto / CrowdStrike bar) | 🔧 | Agent studies the three vendors' doc conventions (task-first titles, one procedure per page, prerequisites, "what you will see", screenshots/captures, plain verbs, no AI-tells), writes `docs-portal/STYLE.md`, applies to every page, adds a denylist guard for AI-tell phrasing like the frontend copy guard. |

## C. Package, licensing, patching

| # | Item | Status | Evidence / next step |
|---|---|---|---|
| C1 | Is the package ready to ship? | 🔧 | Facts: no `v*` tag, no CHANGELOG/RELEASE NOTES, installer + update.sh + deploy-qualify exist, images unbuilt for release (owner-reserved tag/GHCR per Project 2 P4). Agent: release checklist, RELEASE_NOTES for the diff to today, CHANGELOG, SBOM (Go vendored 9 modules, 27 npm, Python, 28 container images), a clean-clone install dry run. Tag + publish stay 👤. |
| C2 | Open-source licence obligations | 🔧 | Agent: licence inventory of every Go module, npm package (+ transitive), Python package, and container base image; classify (permissive / weak copyleft / strong copyleft / non-OSS like BUSL, SSPL, Elastic); NOTICE completeness (NetClaw attribution present); decision doc with any obligation (attribution files shipped, source-offer) and any package to replace. |
| C3 | Automate patching all packages (plan) | 🔧 | Agent: plan + config: Renovate/Dependabot-equivalent for Go modules (vendored), npm, pip, GitHub Actions, container image digests; CI gates already blocking (govulncheck, trivy, gosec); a monthly "patch train" runbook; auto-merge policy for patch-level with green gate; emergency path (today's Go 1.26 raise is the template). |

## C2. Commercial tiering

| # | Item | Status | Evidence / next step |
|---|---|---|---|
| C4 | Free tier vs licensed tiers — which parts of the whole solution go where (owner ask) | 🔧 | Fable design: `docs/design/TIERING_PLAN_2026-09-03.md` — aligned with the capacity/pricing model (price per device, retention upsell, burst = SLO not billing; security findings as a per-tenant paid service). Owner decision needed on the cut lines. |

## D. Owner-visible status (updated each day)

**2026-09-03 end of day:** A1–A3, A5, B2–B3, C1–C3 in flight; A4, A6 queued behind them; A7 and the release tag/publish are yours. Owner 2026-09-03 night: **commit + push + CI green authorized at end of work**; running autonomously overnight; scenario tests (docs/qa/scenarios/) gate every closure. First status report due 2026-09-04.
