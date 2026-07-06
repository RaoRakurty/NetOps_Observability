# Correlix — Road to GTM (ordered master task list)

> Created 2026-07-06 from the market analysis + TRACKER state. Ordered by
> dependency: each phase unblocks the next; phases marked ∥ run in parallel.
> Owner tags: 👤 owner · 🤖 agent/software · 👥 both. Rough timeline: ~6 months.
>
> **Critical path:** cloud lab → cross-seam correlation testing → accuracy
> bench → scale/HA proof → launch. Company/marketing tracks run in parallel
> and never block product.
>
> Positioning (agreed 2026-07-06): **"The RCA engine for networks that can't
> leave the building"** — on-prem / air-gapped / sovereign / MSP beachhead.

---

## Phase 0 — Close what's in flight (Weeks 1–2)

Finish open tails so nothing half-done leaks into the proof phases.

| # | Task | Who |
|---|------|-----|
| 0.1 | Stream 1 tail: time-intel rollups read persisted snapshots (lift 5000 live-scan cap) | 🤖 |
| 0.2 | Inbound ServiceNow state-sync (full human-phase timing lights up ack/mitigate/resolve) | 🤖 |
| 0.3 | Stream 3: #85 four per-hop backend metrics + #77 topology polish (health-enrichment join, canvas on `/api/topology/graph`, capacity util-binding label fix) | 🤖 |
| 0.4 | Correlix/Iris AI P4 remainder; owner applies strict ClickHouse tenant policies (cmd in memory) | 👥 |
| 0.5 | Path Trace STAMP hop metrics: answer the 4 held design questions → land held code | 👤→🤖 |
| 0.6 | Brand: pick eye-logo P1–P6 → finalize assets everywhere (favicon, login, reports, site) | 👤→🤖 |
| 0.7 | Lab hygiene: lan-sw1 console recovery · confirm NetFlow no longer dry (48h check) | 👤 |

**Exit:** TRACKER streams 1 & 3 fully ✅; no "code held" items.

---

## Phase 1 — Cloud ingestion + cross-seam correlation (Weeks 2–6)

The item you named first — this generates the incident surface the whole proof
story depends on.

| # | Task | Who |
|---|------|-----|
| 1.1 | **#70 Build the AWS lab network** (VPCs, TGW, VPN back to the clab lab, small EC2 workloads). 💰 ~$150–300/mo (TGW attachments + VPN + instances + flow-log S3). Agent supplies explicit step-by-step AWS console/CLI runbook | 👤 |
| 1.2 | **#68 Cloud ingestion (3-tier causal model)**: VPC flow logs → pipeline; CloudWatch health/metric signals; CloudTrail change events | 🤖 |
| 1.3 | #81 cloud light-ups: App-Map traffic edges, real app/resource health, change timeline, Dependencies tab, source-IP + ENI/resource-key resolution, app names at remaining read paths (logs search, top-talkers, tunnels, findings, events) | 🤖 |
| 1.4 | Cloud/DX RCA mislabel fix + seam-graph (parked awaiting real AWS — now unblocked) | 🤖 |
| 1.5 | #69 P2 service catalog + `svc_flow_rollup` + baselines | 🤖 |
| 1.6 | 🧪 **TEST — cloud E2E:** flow logs land tenant-scoped in ClickHouse; App-Map edges/health/change render from REAL cloud data (done = rendered) | 👥 |
| 1.7 | 🧪 **TEST — cross-seam correlation:** inject faults across the seams (drop the VPN tunnel, blackhole a route, sever a TGW attachment, kill an EC2 app) → RCA names the correct seam with evidence, auto-files ticket | 👥 |

**Exit:** an on-prem↔cloud incident produces one correct RCA + ticket, end to end.

---

## Phase 2 — RCA Accuracy Bench (Weeks 5–10) ← flagship proof

Nobody in the market publishes RCA accuracy. The vendor who does resets the
conversation. This is the single highest-leverage GTM asset.

| # | Task | Who |
|---|------|-----|
| 2.1 | Build the fault-injection scenario suite (extend the FortiGate fault-injection methodology): 30–50 scripted scenarios — link down, optical degradation, BGP/OSPF flaps & policy errors, HW/env faults, config drift, cloud-seam faults, app-layer faults | 👥 |
| 2.2 | Run the full suite repeatedly on lab + AWS; accumulate real incident history | 👤 (inject) 🤖 (harness) |
| 2.3 | **#67 P4 replay calibration** against that history; tune the 57 enabled signatures; unblock the 42 Layer-2-kind backlog templates as event kinds land | 🤖 |
| 2.4 | 🧪 **TEST — publish the Accuracy Bench Report:** precision/recall per scenario class, median time-to-identify, ≥2-stream corroboration rate, false-positive rate. Reproducible methodology appendix | 👥 |

**Exit:** numbers good enough to put on the website. If they aren't good yet,
iterate 2.2↔2.3 — this loop IS the product maturing.

---

## Phase 3 — Scale, HA & reliability proof (Weeks 8–14)

| # | Task | Who |
|---|------|-----|
| 3.1 | Multi-node Kafka support (BROKER_URLS already abstracts brokers — add clustered profile + docs) | 🤖 |
| 3.2 | K8s/Helm packaging (Phase 2 of #97 packaging) | 🤖 |
| 3.3 | Disk/retention guardrails: OpenSearch ILM + watermark alerts, CH/VM retention config, self-protection (the OS flows-flood outage, productized) | 🤖 |
| 3.4 | 🧪 **TEST — load:** 5,000 simulated devices + 50k flows/s (tgen + SNMP sim), 72h sustained. Record ingest lag, query latency at 30/90-day retention. **Publish the numbers** | 👥 |
| 3.5 | 🧪 **TEST — chaos/HA:** kill every one of the ~19 services in turn → no data loss, no silent blind window, watchdog + in-app alerting both fire | 👥 |
| 3.6 | 🧪 **TEST — 30-day soak** on VM .123 bundle: memory/disk growth, cert expiry, log rotation | 👤 (passive) |
| 3.7 | 🧪 **TEST — backup/restore/DR:** documented runbook + full restore drill onto a clean host | 👥 |
| 3.8 | Stream 6 SaaS-hardening pass: #16 remaining 3 sub-items, #33 users repo finish, #75, ingest one-way-door decision | 🤖 |

**Exit:** published scale sheet + "kill anything, we stay honest" claim you can demo live.

---

## Phase 4 — ∥ Productization & packaging (Weeks 10–16)

| # | Task | Who |
|---|------|-----|
| 4.1 | **Build licensing** (Ed25519 offline license files; no-license = FREE tier; entitlements for correlation/automation/AI; 30-day eval auto-mint). Design agreed 2026-07-03, ~2 days | 🤖 |
| 4.2 | 🧪 **TEST — licensing enforcement:** free-tier lockouts, expiry behavior, tamper rejection, eval mint, upgrade-in-place | 👥 |
| 4.3 | **BYO / on-prem LLM** for Iris AI: Ollama/vLLM/Bedrock/Azure-OpenAI endpoints behind the copilot proxy. "Your incident data never leaves the network — including the AI" | 🤖 |
| 4.4 | 🧪 **TEST — AI red-team:** prompt injection, cross-tenant leakage via prompts, output-handling, cost/token caps (extends OWASP §15 work) | 👥 |
| 4.5 | Release engineering: semver, changelog, GPG-signed bundles (owner key), versioned upgrade path | 👥 |
| 4.6 | 🧪 **TEST — upgrade:** bundle vN → vN+1 on live data, zero loss, documented | 👥 |
| 4.7 | 🧪 **TEST — fresh-install matrix:** Ubuntu 22/24 + RHEL 9 + fully air-gapped install; `preflight.sh` + CI fresh-install-integrity stay green | 👥 |
| 4.8 | Evaluator docs site: install, quick-start, admin guide, API reference, integration guides (from existing `docs/`) | 🤖 |
| 4.9 | UI final QA: #71 panel-fix sweep, admin form wizardization (#20), cross-browser pass, accessibility scan, empty-state audit | 🤖 |

**Exit:** a stranger can download, install, evaluate, and license without talking to you.

---

## Phase 5 — ∥ Trust & security artifacts (Weeks 12–18)

| # | Task | Who |
|---|------|-----|
| 5.1 | SBOM publication + security-disclosure/CVE process page | 🤖 |
| 5.2 | Re-run the IAM/tenancy audit suite (`scripts/audits/run.py`) + full gitleaks/trivy/govulncheck pass; fix all findings | 🤖 |
| 5.3 | 🧪 **TEST — third-party penetration test.** 💰 $8–25k, 4–6 wk lead time — book early | 👤 |
| 5.4 | Security whitepaper: zero-trust architecture, FORCE-RLS tenancy, vault+TPM, OWASP-LLM hardening, offline build | 🤖 |
| 5.5 | SOC 2 Type I kickoff once company exists (Phase 6). 💰 $15–40k (auditor + Vanta/Drata), 2–3 months. Announce the *roadmap* before completion — sovereign buyers reward trajectory | 👤 |

---

## Phase 6 — ∥ Company formation (START WEEK ~8 — long lead times)

Runs fully parallel to product. Nothing here blocks engineering; several items
(trademark, insurance, SOC 2) have long fuses — start early.

| # | Task | Who |
|---|------|-----|
| 6.1 | **Trademark + name clearance for "Correlix"** — USPTO search (Class 9/42), domain grab (correlix.com/.io/.ai), international quick-check. Do FIRST: a forced rename later poisons everything downstream | 👤 |
| 6.2 | **Incorporate.** Bootstrap → LLC; venture path → Delaware C-Corp (Stripe Atlas / Clerky, ~$500). Then: EIN, business bank (e.g. Mercury), bookkeeping | 👤 |
| 6.3 | **IP assignment** — formally assign all pre-incorporation code/brand to the company. Critical for any future diligence | 👤 |
| 6.4 | Founder hygiene: cap table, 83(b) election within 30 days if C-Corp, E&O + cyber insurance (enterprise buyers ask for certificates) | 👤 |
| 6.5 | Legal doc set: EULA/license agreement (matches 4.1 tiers), privacy policy, ToS, DPA template, support SLA doc. Template + lawyer review 💰 ~$2–5k | 👤 |
| 6.6 | **Pricing & packaging sheet**: Free (SNMP discovery+monitoring) / Pro (correlation+RCA) / Enterprise (automation, AI, multi-org, support). Anchor vs LogicMonitor/Auvik per-device pricing; flat self-hosted tiers | 👥 |
| 6.7 | Support model: intake channel (email + community forum/Discord), SLA tiers, install-support runbooks | 👥 |

---

## Phase 7 — ∥ Marketing presence & content (Weeks 12–20)

| # | Task | Who |
|---|------|-----|
| 7.1 | **Website** on correlix.com: hero = positioning line; pages — product, RCA accuracy bench (Phase 2 output IS the centerpiece), security/trust, pricing, docs, download/free-tier CTA. Agent builds; owner reviews | 👥 |
| 7.2 | **LinkedIn**: company page + founder profile upgraded to Correlix. Cadence 2–3 posts/wk, build-in-public: bench results, RCA war stories, lab screenshots, "how we correlated X" threads. LinkedIn is THE channel for NetOps buyers | 👤 |
| 7.3 | Hosted demo environment: tgen-driven live data + guided tour; 3–5 min demo video (screen capture + voiceover) | 👥 |
| 7.4 | Sales collateral: battlecards vs ThousandEyes / Datadog NPM / Kentik / Selector / Auvik; ROI one-pager; accuracy-bench PDF; security whitepaper (5.4) | 🤖 |
| 7.5 | Community seeding: r/networking + r/sysadmin presence, NANOG list, Packet Pushers / network podcasts outreach, conference lightning-talk submissions | 👤 |
| 7.6 | Email capture + newsletter; accuracy bench report as the lead magnet | 👥 |

---

## Phase 8 — ∥ Design partners & real-world validation (Weeks 14–24)

| # | Task | Who |
|---|------|-----|
| 8.1 | Real-hardware validation bench: used enterprise gear (Cat9k/Nexus, PA, F5, a couple of APs). 💰 ~$3–8k used | 👤 |
| 8.2 | Vendor profiles for PA/F5/APs on real gear; Port Intelligence rendered on real optics (its first real render) | 🤖 |
| 8.3 | **Recruit 3–5 design partners** — free enterprise license ↔ weekly feedback, device-quirk telemetry, logo/testimonial rights. Source: owner's network + LinkedIn (7.2) | 👤 |
| 8.4 | Onboard partners, run weekly feedback loop, fix quirks fast, extract 1–2 written case studies | 👥 |
| 8.5 | NMS integration real-vendor contact validation (already owner-gated in tracker) | 👤 |
| 8.6 | 🧪 **TEST — time-to-value:** a network engineer who has never seen Correlix installs from docs alone in <1 hour. Recruit a friendly stranger; watch, don't help | 👤 |

**Exit:** ≥3 external networks running Correlix; ≥1 public case study; TTV <1h proven.

---

## Phase 9 — Launch (Week ~24)

| # | Task | Who |
|---|------|-----|
| 9.1 | Launch-readiness checklist: website live · free tier downloadable · docs public · demo video · bench report · security page · pricing · support intake · signed bundles | 👥 |
| 9.2 | Launch motions (same week): Show HN post · LinkedIn announcement + partner testimonials · r/networking post · NANOG lightning talk · Product Hunt (secondary) | 👤 |
| 9.3 | Post-launch loop: opt-in install telemetry, download→install→license funnel metrics, weekly release cadence, public roadmap | 👥 |

---

## Master testing checklist (consolidated)

Continuous (already gating): Go vet/test/race, staticcheck, gosec, govulncheck,
frontend build, fresh-install-integrity CI, isolation tests per feature (§3a).

| Test | Phase | Status |
|------|-------|--------|
| Cloud ingestion E2E (rendered on real data) | 1.6 | ⏳ |
| Cross-seam fault correlation (on-prem↔cloud) | 1.7 | ⏳ |
| Fault-injection suite, 30–50 scenarios | 2.1–2.2 | ⏳ |
| RCA accuracy bench (precision/recall/MTTI) — published | 2.4 | ⏳ |
| Load: 5k devices / 50k flows/s / 72h — published | 3.4 | ⏳ |
| Chaos/HA: every service killed, no blind window | 3.5 | ⏳ |
| 30-day soak on VM bundle | 3.6 | ⏳ |
| Backup/restore/DR drill | 3.7 | ⏳ |
| Licensing enforcement | 4.2 | ⏳ |
| AI red-team (injection/leakage/caps) | 4.4 | ⏳ |
| Upgrade vN→vN+1 with live data | 4.6 | ⏳ |
| Fresh-install matrix (Ubuntu/RHEL/air-gapped) | 4.7 | ⏳ |
| Tenancy/IAM audit re-run + scanner pass | 5.2 | ⏳ |
| Third-party penetration test | 5.3 | ⏳ |
| Real-hardware vendor matrix (incl. real optics) | 8.2 | ⏳ |
| Stranger time-to-value <1h | 8.6 | ⏳ |
| RCA→ticket E2E vs real ServiceNow PDI | 0.2/1.7 | ⏳ (mock-validated ✅) |

## Explicitly deferred past GTM

Wireless AP monitoring (owner design pending) · VXLAN/EVPN overlay #82 (needs
real gear) · unified event console #53 / AIOps grouping #44 (discuss-first) ·
hosted SaaS offering (one-way-door decision in 3.8 first) · global internet
vantage points (concede to ThousandEyes; branch prober mesh instead) · SOC 2
Type II · Common Criteria (announce intent only).

## Budget flags (owner) 💰

AWS lab ~$150–300/mo · pen test $8–25k · SOC 2 Type I $15–40k · used hardware
$3–8k · incorporation+legal ~$3–6k · insurance ~$2–4k/yr · trademark ~$1–2k.
Total cash to GTM (ex-time): roughly **$35–85k**, most of it deferrable
(SOC 2 and pen test can trail launch by a quarter if bootstrapping).
