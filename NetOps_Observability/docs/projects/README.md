# Active projects — priority order

Owner-set portfolio (2026-08-27; **redefined 2026-09-01** — Project 1 closed
DONE, **Productization & Design Partners** inserted as the new Project 2, and
the former Projects 2/3 renumbered to 3/4). Four projects, executed **in this
order**. Each has its own tracker in this directory. The master
`docs/TRACKER.md` remains the authoritative id registry (shipped or descoped
rows are deleted, so the set shrinks); these project trackers are the
**execution views** that organize and sequence the work.

| # | Project | Priority | Tracker | One-line |
|---|---------|----------|---------|----------|
| 1 | **Scale Testing** | ✅ COMPLETE (2026-09-01) | [01-SCALE-TESTING.md](01-SCALE-TESTING.md) | Host ceiling + binding resource found at nominal AND storm; completion record `docs/scale/PROJECT1_DONE_2026-09-01.md`. |
| 2 | **Productization & Design Partners** | 🟦 **BUILT — owner review + deploy/qualification pending** | [02-PRODUCTIZATION-DESIGN-PARTNERS.md](02-PRODUCTIZATION-DESIGN-PARTNERS.md) | Operator-first UI, RCA hero experience, deployment simplicity, pilot/design-partner readiness. **OPENED 2026-09-02**; gap report + wave-1 plan in [02-GAP-REPORT-2026-09-02.md](02-GAP-REPORT-2026-09-02.md), landed state with commits in its **§3b/§3c ledgers**. The P1 bucket (P0–P3, P5–P7, G6, G10 and the 184–211 engine rows) is code at HEAD; **nothing is deployed**, the V1 lab leg has not run, no `v*` tag exists, and the shipping wave (P4) is owner-reserved. |
| 3 | **Security CTEM** | 🟦 **DEPLOYED to the lab — lane ON, waiting on a tenant** | [03-SECURITY-CTEM.md](03-SECURITY-CTEM.md) | Network-security section grounding into the engine as the 4th evidence class. All build items landed; deployed 2026-09-03 with `FEATURE_SECURITY_LANE` + `FEATURE_CONFIG_BACKUP` ON (SR Linux/EOS capture + hardening device-verified). Zero findings so far for one honest reason: the lab's devices are platform-owned and the lane scans tenant-owned devices only — first finding flows when a tenant owns spine1/2 (owner action). `/code-review ultra` pending. |
| 4 | **Troubleshooting protocols** | 🟦 **BUILT + DEPLOYED (waves 0–3, 2026-09-02/03)** | [04-TROUBLESHOOTING.md](04-TROUBLESHOOTING.md) | Investigation surface · live SSH collect · Iris Phases A–B (skills, chaining, parsers, state battery, memory) · IGP depth (IS-IS live-attested) · BGP depth/BMP/alerting/classes/peers/bogons · VRF interfaces · perf wave 2 + copy pass · shell error boundary. Open: BGP tracker rows 2/3/6/7/9/11, owner-doc ingestion, Junos/NX-OS hardening dialects, `/code-review ultra`. |

Each project ends with an owner-triggered **`/code-review ultra`** (I cannot
launch it; I hand off when a project reaches a reviewable state). Project 1's
ultra review is dispositioned in
`docs/scale/ULTRA_REVIEW_DISPOSITION_2026-09-01.md`.
