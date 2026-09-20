<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Correlix -->

# Iris — design review, strategy fit, and the road to a commercial product

**Date:** 2026-09-20 · **Status:** review of record
**Inputs:** the shipped code at `eef2ef94`; our own design baseline `docs/design/correlix-ai-hld.md` (2026-06-29);
the new external strategy `AiStratgey.md` (Kentik study + Correlix gap analysis);
five independent read-only surveys of the implementation (pipeline, guardrails, data foundation,
detection/RCA/eval, agent/tools/governance).
**Owner's commercial goal, 2026-09-20 (verbatim):** *"noc admin should be able to retrieve outputs from
the devices, able to modify the output of show commands like noc admin wants and more operational tasks
and also automations, also should be able to teach the customer specific networks, able to give runbooks,
mops, may able to write with approval in the loop, MCP should be supported."*

---

## 1. The headline

**The external strategy's Correlix section is written against a baseline it never received.** It says so
itself: *"Because no Coreelix architecture or current maturity baseline was supplied, the following gap
analysis uses a conservative assumption…"* It then prescribes **15–18 months and 24–30 people**.

Measured against the code, its **Months 0–3** milestone (canonical entity model, telemetry contracts,
enrichment, incident corpus, eval harness, baseline anomaly models — 6 deliverables) and its
**Months 3–6** milestone (seasonal/change-point detection, event clustering/correlation, topology graph,
evidence store, first RCA ranking — 5 deliverables) are **all shipped**. Months 6–9 (NL query, typed tool
registry, model router, investigation agent, evidence citations) is shipped except the router's wiring.

The three architectural choices the strategy calls decisive are **already our architecture**, and in two
cases ours is stricter:

| Strategy's recommendation | Correlix today |
|---|---|
| "The RCA engine should be independent of the LLM" | The correlation engine is 46,647 lines of Python with **zero** model imports. Verdict, confidence and evidence are written to ClickHouse with no model in the path. |
| "Score candidates `R(c) = w_t·T + w_g·G + w_Δ·C + w_a·A + w_h·H − w_u·U`" | We **split** it: grouping carries T and G multiplicatively with a hard topology-grounding precondition; ranking carries coverage and contradiction; **verdict is an orthogonal gate, not a score**. A structurally impossible signature is *refused*, not out-weighed — which is how a false positive with confidence 1.0 went 589 rows → 0 with accuracy flat. An additive score cannot express that. |
| "Authorization at the tool boundary; never trust the model" | `PolicyEngine.EvaluateTool` runs **twice** (manifest filter + re-authorization at execution). The model can never name a tool, a scope, or an unauthored skill. Cross-tenant → `ErrNotFound`, never a 403 that leaks an id. |

**Corrected sizing.** On the ratified scope — network-first, single appliance, not a SIEM — the remaining
work across all three slices is **roughly 45–90 engineer-weeks**, not 24–30 FTE for 15–18 months.

---

## 2. Maturity baseline, measured

| Capability | Score | Evidence |
|---|---:|---|
| Network data foundation | **4/5** | 17 typed entities enum-pinned across Python and ClickHouse; `tenant_id` leads every partition key with a row policy that **fails closed at the database** (an unscoped query errors, it does not return rows); 61.8 M `corr_edges`, 711 M archived signals; frozen Service Path Graph contract with a 7-rank resolution ladder where rank 7 can never become an edge. |
| Rules / statistical / ML detection | **3/5** | Two-sided CUSUM change-point (H=4σ, K=0.5σ) with onset = run start and per-source clock budget; baseline frozen while an episode is open; 145 promtool-unit-tested alert rules. **Missing: seasonal baselines, MAD/robust z, forecasting.** |
| Correlation | **5/5** | Deterministic edge build, `exp(-gap/τ)×w_topo×w_reinforce`, 7-rung topology evidence ladder, cross-modality reinforcement, direction on a 2-of-3 vote. Hard invariant: no topology grounding ⇒ no edge, ever. |
| Evidence-scored RCA | **4/5** | 103-signature catalog; `confidence = coverage × graph_support × direction_agreement`; contradiction → ×0.2 plus the beaten competitor is force-listed; `undetermined` is first-class with `evidence_missing` derived mechanically. **Missing: change-proximity and historical-association terms; `graph_support` is hard-wired to 1.0.** |
| Agentic investigation | **4/5** | 26 typed tools with JSON-Schema args, no free-form SQL/shell; deterministic skill chain (4 rounds, 16 calls, 45 s) where the next hop is an authored machine condition first and a *closed* model choice second. Model-driven loop built and tested but **dark** (`FEATURE_AI_TOOLS=false`). |
| Operational knowledge | **3/5** | 13 compile-verified skills + 354 authored explanations + a TAC catalogue of 85 issue classes / 1,273 intents / 1,662 command bindings / 163 forbidden rules. **Customers cannot author any of it.** |
| AI governance | **4/5** | Double authorization, arg-name-only audit, fail-safe redaction, deterministic citation stripping, per-tenant entitlement and BYO key, FORCE-RLS investigation memory. |
| Evaluation discipline | **4/5** | CI-blocking: 61 golden fixtures (incl. injection and decline categories) with hit@1 ≥ 0.75 / hit@3 ≥ 0.90; 116 correlation fixtures with every enabled signature covered. Rig-measured RCA accuracy 345/345 across 11 legs. |
| Autonomous remediation | **1/5** | Deliberate. `CapWrite`/`CapExecute` hard-denied for the agent. |

---

## 3. What the commercial goal requires that we do not have

The owner's seven asks, against the baseline:

| # | Commercial ask | Status | What is actually missing |
|---|---|---|---|
| 1 | Retrieve outputs from devices | **Shipped** | TAC captures run bounded read-only collections over SSH, output-only enforced at three layers. |
| 2 | **Modify the show-command set the way the NOC admin wants** | **Half** | A customer can upload a command list and it is validated against the output-only policy; there is no per-tenant *authoring/versioning* of a named command set with diff and rollback, and no output shaping. |
| 3 | More operational tasks and automations | **Partial** | Everything is operator-initiated. No alert-triggered investigation, no scheduled investigation, no workflow. |
| 4 | **Teach Iris the customer's specific network** | **Absent** | There is no versioned org-context store. The only knob is a single free-text platform-admin field that **replaces** the whole persona — unversioned, undiffed, no rollback. That is the strategy's own "runbook poisoning" risk, live. |
| 5 | **Runbooks and MOPs the customer can give** | **Absent for customers** | Our 13 skills *are* runbooks, and stricter than Kentik's (the API refuses to boot on a dangling hop). But they are compiled in. A customer cannot author, version or test one. |
| 6 | Write with approval in the loop | **Exists, not agent-reachable** | Five-gate wireless actions (blast radius 1, named approver, verification, rollback), TAC Escalate→Prepare→Confirm, credential dry-run. None of it is reachable from Iris, by design. Making it agent-reachable is a policy-tier change, not new machinery. |
| 7 | MCP support | **Absent** | HLD §9 defers it to P7 and says a future MCP server is "a thin, optional, off-by-default adapter" over the same tools. `AITool` is genuinely the right shape. |

---

## 4. Defects found during this review

| Sev | Defect | Evidence |
|---|---|---|
| **High** | **A configured provider key silently un-grounds free text.** `Opsis.tsx:253` routes free-text to the plain chat proxy when `key_present`, bypassing classification, skills, policy, TAC, quality and citations — while the panel still tells the operator "Answers are grounded, tenant-scoped and cited." Latent today (`key_present: false` on the lab), fires the moment a key is configured, which is the normal production state. The roadmap's own top-priority fix, still open. |
| **High** | **`ListProblemsInWindow` 502s for a platform owner.** Same class as the `ListActiveProblems` bug fixed in `eef2ef94`. Measured on the lab at the 1 GiB ceiling: a 30-day cross-tenant window reads 2,431,209 rows / 732 MiB and peaks at 1022.9 MiB → `Code 241`. `bounded_io_test.go` Rule 5 passes it because it checks for a bound, not for the narrow-pick split. |
| **High** | **No behavioural test protects the skill chain.** ~30 authored conditions across 13 skills; the loader validates shape only. The 11 `verdict:phrase=` rules match a *word* in the engine's authored operator phrase — reword one NOC signature from "link" to "circuit" and four routing rules die silently in three skills with CI green. |
| **Medium** | **RCA workspace grounds in the browser.** `RcaWorkspace.tsx:60` concatenates the operator's text *after* the context and posts to the ungrounded proxy, so a question can rewrite its own grounding. `RcaAskAi.tsx:28` already does it correctly; this path should be deleted. |
| **Medium** | **No data-vs-instruction fence on the agent loop**, and evidence text is newline-unsanitised, so planted syslog can forge additional evidence bullets. The curated corpus *is* fenced; the attacker-reachable one is not — the defence is inverted. |
| **Medium** | **The narrative can overclaim on an `undetermined` verdict.** `problemPrompt` asks for "the likely root cause and why" regardless of tier, and nothing post-checks the prose. Structured fields stay honest; the headline the operator reads may not. |
| **Medium** | **`hit@3` is 0.91 against a 0.90 CI floor**, down from the documented 0.97. One corpus edit from a red build, and `docs/ai/evals.md` still cites 0.97 as the reason vector retrieval stays deferred. |
| **Medium** | **Four enrichment exporters export ~nothing.** Every 60 s on the lab: 2 devices, 0 iface-IPs, 0 ifIndexes, 0 links, 0 seams, 0 endpoints. 98 % of graph edges are undirected as a direct consequence. This is a **population** problem, not an architecture problem. |
| **Low** | `ProductKB` retrieval is dead code (the docs index always wins), guarded by a 477-line link test. `ItsmNote` and `ContradictingEvidence` are declared and never filled. `docs/COPILOT.md` contradicts the LLM01 invariant the code enforces. `docs/ARCHITECTURE.md` is ~2 years stale and still calls RCA "a stub — the algorithm is a placeholder". |

---

## 5. Where the strategy is wrong about us, on the record

1. **The 6–9 month / 5–8 engineer data-platform contingency is inverted.** The data foundation is the most finished tier, not the least.
2. **"Poor telemetry semantics" is the wrong diagnosis of a real risk.** Our semantics are enum-pinned, provenance-carrying and abstention-capable. Our **coverage** is thin. Same failure, opposite cause — and the fix is collectors and an estate, not schema work.
3. **"Cross-tenant leakage → tenant-scoped credentials at the tool layer"** understates what is built: the row policies fail closed *at the database*.
4. **"Lack of labels → RCA quality cannot be measured."** We measure it. The real exposure is the inverse: 100 % on ~12 self-authored archetypes against a 103-signature catalog, not held out, rig-gated rather than CI-gated.
5. **Tier 4–5 writes (restart workload, routing change, BGP, firewall) are not "later" here — they are prohibited by owner decision** and structurally impossible: config/restart/daemon commands are unknown to the product, enforced at ingestion, at load, and again on the rendered string. Do not put them on a roadmap.
6. **`execute_runbook` as a model-callable tool would be a regression**, not an upgrade: it restores exactly the agency the skill-chain design removed.
7. **Seam-level ownership has no row in the strategy's scorecard at all** — and it is a differentiator, not an omission.

---

## 6. Sequencing to a commercial Iris

Ordered by dependency, not by visibility. Each row is a tracker item with effort and test scope.

| # | Item | Why it comes here | Eng-weeks |
|---|---|---|---:|
| 1 | Skill-chain behavioural test cases (`CASES.yaml`, loader-required) + reference test cross-checking every `signature=` and `verdict:phrase=` | The deterministic chain **is** the investigator in production. 30 conditions, none proven to fire. Everything below becomes measurable once this exists. | 2–3 |
| 2 | Route free text to the grounded engine; delete browser-side grounding; label any ungrounded bubble | The product's central claim is false on a keyed deployment. | 1–2 |
| 3 | `ListProblemsInWindow` narrow-pick fix + tighten Rule 5 | Measured 502 for a platform owner. | 1 |
| 4 | Injection hardening: newline-strip at the four rendering boundaries; non-overridable data-not-instructions fence; multi-line injection fixture | Syslog is attacker-reachable. | 1 |
| 5 | Verdict-conditional narrative + certainty-marker post-check | Honesty is the product. | 1 |
| 6 | **Versioned customer context store** (org knowledge, diff, approval, rollback, audit) replacing the single free-text override | Commercial ask #4. Also closes the runbook-poisoning risk. | 2–3 |
| 7 | **Tenant-authored runbooks/MOPs**: schema, authoring API, versioning, validation against the same loader rules, mandatory test cases | Commercial ask #5. Depends on #1 and #6. | 6–8 |
| 8 | **Per-tenant command-set authoring** with diff/rollback + output shaping for captures | Commercial ask #2. | 4–5 |
| 9 | Wire `RouteFor` tiers to real models (`ModelFast`/`ModelStrong`) | Cost, not correctness. Policy already exists and is tested. | 1–2 |
| 10 | `get_recent_changes` + `get_config_diff` tools over the existing `internal/configdrift` store | Cheapest item in the whole review; two of the strategy's named tools over a built store. | 1–2 |
| 11 | Populate the entity-resolution bridges (interface-IP, ifIndex) | Unblocks three direction sources and the 98 %-undirected-edge problem. | 4–6 |
| 12 | `changed_by` actor + deploy ingest, feeding a change-proximity RCA term | Highest-value missing RCA *feature*; the strategy is right about this one. | 4–6 |
| 13 | Field-labelled eval corpus: harvest `rcafeedback` + promoted RCAs into the twin corpus as a **held-out** split | Converts the weakest number (100 % on self-authored synthetics) into a defensible one. Gates external launch. | 3–4 |
| 14 | Add `CapProbe`/`CapDiagnostic` capability tier; reclassify the two live tier-2 tools | Today `run_protocol_diagnostic` is labelled `CapRead` while it SSHes to a device. | 2 |
| 15 | **Agent-reachable HITL writes**, routed through the existing 5-gate / dry-run / named-approver machinery — product and ticket writes only, never devices | Commercial ask #6. Depends on #14. | 4–6 |
| 16 | Alert-triggered and scheduled investigations | Commercial ask #3. | 3–4 |
| 17 | **MCP gateway** as a thin, off-by-default adapter over `AITool`, per-tenant audience-scoped | Commercial ask #7. HLD P7. Depends on #14. | 4–6 |
| 18 | Seasonal baselines + MAD/robust z in the detector | The only gap that limits what we can **detect** rather than what we can prove. Needs #13 to show it improved anything. | 12–18 |
| 19 | Production AI telemetry: tool-selection accuracy, completion rate, p95 investigation latency, cost per investigation; publish compression ratio and top-3 accuracy | The strategy's launch gates need numbers we do not emit. | 3–4 |
| 20 | Doc corrections: `ARCHITECTURE.md`, `COPILOT.md`, `evals.md`, the Redis/Valkey line in `CLAUDE.md` | `ARCHITECTURE.md` is the single document most likely to make the next external reviewer write this same strategy doc. | 1 |

**Declined, on the record, so they are not re-proposed:** OTLP traces and trace critical path (~20–30 ew; we are
network-first, not an APM, and DEM RUM already covers the user side); hosts/pods as entities and K8s inventory;
an L7 `calls` edge (inferring it from L4 flows would violate this codebase's own honesty rules); a materialised
feature store (it breaks the replay determinism contract, which is load-bearing); and tier 4–5 device writes
(prohibited by owner decision).

---

## 7. Test scope per item (what "done" means)

No item is done without these. Every one is red-first: the test fails on today's code, passes after.

| # | Unit tests | Regression / integration tests |
|---|---|---|
| 1 | Per-skill `CASES.yaml` fixtures: tool results → expected hop path, `Selected` origin (rule\|model\|none), verdict tokens, disclosures | Reference test cross-checking every `signature=` against `internal/protocoldiag` and every `verdict:phrase=` token against the NOC signature catalogue; **zero cases = load error** so a new skill cannot ship untested |
| 2 | Routing unit test: free text with a key present reaches `/api/ai/ask`; ungrounded bubbles carry an explicit not-grounded flag | Frontend test that the "grounded, tenant-scoped and cited" claim renders only beside a cited answer; `RcaWorkspace` posts to `aiAsk` with a correlation id, never a browser-assembled prompt |
| 3 | Query-shape test pinning the narrow-pick/keyed-wide-fetch split | Rule 5 tightened to require the split; isolation test per §3a; measured before/after at the 1 GiB ceiling recorded in the commit |
| 4 | Newline-strip at each of the four rendering boundaries | Multi-line injection golden fixture asserting a forged `[citation-id]` bullet does not survive; a test that the fence cannot be removed by a persona override |
| 5 | Verdict-conditional prompt selection; certainty-marker post-check over a closed vocabulary | Eval asserting an `undetermined` verdict never yields a narrative naming a cause |
| 6 | Context store: version, diff, rollback, audit record; size cap | §3a isolation test; a test that a bad edit cannot drop the default doctrine (the current failure mode) |
| 7 | Runbook schema validation reusing the skill loader's rules (dangling hop, off-allowlist tool, unknown arg) | Tenant-authored runbook must carry cases and pass them before activation; poisoning test: an uploaded runbook cannot widen tool scope |
| 8 | Command-set version/diff/rollback; output-shaping transform unit tests | Every authored command re-validated against `forbidden.yaml` **and** the gate at render time; a test that a tampered stored set still cannot reach a device |
| 9 | Tier resolution per `RouteFor` mode; single-`Model` back-compat | Cost regression: assert a deterministic mode makes zero provider calls |
| 10 | Tool arg-schema and scope tests for both new tools | §3a isolation test each |
| 11 | Bridge builders with fixture SNMP data | An exporter that cannot read its source must emit zero rows **and log it** (the existing honesty contract); assert directed-edge share rises on a fixture estate |
| 12 | Change producer: principal binding, blast-radius computation | RCA scoring test that a change within the window raises the ranked candidate; replay determinism preserved (`config_hash` bump visible) |
| 13 | Corpus importer: `source: field` marking, exclusion from the fitting set | Accuracy reported separately for synthetic vs field splits; no operator feedback ever reaches a fitting path |
| 14 | Capability enum + policy rule per tier; rate limit on probe tier | Every existing tool's tier re-asserted; a tier-2 tool labelled tier-1 fails the build |
| 15 | Approval record, dry-run, idempotency, rollback per write | End-to-end: no write without a named approver; device writes remain structurally impossible |
| 16 | Trigger evaluation and scheduling unit tests | Bounded cost/latency per triggered investigation; a storm cannot fan out unbounded |
| 17 | Schema validation both directions; per-tenant audience scoping | Off-by-default assertion; an MCP client cannot reach a tool the same principal could not reach in-process |
| 18 | Seasonal term and MAD estimator unit tests | Graded rig leg: detector change bumps `engine_version`, so it needs a re-graded run against the field split from #13 |
| 19 | Metric emission unit tests | Dashboard/alert-rule coverage test, as `test_alert_rule_coverage.py` does today |
| 20 | — | Doc drift gate for `ARCHITECTURE.md` claims that contradict shipped behaviour |

## 8. Totals

| Phase | Items | Eng-weeks |
|---|---|---:|
| **Correctness and honesty** (must ship before any commercial claim) | 1–5 | **6–10** |
| **Commercial capability** (the owner's seven asks) | 6–8, 14–17 | **23–34** |
| **Leverage and cost** | 9–13 | **13–18** |
| **Detection depth** | 18 | **12–18** |
| **Instrumentation and docs** | 19–20 | **4–5** |
| **Total** | 20 | **58–85** |

At one to two engineers that is roughly two to three quarters — against the external strategy's 15–18 months
and 24–30 people, because eleven of its first two milestones are already shipped here.
