# Iris AI — Evals

The eval suite (`src/backend/ai/evals_test.go`) encodes the design's
**definition-of-done** (§16) as runnable assertions over the orchestrator, so a
change that regresses a core guarantee fails CI. It runs entirely on the mock
provider — no credentials, offline.

## What each eval asserts

| Eval | Guarantee |
|------|-----------|
| StatusPrioritizesActionable | `/status` focuses a suspected classified incident over undetermined 0% noise |
| ZeroConfidenceWording | 0% → "Confidence not established"; no bare 0% in the body |
| UnclassifiedWording | verdict-only correlations read as "low-evidence", not raw |
| MissingEvidenceCleanWording | `needs ospf_adjacency_change` → humanized, not raw keys |
| OwnerInference | a routing incident infers a network/routing owner |
| ProviderUnavailableEvidenceOnly | provider down → polished evidence-only answer; provider state is a badge, not body text |
| PromptInjectionTreatedAsData | the server-owned system prompt fences evidence as data |
| SlashNLConvergence | a slash command and its NL equivalent share one intent |
| NavigationIncludesLocation | a navigation answer carries a UI deep link |
| CrossTenantDenied | a caller can't explain another tenant's incident |

Plus the verifier evals (`verify_test.go`): fabricated citations are stripped and
the answer is badged **Verified**.

## Golden Q&A set (intelligence plan P3)

`docs/ai/golden-examples/golden-qa.json` is the versioned golden set — 91
fixtures in five categories, loaded by the strict `ai/goldenset.go` loader (a
malformed or underspecified fixture fails loading; nothing is silently
skipped). The evals run deterministically on the mock provider and gate CI:

| Category | Items | Eval | Guarantee |
|----------|-------|------|-----------|
| `docs` | 119 | `TestGoldenDocsRetrieval` (`ai/`) | retrieval ranks an expected portal page: **hit@1 ≥ 0.80, hit@3 ≥ 0.95** (floors) |
| `docs` | 119 | `TestGoldenDocsCitationCorrectness` (`ai/`) | every retrieval hit produces a product answer that CITES an expected page, with a working Help-drawer link |
| `docs` (`nav`) | 105 screens | `TestGoldenCoversEveryNavLeaf` (`ai/`) | every console screen read from `src/frontend/src/nav.tsx` (each nav leaf, plus each in-page view a leaf declares in `subItems` that has no `route` of its own) has a docs item naming it in `nav`, every `nav` names a real screen, and for every screen at least one of its items hits@3 |
| `intent` | 7 | `TestGoldenIntentRouting` (`ai/`) | the deterministic router classifies each question exactly |
| `agent_tool` | 11 | `TestGoldenAgentToolPlumbing` (server pkg) | the expected tool is in the caller's manifest, executes tenant-scoped, yields cited evidence that survives the grounding verifier |
| `decline` | 7 | `TestGoldenDeclines` (`ai/`) | honesty floor: zero hits + explicit "documentation doesn't cover that" + zero citations; `known_gap` items report, never gate |
| `injection` | 5 | `TestGoldenInjection*` (both pkgs) | poisoned doc chunks stay fenced DATA; fabricated `[doc:]` cites are stripped; planted foreign-tenant citations are stripped; injected undeclared-tool calls hit the fail-closed registry; a MULTI-LINE planted log line cannot forge an extra `[citation-id]` evidence bullet (`inject-005`, `evidence_newline`) |

**Retrieval floors** were calibrated from the 2026-07-02 baseline (hit@1 0.81,
hit@3 0.97 on 32 items). By 2026-09-26 hit@3 had eroded to 0.91 (29/32), one
miss above its 0.90 floor (tracker 335). The N-G2 retrieval work (conservative
plural and suffix folding applied to documents and queries alike, release notes
down-weighted, at most two sections per page, a question-level relevance floor)
and the N-G1 coverage work (29 nav-leaf items, one per console screen that had
no page) measured **hit@1 0.89 (54/61), hit@3 1.00 (61/61)**; on the original
32 items alone hit@1 0.88 (28/32), hit@3 1.00 (32/32). The hit@3 floor is now
0.95, a three-miss margin on 61 items. The 29 new items were written alongside
the pages they target, so the original-32 figure is the fairer measure of the
retrieval change itself. A renamed page, broken chunker or scoring regression
still fails CI.

**N-G1 completion (2026-10-03).** Coverage is now counted mechanically: a
docs item carries `"nav": "<section>/<leaf>[/<sub>]"`, and
`TestGoldenCoversEveryNavLeaf` reads the screens from `nav.tsx` (105 today:
76 leaves and 29 in-page views) and fails on a screen with no item, an item
naming no screen, or a screen none of whose items retrieves at hit@3. 58 items
were added (docs-062…119). Measured on all 119: **hit@1 0.91 (108/119), hit@3
1.00 (119/119)**; the original 61 moved from hit@1 54/61 to 55/61. The hit@1
floor moved 0.75 → 0.80.

**Decision gate (plan P5):** hit@3 1.00 on 119 items means BM25 recall is still
NOT the bottleneck, so the vector/hybrid retrieval upgrade stays deferred. The
evidence is the re-measured number above, not the 2026-07-02 one. Revisit only
if the hit@3 floor starts failing on legitimate paraphrase items.

**Known gaps** (`known_gap: true`) are relevance-precision cases we track
without gating (e.g. `decline-004` "payroll exports" surfaces the log-exports
guardrail page). When one starts passing, the eval logs a reminder to drop the
flag.

**Eval report:** set `AI_EVAL_REPORT=/path/report.json` on the retrieval eval to
write the full per-item run (question, expected slugs, top-3, hit@1/3, anchors)
as JSON.

**Live leg (never a merge gate):** `AI_EVAL_LIVE=1` plus a provider key runs
`TestGoldenLiveToolSelection` (server pkg) — asks the real model to pick a tool
for each `agent_tool` fixture and reports the match rate (advisory ≥50% bar,
per plan §2.4: LLM spot checks stay small-N).

## Running

```bash
cd src/backend && go test ./ai/ -run TestEval    # the DoD evals
go test ./ai/ -run TestGolden -v                  # golden-set evals (ai side)
go test . -run TestGolden -v                      # golden agent-loop evals
AI_EVAL_REPORT=/tmp/report.json go test ./ai/ -run TestGoldenDocsRetrieval  # render the eval report
go test ./ai/                                     # full ai package (evals + unit)
```

## Golden examples

`docs/ai/golden-examples/` holds representative answer shapes (the `/status`
briefing, an RCA explanation with an evidence gap, the KB playbook answer) plus
the golden Q&A set above. They document the expected structure of each
answer-mode card; the evals enforce the invariants behind them.
