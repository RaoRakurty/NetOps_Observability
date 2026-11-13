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

`docs/ai/golden-examples/golden-qa.json` is the versioned golden set — 152
fixtures in five categories, loaded by the strict `ai/goldenset.go` loader (a
malformed or underspecified fixture fails loading; nothing is silently
skipped). The evals run deterministically on the mock provider and gate CI:

| Category | Items | Eval | Guarantee |
|----------|-------|------|-----------|
| `docs` | 122 | `TestGoldenDocsRetrieval` (`ai/`) | retrieval ranks an expected portal page: **hit@1 ≥ 0.80, hit@3 ≥ 0.95** (floors) |
| `docs` | 122 | `TestGoldenDocsCitationCorrectness` (`ai/`) | every retrieval hit produces a product answer that CITES an expected page, with a working Help-drawer link |
| `docs` (`nav`) | 108 screens | `TestGoldenCoversEveryNavLeaf` (`ai/`) | every console screen read from `src/frontend/src/nav.tsx` (each nav leaf, plus each in-page view a leaf declares in `subItems` that has no `route` of its own) has a docs item naming it in `nav`, every `nav` names a real screen, and for every screen at least one of its items hits@3 |
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

**Page-aware help (N-G3, 2026-10-17).** The Iris box sends the page behind it
(`context.route`, a real nav leaf only — `iris/pageRoute.ts`); the server
re-validates it against its own table (`ai/docs_pages.go`) and uses it only to
rank that page's docs first and to answer "what am I looking at?". Plain
retrieval is unchanged by construction. Measured on 120 items: plain hit@1
0.90 (108/120), hit@3 1.00 (120/120); asked **from the item's own page** hit@1
0.96; asked from an unrelated page (platform/regions) hit@1 0.90, hit@3 0.99 —
the boost never costs a question asked elsewhere its hit@3 floor
(`TestPageBoostKeepsGoldenRetrieval`).

**Current measurement (2026-11-09):** on 122 docs items, hit@1 0.90 (110/122),
hit@3 1.00 (122/122); 108 screens, all covered. The dated paragraphs above record
how each number moved at the time.

**Decision gate (plan P5):** hit@3 1.00 on 122 items means BM25 recall is still
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

## Held-out split (N-H3)

Part of each corpus is never used for tuning, so the score on it can show
overfitting. The rule is in `src/backend/internal/evalsplit` and nobody chooses
cases by hand:

- `source: "field"` (operator-labelled) is always held out.
- `source: "synthetic"`, the default, is held out when SHA-256 of
  `correlix.evalsplit.v1\0<corpus>\0<group>`, read as a big-endian integer from its
  first 8 bytes, modulo 100, is below 20.
- The group is the case id. The turns of one scripted NL conversation share a
  group so they stay together.
- There is no per-case override. Adding or reordering other cases moves nothing.

| Corpus | Name in the hash | Cases | Held out |
|---|---|---|---|
| NL query (`internal/nlquery/testdata/golden`) | `nlquery` | 215 | 32 |
| Golden Q&A (`golden-qa.json`) | `qa` | 152 | 29 |
| Golden incidents (`ai/testdata/golden_incidents`) | `incidents` | 23 | 3 |
| Phrasing (`ai/testdata/phrasing_golden.json`) | `phrasing` | 165 | 26 |

**Reporting.** `TestCompilerAgainstTheGoldenCorpus`, `TestModelPathAgainstTheGoldenCorpus`,
`TestGoldenDocsRetrieval` and `TestGoldenIncidentCorpus` log each split, and the
live leg `TestModelPathLiveProvider` reports them separately. The release-gate
table (`internal/irisgate`) has Dev and Held-out columns. Gate verdicts and
ratchet floors are still judged on all cases together. Measured 2026-11-09:

| Measure | Dev | Held-out |
|---|---|---|
| Compiler, questions right | 103/141 | 15/24 |
| Compiler, answered precision | 258/301 | 48/55 |
| Docs retrieval, hit@1 | 88/97 | 22/25 |
| Docs retrieval, hit@3 | 97/97 | 25/25 |
| Golden incidents, passing | 20/20 | 2/3 |

**Guards.**

- `TestHeldOutCasesNeverReachTheExampleLibrary` fails if a held-out case is in
  `modelc/examples.v1.json`, by id or by normalized text.
- `TestHeldOutCasesAreAbsentFromSources` (NL) and
  `TestGoldenHeldOutCasesAreAbsentFromSources` (`ai/`) scan non-test sources for
  held-out ids and questions of at least four words. Rewording is not detected.
- `TestOperatorFeedbackHasNoRouteIntoTuning` and
  `TestCorrelationEngineDoesNotReadTheVerdictRegister` keep the RCA verdict register
  out of anything that could be tuned from it.
- Negative controls plant a held-out case and require the same checks to report it.
- `TestGoldenIncidentFixturesDoNotMixTenants` allows more than one tenant in a
  fixture only for `cross_tenant_alias` cases (§3a).

**What the numbers do not prove yet.**

- Every current case is synthetic, and all of them existed while the grammar,
  retrieval and routing were tuned. Removing them from the example library makes
  them held out for the model's few-shot examples, not unseen by the people who
  wrote the rules, so the current gap understates overfitting. Two visible cases
  are recorded in `knownContamination`, and the retrieval relevance floor
  (`ai/docs_index.go`) was calibrated on the docs questions as they stood.
- Three held-out incident cases are too few to read as a rate. The one not passing,
  `mt-skill-model-calls-uncollected-logs-clean`, is a known-defect `expected_failure`.
- The correlation fixtures, `routing_golden.json` and the skill `CASES.yaml` are
  not split. The rig-measured RCA accuracy is not covered either.
- There is no importer for real operator-labelled cases yet, so the field split is
  empty. Item 13 of the commercial review remains open until there is.

Any future calibration, such as the `incidentfp` weights listed as not calibrated in
`docs/audit/INVARIANTS.md`, must use the dev split only.

## Phrasing eval (deterministic routing)

Owner question, 2026-11-11: "can it understand any natural way of asking?". On the lab,
with the model provider timing out, "which devices are down right now?" became a 28 s
troubleshooting walk, "show me the noisiest device today" got "I didn't quite catch
that", and "any bgp peers flapping lately" searched one device's syslog.

`ai/testdata/phrasing_golden.json` holds 165 realistic NOC utterances: device state,
incidents, health, BGP/OSPF/interfaces, top-N and "noisiest", flows, changes, RCA,
history, product help and troubleshooting, in casual, slang, typo and shorthand forms
("rn", "pls", "w/", "whch", "anything on fire"). Each is labelled with the route it should
take and, where it matters, slots (metric, device, state, every-device scope, a minimum
window, limit). `TestIrisPhrasingEval` (root package) asks each one through the real
router with no model: the classic and skill arms exactly as `/api/ai/ask` builds them, and
the data arm with its real grammar, resolver, admission and validator in tenant A's scope.
Only the final executor is a recorder, so nothing reads a backend. It runs in about two
seconds.

Split: `evalsplit` corpus `phrasing`. The six lab utterances are `source: lab`, always dev
and always gated (a lab regression fails the test outright). Synthetic cases are held out
by hash: 26 of 159. Held-out misses are printed only with `IRIS_PHRASING_SHOW_HELDOUT=1`.
`TestPhrasingHeldOutCasesAreAbsentFromSources` (`ai/`) scans the router, the grammar and
normaliser (`internal/nlquery`) and the root `ai_*.go`. Three held-out utterances were
already canonical examples in router comments before the set existed. They are recorded
in `phrasingKnownContamination`, not hidden.

Measured 2026-11-12 (floors ratchet: `minPhrasingDev` 0.98, `minPhrasingHeldOut` 0.84):

| Label | Dev before | Dev after | Held-out before | Held-out after |
|---|---|---|---|---|
| device_state | 2/23 | 23/23 | 0/2 | 2/2 |
| bgp | 5/17 | 17/17 | 0/1 | 1/1 |
| top_n | 6/11 | 11/11 | 1/5 | 3/5 |
| health | 7/12 | 12/12 | 3/4 | 3/4 |
| incidents | 17/19 | 19/19 | 3/3 | 3/3 |
| interfaces | 9/11 | 11/11 | 0/1 | 1/1 |
| device_metric | 5/7 | 6/7 | — | — |
| flows | 6/7 | 7/7 | 1/1 | 1/1 |
| rca | 6/7 | 7/7 | 0/1 | 0/1 |
| troubleshoot | 4/5 | 4/5 | 4/4 | 4/4 |
| changes, history, shift, product_help | 20/20 | 20/20 | 4/4 | 4/4 |
| **all** | **87/139 (0.63)** | **137/139 (0.99)** | **16/26 (0.62)** | **22/26 (0.85)** |

What changed, each a general rule with a positive and a negative unit test:

- **Shorthand** (`lex`): "rn"/"atm" → right now, "nbr(s)", "iface(s)", "cfg", "yday"; "pls",
  "w/", "r", "u" as framing; "aren't"/"isn't" → "are not"/"is not". The router and the
  grammar read the same table. A meaningful expansion is disclosed ("I read "rn" as "right
  now".").
- **Device liveness** (grammar + planner): "which devices are down / offline / unreachable",
  "any boxes not responding", "is cedge-81 up / ok / reachable", "status of edge-a", "how
  many switches are down" compile to a device list or count with a `reachability` filter
  (and a `type` filter for router, switch or firewall). The planner reads the collectors'
  verdict through the optional `plan.ReachabilityScope`, implemented in the root with the
  caller's metric scope filter. A named device is listed with its verdict and is never
  filtered out of its own answer. An unread verdict is "unknown", never "down", and the
  answer says so. The same read now keeps a zero: before, a device whose every poll failed
  read "unknown" and one with a failing collector read "up", on the inventory page too.
- **BGP**: "bgp status / is bgp ok / show bgp peers / check bgp on X" → session state;
  "flapping" next to a BGP word → BGP flaps; "aren't established" → not established.
- **Recency**: "lately", "recently", "these days" with no window → the last 24 hours,
  disclosed. "Most recent N" still counts items.
- **Containment and ranking**: "crc errors on edge-1" is that device's interfaces. A
  ranking that names devices over an interface metric groups by device. "noisiest",
  "loudest" and "chattiest" rank devices by interface flaps, and every superlative now
  discloses the metric it was read as.
- **Router**: "anything on fire", "anything going wrong", "what's up with the network",
  "all good / everything green", a lone "status", "why … the top problem", and "what's
  eating the wan" each land on their intent. "What do I check" is a diagnostic cue, so the
  data arm leaves it to the methods.

Effect on the other corpora: compiler questions 126 → 127 of 171, paraphrases 237 → 243 of
512, answered precision 0.890 → 0.892; held-out compiler numbers unchanged. The model path's
key-path reach rose 0.830 → 0.832. The grammar took 7 more answerable phrasings, 6 of which
the model oracle had accepted, so `minOracleAcceptance` moved 0.58 → 0.57 under the same
rule as 2026-11-10.

**Slow model, one wait (§9).** The lab's 28 s was three model calls waiting out their own
budgets one after another: the route tie-break (5 s), the rephrase (8 s), then the strong
compile or the narration. The breaker needs three failures across requests. Now the first
call in a request that times out, or fails as down, rate-limited or refusing the key,
strikes that provider for the rest of that request (`ai.NoteModelFailed` /
`ai.ModelStruck`). A later stage skips it at once with the first failure's class, so the
footer still reads "timed out". A request waits for at most one model budget.
`iris_model_strike_test.go` pins this end to end: a failing provider is called once per
ask, and twice when the strike is disabled.

**Still failing:** "show me latency on cedge-81" (latency belongs to circuits and probes;
a device does not narrow it yet), "why cant cedge-82 reach the hub" (no method lists
"can't reach"), and four held-out cases. "Noisiest" is read as interface flaps, which is
disclosed. A true event-volume ranking needs a syslog count by device, which the NL engine
does not have.

### Follow-ups of 2026-11-12 (routing policy, verdicts, compound and RCA-context questions)

The lab, right after the phrasing work shipped: "Check RCA and identify the one which has
confirmed" got "I didn't quite catch that" after 12.9 s with a healthy model; "tell me which
tenant are we in and how many devices are connected and how are they discovereD?" was answered
by the integrations module ("connected" had been "corrected" to "connector"); "Explain this
problem" in the RCA workspace returned product help. 22 cases were added, all dev: five lab
cases (`source: lab`) and 17 synthetic ones whose ids hash to dev. Two new fields: `context`
(the UI context, here the RCA workspace's `correlation_id`) and the `verdict` slot; one new
label, `compound` (every part of a multi-part question answered on the deterministic path).

Measured 2026-11-12 (floors unchanged, 0.98 / 0.84):

| | Dev | Held-out |
|---|---|---|
| main, the 165 cases | 137/139 (0.99) | 22/26 (0.85) |
| main, the 187 cases (22 new: 10/22) | 147/161 (0.91) | 22/26 (0.85) |
| after (22 new: 22/22) | 159/161 (0.99) | 22/26 (0.85) |

On main, four of the five lab cases failed (only "list critical issues" passed), and so did
every compound case and "what does this page show" with a problem in view (answered as the
problem).

What changed:

- **A real word is never "corrected"** (`lex`). A word that is the same stem as a vocabulary
  word with a different regular ending ("connect·ed" / "connect·or", "discover·y" /
  "discover·ed") is a word of its own; so is every form of an ordinary word next to a domain
  term ("collector" is not "connector"). `lex.NearDomainWords` is the audit list, asserted on
  the router's and the grammar's vocabularies. "atm" is shorthand only as the last word ("show
  atm interfaces" keeps the network term). Casing never matters ("discovereD").
- **Verdict referents** (grammar): a verdict tier belongs to incidents alone, so "the one which
  has confirmed", "list the suspected ones", "show only confirmed RCAs" are incident lists
  filtered by verdict. "Critical" has no severity column to read: it stays owner decision D1,
  confirmed incidents, and the answer says so ("I read "critical" as confirmed incidents.").
  "What is an RCA" is a definition, never a list.
- **"Connected"** in a device count is read as the inventory and disclosed; "connected to
  edge-1" stays topology.
- **Multi-part questions** (`lex.SplitClauses`, `ai/route_policy.go`): "… and how many …" is a
  second question. Each part is answered on its own when every part is covered: which tenant or
  view the caller is in (from the token: a tenant, the Provider view or the platform owner's All
  tenants view), counts from the grammar, and how devices were discovered (the per-device
  source in the caller's visible inventory). A part nothing deterministic covers sends the
  whole question to the model. A method that claims the whole message still investigates it.
- **The problem in view is the subject** (RCA_DOCUMENT_V2 §5): with a `correlation_id` in the
  context, a question is answered by that problem's grounded explanation — one model call, no
  tie-break, rephrase or compile — unless it names the product's screens. A complaint naming
  something specific still runs its troubleshooting method with the problem as anchor. Another
  tenant's id reads as not found, with no evidence.

**Routing policy (owner, 2026-11-12).** The deterministic path answers only when it covers the
whole question. A question with no recognised intent, or a multi-part question with an
uncovered part, goes to the model, grounded in the caller's data: the agent loop when the
caller has AI investigations, otherwise one strong-tier call over a bounded evidence block
(scope, inventory by source, active problems with their verdicts) whose citations are
verified. "I didn't quite catch that" appears only when no model answered, and the answer says
why. Every answer carries `routing` {path, reason}; the api logs it on the `ask` line and
counts it in `netops_ai_routing_total{path,reason}`.

**The 12.9 s.** Reproduced offline with a healthy fake model: the miss made four model calls —
the fast rephrase (refused: no vocabulary) and then the strong structured compile with its two
repair rounds (`invalid_after_repair`), each a full strong-tier call. The one-strike rule
covers failing providers, not a working model that keeps producing an unusable query. Now a
question with no intent skips the strong compile in `/api/ai/ask`: the rephrase (one fast call)
runs, then the model answers it. The strong compile still serves `/api/ai/query/compile` and
questions with a recognised intent.

## Model-first routing eval (owner, 2026-11-13)

With the AI add-on on (licence + the "Iris AI models" switch), one fast-tier model call
picks the arm that answers every question (`src/backend/ai/planner.go`). The deterministic
arms are unchanged; they are what the planner selects, plus an exact-match cache. Coverage
work is now tools and data, never another phrase rule.

The corpus is `docs/ai/golden-examples/planner-paraphrases.json`: about 20 model-written,
reviewed phrasings for each planner route (typos, abbreviations, indirect wording), plus
module items. It is never regenerated in CI. Three tests read it:

| Test | What it asserts |
|---|---|
| `TestParaphraseCorpusShape` | every route has ≥ 20 distinct phrasings; no phrasing sits under two routes; every module has phrasings |
| `TestEveryParaphraseReachesItsRoutesArm` | with a stub model that returns each item's route, every phrasing reaches that route's arm with routing reason `planner` (340/340 at introduction) |
| `TestParaphraseDeterministicBaseline` | reports the regex router's own accuracy on the same phrasings: the "before" number (227/340, 67 %, at introduction; `noc_focus` 4/20, `top_incident` 7/20, `incident_breakdown` 11/20, `shift_handoff` 12/20) |

A real provider's routing accuracy is the live eval, on the same tag and environment as the
NL query model eval, so one command runs both. It fails below 90 %:

```
NLQ_EVAL_PROVIDER=gemini NLQ_EVAL_API_KEY=... NLQ_EVAL_MODEL=gemini-3.5-flash-lite \
  go test -tags nlqmodeleval ./ai -run TestPlannerLiveProvider -v -timeout 60m
```

A miss found in production is triaged into one of four classes: no tool for it, no data, the
wrong arm chosen, or wording. Only the third touches routing, and the fix is the route's
description or a new phrasing in the corpus, never a regex.

## Replay (N-H2, offline leg)

Replay runs one frozen incident through the real answer path and reports what came
out, so that a change to a prompt, a skill, a tool contract or a model is judged on
cases. Code: `src/backend/internal/irisreplay`, `cmd/irisreplay`. The offline leg
is built; **the live-model leg is not**, and `ModelLeg` is its seam.

```bash
cd src/backend
go run ./cmd/irisreplay run --cases ai/testdata/golden_incidents --report /tmp/a.json --markdown /tmp/a.md
go run ./cmd/irisreplay compare /tmp/a.json /tmp/b.json   # names what changed
go run ./cmd/irisreplay fingerprint
```

**One corpus, one loader.** A case is a golden incident plus optional fields:
`frozen_at`, `engine_version`, `catalog_version`, `topology`, `config`,
`context_version` and `context_facts`, `allowed_tools`, `policy`, `model`,
`model_tool_requests`, `expected`, `source`, `capture`. The schema and strict loader
live in `ai/replay_case.go`, not in the replay package, because the corpus test is
an in-package test of `ai` and cannot import a package that imports `ai`. The corpus
test ignores the new fields, and its per-case report is unchanged by them.

**Frozen seams.** `Freeze` builds the `DataSource` and `TroubleshootDeps` from the
case alone. A seam not in `allowed_tools` is nil, so its tool is not registered, and
a request for it is `OutcomeNotRegistered`: a finding, never a live call. Absent
`allowed_tools` means no tools. The engine is not re-run: replay consumes the stored
`hypotheses` blob and `RCAResult`, and a pin mismatch is reported, never substituted
(the rule of `src/correlation/replay.py`).

**The report**, per case and in aggregate:

| Section | Measures |
|---|---|
| RCA (never gates) | stored and shipped verdict, status, stored leading hypothesis against `expected.leading_hypothesis`, whether the answer names it, contradicting lines |
| Evidence | required and forbidden citations, citations stripped by `VerifyGrounding`, `forbidden_anywhere` hits in the answer and in the prompts, separately |
| Tools | the sequence, requests for unregistered tools, a prohibited tool that ran (fails the case), count against `expected.max_tools` |
| Cost | tokens only when the provider reports them, dollars only with a configured price, otherwise `censored`, never an estimate |
| Latency | wall time on this machine with no provider in it; excluded from determinism |
| Claims | statements by N-B4 class, `unsupported` (not OBSERVED, CORRELIX_RCA or DOCUMENTATION; a RECOMMENDATION is counted apart because it states no fact), certainty-vocabulary hits under an unconfirmed verdict, guard firings |
| Fingerprint | SHA-256 over the bytes of the skill files, rendered prompt builders, tool contracts, the `ENGINE_SEMVER` pins in the cases and the model names, with per-item hashes so that a comparison names the file |

**Gates.** Replay feeds `cross_tenant`, `citation`, `injection` and `audit` as source
`irisreplay.corpus`, tagged per split. It adds no bar. RCA agreement is not a gate.

**Split.** `evalsplit.Assign("incidents", id, source)`. A case derived from a golden
incident keeps its id, so it keeps its split. `source: field` is always held out.

**Export.** `GET /api/ai/replay/export/{correlation_id}` returns one correlation as a
one-element case array the runner can load: `administration:read`, tenant-scoped, 404
for unknown and foreign alike, every string through `ai.Redact`, nothing written on
the server. The ledger holds only hashes, so a tool output is **re-read at capture**
and compared with the ledger's hash. A difference is recorded as "live data moved
since the decision". Reports say re-read at capture, never as seen. A capture never
re-runs a probe or `compile_query`.

**Customer data.** Committed cases are synthetic. Keep captures under
`data/iris-replay/` (gitignored). `tests/test_iris_replay_customer_data.py` refuses
`*.replay.json` under `src/` outside the corpus, and any field case inside it.

**What the offline leg does not prove.**

- The model is scripted. It shows what the guards do with a given reply, not what a
  live model would say. Every corpus reply is the worst plausible one.
- Topology and configuration are tool results as of capture, not as-of state: the api
  has no versioned topology store.
- An exported case replays evidence-only until someone scripts a reply, because the
  ledger keeps no reply text.
- Module reads such as `get_ticket_status` cannot be scripted in a case, so the classic
  path reports them as not registered. Grounding stamps on evidence rows beyond the
  stored blob do not survive export (they are never serialized).
- The export has no synthetic marker to read from a correlation object yet, so every
  HTTP export is `source: field`.

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
