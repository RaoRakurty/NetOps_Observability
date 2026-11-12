# RCA document v2 — topology, causality, wording, Iris (plan of record, 2026-11-12)

Owner direction 2026-11-12: "RCA doc improvements — once analysed with Fable and finalised, add them to the design doc and start implementing in parallel." Inputs:

- the owner's audit brief (regression case **P-3E0400**, whose eight-page PDF says *"this correlation object is not path-shaped (no measured path entity is attached)"*);
- Fable's read-only diagnosis of the same day;
- the parked NOC RCA document, PR #197 (owner decisions D1, D3, D4 of 2026-11-11);
- the owner's report that Iris inside the RCA view "doesn't work".

The engine is not changed by this plan. Everything here is report-builder, renderer, wording and Iris routing. The engine already emits what the overlays need: stage [5] `corr_edges` carry `grounding_kind`, `direction_basis`, `direction_conf` and `w_topo`.

Fixture: `src/backend/internal/rca/testdata/p3e0400/` holds `detail.json`, `path-view.json` and `rca-report.json`, captured from the lab 2026-11-12 04:57Z before the lab's RCA data is wiped.

## 1. Diagnosis (verified)

**P-3E0400 is case (c): the renderer suppresses topology whenever no *measured probe path* is attached.**

- **The report has one topology source, the probe-path spine.** The chain is:
  - `rca_report_http.go:87`
  - → `rcaPathBlock` (`path_graph_api.go:600-617`)
  - → `rcaPathSpine` (`:250`)
  - → `chCorrPathRef.PathRefFor` (`:113-166`), which reads `corr_signals_archive … entity_type='path'`.

  No path row means `reasonNoPathEntity` (`:209`), and `rep.Topology = rcaTopologyFromSpine(pathBlock)` (`rca_report_http.go:112`, `:339`) marks the section unavailable.
- **The topology stores are never consulted:** inventory, LLDP/CDP, the persisted graph, the SD-WAN overlay.
- **The association with the device worked.** All 6 signals ground at rank 1 on `cedge-60-07ae8615`. There are no adjacency rows for it, which is consistent with trackers 334, 349 and 366, but the sentence is decided before any topology store is read.
- **The UI, PDF and path-view use three different derivations** (`pathModel.ts:546-558`, `rca_report_html.go:481/878`, `path_view.go:400-440`):
  - their wording differs;
  - the UI has an adjacency fallback that the PDF lacks;
  - the client print fallback would draw a node that the server PDF denies.

**The title "Link state change" is unsupported.**

- **Where it comes from:** `buildRcaTitle` (`rca_report_wording.go:1049`) → `noclabel.SignatureTitle` cascade `contains("link","access","uplink")` (`internal/noclabel/labels.go:192`, UI mirror `labels.ts:113/199`).
- **What the template actually requires:** "Local link fault" needs both `link_state_change` and `if_metric_anomaly`.
- **What was observed:** `satisfied=[if_metric_anomaly]`, `missing=[link_state_change]`. No link-state event exists in the object.

**Iris inside RCA.**

- The view's Ask AI card sends "Explain this problem" with `context.correlation_id`. The deterministic router answers it as a *product-help* question, describing what the feature is, and never explains the problem (`mode=product_answer`, `intent=explain`).
- Follow-ups work but are slow (13 s), and they repeat the wrong title.

## 2. Topology: one model, three layers, four states

New `internal/rca/topology_context.go`. The report, the path view, the UI and the PDF all consume this one struct. It is built once per request.

```go
type TopologyContext struct {
    State       string           // topology_with_path | topology_only | device_only | no_asset_mapping
    Sources     []TopologySource // {Kind: lldp|cdp|bgp_ls|sdwan_overlay|controller|inventory, ObservedAt, Stale, Freshness}
    Nodes       []TopoCtxNode    // {ID, Label, Role, Source, LastSeen, Stale}
    Edges       []TopoCtxEdge    // {ID, A, APort, B, BPort, Relationship, Protocol, Confidence, FirstSeen, LastSeen, Stale}
    Faults      []FaultMark      // layer 2: {TargetType node|interface, TargetID, Kinds, PeakSeverity, EvidenceRefs} — observed, no causation
    Causal      []CausalMark     // layer 3: {From, To, Relation verified|suspected|unknown, Basis, EvidenceRefs}
    Spine       *TopologyView    // the existing measured path, when present
    Reason      string
    Remediation string
}
```

The three layers:

1. **Topology context.** Known devices, interfaces and links from inventory and discovery: LLDP/CDP, BGP-LS, the persisted reconciled graph, and SD-WAN overlay/controller links. Each carries its source and freshness (`last_seen`, `stale`). The graph is the 1-hop ego-graph of the affected devices, capped at 24 nodes with "N more".
2. **Measured fault overlay.** Devices and interfaces carrying attached anomalous evidence, with kind, peak severity and evidence links. This layer never implies causation.
3. **Causal overlay.** Built from `corr_edges` and the verdict:
   - **verified:** authoritative grounding and a confirmed verdict;
   - **suspected:** `direction_conf > 0` or a suspected verdict;
   - **unknown:** `direction_basis none`, or a topology edge with no engine edge.

   These are drawn distinctly: solid, dashed, and marked "?".

The four states, with required fallback behaviour:

| State | When | Renders |
|---|---|---|
| `topology_with_path` | measured spine and topology edges | full topology with fault and causal overlays |
| `topology_only` | topology edges, no measured path | known topology; causal path marked **unverified** |
| `device_only` | device in inventory, no neighbour/path data | a device diagnostic card: device, role, source, last seen, the evidence interfaces, which neighbour sources were read and came back empty, and remediation (enable LLDP/CDP, the overlay notices, discovery flags) |
| `no_asset_mapping` | the affected entity is not in inventory | an explicit data-availability error with remediation |

P-3E0400 must render `device_only` (or `topology_only` if the lab holds its links). It must never render "not path-shaped".

**Never invent.** Every node and edge id must come from a source row. This is enforced by a property test.

**Tenant isolation (§3a).** Topology reads are scoped by the **object owner's tenant** (`canonicalCorrTenant(meta.tenant_id)`) AND by the caller's visibility, with parity to `rcaPathSpine`'s two checks. A cross-tenant principal reading tenant A's report never sees tenant B's neighbours. An operator-restricted tenant's neighbours stay hidden from the platform owner.

## 3. Wording and claims (every claim supported by evidence)

1. **Title.** The title names the *observed* condition. When the top hypothesis has a missing mandatory clause, the hypothesis becomes a suffix. P-3E0400: **"Interface metric anomaly on cedge-60-07ae8615 (4 interfaces) — possible local link fault"**. Only a fully satisfied signature may title the report with its condition.
2. **Hypothesis labels.**
   - Hypotheses use the catalog `title` ("Local link fault"), not the event-phrase cascade.
   - Explicit labels are added for mac-flap and similar.
   - `access` is dropped from the cascade.
   - The Go and TS mirrors stay in sync, with a parity test.
3. **Competitors that weren't observed.** A template with no mandatory clause satisfied is *"nearest competitor — not observed"*, never `observed`/`active`. In P-3E0400 these are DNS, MAC flap and OSPF at 0.05.
4. **Localisation.** One consistent sentence across the report, path view and at-a-glance. It is "evidence concentrates on <device>; not independently localised" unless independent evidence localises it.
5. **Detection lag.**
   - `first_correlix_detection` := version-1 `created_at` of the object.
   - "First credible failure" is relabelled "earliest attached anomalous observation (detector onset, not fault onset)".
   - The pair is omitted when both are the same observation.
6. **Telemetry coverage.** Cadence comes from per-(entity, metric) series or the collector's schedule. Otherwise `cadence_known:false` and no gap/partial/minimal claims are made. (Burst polling made a 1 s "cadence" and fake gaps.)
7. **Modality labels.**
   - "Routing & link events" is labelled by actual kind: a generic `device_alarm` is not a routing event.
   - The report says when an alarm is not a witness for the top template's clauses.
8. **Service wording.** No "end-to-end service checks" or "affecting the monitored service" without service-scope evidence (`rca_recovery.go:233`, `rca_report_wording.go:1219`).
9. **Path-view annotations.** These are kind-aware. An `if_metric_anomaly` is not an "interface state change on this link".

## 4. The NOC document (PR #197, owner D1/D3/D4) — unparked into this plan

These are carried as decided in PR #197:

- **Ten NOC sections:**
  1. What broke
  2. Who is affected
  3. When
  4. Cause and how sure
  5. How we know
  6. Where the break is (renders §2 TopologyContext)
  7. Background (not a cause)
  8. Other explanations
  9. Who owns the fix
  10. What to do now · recurrence
- **The rest of the document:** appendices, and a "How to read this RCA" guide.
- **Four confidence phrases** (D4): Confirmed cause · Likely cause · Possibly because of X · Cause not determined. One Go helper and one TS helper.
- **Background band** (D1): `context_story` hypotheses and standing findings never count as impact, Break-here, promotion or owner.
- **Impact never from the verdict.** Only the impact axes count, and confirmation requires a measurement-source pair.
- **Promotion** (D3): a real outage with a measurement pair; a repeat offender (3 or more in 7 days); or a multi-site controller/hub outage. Never background-only, never never-established peers.

## 5. Iris inside the RCA view

1. **The problem in view is the default subject.** With `context.correlation_id` present, every question is about that problem. "Explain this problem" must produce the grounded explanation of the problem, never product help.
2. **A real conversation.** The RCA panel is a chat scoped to the problem, with follow-ups and suggested questions:
   - why only suspected;
   - what to check next;
   - who is affected;
   - what changed;
   - top talkers on the affected link.

   It docks in the workspace, not as a one-shot card.
3. **Routing.** Model-first with grounded tools over that problem's evidence, under the §15 guards. The policy is the 2026-11-12 one: deterministic only when it covers the whole question. "Didn't catch that" only when the model is down.
4. **Same words as the document.** Answers use the §3 title rule, the §4 four phrases, and the §2 topology states, so Iris and the PDF never disagree.
5. **Speed.** The one-model-strike rule; a contextual answer in ≤ 5 s on the lab when the model is healthy.

## 6. Workstreams (parallel; file ownership split to avoid conflicts)

| WS | Owner | Owns | Depends on |
|---|---|---|---|
| A — topology model | agent | `internal/rca/topology_context.go` (new) and its tests; the `TopologySourceReader` implementation in `src/backend`; `path_graph_api.go`, `rca_report_http.go` wiring, `path_view.go` embedding; a NEW HTML partial `topologyContext` (+ SVG) in its own file; §3a isolation test + pgintegration | — |
| B — wording + NOC document backend | agent | PR #197's backend (rebased onto main); `rca_report_wording.go`, `noclabel/*`, `rca_semantics.go`, `rca_coverage.go`, `rca_recovery.go`, `rca_report.go` hypotheses/branches, the `rca_report_html.go` section structure (places A's partial in section 6) | A's partial name/contract (§2) |
| C — frontend | agent | PR #197's frontend; `pathModel.ts`/`RcaPathCausality.tsx` consuming `topology_context`; removing `topoGraph.ts`'s context branch and `rcaCase.ts`'s legacy chain; `rcaExport.ts` from `topology_context`; `labels.ts` mirror; the Iris RCA chat panel (`RcaAskAi.tsx` → docked chat) | A's JSON contract (§2), B's phrases |
| D — Iris routing in RCA | the running Iris follow-up PR | correlation-context routing and the RCA question set in the phrasing eval (backend `ai/`) | — |

Merge order: A and D first, then B, then C. One train if they're green together.

## 7. Tests (required)

- **Go:**
  - the four topology states;
  - a no-invention property;
  - P-3E0400 → `device_only`, with no "not path-shaped" string;
  - builder equality between the report and the path view;
  - HTML goldens per state (the HTML is the PDF input);
  - the title rule;
  - noclabel Go/TS parity;
  - detection lag, coverage cadence, recovery wording, annotation wording.
- **§3a:** `rca_topology_context_isolation_test.go`:
  - own-only neighbours;
  - cross-tenant 404;
  - `as_tenant` ignored;
  - operator-restricted tenant hidden.

  Plus the pgintegration leg.
- **Frontend:**
  - the four states from the fixture;
  - `rcaExport` using `topology_context`;
  - Playwright on the mocked fixture, asserting that the UI state text equals the server HTML state;
  - the RCA chat panel.
- **Iris:** RCA-context questions in the phrasing set (dev split): "Explain this problem", "why only suspected", "what should I check", "who is affected", "what changed before this". Each must route to the problem.
- **Before/after:** P-3E0400 HTML/PDF snapshots and UI screenshots, light and dark, attached to the PRs.

## 8. Not in scope

- engine changes;
- populating topology stores (trackers 334/349/366 are ops/data work);
- deploying to the lab without the owner's approval (owner brief: "Do not make production changes without approval").
