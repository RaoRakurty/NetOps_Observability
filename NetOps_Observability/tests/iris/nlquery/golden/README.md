<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Correlix -->

# Iris NL query golden corpus — pointer

The corpus does **not** live here. Its canonical location is

```
src/backend/internal/nlquery/testdata/golden/
```

so that `go test` reaches it and the gate module (`src/backend`) stays self-contained
(design of record: `docs/architecture/iris-nl-query-design.md` §7; tracker 337 N-C6).
This directory only holds this pointer.

## What is there

| File | Holds |
|---|---|
| `fixture.json` | The fixed two-tenant inventory every case is written against: tenant A (`t-acme`, the asking tenant) and tenant B (`t-globex`). `now` is fixed (`2026-09-24T15:00:00Z`) so relative and calendar windows are deterministic. Tenant B's `device:gx-edge-9` carries the site label `dfw-hq` — the same slug as tenant A's `site:dfw-hq` — as the isolation trap. |
| `<category>.json` | Answerable questions, one file per category (metrics, interfaces, devices, circuits, sites, applications, bgp, routes, sdwan, dns, changes, configuration, incidents, users, cloud, providers, time_comparisons, aggregation, ranking, grouping). |
| `unsupported.json` | Questions the v1 AST must **refuse** rather than approximate: flows and log search, "all time", actions ("restart the router"), cross-tenant requests and prompt-injection attempts, and questions the v1 AST has no shape for. Their `category` field places them in the category counts (all `flows` questions are here). |

## Case format

```json
{
  "id": "sites-001",
  "category": "sites",
  "question": "Show WAN loss in Dallas.",
  "context": {"tz": "America/Chicago", "incident_id": "…", "prior_ast": {…}, "cross": true, "script": "N-S2a", "turn": 1},
  "expect": {
    "intent": "show_metric",
    "entities": [{"input": "Dallas", "type": "site", "id": "site:dfw-hq", "method": "site_store"}],
    "ast": {"v": 1, "query_type": "metric_series", …},
    "alternates": [],
    "result_semantics": {"kind": "timeseries", "must_include_refs": ["circuit:dfw-comcast-1"]}
  },
  "paraphrases": ["dallas wan loss", "wan packet loss at DFW"]
}
```

- `expect.ast` is a CorrelixQueryAST v1 that must decode (`ast.Decode`) and validate
  (`validate.Validate`) against the embedded catalog and the fixture scope. Every paraphrase
  maps to that same AST. `alternates` are other readings that are equally acceptable.
- `context.tz` is the IANA zone the compiler uses to turn calendar words into absolute windows.
  `context.incident_id` is the incident page the question is asked on. `context.prior_ast` is
  the previous turn's AST for a follow-up; a `script` + `turn` pair chains the flagship
  multi-turn scripts (N-S1, N-S2a, N-S2b, N-S3), and each turn's `prior_ast` must equal the
  previous turn's `expect.ast`.
- `context.cross: true` marks a platform-operator principal. It is required for gated metrics
  (`circuit_*`, `probe_*`) until N-B5; the test also proves those ASTs are refused with
  `scope_unavailable` for a workspace user.
- `entities[].method` is the catalog resolver for the type, or `context` when the entity
  comes from the conversation or the incident on screen. The AST names exactly the listed
  entities, so entity precision can be scored.
- `result_semantics` is checked against the fixture: for change and incident lists the
  `must_include_refs` rows and `min_rows` must hold. For metrics the fixture has no values,
  so only *which* entities are selected is claimed. `group_counts` counts contributing rows.
- A question with no time has `"time_range": {}`. The validator applies and reports the
  default window.
- Duration tokens are normalized: `Nm` below an hour, `Nh` up to 24 h ("last day" = `24h`),
  `Nd` from 2 days up.
- Unsupported cases carry either `expect.reject_code` + `expect.rejected_ast` (the AST a
  naive compiler would produce, which the validator must reject with that closed code, or
  `unknown_field` for a smuggled tenant field that strict decode refuses) or
  `expect.decline` (`not_a_query` for actions and prompt extraction, `not_expressible_v1`
  for real questions the v1 AST cannot represent). `foreign_probe: true` marks a case whose
  rejected AST names a tenant-B id. The test proves it is refused byte-identically to an
  id that never existed.

## Running it

```bash
cd src/backend
go test ./internal/nlquery/ -run TestGoldenCorpus -count=1 -v   # logs the per-category counts
```
