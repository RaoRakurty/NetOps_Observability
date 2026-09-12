# Governed Tool Registry

Tools are the **only** way the AI reads data. They are tenant-scoped, read-only,
permission-checked, module-aware, and injection-safe (the query name is fixed by
the tool, never the model).

## Contracts (`src/backend/ai/tools.go`)

- `AITool` — `Name() / Module() / Capability() / RequiredPerms() / Freshness() /
  Run()`. The Policy Engine reads `Capability()` to decide if the AI may run it
  (v1: only `CapRead`).
- `DataSource` — the stable RCA contract (`GetProblem`, `GetProblemEvidence`,
  `ListActiveProblems`).
- `ModuleDataSource` — the P4 extension seam: `ModuleQuery(ctx, p, query, args)`.
  Module tools are all instances of one `moduleReadTool` type wired to a fixed
  query name, so adding a module tool is a registry line, not a new type.

Server implementation: `src/backend/ai_datasource.go` (the only place AI touches a
store). Every query is tenant-scoped via `chRowsScope(scope, …)` or a `(tenant,
cross)` store call.

## Tools wired today

| Module | Tools |
|--------|-------|
| correlations_rca | `get_problem`, `get_problem_evidence` |
| command_center | `get_active_major_incidents` |
| flow_analytics | `get_top_talkers`, `get_flow_summary`, `get_service_flow_summary` |
| telemetry | `get_metric_anomalies` |
| app_identification | `get_app_identity_summary`, `get_low_confidence_app_matches` |
| integrations | `get_integration_health` |
| itsm | `get_ticket_status` (RCA enrichment) |
| product_navigation | `find_feature` |
| network_expert_kb | curated-knowledge retrieval (deterministic, no tenant data) |

Tools listed in a module's registry entry but not yet in `moduleTools` route to an
honest "not built yet" — never faked data. See `adding-new-tool.md`.

## Result shape

A tool returns `ToolResult{ Items []EvidenceItem, Truncated bool, Notes []string }`.
Each `EvidenceItem` carries a stable `CitationID`, a `Kind`, the `Text`, and a UI
`Href` so every answer is verifiable (anti-black-box).
