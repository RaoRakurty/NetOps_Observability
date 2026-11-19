# Governed Tool Registry

Tools are the **only** way the AI reads data. They are tenant-scoped,
permission-checked, module-aware, and injection-safe (the query name is fixed by
the tool, never the model). None changes a device.

## Contracts (`src/backend/ai/tools.go`)

- `AITool` — `Name() / Module() / Capability() / RequiredPerms() / Freshness() /
  Run()`. The Policy Engine reads `Capability()` to decide if the AI may run it
  (`ai/policy.go` `EvaluateTool`): `CapRead` and `CapProbe` (a read-only device
  session, show commands only, rate-limited hard) are allowed; `CapNetProbe`
  (active probes from Correlix's own collector) only when the server's per-request
  gate says the probe switch, AI investigations and the workspace opt-in are all
  on, and never at a model's choice; `CapWrite` / `CapExecute` are denied to the
  tool loop. The two approval-gated writes (an ITSM note on the case's linked
  ticket, a finding to investigation memory) are not tools: a concluded
  investigation may only PROPOSE them, and they run through
  `internal/irisaction` after a different person approves.
- `DataSource` — the stable RCA contract (`GetProblem`, `GetProblemEvidence`,
  `ListActiveProblems`).
- `ModuleDataSource` — the P4 extension seam: `ModuleQuery(ctx, p, query, args)`.
  Module tools are all instances of one `moduleReadTool` type wired to a fixed
  query name, so adding a module tool is a registry line, not a new type.

Server implementation: `src/backend/ai_datasource.go` (the only place AI touches a
store). Every query is tenant-scoped via `chRowsScope(scope, …)` or a `(tenant,
cross)` store call.

## Tools wired today

45 tools (`ai/toolspec.go` is the authoritative list; this table groups them):

| Area | Tools |
|--------|-------|
| RCA and incidents | `get_problem`, `get_problem_evidence`, `get_active_major_incidents`, `get_actionable_incidents`, `get_incident_history`, `get_case_timeline`, `get_rca_verdict`, `get_causal_chain`, `get_blast_radius`, `get_owner`, `get_affected_entities`, `get_confidence_breakdown` |
| Memory and knowledge | `recall_investigations`, `find_similar_incidents`, `search_workspace_knowledge`, `search_docs` |
| Flows | `get_top_talkers`, `get_flow_summary`, `get_service_flow_summary` |
| Telemetry and logs | `get_metric_anomalies`, `search_logs`, `get_device_health` |
| Device state (read-only device session) | `get_device_state` (areas: interfaces, igp, bgp, routes, l2, platform, evpn, redundancy, vpn, upgrade, logs), `run_protocol_diagnostic` |
| Topology, WAN and paths | `get_topology_context`, `get_network_topology`, `get_overlay_state`, `get_tunnel_state`, `get_path_evidence`, `get_probe_results` |
| Active probes (`CapNetProbe`) | `run_ping`, `run_traceroute`, `run_dns_test`, `run_http_test` |
| Changes | `get_recent_changes`, `get_config_diff` |
| BGP | `get_bgp_watchlist`, `get_bgp_rpki`, `get_bgp_feed_recent` |
| Apps, integrations, ITSM, security | `get_app_identity_summary`, `get_low_confidence_app_matches`, `get_integration_health`, `get_ticket_status`, `get_security_findings` |
| NL query | `compile_query` |

Tools listed in a module's registry entry but not yet in `moduleTools` route to an
honest "not built yet" — never faked data. See `adding-new-tool.md`.

## Result shape

A tool returns `ToolResult{ Items []EvidenceItem, Truncated bool, Notes []string }`.
Each `EvidenceItem` carries a stable `CitationID`, a `Kind`, the `Text`, and a UI
`Href` so every answer is verifiable (anti-black-box).
