# Adding a new governed tool

A module read-tool is **a registry line + one query case** — no new type, no new
interface method. Tools are tenant-scoped, read-only, and injection-safe by
construction (the query name is fixed by the tool, never the model).

## Steps

1. **Implement the data fetch** in `src/backend/ai_datasource.go` — add a `case`
   to `ModuleQuery` calling an existing tenant-scoped source (`chRowsScope(...)`
   for ClickHouse, or a store method with `p.Tenant, p.Cross`). Return cited
   `ai.EvidenceItem`s; return an **empty** result (not an error) when there's no
   data, and `ai.ErrNotImplemented` only for an unknown query name.

   ```go
   case "service_flow_summary":
       return d.moduleServiceFlows()
   ```

2. **Register the tool** in `src/backend/ai/tools.go` `moduleTools`:

   ```go
   {"get_service_flow_summary", "flow_analytics", "service_flow_summary",
       []string{"flows:read"}, FreshnessRecent},
   ```

   Fields: tool name, module id, the fixed `ModuleQuery` name, required perms
   (any-of), freshness.

3. **Route to it** (if it answers a question):
   - For a module-health question, add the tool name to the module's `moduleRoute`
     `tools` list in `orchestrator.go` (and widen the route regex if needed).
   - For RCA enrichment (needs `problem_id`), add the tool name to the
     `problem_explanation` plan's `Tools` in `Classify`. It receives
     `args["problem_id"]`.

4. **Add it to the module's `Tools` list** in `registry.go` for documentation.

5. **Test** (`go test ./ai/`): route classification + (if store-backed) a
   cross-tenant isolation assertion. The route-isolation ledger
   (`route_isolation_test.go`) already covers `/api/ai/ask`.

## Rules

- Never add a raw-SQL or log-dump tool.
- Never let the model supply the query name or a free-form filter.
- Tenant scope is enforced in the data source, never in the tool.
- Write/execute tools are out of scope until the P6 action gate (draft-only today).
