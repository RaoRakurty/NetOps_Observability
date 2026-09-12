# Module Registry (Application Knowledge Layer)

The Module Registry (`src/backend/ai/registry.go`) is **code, not prose** — it
teaches the orchestrator the Correlix application structure so it can route a
question to the right module and govern it. `GET /api/ai/modules` serves the
per-caller view (which modules are enabled).

Each `Module` declares: `id`, `display_name`, `description`, `entities`,
`question_categories`, `tools`, `permissions` (RBAC any-of), `freshness`,
`sensitivity`, `availability` (`stable` | `future`, with an optional feature
flag), `cross_module`, and `response_modes`.

## Registered modules

`command_center`, `event_management`, `correlations_rca`, `topology`,
`cloud_app_observability` (future, `ENABLE_CLOUD_APP_OBS`), `app_identification`,
`telemetry`, `flow_analytics`, `itsm`, `reports`, `integrations`, `tenant_admin`,
`audit`, `product_navigation`, `network_expert_kb`.

## Availability gate

`IsModuleEnabled(id, flags)` returns true only for a `stable` module whose feature
flag (if any) is on. A `future` module is registered so the router knows it exists
and answers with an honest *"not enabled yet"* disclosure — never faked data.

## Adding a module

Add a `Module` literal to `modules`. Mark it `AvailabilityFuture` until its tools
exist; the orchestrator will route to it and disclose honestly. When the tools land
(see `adding-new-tool.md`), flip it to `AvailabilityStable`.
