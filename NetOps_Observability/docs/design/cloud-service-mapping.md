# Cloud service mapping — tag-optional, read-only, evidence-backed

Status: P1 partially shipped (see the matrix at the end). Owner-gated items and
the M:N model evolution are called out honestly.

## Problem

The live monitoring service principal is **read-only** (Azure Reader + Monitoring
Reader) and the lab's Azure VMs arrive with **empty tags** `{}`. Requiring tags
for attribution is therefore wrong: every Azure resource read as "Untagged" and
went unattributed, and the SP cannot write tags to fix it. Correlix must attribute
resources **without write access** and **without mandatory tags** — and the design
must apply identically to AWS/GCP/on-prem via provider adapters, never with
Azure-specific conditionals.

## Principles (non-negotiable)

1. **Tags/labels are HINTS, never truth, never a collection prerequisite.** Tag
   absence never fails collection. A present tag is used verbatim as the strongest
   hint; an absent tag falls through to inference.
2. **Relationships > naming/tagging.** Resource relationships and observed
   connectivity are stronger evidence than a name or a tag.
3. **Read-only, least-privilege.** Monitoring requires reads only. Manual overrides
   are stored INSIDE Correlix — never written back as cloud tags. Correlix never
   auto-broadens its own grant.
4. **Explainable, component-based confidence.** Every inference carries a
   confidence rung AND a human basis listing which signals fired. Low confidence is
   qualified, never presented as fact. Inferred membership is NOT causal proof.
5. **Provider-neutral.** One shared model + contracts; adapters normalize each
   cloud into it.

## Shipped contracts

### 1. Cloud event contract (one shared shape across providers)

`deployment/docker/cloud-ingest/cloud_events.py` is the single source of the
MetricEvent, CloudChangeEvent, and CloudHealthEvent shapes. AWS/Azure/GCP emit
through the same builders, so routing fields (`provider`, `account`,
`resource_id`, `region`, `severity`, `metric`/`metric_name`, `observed_at`) are
top-level and identical across providers — never buried in the `attrs` dimension
bag. `test_cloud_events.py` asserts AWS==Azure==GCP key sets and forbids
hand-rolled event dicts (the exact drift that silently dropped the GCP metric lane).

### 2. Capability-based read-only permissions

`capabilities.py` models discrete read capabilities (inventory_read, metric_read,
resource_health_read, activity_event_read, topology_read, network_watch_read,
diagnostic_settings_read, resource_graph_query, cost_read), each mapped to the
exact API action + built-in role + whether optional. `azure_permissions.py` is the
Azure adapter that invokes the ACTUAL ARM read per capability and reports a
per-capability status (available / missing_permission / scope_not_granted /
not_configured / api_disabled / not_applicable). Only the two required
capabilities gate; a missing optional capability is a coverage gap. See
`CREDENTIALS.md` for the capability→permission matrix + sample RBAC JSON.

### 3. Built-in service inference (`service_infer.py`)

Conservative, explainable, tag-free. For every resource that lacks an app tag, it
infers a BusinessService name + confidence + basis from:

- **Resource-group naming convention** (`rg-payments-prod` → `payments`) →
  `suspected`. Environment/region tokens are stripped; a pure-convention or
  generic RG yields no name.
- **Structural corroboration** — resources in the RG that share a **subnet** or a
  **hostname prefix** promote the name to `strong` (a real tier, not just a name).
- **Lone hostname role** (`grafana01` → `grafana`) → `weak` (display hint only).
- **No usable signal** → no inference; the resource stays honestly unknown and is
  monitored + rendered with resource-based wording.

Safety rules honored: never infer one service from shared infra alone, never merge
on a shared RG alone, never treat a name as ownership, never treat `prod` as
criticality. Confidence maps to the Go ladder: strong→Strong, suspected→Suspected,
weak→Weak, none→Unknown. Inference NEVER reaches Confirmed (only a tag or a manual
override does).

Attribution wiring (`src/backend/cloud/resolve.go`): a tag wins; else a
strong/suspected inference sets a real `AppID` (attributed, labeled
`SrcInferredService` with its confidence + basis); a weak inference is a display
hint (AppID empty, so the coverage funnel is not over-claimed). This flows through
the identity map → Resource/Alerts/Service-View unchanged, so the untagged Azure
fleet stops reading as "Untagged".

### 4. BusinessService + manual overrides (migration 0024)

`migrations/0024_business_service.sql`: `business_services` (named registry) +
`resource_mappings` (resource→service override), both FORCE-RLS tenant-isolated.
`business_service_store.go` + `business_service_handlers.go` expose CRUD + bulk
assignment; a manual assignment is authoritative (confirmed) and, via
`overlayManualMappings`, wins over inference on the Resources surface — stored
internally, never written to the cloud. Cross-org isolation proven in
`business_service_isolation_test.go`.

## Shared seam for the topology agent — ResourceRelationship

A separate agent owns cloud **topology discovery** (VPC/VNet→subnet→route-table→
gateway edges, `azure_topology.py`, `GET /api/topology/cloud`, the canvas). The
inference engine here should CONSUME that canonical relationship graph rather than
re-discover it. Proposed shared contract (define once, both sides import):

```
ResourceRelationship {
  tenant_id        string
  provider         string          # aws | azure | gcp
  src_resource_id  string          # canonical provider_resource_id
  dst_resource_id  string
  relation         string          # nic_of | in_subnet | in_vnet | routed_via |
                                   # fronted_by_lb | backend_of | egresses_via |
                                   # private_endpoint_of | resolves_to
  evidence         string          # which API fact established it (route table, LB pool…)
  observed_at      timestamp       # temporal/provenance-aware
}
```

Today `service_infer.py` derives the subnet/hostname structural signal from the
inventory itself (NIC `ipConfigurations` → subnet id). When the topology agent
publishes the ResourceRelationship graph, the inference should consume LB-backend,
route-table, gateway, and private-endpoint edges as additional (stronger)
structural evidence, and cite the specific `evidence` + relationship in its basis.
**This is the coordination seam — neither side should duplicate the other's
discovery.**

## Remaining P1 (honest — not yet shipped)

- **Many-to-many membership + provenance metadata (P1.5/P1.6).** The shipped
  `resource_mappings` is 1:1 (one override per resource). The target model is a
  temporal, provenance-aware `service_resource_membership` (a resource in MANY
  contexts — business/technical service, env, path, ownership, compliance;
  `membership_role` incl. `shared_dependency`; `manually_confirmed/rejected`;
  `evidence_ids`; `explanation`; `valid_from/valid_until/observed_at`) plus a
  `cloud_metadata_entry` precedence chain (manual > CMDB > tenant rule > tag >
  relationship > hierarchy > DNS > flow > naming > unknown). This is an additive
  migration evolution; the 1:1 store is the interim.
- **Canonical typed CloudResource constructor + dead-letter** with reason codes
  (P1.4). `cloud.CloudResource` exists and tags are optional; the shared typed
  constructor + malformed-resource dead-letter is not yet built.
- **RCA metadata fields (P1.9).** The inferred service NAME reaches the report
  subject via attribution today (proven in `rca_inferred_service_test.go`). The
  explicit `affected_service`/`mapping_source`/`mapping_confidence`/`service_role`
  + incident-time mapping version fields require threading attribution provenance
  through the correlation object → ClickHouse → report (a live-stack change).
