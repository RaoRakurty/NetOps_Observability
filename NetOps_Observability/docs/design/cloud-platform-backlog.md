# Cloud Platform — unified backlog (Connectors + Product-Review merged)

Single prioritized backlog merging the **Cloud Connectors** roadmap and the
**Cloud Monitoring product-review** top-25 + 50-missing-features
(`docs/design/research/cloud-monitoring-product-review-2026-07.md`). Ordered by
**implementation flow** (developer preference): build the data + credential
foundation first, then the surfaces that consume it, then governance,
detection→resolution, breadth, and polish. Priority follows the flow —
foundation is P0 because everything downstream depends on it.

## Already shipped (not re-listed below)
Connector domain model + RLS storage + identity broker + **live token exchange**
(AWS STS SigV4 / Azure Entra / GCP STS) + validate live-trust-proof · GCP
console-link allowlist fix (rev #3) · Cloud topology mock removal (rev #4) ·
in-product bulk attribution drawer (rev #5) · nav vocabulary (rev #13) · shared
inventory read (rev #14). Log-family lanes live on all 3 clouds (#105).

---

## WAVE 1 — Data & credential foundation (P0 · unblocks everything)
1. **Cloud inventory → Postgres store + pagination + server-side filters** (rev #2).
   Replace in-memory `memCloudStore`; add `limit/cursor/provider/account/region/
   type/tag/attribution` to `/api/cloud/resources`. Root of every scale failure;
   free-text search, findings pagination, export, saved views all sit on it. **L.**
2. **Per-tenant ingestion — poller → connector store** (connector follow-up +
   missing #3). cloud-ingest sidecar consumes the connector store (via the broker's
   `TokenFor`) instead of env creds → true multi-tenant "live connectors". Backend
   ready (token exchange done). Pairs with #1. **M–L.** *(blocked by nothing new;
   benefits from #1's store.)*
3. **Connector onboarding wizard UI** (rev #1). Front-end over the done 7-step API:
   provider catalog → draft → auth method (federated dominant) → trust templates →
   scopes → validate-with-findings → activate. Highest business value; parallelizable
   with #1/#2 (frontend over stable API). **L.**

## WAVE 2 — Make telemetry answerable (P1)
4. **Data Sources = connectors + health** (rev #10 + #11 + missing #9/#10). Accounts
   from connectors not discovered resources; identity-vs-telemetry health split; red
   rows for silent accounts; pollers emit `permission_denied`/`misconfigured` into
   ingestion status ("IAM denied X since Tuesday"). *Blocked by #2, #3.* **M.**
5. **Interactive scope bar + real time-range** (rev #6). Provider/account/region/env
   global filters feeding all tabs; real 1h/24h/7d param through signal endpoints
   (kills the dishonest "Last 1h" label). *Blocked by #1.* **M.**
6. **Alert episode grouping + triage** (rev #7 + missing #4). Collapse repeated
   (resource, signal, state) into episodes w/ first/last/count + flap detection;
   ack/assign/mute/snooze/notes with audit trail. **M.**
7. **Embedded investigation view + verification loop** (rev #8 + #20). Open the
   correlation object in a drawer/split-pane inside Service View (no context-losing
   jump); close requires/records "signal clear for N min" → recovery banner. **M.**

## WAVE 3 — Service model & impact (P1/P2)
8. **Service catalog UI + Overview impact rework** (rev #12 + #22). CRUD over
   `business-services` (criticality/owner/description); Services tab joins catalog +
   derived apps; Overview degraded-services strip replaces the permanent-dash cards. **M.**
9. **Service dependency map from flow telemetry** (rev #15). `talks_to` edges from the
   live `cloud_flow_*` signals, volume-weighted — the map's own caption already
   promises this. *Benefits from #1.* **M–L.**
10. **Scale-out the tables** (rev #16/#24/#25/#17 + missing #25/#26). Findings/health
    pagination cursors in UI, free-text server-side search, CSV/JSON export honoring
    filters+tenancy, URL-persist filter/drawer state, saved views. *Blocked by #1.* **M.**

## WAVE 4 — Governance + detection→resolution (P2)
11. **Real Settings editors** (rev #9 + missing #12/#29). Required-tags editor (drives
    `missingTags`+coverage), attribution-precedence editor, RCA-window editor —
    per-tenant, persisted, audited; RBAC split operational vs governance; cloud-surface
    audit view. Delete the fake CTAs. **M–L.**
12. **Detection→resolution** (rev #18/#19/#23). Notification routing from cloud signals
    (reuse platform notifier lanes); resolution actions v1 (console/ITSM ticket/runbook
    per service); change→incident correlation card made real. **M.**
13. **Connector runtime hardening** (connector follow-ups). Azure certificate auth,
    keyless AWS `AssumeRoleWithWebIdentity`, workload-assertion minting (platform OIDC
    issuer), live permission validation / scope discovery, per-exchange metrics. **M.**

## WAVE 5 — Breadth & scale-out (P2/P3)
14. **Metrics & monitoring** (missing #17/#18/#19). Metric charts (CPU/net per
    resource/app — data's in the store, zero charts today), SLOs/error budgets,
    cloud monitor authoring (thresholds/anomaly toggles).
15. **Workload breadth** (missing #20/#21). K8s/container layer (EKS/AKS/GKE inventory
    + health); serverless/PaaS classes (Lambda/Functions/Cloud Run, RDS/SQL/Cloud SQL) —
    inventory is VM-only today.
16. **Security & provider-event lanes** (missing #22/#30/#31). LB/WAF/DNS security-findings
    view over the built rollup lanes; provider incident/maintenance lane (AWS Health free);
    hybrid-seam gateway telemetry rendered (built, awaiting infra).
17. **Extensibility & org onboarding** (rev #23 + missing #15). Provider
    enums/labels/allowlists from one registry (Oracle/Alibaba/vSphere = adapter work,
    not UI surgery); org-level multi-account onboarding (AWS Orgs / mgmt groups / folders).
18. **Cost** (missing #24). Cost ingestion + cost-of-degradation context.

## WAVE 6 — Accessibility & polish
19. **Keyboard + WCAG 2.2 AA pass** (rev #21). Arrow-key tabs, focus-trapped drawers, ESC,
    non-color status encodings, `aria-live` on freshness. (Procurement gate.)
20. **Resource detail pages + search-first global nav** (missing #27/#28). Permanent URL
    per resource; global "find resource/app/account by name/id/IP".

---

## Execution model
Waves 1-2 are the near-term critical path. Each item ships behind the house rules
(tenant-scoped, honesty-first, customer-facing language, design-system primitives,
CI-green incl. golangci-lint, isolation test with any data-returning surface).
Foundation items (#1, #2, #3) start first — #1 and #3 parallelize; #2 pairs with #1.
Task IDs in the task list mirror this order with blockedBy dependencies encoding the flow.
