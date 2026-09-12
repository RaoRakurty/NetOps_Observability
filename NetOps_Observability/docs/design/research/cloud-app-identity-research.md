# Cloud App Identity + Caching — Research Findings (#81 P3)

> Deep-research pass `wf_7377f641-26d`, 2026-06-25. 5 angles · 22 sources fetched ·
> 98 claims → 25 verified (3-vote adversarial) → **24 confirmed, 1 killed**. All
> confirmed claims are backed by **current (2025–2026) PRIMARY vendor docs** with
> unanimous 3-0 votes. Captured immediately (unlike the first app-id pass).
> Feeds `docs/design/cloud-app-observability-rca.md`.

## Verdict (validates the design)

IP-range matching is the **wrong tool** for cloud flow logs — VPC/NSG flow logs are
dominated by private east-west IPs, and the app-bearing fields are **versioned,
optional annotations that must be explicitly enabled**. Application identity lives in
**cloud resource metadata, not IP ranges**. The recommended architecture is a
**per-cloud, agentless inventory-enrichment connector** that builds
`(resource-id / private-IP / ENI / ARN → app)` maps from resource-graph APIs, feeding
the SAME confidence-fusion model as a new high-trust source (tag = authoritative,
resource-graph-name = strong, native service field = authoritative-for-provider,
IP-range = weak fallback). Fast resolution = a multi-tier cache (per-flow result cache
over an IP/ENI/resource-id→app LRU, negative caching, bloom-skip), **warmed from
inventory snapshots and invalidated EVENT-DRIVEN** via change feeds, TTL as backstop.
Untagged/unattributable traffic is a **first-class "unknown" + tag-coverage feature**.

## Confirmed findings (per-provider log fidelity)

**1. AWS — app identity is NOT in default flow logs; it's versioned, opt-in.**
Default v2 = 14 5-tuple/network fields only. Resource identity is custom-format + versioned:
`vpc-id/subnet-id/instance-id/pkt-srcaddr/pkt-dstaddr` = **v3**; `pkt-src/dst-aws-service`,
`flow-direction`, `traffic-path` = **v5**; `ecs-cluster-arn/ecs-service-name/ecs-task-id` =
**v7**; `instance-tag/interface-tag/asg-tag` = **v11**. `instance-id` returns `'-'` for
requester-managed ENIs (NAT gateways) and is **empty for Lambda/managed-service flows**.
→ **Connector must detect the customer's flow-log version, prefer `pkt-dst-aws-service`
(authoritative for AWS-owned services), and fall back to ENI→resource-graph when
`instance-id='-'`.** [src: docs.aws.amazon.com/vpc/.../flow-log-records.html]

**2. Azure — app identity in resource IDs, not the 5-tuple.** Traffic Analytics
enriches each flow with `SrcVm/DestVm` (`<RG>/<VMName>`), `SrcNic/DestNic`,
`SrcSubnet` (`<RG>/<VNet>/<Subnet>`), `SrcSubscription`, region; classifies `FlowType`
(IntraVNet/InterVNet/S2S/P2S/AzurePublic/ExternalPublic/Malicious/UnknownPrivate/Unknown);
exposes Azure-service ownership for AzurePublic via `PublicIPDetails` (needs a join to
NTAIpDetails, MS-owned IPs only). **Raw VNet flow logs = comma-separated tuple ONLY**
(no instance/ENI/VM id); record-level `targetResourceID` = the **VNet scope**, not the
per-flow workload (MAC→NIC→VM still needs a Resource Graph join). → **Prefer Traffic
Analytics if enabled (pre-joined); else join raw flow logs against Azure Resource Graph
by NIC/MAC/private-IP.** [src: learn.microsoft.com/.../traffic-analytics-schema, vnet-flow-logs-overview]

**3. GCP — richest in-log identity, but every app field is optional.**
`src_instance/dest_instance` (project_id, vm_name, region, zone, managed_instance_group);
`src_gke_details/dest_gke_details` (cluster_name/location, pod_name/namespace,
workload_name/type ∈ DEPLOYMENT/REPLICA_SET/STATEFUL_SET/DAEMON_SET/JOB/CRON_JOB/RC,
service_name/namespace capped at 2 then MANY_SERVICES). Enables **K8s-workload-level
attribution directly from flow logs** — but these are metadata annotations
(INCLUDE_ALL / EXCLUDE_ALL / CUSTOM_METADATA), on by default yet disable-able; only
5-tuple/reporter/rtt_msec/bytes/packets/start/end are **always** present. GKE Pod
annotations also depend on IP-masquerade config. → **GCP connector cannot assume
metadata fields exist; fall back to Cloud Asset Inventory on private IP when stripped/masqueraded.**
[src: cloud.google.com/vpc/docs/flow-logs, about-flow-logs-records]

## Confirmed findings (inventory + caching + scale)

**4. Agentless resource→app maps from resource-graph APIs; near-real-time via event feeds.**
**GCP Cloud Asset Inventory feeds** are the strongest model: Pub/Sub **TemporalAsset**
format carrying **BOTH current and priorAsset state** — exactly the delta a cache needs
to invalidate/update on change. Feeds monitor RESOURCE / IAM_POLICY / ORG_POLICY /
ACCESS_POLICY / OS_INVENTORY / RELATIONSHIP (RELATIONSHIP needs SCC Premium/Enterprise).
→ **Model invalidation on the prior+current-state feed pattern; use AWS CloudTrail/
EventBridge and Azure Event Grid as the equivalents; TTL as a backstop where feeds are
unavailable/gated.** [src: cloud.google.com/asset-inventory/docs/monitor-asset-changes, feeds]

**5. ECS awsvpc = clean 1:1 ENI→task.** Each awsvpc task gets its own dedicated ENI with
one private IPv4, and a task has exactly one ENI → **ENI is a 1:1 key from a flow-log
private IP to a specific ECS task**. Caveat: ENI is detached/deleted when the task stops
and IPs recycle → **IP→task resolution is point-in-time; the cache/inventory join must be
TIMESTAMP-BOUNDED** (correlate the flow window against the ENI lifetime). ENI→task→service
is the AWS backbone where `instance-id='-'`. [src: docs.aws.amazon.com/AmazonECS/.../task-networking-awsvpc.html]

**6. Tag attribution is authoritative, but the AWS tagging API structurally excludes
untagged resources.** `GetResources` returns ARN + key/value Tags, scoped to one Region,
filterable by ResourceTypeFilters + TagFilters (≤50 keys × 20 values) — but returns
**ONLY tagged (or previously-tagged) resources** and explicitly NOT never-tagged ones.
**To find untagged → AWS Resource Explorer `tag:none`.** → **Build the tag-coverage report
from the gap between full inventory (Config/describe-*/Resource Explorer) and GetResources;
surface untagged/orphaned resources + 'unknown'-attributed traffic as a product feature;
keep 'unknown' first-class — never guess app=X.** [src: docs.aws.amazon.com/resourcegroupstagging/.../API_GetResources.html]

**7. Connectors need cloud SDKs (NOT Go-stdlib) — the explicit exception to our rule.**
Rate limits to engineer around: **Azure Resource Graph** ~15 queries/5s/user (headers
`x-ms-user-quota-remaining`/`-resets-after`), max **1,000 records/response**, skip-token
paging (each page = one quota unit). **GCP CAI** SearchAllResources 400/min/project,
1,500/min/org; ListAssets 100/min/project, 800/min + 650k/day/org. **AWS GetResources**
per-second Service-Quota throttle (ThrottledException = HTTP 400). → **Connectors
paginate, back off on throttle headers/exceptions, batch by region/account, prefer bulk
snapshot APIs (Config aggregators / SearchAllResources / ARG) for cache warming over
per-flow API calls. These SDK-driven connectors are the documented exception; the
in-memory radix-trie + LRU resolution path and the fusion engine STAY stdlib.**

## Caveats (verifier-flagged)

- **Flow-log field versions evolve** (AWS already at v11 tags; GCP/Azure update quarterly)
  → **version-detection must be data-driven, not hard-coded.**
- Gated/conditional: GCP RELATIONSHIP feeds need SCC Premium/Enterprise; GKE Pod
  annotations depend on IP-masquerade; Azure `PublicIPDetails` needs an IP-details join +
  MS-owned IPs only; Azure `targetResourceID` = VNet scope, not per-flow workload.
- Rate limits are vendor-stated "subject to change" (ARG 15/5s framed as an example).
- **NOT independently verified → design recommendation, not cited fact:** caching internals
  (ARC vs LRU sizing, bloom false-positive budgets, exact memory bounds at millions of
  resources, sharding key), and competitor enrichment/cache internals (Datadog CNM, Kentik
  Cloud, GCP Network Intelligence Center). Treat as sound engineering inference.

## Killed claim (1-2 vote)
- Azure skip-token paging specifics (`$skipToken` + `resultTruncated` exact mechanism) —
  refuted; do not rely on that precise description, re-check the API ref when building.

## Open questions (carry into design / future research)
1. Concrete sourced caching internals of the leaders (TTLs, tier sizing, invalidation triggers) vs our inferred multi-tier design.
2. Realistic event-feed latency/completeness for AWS CloudTrail/EventBridge & Azure Event Grid (vs GCP's verified prior+current feed); is TTL-backstop staleness acceptable for IP/ENI recycling windows?
3. Actual memory footprint + eviction at millions of resources/tenant; the right hot/warm tier boundary + sharding key (tenant? account? region?).
4. For AWS `instance-id='-'`/Lambda/managed flows, which combo of Config relationships + ENI describe-* + `pkt-dst-aws-service` gives best coverage, and the residual legitimate-'unknown' %.

## Direct design implications (→ P3A/P3B)
- **Per-flow attribution priority:** native in-log resource field (GCP instance/GKE, AWS v7 ECS, AWS `pkt-dst-aws-service`) → ENI/NIC/private-IP → resource-graph join → tag → else unknown. Confidence follows the source.
- **ENI/NIC is the primary east-west join key**, timestamp-bounded.
- **Event-driven invalidation** (prior+current state) is the cache-correctness model; TTL backstop.
- **Tag-coverage = gap between full inventory and tagged-only API.** Ship it as a feature.
- **SDK exception:** real connectors use cloud SDKs (documented per-provider IAM + rate limits); the resolver/cache/fusion stay stdlib. Fixture provider first (no fake connector claims).
