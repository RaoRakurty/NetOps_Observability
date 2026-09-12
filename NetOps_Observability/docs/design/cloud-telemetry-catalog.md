# Cloud Telemetry Catalog — completeness audit (#105, 2026-07-14)

Three provider-specialist audits (web-verified against current provider docs)
answering the owner's directive: *"ensure we are polling and organizing ALL
possible cloud telemetry, correlated with network devices."* This file is the
durable record: the full surface per provider, what we ingest, what's missing,
ranked. The parity matrix (`cloud-provider-parity.md`) stays the scoreboard;
this is the map it draws from.

**Headline finding (all providers):** the compute-instance slice is well
covered (inventory/lifecycle truth, canonical metrics, provider health,
changes, flow logs on AWS) — but the **managed network-gateway plane is
rendered, not measured**: `discover.py` draws vgw/tgw/NAT edges in the path
graph while zero telemetry is polled from those nodes. The highest-value
missing class on every provider is exactly the hybrid seam:

- **AWS**: DX (`VirtualInterfaceBgpStatus` is now a first-class CW metric +
  per-lane optical light levels), Site-to-Site VPN `TunnelState` + IKE/BGP
  vended logs, TGW `PacketDropCountBlackhole/NoRoute` + TGW flow logs
  (`packets-lost-*` fields VPC-FL cannot carry), NAT `ErrorPortAllocation`.
- **Azure**: ExpressRoute `BgpAvailability`/`ArpAvailability` per peer, VPN GW
  `BgpPeerStatus` (poll-only — NOT exportable via diagnostic settings) +
  tunnel drop/TS-mismatch counters, Route Server/vWAN BGP peers, Azure
  Firewall health/SNAT, NAT `SNATConnectionCount(Failed)`.
- **GCP**: (section appended when the third audit lands.)

## Corrections to prior assumptions (encode everywhere)

1. **AWS Health lane is NOT paid-only**: account-specific `aws.health` events
   on EventBridge are FREE with no support plan (DX maintenance, VPN endpoint
   replacement, EC2 retirement, AZ issues). The Health *API* needs a support
   plan; the event feed doesn't. Parity matrix row corrected. This is the
   "AWS admits fault" lane and the peer of Azure Resource Health.
2. **VPC flow logs are at v11**, not v5 — v5 `traffic-path` (per-flow egress
   edge!), v3 `tcp-flags`, v8 `reject-reason`, v11 `next-hop-*` (native
   per-flow next-hop — purpose-built for our path graph). Our parser already
   maps fields by name and accepts a custom layout; nothing configures it yet.
3. AWS "CloudWatch Network Monitor" renamed **Network Synthetic Monitor**; its
   **Network Health Indicator** = an official binary "was AWS's network at
   fault" — the strongest possible seam-verdict corroborator.
4. DX `ConnectionCRCErrorCount` deprecated → `ConnectionErrorCount`; TGW drop
   metrics are `PacketDropCount*` (singular Packet).
5. Region pinning: R53 health checks = us-east-1; Network Manager / Cloud WAN
   / Global Accelerator metrics+events = us-west-2. The poller is
   single-region today — these lanes need pinned clients.
6. Azure: **metric dimensions are load-bearing** — `BgpPeerStatus` (per peer),
   NAT/LB SNAT metrics are poll-only and dimension-split; diagnostic-settings
   metric export FLATTENS dimensions. Our poll-the-Metrics-API architecture is
   therefore *required*, not just preferred. `azure.poll_metrics` needs
   `$filter` dimension support (~30 lines) — it unlocks four top-10 items.
7. Azure Scheduled Events (IMDS 169.254.169.254) are **structurally
   agent-only** — record n/a, never fake.
8. Azure Event Hubs Standard speaks the **Kafka wire protocol** — an Event Hub
   lane is a consumer config for our existing Kafka stack, not new code.
9. Azure export-cost asymmetry: diagnostic settings → storage ≈ $0.25/GB vs
   Log Analytics ingestion ≈ $2.30/GB (~9×). Pull-from-storage stays the
   default; the LA query API is a secondary lane only for LA-only payloads
   (Connection Monitor hop paths, App Insights availability runs).
10. At product scale, AWS metric delivery flips to **CloudWatch Metric
    Streams** ($0.003/1k updates via Firehose→HTTP, OTel) vs GetMetricData
    polling ($0.01/1k); Azure scale path = `metrics:getBatch` (50 res/call);
    EventBridge **API destinations** = the push front door for events.

## AWS — ranked top-10 missing (full detail in audit, condensed here)

| # | What | RCA | Effort |
|---|---|---|---|
| 1 | Hybrid-gateway metric pack: AWS/DX (BGP status, light levels) + AWS/VPN TunnelState + AWS/TransitGateway blackhole/no-route drops + AWS/NATGateway port-alloc errors | 5 | M (NAT alone S — ids already discovered) |
| 2 | AWS Health events (free EventBridge `aws.health`) → provider-incident lane + suppression windows | 5 | M (S once EventBridge→CW-Logs pattern exists) |
| 3 | VPC flow-log field upgrade (traffic-path, tcp-flags, reject-reason, next-hop) — parser ready, config missing | 5 | S |
| 4 | Network Manager events (IPSEC-DOWN/BGP-DOWN/TGW-ROUTE-INSTALLED) — the only push BGP/IPsec signal on AWS | 5 | M (shares #2 lane) |
| 5 | ELB metric pack (ALB target health + ELB-vs-target 5xx split; NLB port-alloc/RST; GWLB GENEVE drops) | 5 | S/M (lab ALB owner-gated) |
| 6 | TGW flow logs (loss-in-record + cross-VPC attribution) | 5 | M |
| 7 | S2S VPN vended logs (IKE phases + 2025 BGP stream) | 4 | S |
| 8 | EC2/EBS health tail: StatusCheckFailed_AttachedEBS (one dict line!), VolumeStalledIOCheck, BurstBalance, spot/state events | 4 | S |
| 9 | CloudTrail→S3 delivery (escapes 2 TPS LookupEvents throttle) + AWS Config diffs/relationships (scoped to network types — ENI-churn cost trap) | 4 | M |
| 10 | Internet Monitor (city×ASN internet-path blame) + Network Synthetic Monitor NHI | 4 | M ($ flag) |

Also: PrivateLink RST metrics (S, free), CloudTrail network-activity
`VpceAccessDenied` events, Reachability Analyzer as an on-demand RCA *action*
($0.10/run), RDS failover events. Structural n/a: IGW/EIP metrics (no
namespace exists), GWLB access logs (feature doesn't exist). Skip: S3 server
access logs (lossy, hours-late — CloudTrail data events are the honest option),
CloudWatch RUM (no export), X-Ray (app-plane, defer).

## Azure — ranked top-10 missing (condensed)

| # | What | RCA | Effort |
|---|---|---|---|
| 1 | VPN GW + ExpressRoute circuit/gateway metrics (BgpAvailability, ArpAvailability, BgpPeerStatus/peer, tunnel drops, routes adv/learned) | 5 | S/M (needs `$filter` dimension support — the keystone primitive) |
| 2 | Service Health events lane (free; ServiceIssue/PlannedMaintenance/RCA docs + impactedResources) | 5 | S |
| 3 | VNet flow-log storage-blob reader (v4 flowTuples → existing rollups; NSG-FL retires 2027-09) | 5 | M (already build-order #2) |
| 4 | ARG `resourcechanges` diff lane — property-level before/after + changedBy, <5 min, free | 5 | S |
| 5 | Connection Monitor ingestion (Azure-native active path measurement; metrics S, hop-path via LA query M) | 5 | S/M |
| 6 | NAT GW + Std LB health metrics (SNAT exhaustion, DipAvailability per backend — fills "LB target health" row with NO new lab infra) | 4 | S |
| 7 | Azure Firewall metrics + AZFW structured logs (deny-rollups → firewall_logs family) | 4.5 | S+M |
| 8 | VPN diagnostic logs (TunnelDiagnosticLog/IKEDiagnosticLog — flap→cause) | 4 | M |
| 9 | ARG HealthResources annotations (LiveMigration/HostReboot — "why" behind VM dark) + VmAvailability `Context` dim | 4 | S |
| 10 | App Gateway / Front Door backend+origin health metrics, access/WAF logs | 3.5–4 | S+M |

Below the cut: DNS security-policy `DnsResponse` logs (drill #6 wave), Traffic
Manager endpoint status (trivial add-on), App Insights availability (customer's
own synthetics as corroboration; URL-ping tests retire 2026-09), Private Link
metrics, Resource Health history. Defer: ExpressRoute Traffic Collector
(collector ~$0.70/hr). n/a: Scheduled Events (agent-only).

## GCP — ranked top-10 to reach parity (condensed)

**Audit verdict:** GCP is the *strongest* provider for our pull architecture —
live per-peer BGP state via free REST, explicit platform-fault logs, free
Google-measured inter-zone RTT/loss, and everything in the top-10 (except
flow logs at customer scale) is **pull-only with zero customer-side
infrastructure** ("no sink, no agent, read-only SA" — a stronger onboarding
story than AWS, which needs S3 buckets).

| # | What | RCA | Effort |
|---|---|---|---|
| 1 | Cloud Router BGP/BFD lane: `getRouterStatus` per-peer poll (status/state/uptime/learned+advertised routes/BFD/statusReason — free REST) + `bgp/session_up`·`bfd/session_up` metrics + gce_router event logs | 5 | M |
| 2 | Seam-device inventory + egress topology (routes.list next-hops, VPN gateways/tunnels, Interconnect attachments, Cloud Routers, NATs) — gcp.json has instances only; without this no GCP fault can be DRAWN on the RCA path | 5 | M |
| 3 | VPN + Interconnect telemetry: `tunnel_established`, drop counters, IKE event logs; `link/operational` + **rx/tx optical light levels** | 5 | S–M |
| 4 | **Firewall Rules Logging DENIED = the REJECT lane** (KEY CORRECTION: GCP flow logs have NO accept/reject field — denied traffic never appears in vpc_flows; drill #3 lives in firewall logs, with the rule name in-record — better than AWS) | 5 | M |
| 5 | Platform-fault lane: **system_event audit logs** (`hostError`, `preempted`, `automaticRestart`, live-migration — free, always-on) + Personalized Service Health `events.list` (free — beats AWS's paid Health API) | 5 | S |
| 6 | VPC Flow Logs ACCEPT volume + per-flow **`rtt_msec`** (prefer the Network-Management-API config: 100% sampling + covers Interconnect/VPN attachments) | 4 | M (L at scale → Pub/Sub sink) |
| 7 | Cloud NAT exhaustion: `nat_allocation_failed`, drops with `reason=OUT_OF_RESOURCES`, `port_usage` (gateway-scoped, not per-VM — billing) | 4 | S |
| 8 | LB lane: `response_code_class` 5xx metrics + **`backendServices.getHealth`** (LB-target-health with NO lab infra needed!) + request logs (`statusDetails`); **Cloud Armor rides the same log** — one lane closes two matrix rows | 4 | M |
| 9 | Google-measured RTT/loss (Performance Dashboard `vm_flow/rtt`, `cloud_netslo` probe loss — free, agentless; no AWS/Azure equivalent) + `quota/exceeded` signal | 4 | S |
| 10 | DNS: `query/response_count{response_code}` metric first (free NXDOMAIN rate, no log costs), `dns_queries` logs for forensics | 3.5 | S–M |

GCP corrections encoded: parity "provider verdict n/a" revised to **"synthesized:
control-plane status + system_event hostError"** (never fabricate a metric;
`instance/uptime` is explicitly disqualified by Google for availability);
`REPAIRING` must map to degraded (it IS broken — platform-side), never benign
stopped; Cloud Logging `entries:list` is free but hard-capped at 60 req/min per
project (consolidate polls per family, never per-instance); Monitoring reads
billed **$0.50/M time series returned** (2025-10 regime) — every new lane
states its series count; audit-poller cursor needs overlap + insertId dedup
(FIXED in gcp.py same-day); Cloud Trace = skip (empty without customer
instrumentation); Cloud Asset Inventory `batchGetAssetsHistory` = free 35-day
config diffs (Phase-2 change-evidence upgrade, GCP's ARG-resourcechanges
analog). New SA roles when lanes land: `roles/servicehealth.viewer` (+ API
enablement), later `roles/cloudasset.viewer`.

## Cross-provider architecture decisions this catalog forces

1. **Two framework primitives unlock most of the top-10s:**
   - AWS: an **EventBridge→CloudWatch-Logs→existing FilterLogEvents** pattern
     (pure pull, no inbound endpoint) carries Health, Network Manager, spot,
     RDS, Config events — one Terraform rule per class.
   - Azure: **dimension support in `poll_metrics`** + a **shared storage-blob
     reader** (sibling of `_poll_s3_lane`).
2. **Resource-type enumeration** joins the inventory writers: DX/VPN/TGW/NAT
   (AWS describe calls) and `Microsoft.Network/*` lists (Azure) — the seam
   nodes become inventory rows with telemetry, not just drawn edges.
3. **Cost-tier policy (owner direction 2026-07-14, supersedes the collector
   push): FREE lanes always on, METERED lanes are a customer toggle.**
   - Always-on (free/near-free): inventory describes, change/audit events,
     provider health events (free on all 3), S3/storage-delivered logs,
     Azure metric reads (not billed), GCP Logging `entries:list` reads (free,
     60 req/min cap), GCP Monitoring within its 1M-series free tier.
   - Toggle (provider meters the reads): AWS CloudWatch `GetMetricData`
     ($0.01/1k values) → `AWS_METERED_METRICS=off`; GCP Monitoring past free
     tier → `GCP_METERED_METRICS=off`. Off renders honestly in the matrix as
     disabled-by-choice, never silently missing; prod shape = per-tenant
     connector setting with the projected $ shown before enabling.
   - **Edge Cloud Collector: ON HOLD** (owner) — revisit as the scale/privacy
     option; the cost-tier toggle covers the near-term concern.
4. **Every high-volume lane keeps the P1-6 law**: bounded rollups, never
   per-record firehose.
