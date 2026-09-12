# Hybrid-Seam Telemetry — finalized design (#105, 2026-07-14)

The design that turns the telemetry catalog's unanimous top gap into product:
cloud-side seam evidence (BGP, tunnels, physical links, gateway drops, NAT
exhaustion) correlated with on-prem device telemetry. Finalized against the
LIVE repository (not assumptions) after the three-provider audit
(`cloud-telemetry-catalog.md`) and a principal-architect review prompt whose
corrections are folded in below.

## 1. Current-state data path (verified in code, not docs)

```
provider API/log/event
  → cloud-ingest poller (compose svc; boto3 / stdlib-REST+SP / google-auth SA;
     checkpointed via .poller-state.json; per-provider failure domains)
  → two emission paths:
      metrics  → Vector :8690 (NDJSON MetricEvent) → netops.metrics → VictoriaMetrics
      signals  → Kafka netops.cloud → correlation handle_cloud
  → cloud_producers.cloud_signal_from_event (kind contract CLOUD_KINDS;
     tenant EXPLICIT on every event, dropped if absent — default-closed)
  → netops.corr_signals (CH; ts = provider observation, ingest_ts separate;
     observer_id cloud:<acct>:<region>; modality_class; entity model)
  → engine grounding → corr_current/objects → RCA verdict → Service View / reports
```

Strengths found: observation-vs-ingest time already first-class in the schema;
tenancy default-closed; bounded-rollup law; provider-blind canonical series.
Defects found & fixed this session: gcp audit cursor had no late-arrival
overlap/dedup (fixed); `.get` substring exclude over-matched (fixed);
seam plane entirely unmeasured (this design).

## 2. Canonical model — mapped onto EXISTING conventions (no duplicate structs)

The prompt's normalized model maps to what the repo already has; we extend,
never fork:

| Prompt field | Repository home |
|---|---|
| tenant_id | event `tenant_id` (explicit, default-closed) |
| provider / account / region | attrs.provider / attrs.account / attrs.region (+ observer_id) |
| resource_id (immutable, native) | signal entity_id + attrs (vif_id, tunnel_ip, circuit, peer…) |
| seam/topology association | engine-side: entity_tokens + seam store (existing seam model) |
| signal_kind | CLOUD_KINDS entry |
| evidence_class | attrs.evidence_class (state, state_transition, route_change, forwarding_drop, physical_health, capacity, saturation, traffic, configuration_change, provider_health, resource_health, flow_evidence, synthetic_evidence) |
| observed_at / collected_at | ts / ingest_ts (already distinct columns) |
| sample period / delay / staleness | attrs.period_s + the cloud_state_unknown transition (below) |
| quality flags | attrs (flap, stale_after_s, status_message…) |
| raw reference | attrs.request_id / native metric name in metric_name |

Kind mapping to the prompt's list: `cloud_configuration_change` = existing
`cloud_change`; `cloud_flow_reject` = existing `cloud_flow_log` (REJECT);
`cloud_nat_allocation_failure` folded into `cloud_nat_port_exhaustion`
(ErrorPortAllocation IS the allocation failure); remaining kinds registered
verbatim (see cloud_producers.py seam block).

## 3. Time semantics (P0, implemented)

* Every seam signal's `ts` = the provider's OWN observation time.
* State is tracked per provider-native key by `seam_state.SeamStateTracker`
  (pure, persisted in poller state): transitions emit exactly once; repeats
  are silent; ≥3 transitions/15 min marks a flap; restart never re-announces.
* **Freshness rule 4**: a state not re-confirmed within 3 poll cycles emits
  `cloud_state_unknown` (from_state recorded) — an "up" can never be eternal.
* Absence ≠ zero: empty metric responses emit nothing (tested).
* Counters use reset-safe deltas (`counter_delta`, tested).
* Log/event lanes keep trailing-overlap + id dedup (CloudTrail P0-3 pattern;
  gcp entries:list overlap+insertId shipped earlier today).

## 4. Collection architecture (with the cost policy)

FREE state lane (always on, `CLOUD_SEAM_TELEMETRY=off` to disable, 120s):
* AWS `describe_vpn_connections` VgwTelemetry → **per-tunnel** state keyed by
  outside IP (the fractional-aggregate TunnelState trap is structurally
  impossible — the aggregate is never read); `describe_virtual_interfaces`
  bgpPeers → per-VIF/per-AF BGP state; `describe_connections` → physical
  connection state (hosted vs dedicated recorded — optics exist only on
  dedicated).
* GCP `routers.getRouterStatus` → per-peer BGP status + numLearnedRoutes
  (free REST; the strongest free seam source of the three).
* Azure Metrics REST **with `$filter` dimensions** (the keystone the audit
  identified): ER `BgpAvailability`/`ArpAvailability` per PeeringType (ARP=L2,
  BGP=L3, labeled), VPN-GW `BgpPeerStatus` per peer, tunnel drop counters per
  connection. (Azure metric reads are unbilled.)

METERED add-on (inside the same cycle, honors `AWS_METERED_METRICS` /
`GCP_METERED_METRICS`): TGW `PacketDropCountBlackhole` vs `NoRoute` (DISTINCT
kinds — different faults, different owners), NAT `ErrorPortAllocation` +
`PacketsDropCount`, DX `ConnectionErrorCount` (+light levels queued).

Rules implemented: batching (GetMetricData 500/call), pagination everywhere,
per-family isolation (one family's failure never rolls back another),
discovery cadence separate from metric cadence, in-flight-bucket exclusion.

## 5. Route-count semantics (Phase 11)

`material_route_drop(prev, cur)`: material = ≥10% loss OR any loss on tables
≤10 routes OR collapse to zero — expected-count context, never a fixed
threshold; no baseline → no claim. BGP-up-with-routes-collapsing emits
`cloud_route_count_drop` (route_change evidence) — deliberately NOT a session
fault (the narrative must say advertisement/policy, not outage).

## 6. Correlation scenarios (engine-side, existing machinery)

The kinds are grounded by the existing engine (entity tokens: tunnel outside
IPs, gateway ids — the same tokens path/probe/on-prem BGP signals carry).
Confirmation stays behind the ≥2-independent-streams law: e.g.
`cloud_bgp_session_down` (cloud API observer) + on-prem BGP trap/syslog
(device observer) = two planes → hybrid seam failure confirmable; a single
plane stays suspected. Signature-catalog wording for each scenario pair
(hybrid BGP both-sides, physical-before-BGP, route-loss-session-up,
blackhole+flow-reject, selector-mismatch, NAT exhaustion, provider-incident
overlay, telemetry disagreement → undetermined) is the P2 slice — kinds and
evidence land now so the engine can already attach them as evidence.

## 7. Cost & cardinality

State lanes: describe/REST calls — free (AWS/GCP) or unbilled (Azure); series
cardinality = #tunnels + #peers + #VIFs (tens, not thousands; keys are seam
objects, never flows/prefixes/destinations). Metered lanes: GetMetricData
$0.01/1k values — at 5 TGW+NAT+DX resources ≈ pennies/month; scales linearly
and stays behind the metered toggles. Small/medium/large estimates live in
the catalog doc §cost; high-cardinality evidence (flow logs) stays in CH/OS,
never VictoriaMetrics.

## 8. Security / tenancy

Read-only IAM only (iam-policy-aws.json + CREDENTIALS.md; seam lane adds
`directconnect:Describe*`, `ec2:DescribeVpnConnections`,
`ec2:DescribeTransitGateways` — policy file updated). Tenant is stamped
explicitly on every event; kinds ride the existing default-closed drop.
No secrets in signals; status messages are provider prose, PII-free.

## 9. Sequencing (remaining after this landing)

* P1 tail: DX light levels per OpticalLaneNumber (dedicated-only), Azure
  ER-Direct port optics, GCP VPN tunnel metrics + Interconnect link state,
  NAT gateway-scoped GCP metrics, route quota pressure.
* P2: provider/resource-health event lanes (task #16), signature catalog
  wording for the 8 scenarios, seam-store topology binding for cloud gateway
  ids, scenario golden tests end-to-end through the engine.
* P3: saturation (gateway CPU/flows), LB/firewall extensions (#12), Internet
  Monitor / Connection Monitor synthetic corroboration.

Genuine blockers: the LAB has no managed VPN/TGW/DX/ER/Cloud-Router resources
(NVA-based tunnels only) — the lanes run and degrade to zero honestly; live
transition validation needs either a managed seam in the lab (owner infra,
~$36/mo for an AWS S2S VPN+TGW drill setup, destroyable) or the GCP/Azure
gateway builds queued with parity tasks.
