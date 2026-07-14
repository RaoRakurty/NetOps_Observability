# Hybrid-Seam Telemetry — Final Report (#105, 2026-07-14/15)

The required final output of the hybrid-seam assignment (16-phase prompt).
Written after the P0+P1-core landing (`54955b4` + the route-drop closure
commit that follows it). Companion docs: `../cloud-telemetry-catalog.md`
(research), `../cloud-seam-telemetry-design.md` (design),
`../cloud-provider-parity.md` (matrix).

## 1. Executive verdict

**Before this work: NOT sufficient for hybrid-cloud RCA.** The topology drew
hybrid seams (DX, ER, Interconnect, VPN, transit) but measured none of them —
the platform could see a workload sicken and a tunnel exist, but never the
gateway plane between them. That was the unanimous #1 gap across all three
provider audits.

**What was implemented:** the full P0 foundation (canonical seam kinds,
observation-time semantics, freshness→unknown, transition dedup, restart-safe
state, tenant-explicit events) and the P1 core state lanes on all three
providers: AWS per-tunnel VPN + per-VIF DX BGP + TGW/NAT/DX drop counters;
Azure ER BGP/ARP per PeeringType + VPN-GW BGP per peer + tunnel drops; GCP
Cloud Router per-peer BGP + learned-route collapse. Route-count-collapse
evidence now exists on AWS (accepted routes per tunnel, gated on
tunnel-up) and GCP (learned routes per peer). 35 seam tests + 546-test
correlation suite green. Lanes are LIVE in the lab and degrade to honest
zeros (no managed seam resources exist there yet).

**Now sufficient?** The *evidence plane* is sufficient for the P1 scenarios
(hybrid BGP both-sides, route-loss-session-up, blackhole vs no-route, NAT
exhaustion, physical-before-BGP on DX). Scenario *wording* (signature
catalog), provider-health event lanes, and seam-topology binding remain (§12)
— cloud seam evidence reaches the engine as signals but is not yet narrated
by dedicated signatures.

## 2. Research corrections

Confirmed from the original research (web-verified 3-agent audit):
- Azure seam metrics are poll-only with `$filter` dimensions (BgpPeerStatus
  per BgpPeerAddress; ER per PeeringType) — diagnostic-settings export
  flattens them. `$filter` support was indeed the keystone.
- GCP `getRouterStatus` is free REST and the strongest free seam source.
- GCP flow logs have no accept/reject field → Firewall Rules Logging is the
  GCP REJECT lane.
- AWS Health events are deliverable free via EventBridge (prior "paid API
  only" claim was wrong).
- GCP has no StatusCheckFailed equivalent; verdict must be synthesized.

Required qualification:
- "Azure metric reads are unbilled" — true for the Metrics REST API reads we
  do; NOT true for Log Analytics-routed export. Recorded per-lane, not
  globally.
- "FREE seam lane" — describe/REST calls are free but rate-limited;
  CloudTrail LookupEvents is 2 TPS (and the current checkpoint logic re-reads
  20 pages/cycle when all events are filtered — defect, §12).

Found incorrect during takeover (claims by in-flight work, fixed):
- Design doc claimed `iam-policy-aws.json` carried the seam describes — the
  file did not; the lane worked only via broader ambient lab creds. Fixed:
  4 read-only actions added.
- The deployed Azure seam lane built its ARM `$filter` URL with raw spaces —
  urllib rejects those, and the escaping exception was killing the WHOLE
  Azure cycle including health/activity lanes. Fixed live (percent-encoding
  + per-lane failure domains).

## 3. Current-state architecture

```
provider API/log/event
  → cloud-ingest poller (compose svc; boto3 / stdlib-REST+SP / google-auth;
     .poller-state.json checkpoints; per-provider AND per-lane failure domains)
  → metrics  → Vector :8690 NDJSON → netops.metrics → VictoriaMetrics
    signals  → Kafka netops.cloud → correlation handle_cloud
  → cloud_producers.cloud_signal_from_event (CLOUD_KINDS contract; tenant
     explicit, default-closed dead-letter on unknown kind / missing entity)
  → netops.corr_signals (CH; ts=provider observation, ingest_ts separate;
     observer_id cloud:<acct>:<region>)
  → engine grounding → corr_current/objects → RCA verdict → Service View
```

Strengths: observation-vs-ingest time first-class in schema; tenancy
default-closed; bounded-rollup law enforced program-wide; provider-blind
canonical series; cost gates (`AWS_METERED_METRICS`/`GCP_METERED_METRICS`).

Defects found and fixed this program: GCP audit cursor lacked late-arrival
overlap/insertId dedup; substring excludes over-matched; ARM $filter URL bug
(above); IAM contract drift (above); flow-log sink unbounded growth (rolled).

## 4. Prioritized telemetry (implemented wave)

Provider-neutral ranking (state > drops > route > saturation > traffic):
1. Seam state transitions (BGP session, VPN tunnel, physical link) — the
   direct answer to "did it fail on the cloud side too".
2. Forwarding drops with DISTINCT causes (blackhole ≠ no-route ≠ port-alloc)
   — different faults, different owners.
3. Route-count collapse while session up — the "policy, not outage" class.
4. NAT allocation FAILURES (never utilization guesses).
5. Physical/link health (DX connection state; ER ArpAvailability as L2).

Per provider: AWS VgwTelemetry per tunnel / DX bgpPeers per VIF / TGW
blackhole+no-route / NAT ErrorPortAllocation; Azure ER BgpAvailability(L3)+
ArpAvailability(L2) per PeeringType / VPN-GW BgpPeerStatus per peer / tunnel
drop counters; GCP getRouterStatus per peer + numLearnedRoutes.

## 5. Files changed

| File | Purpose |
|---|---|
| `cloud-ingest/seam_state.py` | Pure core: SeamStateTracker (dedup/flap/freshness/persistence), counter_delta, material_route_drop |
| `cloud-ingest/seam_aws.py` | AWS lane: free describes → transitions + route-drop; metered CW drop/error counters |
| `cloud-ingest/azure.py` | +poll_seams (ER/VPN-GW via $filter dims) + URL-encoding fix |
| `cloud-ingest/gcp.py` | +list_routers/poll_router_seams (BGP + route collapse) |
| `cloud-ingest/poller.py` | Seam wiring: CLOUD_SEAM_TELEMETRY, SEAM_EVERY_S, per-lane isolation |
| `cloud-ingest/Dockerfile` | ships seam modules |
| `cloud-ingest/iam-policy-aws.json` | +4 read-only seam describes |
| `src/correlation/cloud_producers.py` | 13 seam kinds registered (modality/entity contract) |
| `cloud-ingest/test_seam_state.py` / `test_seams.py` / `src/correlation/test_seam_kinds.py` | 35 unit/regression/contract tests |
| docs: design doc, catalog, parity matrix, TRACKER | durable record |

## 6. Schema and migrations

**None required.** Seam signals ride the existing `corr_signals` schema
(ts/ingest_ts already distinct; attrs carry evidence_class + native ids);
kinds are a code-level contract (CLOUD_KINDS). No CH/PG migration, nothing to
roll back; disabling the lane (`CLOUD_SEAM_TELEMETRY=off`) is the rollback.

## 7. Configuration

| Flag | Default | Cost implication |
|---|---|---|
| `CLOUD_SEAM_TELEMETRY` | on | free/unbilled state reads only |
| `SEAM_EVERY_S` | 120 | describe/REST call volume (free tier) |
| `AWS_METERED_METRICS` (existing) | on | gates TGW/NAT/DX GetMetricData ($0.01/1k values) |
| `GCP_METERED_METRICS` (existing) | on | gates Monitoring reads ($0.50/M series past free) |

Azure seam reads are Metrics-REST (unbilled). Existing env vars preserved;
no defaults changed.

## 8. Security

- IAM: read-only, enumerated actions (no wildcards): `ec2:DescribeVpnConnections`,
  `ec2:DescribeTransitGateways`, `directconnect:DescribeConnections`,
  `directconnect:DescribeVirtualInterfaces` added to the committed contract.
  Azure: existing Reader-scoped SP suffices (resource list + metrics read).
  GCP: existing compute.viewer covers getRouterStatus.
- Tenant: stamped explicitly on every event by the poller; correlation
  default-closed (dead-letter without tenant). No cross-tenant cache or
  dedup keys — all tracker keys are per-poller-instance, single-tenant lab
  today; multi-account/tenant fan-out is backlog (§12).
- No secrets in signals; status messages are provider prose.

## 9. Tests

Commands: `python3 -m pytest test_seam_state.py test_seams.py -q` (cloud-ingest),
`python3 -m pytest -q` (correlation).
Results: **35 seam tests + 546 correlation tests, all green.**
Covered: transition dedup, first-sight silence, flap, freshness→unknown,
persistence round-trip, garbage state tolerance, counter resets,
route-materiality context, per-tunnel key separation (fractional-aggregate
trap), blackhole-vs-noroute distinctness, absence≠zero, kind contract
(modality/entity/observed_at-wins/native-id retention), route-collapse-
while-up vs down-tunnel silence.
Gaps: the 20 golden END-TO-END scenario tests (through engine → narrative)
are NOT built — the largest test debt (§12). No live-transition fixture yet
(no seam infra in lab).

## 10. Cost and scale

State lanes: API calls = 4 describes (AWS) + ~2+N REST (Azure) + 1+R REST
(GCP) per cycle; at 120s ≈ 2.9k calls/day/provider — free/unbilled.
Series cardinality = #tunnels + #peers + #VIFs + #circuits (tens; keys are
seam objects, never flows/prefixes). Metered adds ≈ 5 metrics × resources /
5 min: small (≤10 seams) ≈ pennies/month; medium (100) ≈ $2–4/mo; large
(1000 seams) ≈ $30–40/mo CloudWatch — linear, gated. Correlix storage: seam
signals are transition-rate (near-zero steady-state); metric points ≈
resources × 5 series × 288/day → trivial for VictoriaMetrics at any tier.
High-cardinality evidence (flow logs) stays in CH/OS by law.

## 11. Provider limitations

- AWS: optics (`ConnectionLightLevelTx/Rx`) exist on DEDICATED DX only —
  hosted connections recorded as `hosted`, absence explained not faked.
  VgwTelemetry state cadence is provider-controlled; sub-minute flaps can be
  missed between describes. CloudTrail LookupEvents 2 TPS.
- Azure: seam metrics are poll-only (no export path); PT5M granularity on ER
  availability; maintenance can dip BgpAvailability without a customer-edge
  fault — treated as degraded, needs Service Health corroboration (P2 lane).
- GCP: no provider verdict metric (synthesized); getRouterStatus is point-in-
  time (no history); BFD/optics/Interconnect state not yet implemented here.
- All: provider observation lag means seam evidence trails on-prem traps by
  up to one poll + publication delay — correlation windows must (and do)
  compare `observed_at`, never arrival.

## 12. Remaining work (prioritized, honest)

1. **Seam-topology binding** — attach seam signals to the seam store /
   entity-token graph so evidence lands on the DRAWN seam (today: native ids
   in attrs, engine joins by tokens only). No `topology_unmapped` flag yet.
2. **Signature-catalog wording** for the 8 scenario pairs (hybrid-BGP
   both-sides, physical-before-BGP, route-loss-session-up, blackhole+reject,
   selector-mismatch, NAT exhaustion, provider-incident overlay,
   telemetry-disagreement→undetermined) + golden end-to-end tests (20).
3. **Provider/resource-health event lanes** (AWS Health via EventBridge,
   Azure Service Health, GCP PSH) — the maintenance-ambiguity discriminator.
4. **Azure route counts + gateway saturation, GCP Cloud NAT + BFD +
   Interconnect, DX prefix metrics + optics** — needs a per-metric
   research pass (names/dims verified against current official docs) before
   code; do NOT hand-roll unverified metric names.
5. Missing kinds intentionally unregistered until an emitter exists:
   bfd pair, route churn/quota family, optical_degradation, ttl_drop,
   selector_mismatch, saturation.
6. CloudTrail checkpoint burn (20-page re-read when all filtered) — cheap fix.
7. Quality-flag vocabulary (fresh/delayed/stale/partial/…) — freshness is
   enforced (unknown transitions) but flags aren't stamped on every signal.
8. Multi-account/multi-project fan-out + per-tenant credentials.

**Blockers (owner):** lab has NO managed seam resources — live transition
validation needs an AWS S2S VPN+TGW drill build (~$36/mo, destroyable) or
Azure VPN-GW/ER, and GCP needs project+SA key (CREDENTIALS.md).

## 13. RCA narratives now enabled (evidence-plane level)

1. **Hybrid BGP failure:** on-prem CE syslog BGP-5-ADJCHANGE down +
   `cloud_bgp_session_down` (dxbgp:dxvif-7:p1, observed 21:58Z) within the
   window → two independent observers, seam failure CONFIRMED; owner: circuit.
2. **Routes gone, session up:** `cloud_route_count_drop` (accepted 4→0,
   tunnel_state=up) with NO tunnel/BGP transition → "advertisement/policy
   change on the customer side of vpn-0abc; the tunnel is healthy" — never
   reported as an outage.
3. **Blackhole vs missing route:** `cloud_gateway_blackhole_drop` on tgw-1 →
   "an explicit blackhole route is discarding traffic (someone configured
   this)"; `cloud_gateway_no_route_drop` → "propagation/route-table gap" —
   different verdicts, different owners, never merged.
4. **NAT exhaustion:** `cloud_nat_port_exhaustion` (ErrorPortAllocation>0)
   + app connect-failure symptoms → allocation FAILURE evidence, not an 80%
   guess; remediation: scale NAT/split subnets.
5. **One redundant tunnel down:** vpn:…:52.0.0.2 down while :52.0.0.1 stays
   up → per-tunnel keys mean the narrative is "redundancy lost, service
   intact" — the fractional-aggregate trap that reports "VPN 50% down" is
   structurally impossible.
6. **Stale ≠ up:** provider stops publishing → `cloud_state_unknown` after
   3 cycles → "cloud-side visibility lost at HH:MM (last confirmed up at
   HH:MM)" — evidence gap surfaced, never an eternal green.
