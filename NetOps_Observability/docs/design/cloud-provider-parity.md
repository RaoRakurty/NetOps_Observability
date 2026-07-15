# Cloud Provider Parity Program (#105)

**Owner directive (2026-07-14):** every capability achieved and tested on one
provider must exist and be tested on ALL providers. GCP is built up to the
AWS/Azure level FIRST; then the remaining gaps (Azure VNet flow logs, the
log-fidelity families) close everywhere; the topic closes only when the matrix
below shows parity — **and every failure drill in the acceptance suite has
passed on every provider.**

## Parity matrix (source of truth — update with every landing)

Legend: ✅ live-validated · 🔧 built, awaiting live validation (owner-gated
infra/creds) · 🕳 not built · n/a provider has no equivalent (documented, not
skipped silently).

**2026-07-14 telemetry audit:** the full per-provider surface + ranked gaps now
live in `cloud-telemetry-catalog.md` (three web-verified audits). Its headline:
the **hybrid-seam gateway plane** (DX/ER/VPN-GW BGP state, TGW/Router drops,
NAT exhaustion) is drawn in our topology but not measured on ANY provider —
rows added below. Corrections from the audit are folded in.

| Capability | AWS | Azure | GCP |
|---|---|---|---|
| Inventory (live poller-written fixture, stable ids, power_state) | ✅ `discover.py` | ✅ `azure.write_inventory` | 🔧 `gcp.write_inventory` (instances only — seam devices queued) |
| Canonical metrics (cpu/net in/out) | ✅ CloudWatch | ✅ Azure Monitor | 🔧 Cloud Monitoring |
| Provider health verdict (status checks) | ✅ StatusCheckFailed (+System/Instance; `_AttachedEBS` queued) | ✅ VmAvailabilityMetric (inverted; `Context` dim queued) | 🕳 SYNTHESIZED: control-plane status + system_event `hostError` (uptime metric disqualified by Google; REPAIRING→degraded) |
| **Hybrid-seam gateway metrics (BGP state, tunnel state, drops, NAT exhaustion)** | 🔧 `seam_aws.py`: per-tunnel VPN `VgwTelemetry` + per-VIF DX BGP + DX link state (FREE describes) → transition signals; TGW blackhole/no-route drops (kept DISTINCT), NAT `ErrorPortAllocation`, DX errors (metered, `AWS_METERED_METRICS`-gated). Wired + unit-tested; live render needs seam infra in lab | 🔧 `azure.poll_seams`: ER `BgpAvailability`/`ArpAvailability` per `PeeringType` + VPN-GW `BgpPeerStatus` per peer (`$filter` dims — the keystone, done) + tunnel packet drops per connection. Wired + unit-tested; lab subscription has no ER/VPN-GW yet | 🔧 `gcp.poll_router_seams`: Cloud Router `getRouterStatus` per-peer BGP + `material_route_drop` on learned routes (FREE REST — strongest free seam source). Wired + unit-tested; blocked on GCP creds (owner). Interconnect optics queued |
| **Provider incident/maintenance events** | 🕳 `aws.health` via EventBridge — **FREE, prior "needs paid API" claim was WRONG** | 🕳 Service Health events API (free) | 🕳 Personalized Service Health (free — build) |
| Burstable credit visibility | ✅ CPUCreditBalance | n/a (B-series credits metric: queued check) | n/a (no burstable credit metric) |
| Resource health lane | 🕳 (= the Health events row above) | ✅ Resource Health | 🕳 system_event lane (S) |
| Change/audit lane | ✅ CloudTrail (paginated, filtered) | ✅ Activity Log | 🔧 Audit Logs (`poll_audit_log`) |
| Flow logs → REJECT faults | ✅ VPC flow logs (S3+CW lanes) | 🕳 **VNet flow logs** (queued next after GCP) | 🔧 **Firewall Rules Logging DENIED** rollup (`gcp.poll_log_lanes`, gate `GCP_FIREWALL_LOGS`) — GCP flow logs carry NO deny records (catalog KEY CORRECTION); the rule is named in-record, entity = the rule, same `cloud_flow_log`/REJECT kind |
| Flow logs → ACCEPT volume rollup | ✅ `vpc_accept_rollup` | 🕳 (with VNet flow logs) | 🔧 `vpc_flows` → per-instance `cloud_flow_volume` rollup (gate `GCP_VPC_FLOW_LOGS`) |
| LB access logs → LB-plane 5xx | 🔧 parser live-unvalidated (fidelity drill) | 🕳 App Gateway/Front Door access logs | 🔧 LB request-log 5xx rollup per (LB, status), `statusDetails` = LB-vs-target blame in-record (gate `GCP_LB_LOGS`) |
| LB target health | 🕳 blocked: no ALB in lab (owner infra) | 🕳 App Gateway backend health | 🕳 backend service health (`backendServices.getHealth`, no lab infra needed — next slice) |
| WAF blocks → `cloud_waf_log` | 🔧 parser+rollup built (fidelity drill) | 🕳 Azure WAF logs | 🔧 Cloud Armor DENY rollup per (policy, rule priority) — rides the SAME LB request-log fetch (gate `GCP_LB_LOGS`) |
| DNS failures → `cloud_dns_log` | 🔧 R53 Resolver parser built (fidelity drill) | 🕳 DNS Analytics / Resolver logs | 🔧 `dns_queries` error rollup per (name, rcode), entity = the queried NAME (gate `GCP_DNS_LOGS`) |
| Console deep-links | ✅ | ✅ | 🕳 `cloud_console.go` GCP formats |
| Provider mark (official icon) | ✅ | ✅ | 🕳 official GCP icon set (vendor + terms doc) |
| Ingestion matrix facet | ✅ | ✅ | 🔧 automatic once signals stamp `provider:gcp` (done in lanes) |
| IAM/credential contract committed | ✅ `iam-policy-aws.json` | ✅ CREDENTIALS.md roles | 🔧 CREDENTIALS.md roles (added) |
| Least-privilege posture | lab: ambient creds (interim) | SP, 2 reader roles | SA file, 3 viewer roles |

## Acceptance suite (every drill × every provider)

A provider is "at level" only when each drill below has been run against it
live, watched rendered (Service View + RCA), and its golden log lines are
captured as test fixtures:

1. **Host stop/start** — power_state truth (stopped ≠ broken), metrics stop,
   dashboards degrade honestly, recover on start. (AWS ✅ · Azure ✅ · GCP 🕳)
2. **Underlay blackhole / tunnel fault** — path evidence + seam blame.
   (AWS ✅ WU drill · Azure ✅ C5/W2 · GCP 🕳)
3. **Security-rule block** — flow REJECTs + change event correlate.
   (AWS ✅ drill-002 · Azure 🕳 · GCP 🕳)
4. **LB target kill** — LB-vs-target blame seam. (all 🕳 — needs fidelity infra)
5. **WAF rule misfire** — blocks spike + CloudTrail/audit change → RCA names
   the rule. (all 🕳)
6. **DNS breakage** — NXDOMAIN spike joins app symptom. (all 🕳)
7. **Provider console pivot** — every row's deep-link opens the right page.
   (AWS ✅ · Azure ✅ · GCP 🕳)

## Build order (agreed)

1. **GCP to AWS/Azure level** — inventory/metrics/audit lanes (built, this
   commit), then live validation (owner: project + SA key), console links,
   official icon, flow logs.
2. **Azure VNet flow logs** — storage-account reader → the same REJECT/volume
   rollups (NSG flow logs retire 2027-09; VNet flow logs only).
3. **Log-fidelity families everywhere** — LB / WAF / DNS per provider, each
   validated with real traffic once (Terraform apply → drill → capture goldens
   → destroy).
4. **Acceptance sweep** — the 7-drill suite per provider; parity declared only
   on a full-green matrix.

## Owner-gated inputs

- GCP: project id + service account key (roles/compute.viewer,
  roles/monitoring.viewer, roles/logging.viewer), lab VMs mirroring the
  AWS/Azure hosts (app + NVA shape) for drills.
- AWS: ALB/WAF/R53-resolver-logging Terraform apply windows (~$2–3/drill day).
- Azure: VNet flow-log enablement + storage account (pennies at lab volume).

## Standing honesty rules for this program

- A lane with no producer stays "Coming soon" in the matrix UI — never faked.
- A provider gap that is structural (no equivalent API) is recorded as n/a
  with the reason — parity means "same truth available", not "same rows".
- Per-record firehoses are forbidden: every high-volume log family lands as
  bounded rollups (the P1-6 discipline).
- Fixture files written by pollers are LIVE data; the demo/synthetic badge
  must reflect collection mode, not transport. ✅ DONE 2026-07-15: every
  inventory writer (discover.py / azure.py / gcp.py) stamps
  `collection: {mode: live_poller, collected_at}`; the API derives per-file
  connector provenance from the stamp (cloud/provider.go `Connectors`,
  default-closed — no stamp or unknown mode reads "fixture"), serves it on
  `GET /api/cloud/resources` (`connectors`, tenant-scoped), and the UI badge
  is measured (`deriveConnectorKind`): "Live telemetry" only when EVERY
  contributing inventory file is live-poller written.
- CloudTrail checkpoint burn (side-find, closed 2026-07-15): `trail_ts` now
  advances over everything SEEN (matched or excluded) via `trail_state.py`,
  with a 15-min delivery-lag guard on empty windows — quiet periods no longer
  re-read the 20-page ceiling every cycle.
- GCP log-fidelity lanes landed 2026-07-15 (parsers built, live validation
  owner-gated): `gcp_log_lanes.py` (pure bounded rollups, cardinality-capped
  at 100 keys/batch with an honest `rollup_truncated` stamp) +
  `gcp.poll_log_lanes` (per-lane opt-in gates, per-lane checkpoints +
  isolation) on a shared `gcp.list_log_entries` reader (the audit lane's
  overlap + insertId-dedup + advance-over-everything-seen discipline,
  bounded at 5 pages × 200 entries/lane/cycle; audit lane refactored onto
  it). NO new signal kinds — all five lanes reuse the provider-blind
  `cloud_flow_volume` / `cloud_flow_log` / `cloud_lb_log` / `cloud_waf_log` /
  `cloud_dns_log` contract, so correlation/UI need zero changes. Cadence
  `GCP_LOG_LANES_EVERY_S` (default 120s) keeps 4 lanes inside the 60 req/min
  entries:list project quota.
