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

| Capability | AWS | Azure | GCP |
|---|---|---|---|
| Inventory (live poller-written fixture, stable ids, power_state) | ✅ `discover.py` | ✅ `azure.write_inventory` | 🔧 `gcp.write_inventory` |
| Canonical metrics (cpu/net in/out) | ✅ CloudWatch | ✅ Azure Monitor | 🔧 Cloud Monitoring |
| Provider health verdict (status checks) | ✅ StatusCheckFailed (+System/Instance split) | ✅ VmAvailabilityMetric (inverted) | n/a — no equivalent platform metric; uptime-liveness refinement queued |
| Burstable credit visibility | ✅ CPUCreditBalance | n/a (B-series credits metric: queued check) | n/a (no burstable credit metric) |
| Resource health lane | n/a (needs paid Health API) | ✅ Resource Health | 🕳 (Personalized Service Health — evaluate) |
| Change/audit lane | ✅ CloudTrail (paginated, filtered) | ✅ Activity Log | 🔧 Audit Logs (`poll_audit_log`) |
| Flow logs → REJECT faults | ✅ VPC flow logs (S3+CW lanes) | 🕳 **VNet flow logs** (queued next after GCP) | 🕳 VPC Flow Logs (via Logging sink) |
| Flow logs → ACCEPT volume rollup | ✅ `vpc_accept_rollup` | 🕳 (with VNet flow logs) | 🕳 |
| LB access logs → LB-plane 5xx | 🔧 parser live-unvalidated (fidelity drill) | 🕳 App Gateway/Front Door access logs | 🕳 Cloud Load Balancing logs |
| LB target health | 🕳 blocked: no ALB in lab (owner infra) | 🕳 App Gateway backend health | 🕳 backend service health |
| WAF blocks → `cloud_waf_log` | 🔧 parser+rollup built (fidelity drill) | 🕳 Azure WAF logs | 🕳 Cloud Armor logs |
| DNS failures → `cloud_dns_log` | 🔧 R53 Resolver parser built (fidelity drill) | 🕳 DNS Analytics / Resolver logs | 🕳 Cloud DNS logging |
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
  must reflect collection mode, not transport (task: stamp + surface).
