# Cloud Demo Traffic Program — full component chain, fault campaign, demo evidence book

**Owner directive (2026-07-15):** enable ALL traffic-path components (WAF, LB,
firewall layer, DNS) on ALL three providers, route real app traffic through
them end-to-end (end user → leaf → edge → cloud entry → app), inject every
component-level fault class, and capture demo-grade documentation — a
screenshot of every component's logs, from every provider, rendered in
Correlix. **Acceptance = the complete evidence book, nothing less.**

Extends #105 (parity program). The log parsers/lanes for every family below
are ALREADY BUILT and live-wired (see `cloud-provider-parity.md`); this
program builds the *emitting infrastructure + traffic + faults + evidence*.

Readiness (2026-07-15): traffic generator, capture harness, executable runbook
and the evidence-book skeleton are BUILT and validated with instances down —
see `docs/demos/cloud-fidelity-evidence/` and `scripts/lab/cloud-edge-traffic/`
+ `scripts/lab/evidence-capture/`. What remains is the owner-gated live window
(apply → run campaign → capture).

---

## 1. Traffic-flow design (per provider, two planes)

### Plane A — public app plane (END USER path; to build)
```
end user (lab client VM behind leaf1/leaf2, clos fabric)
  → lab edge (.122) → Internet egress
  → provider DNS (logged)               [cloud_dns_log]
  → WAF (logged)                        [cloud_waf_log]
  → L7 load balancer (access-logged)    [cloud_lb_log]
  → cloud firewall layer (logged)       [cloud_flow_log REJECT / accept volume]
  → app VM (edge app host)              [metrics, power_state, app-experience]
```

- **AWS**: Route 53 (public hosted zone, opt-in) → AWS WAF (WebACL on ALB) → ALB
  (access logs → S3 `correlix-edge-alb-logs-…/alb/`) → SG + VPC flow logs →
  `correlix-edge-app-host-01` (10.63.10.10) backend. Module: `aws-alb-waf`.
- **Azure**: DNS zone (opt-in) → **Azure Front Door STANDARD** (WAF + L7; access
  + WAF + health-probe logs → diagnostic settings → storage
  `correlixedgelogs1`) → NSG + **VNet flow logs** → `correlix-edge-app-host-01`
  (10.63.10.10) origin. Module: `azure-frontdoor-waf`. Front Door Standard
  (~$35/mo) replaces the heavy App Gateway WAF_v2 (~$277/mo) — it fits the $10
  campaign budget and still gives WAF (custom rules) + L7 + access logs. Managed
  OWASP rulesets need Premium, so the WAF-misfire scenario uses a custom rule.
- **GCP**: Cloud DNS (public zone, query logging ON — opt-in) → Global external
  Application LB + **Cloud Armor STANDARD** policy (blocks ride the LB request
  logs — one log family, two lanes) → firewall rules logging (incl. a logged
  deny-all) → `correlix-edge-app-host-01` (10.63.10.10) backend (instance group
  of 1). Module: `gcp-lb-armor`.

App payload: a lightweight stdlib HTTP app baked into each backend by cloud-init
(`correlix-faultlab-iac/cloud-init/edge-app.yaml`, GCP shell equivalent),
serving `/` (200; 500 while `/boom` armed), `/health` (always 200 — keeps the LB
target green), `/boom` (arms the persistent 500 — LB target-error surface) and
`/heal` (clears it).

### End-to-end traffic generation (the END-USER hop; BUILT)

The end-user hop is a dedicated, dependency-free HTTP generator —
`scripts/lab/cloud-edge-traffic/` (`cloud_edge_traffic.py`, Python stdlib
`http.client`). It is **not** `tgen` (which synthesises RFC flow records and
crafts raw frames toward the lab collector, and is not an HTTP client). It runs
as a **systemd service on a lab client VM behind a clos leaf**, so every request
traverses the real path — client → leaf → spine → edge (.122) → Internet →
provider DNS → WAF → LB → firewall → app — lighting up EVERY component's log
lane honestly, per provider.

- **Rate:** 1–5 req/s per provider, **hard-clamped to ≤ 5 req/s** in code
  (bounded-rollup law, §7). ~25% of requests hit `/health`, the rest `/`.
- **Endpoints:** read from a config file the owner fills post-apply from
  `terraform output` (`aws_alb_dns_name` / `azure_frontdoor_hostname` /
  `gcp_lb_ip`, or the `*_app_fqdn` when public DNS is on) — never hardcoded.
- **/boom toggle:** `… boom <prov>` / `… heal <prov>` arm/clear the LB
  target-error scenario (D&lt;p&gt;3) out of band from the steady stream.
- **Free path evidence:** the client → edge portion is already observed by the
  lab's flow pipeline (goflow2 → Flows / Service View path lane) and the
  prober/client vantage (STAMP + traceroute), so the fabric hops render without
  extra wiring. The generator's own per-provider summary (2xx/4xx/5xx/fail) is a
  client-side corroboration of each fault.
- Deploy: `CLIENT_HOST=<lab-client-behind-leaf> ./deploy.sh` (see the dir's
  README — `CLIENT_HOST` must egress via the leaf, or the path is dishonest).

Traffic source lineage: this replaces the earlier "tgen gains an HTTP profile"
idea — a separate stdlib client is cleaner, installs anywhere, and makes genuine
sockets rather than synthetic records.

### Plane B — private/hybrid plane (EXISTS today)
```
lab client → leaf → edge → IPsec NVA (AWS/Azure; GCP NVA = IaC ready, not applied)
  → private app/data subnets
```
Already instrumented: seam telemetry (BGP/tunnel), flow logs, firewall logs,
probes, app-experience. The campaign reuses it for the underlay/tunnel fault
class; no new build except the GCP NVA (owner-gated apply, IaC exists).

## 2. Log family → Correlix lane map (all lanes BUILT, per #105)

| Component | AWS source | Azure source | GCP source | Correlix kind |
|---|---|---|---|---|
| DNS | R53 resolver logs (LIVE) + public-zone query logs | DNS zone `QueryAnswerLog` (reader built) | Cloud DNS `dns_queries` (LIVE) | `cloud_dns_log` |
| WAF | WAF logs → S3 (parser built) | Front Door `FrontDoorWebApplicationFirewallLog` (reader built) | Cloud Armor in LB logs (parser built) | `cloud_waf_log` |
| LB | ALB access logs (parser built) | Front Door `FrontDoorAccessLog` (reader built) | LB `requests` logs (parser built) | `cloud_lb_log` |
| Firewall | VPC flow logs (LIVE) | VNet flow logs (LIVE) | Firewall rules logging (LIVE, bus-verified) | `cloud_flow_log`/`cloud_flow_volume` |
| Change/audit | CloudTrail (LIVE) | Activity Log (LIVE) | Audit Logs (LIVE) | `cloud_change` |
| Host | CW metrics+status (LIVE) | Azure Monitor (LIVE) | Cloud Monitoring (LIVE) | `cloud_metric`/status |
| Seam | VPN/DX telemetry (LIVE) | ER/VPN-GW (LIVE, no infra) | Router BGP (LIVE, needs NVA) | seam kinds |

> Azure note: Front Door also emits `FrontDoorHealthProbeLog` (target-health
> evidence for the LB-target-kill scenario). All three FD categories are enabled
> in the `azure-frontdoor-waf` module's diagnostic setting.

## 3. Fault campaign — test cases (each = inject → observe → screenshot → revert)

Per provider, seven scenario families (IDs `D<provider><n>`; every scenario
also asserts the paired `cloud_change` audit event correlates). **Exact,
copy-pasteable inject/revert commands per provider live in
`docs/demos/cloud-fidelity-evidence/RUNBOOK.md`.**

| # | Scenario | Injection (revertible) | Expected Correlix evidence |
|---|---|---|---|
| 1 | DNS fault **family** (Route 53 / Azure DNS / Cloud DNS) — NXDOMAIN burst, record deletion/blackhole, misdirection, failover flip, TTL (see RUNBOOK) | `cloud_dns_log` NXDOMAIN/wrong-answer spike joins app symptom; RCA names the record; paired `cloud_change` correlates |
| 2 | WAF misfire | add a block rule matching legit demo traffic | `cloud_waf_log` BLOCK spike per (ACL,rule); change event names the rule; app-experience drop |
| 3 | LB target kill | arm `/boom` (500 on `/`) — host stays up | `cloud_lb_log` 5xx + target-health degradation; LB-vs-target blame split |
| 4 | Firewall block | insert deny rule for app port (SG/NSG/GCP rule) | `cloud_flow_log` REJECT rollup naming the rule + change event |
| 5 | Host stop | stop the app VM | power_state truth (stopped ≠ broken), metrics cease, honest degrade |
| 6 | Tunnel/underlay fault | existing WU-drill blackhole on the NVA path | seam blame + path evidence (existing validated family) |
| 7 | Console pivot | none — every evidence row deep-links | operator lands on the exact provider console page |

Ordering per provider: 3 → 2 → 4 → 1 → 5 → 6 (least- to most-disruptive), one
fault at a time, ≥20 min soak between, revert verified before the next.

## 4. Evidence book (the acceptance artifact)

Location: `docs/demos/cloud-fidelity-evidence/` — `index.md` + `RUNBOOK.md` +
`<provider>/<scenario>/` (skeleton BUILT: 21 dirs, each with a ready
`01-inject.md` template) each containing:

1. `01-inject.md` — what was changed, exact command/console step, timestamp.
2. `02-provider-log.png` — the component's own log (provider console view) —
   owner-assisted capture (needs your console session) OR CLI log excerpt
   rendered to a styled page when a console screenshot isn't practical.
3. `03-correlix-signal.png` — the signal in Correlix (Service View cloud lane /
   log evidence) — **automated headless capture** via the Playwright harness
   (`scripts/lab/evidence-capture/`, against :8000).
4. `04-correlix-rca.png` — the RCA object/incident view naming the component.
5. `05-recovery.png` — honest recovery after revert.

Style (owner acceptance standard, 2026-07-15): **LIGHT MODE + ZOOMED** — the
harness forces `netops.theme=light` and asserts it, and shoots at
`deviceScaleFactor=2` (high-DPI) with a 1600×900 logical viewport, plus
element-scoped shots of the specific log panel so text is large and legible.
Timestamps visible; one caption line per shot (scenario, provider, component,
what to notice) — so any single image is drop-in usable in a customer demo deck.
Run per scenario: `./capture-scenario.sh <provider> <scenario> all` (fault peak)
then `… recovery` (post-revert). Harness validated against the live local stack
(light asserted, 2× DPI, Service View cloud lane + Log Search routes).

## 5. Cost + teardown (owner approval gates the applies)

**Decision (2026-07-15): campaign-window, ~$10 budget, reaper-enforced.** Bring
the full chain up in a bounded window, run the campaign + capture, then
`terraform destroy`. The estate is existence-billed, so the OFF switch is
`destroy`; `scripts/edge-demo-ttl.sh` enforces a **$10 hard budget** at a
conservative **$0.16/hr** → ~60h of runtime, and a cron `reap` razes the env on
lease-expiry/budget. LOCAL Terraform state (no backend block) so the reaper's
`has_state()` check works and the env is always safe to raze. Front Door
STANDARD (not App Gateway WAF_v2) keeps Azure inside this budget.

### Cost table (VERIFIED 2026-07-15, from the IaC budget guards)

| Provider | Chain (edge-demo module) | Standing est. | While-up est. |
|---|---|---|---|
| AWS | ALB + WAF (1 managed group) + VPC flow logs→S3 + Route 53 | ~$28.0/mo | ~$0.038/hr |
| Azure | **Front Door STANDARD** + VNet flow logs + Azure DNS | ~$39.0/mo | ~$0.053/hr |
| GCP | global ext ALB + Cloud Armor STANDARD + fw-logs + Cloud DNS | ~$28.8/mo | ~$0.039/hr |
| **All three** | | **~$95.8/mo** | **~$0.13/hr** |

- **Campaign window (chosen):** at ~$0.13/hr all-three, the **$10 reaper budget
  ≈ 60–75h** of runtime — enough to run the full 7×3 campaign + capture and
  destroy. Reaper rate is padded to $0.16/hr for safety.
- **Standing estate (not chosen):** ~$95.8/mo to keep the chain up permanently;
  rejected for cost. (Front Door Standard already removed the old ~$180/mo Azure
  AppGW blocker, but the campaign-window model is still preferred.)
- Everything is IaC'd in `correlix-faultlab-iac/environments/edge-demo` with
  per-cloud toggles (`enable_aws`/`enable_azure`/`enable_gcp`) and modules
  `aws-alb-waf`, `azure-frontdoor-waf`, `gcp-lb-armor`, plus opt-in public-DNS
  modules (`aws-public-dns`, `azure-public-dns`, `gcp-public-dns`) — so the whole
  chain is one `apply`/`destroy`. Azure apply is owner-gated (interactive
  `az login`).

## 6. Build order

1. Owner decisions: ✅ campaign-window + $10 budget agreed; remaining = the apply
   window + `az login` for Azure.
2. IaC modules for the public chain (3 providers) + log enablement — **built**
   (`aws-alb-waf`, `azure-frontdoor-waf`, `gcp-lb-armor`, `*-public-dns`).
3. App payload + end-to-end HTTP generator + capture harness + runbook +
   evidence skeleton — **built & validated with instances down** (this program).
4. Live window (owner-gated): apply → start generator → baseline screenshots →
   fault campaign per §3 (GCP → AWS → Azure), evidence book capture as each
   scenario lands.
5. Teardown (`destroy`) + final `index.md` matrix + parity-matrix flips to ✅ for
   every live-validated family.

## 7. Honesty rules (inherited, binding)

- No fabricated log lines, ever — a screenshot only enters the book from a
  real injection on real infrastructure. The capture harness makes capture
  repeatable; it renders only what the live stack really shows.
- Blocked/absent evidence is recorded as a gap with the reason, not papered
  over (e.g. GCP `6-tunnel` = NVA not applied).
- Bounded rollups stay the law; the campaign must not turn lanes into
  firehoses (traffic held at demo rates — the generator hard-clamps ≤ 5 req/s).
