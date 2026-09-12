# Cloud Fidelity Evidence Book

The **acceptance artifact** for the Cloud Demo Traffic Program
(`docs/design/cloud-demo-traffic-program.md`). Acceptance =
**a light-mode, zoomed screenshot of every significant log of every component,
for every provider**, each traced to a real fault injection on real infra.

> **Honesty (program §7):** every image here comes from a real injection on real
> infrastructure during the capture window. A blocked/absent lane is recorded as
> a **gap** (in that scenario's `01-inject.md`) with the reason — never faked,
> never a synthetic log line.

## How this book is produced

1. Bring the edge estate up (owner-gated `terraform apply`, campaign window,
   ~$10 budget, reaper-enforced — see design doc §5).
2. Start the end-to-end traffic generator on the lab client behind a leaf
   (`scripts/lab/cloud-edge-traffic/`) — 1–5 req/s to each cloud's public app,
   traversing the real fabric. Baseline logs flow for every component.
3. Run the fault campaign per **`RUNBOOK.md`** (order `3→2→4→1→5→6`, one at a
   time, ≥20 min soak, revert-verified).
4. Capture with the light-mode/high-DPI harness
   (`scripts/lab/evidence-capture/`) as each scenario lands.

## Directory layout

```
<provider>/<scenario>/
  01-inject.md            what changed, exact command, timestamp   (template ready)
  02-provider-log.png     the component's own log (provider console / CLI excerpt)
  03-correlix-signal.png  the signal in Correlix (Service View cloud lane / log)  [harness]
  04-correlix-rca.png     the RCA / incident view naming the component            [harness]
  05-recovery.png         honest recovery after revert                            [harness]
```

Providers: `aws` `azure` `gcp`. Scenarios (dir names):

| Dir | Scenario (§3) | Primary Correlix lane (§2) |
|-----|---------------|-----------------------------|
| `3-lb-target` | LB target kill (`/boom`) | `cloud_lb_log` 5xx + target health |
| `2-waf` | WAF misfire (block legit) | `cloud_waf_log` BLOCK + `cloud_change` |
| `4-firewall` | Firewall deny :80 | `cloud_flow_log` REJECT + `cloud_change` |
| `1-dns` | **DNS fault family** — Route 53 / Azure DNS / Cloud DNS, 5 case types (NXDOMAIN burst, deletion/blackhole, misdirection, failover, TTL) | `cloud_dns_log` + paired `cloud_change` |
| `5-host-stop` | App VM stopped | `cloud_metric`/status power_state |
| `6-tunnel` | Underlay/tunnel fault | seam (BGP/tunnel) + path |
| `7-console-pivot` | Deep-link to console | (no inject) console landing |

## Screenshot standard (owner acceptance)

- **Light mode** (`netops.theme=light`) — the customer-facing canvas.
- **Zoomed / high-DPI** — `deviceScaleFactor=2`, 1600×900 logical viewport, with
  element-scoped shots of the specific log panel so text is large and legible.
- Timestamps visible; one caption line per shot (scenario, provider, component,
  what to notice) so any single image is drop-in for a customer deck.

The harness (`scripts/lab/evidence-capture/`) forces + asserts light mode and
2× DPI, so `03/04/05` are captured with `./capture-scenario.sh <prov> <dir>`.
`02-provider-log.png` is the provider's own console/CLI view (owner-assisted).

## Progress matrix

Mark `✅` when the light-mode zoomed shot is captured, `—` pending, `GAP` with a
reason (e.g. GCP `6-tunnel` = NVA not applied).

| Provider \ Scenario | 3-lb | 2-waf | 4-fw | 1-dns | 5-host | 6-tun | 7-console |
|---|---|---|---|---|---|---|---|
| AWS   | — | — | — | — | — | — | — |
| Azure | — | — | — | — | — | — | — |
| GCP   | — | — | — | — | — | GAP¹ | — |

¹ GCP NVA (Plane B) is IaC-ready but not applied (owner-gated); `6-tunnel` for
GCP stays a gap until it is.
