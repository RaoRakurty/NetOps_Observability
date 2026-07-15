# cloud-edge-traffic — end-to-end demo traffic to all three clouds

The **END-USER hop** for the Cloud Demo Traffic Program
(`docs/design/cloud-demo-traffic-program.md`). A tiny, dependency-free (Python
stdlib `http.client`) HTTP client that runs on a lab client behind a clos leaf
and issues a steady **1–5 req/s per provider** at each cloud's public app
endpoint, so every component in the chain logs real traffic — honestly.

It is **not** `tgen`. `tgen` (sibling dir `traffic-generator/`) synthesises RFC
flow records (IPFIX/NetFlow/sFlow) and crafts raw frames toward the lab
collector; it is not an HTTP client and never opens a socket to a public cloud
endpoint. This tool is the complementary piece the program needs: a genuine
end-user browser-shaped request stream.

## Why the client host matters (the whole point)

The value is the **path**, not just the destination. Requests must egress the
lab the way a real user's would:

```
this lab client (behind leaf1/leaf2)
  → leaf → spine → lab edge (.122) → Internet egress
  → provider public DNS        → cloud_dns_log
  → WAF / Cloud Armor          → cloud_waf_log
  → L7 load balancer (ALB/FD/GLB) → cloud_lb_log
  → cloud firewall layer (SG/NSG/fw-rules) → cloud_flow_log
  → app VM  (/ , /health , /boom)          → cloud_metric / app-experience
```

So `CLIENT_HOST` (see `deploy.sh`) **must be a host whose default route goes
through the leaf → spine → edge (.122)**. On that host every hop above appears
in its own log lane, per provider — which is exactly the evidence the demo
captures. A host that reached the clouds by some other NIC would still light up
the cloud-side logs but would **skip the fabric hops**, which is a dishonest
path and defeats the "end user → leaf → … → app" claim.

### Path evidence you get for free

The client-side portion of the path (client → leaf → spine → edge) is already
observed by the lab's existing **client vantage / prober** and flow pipeline —
you do **not** build it here:

- **Flow logs** on the fabric (goflow2 → `netops.flows` → ClickHouse) record the
  client → edge → Internet 5-tuples for each provider's public IP as this
  stream runs — visible in **Flows** and the **Service View** path lane.
- The **prober / client vantage** (STAMP + traceroute collectors, when the
  `prober` compose profile is on) captures the client→endpoint path and
  round-trip, so the "client → leaf → … → cloud" hops render without any extra
  wiring. See `docs/design/wan-path-metrics-program` and the path-trace notes.

The cloud-side hops (DNS/WAF/LB/firewall/app) render via the already-built
`cloud_*` lanes (parity program #105); this generator's only job is to *cause*
them.

## Endpoints (parameterized — filled after apply)

Endpoints are known only **after** `terraform apply` and are read from a config
file, never hardcoded:

```bash
cp endpoints.conf.example endpoints.conf     # endpoints.conf is gitignored
$EDITOR endpoints.conf                        # paste terraform outputs
```

Get each value from `correlix-faultlab-iac/environments/edge-demo`:

| Provider | DNS off (default)                          | DNS on (`enable_public_dns=true`) |
|----------|--------------------------------------------|-----------------------------------|
| AWS      | `terraform output -raw aws_alb_dns_name`   | `... aws_app_fqdn`                |
| Azure    | `terraform output -raw azure_frontdoor_hostname` | `... azure_app_fqdn`        |
| GCP      | `terraform output -raw gcp_lb_ip`          | `... gcp_app_fqdn`               |

All edge planes serve **plain HTTP on :80** (demo, no cert). A lane left as
`FILL_ME` / blank is skipped, so a one-cloud demo needs only one line.

## Run / start / stop

Deployed as a **systemd service** (continuous low-rate stream) on the lab client:

```bash
# on your workstation, from this dir, after filling endpoints.conf:
CLIENT_HOST=<lab-client-behind-leaf> ./deploy.sh     # push + enable + start
CLIENT_HOST=<...> ./deploy.sh --status               # service state + logs
CLIENT_HOST=<...> ./deploy.sh --stop                 # disable + stop
```

Or run directly on the client for a foreground test:

```bash
python3 cloud_edge_traffic.py --config endpoints.conf run   # Ctrl-C to stop
```

Logs are structured; every 30 s each lane emits a summary:

```
summary provider=aws window=30s total=61 rate=2.03/s 2xx=61 5xx=0 4xx=0 fail=0
```

During a fault scenario the same line makes the injection visible from the
client side too (5xx climbs for LB-target-kill, 4xx for a WAF block, fail for a
firewall/DNS break) — a free client-vantage corroboration of the Correlix
signal.

## Rate control (bounded-rollups law)

`*_RATE` in the config is requests/second/provider. The generator **hard-clamps
every lane to ≤ 5 req/s** (`RATE_MAX_HARD`) regardless of config — the program's
bounded-rollup law (§7). Config can only ask for *less*. Default is 2 req/s;
~25 % of requests go to `/health`, the rest to `/`.

## /boom — the LB target-error scenario (D&lt;p&gt;3)

The app serves `/boom` (arm a persistent 500 on `/`) and `/heal` (clear it), so
the **host stays up** while the **LB sees target 5xx** — the "LB vs target"
blame split. Toggle it from this tool (one-shot, out of band from the stream):

```bash
python3 cloud_edge_traffic.py --config endpoints.conf boom aws   # arm 500
#   ... soak, capture the cloud_lb_log 5xx + target-health signal ...
python3 cloud_edge_traffic.py --config endpoints.conf heal aws   # revert
```

While boom is armed the steady stream keeps hitting `/` and its summary shows
`5xx` climbing, so the fault is corroborated end-to-end.

## Notes

- **No secrets** anywhere: the config holds only public FQDNs/IPs. SSH creds for
  `deploy.sh` come from env (`CLIENT_PASS`), defaulting to the lab default only.
- **Least privilege**: outbound TCP:80 only; the systemd unit runs `DynamicUser`,
  `NoNewPrivileges`, `ProtectSystem=strict` — no raw sockets, no caps.
- Pure stdlib → installs on any lab client with `python3`, no `pip install`.
- Smoke-tested locally (clamp, lane-skip, real sockets, boom/heal, empty-config
  guard) against the running stack before shipping.
