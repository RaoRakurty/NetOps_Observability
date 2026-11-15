# Every monitored device went silent

Fires as `MonitoredSourcesSilent` (page tier) and fails `deploy-qualify`
check **Q11 monitored sources reporting**.

## What it means

The inventory holds monitored devices, the collectors were reaching them
earlier this week, and now **none** can be polled and **no** syslog or SNMP
trap has arrived from any of them for 30 minutes. The pipeline is not the
suspect: every other liveness check (consumers, lag, Vector sinks) can be
green while this fires, because there is simply nothing arriving to move.

When every lane stops at the same moment, the cause is almost always the
**path between this server and the devices**: a gateway, a route, a VPN or
SD-WAN tunnel the management traffic rides, or a firewall change.

Seen on the lab on 2026-11-14: the lab gateway went down, every lane stopped
at 06:17 UTC, and the platform stayed "healthy" for a day.

## First response

1. **Can this server reach a device?** From the Correlix host:
   `ping <device management address>` and `ip route get <address>`. A
   `Destination Host Unreachable` from your own next hop means the gateway
   itself is gone, not the device.
2. **Is the gateway up?** Check the next hop `ip route get` printed. If it
   does not answer ARP (`ip neigh show <gateway>` reads `FAILED`), the box or
   VM behind it is down or disconnected.
3. **Did anything change on the path?** Firewall rules, VPN/tunnel state, a
   controller the overlay depends on (for Cisco SD-WAN: the vSmart controller
   carries the overlay that management traffic may use).
4. **Is it really every device?** `collector_targets_reachable` per collector
   in VictoriaMetrics, and the Telemetry Coverage page. One site dark is a
   site problem; everything dark is the path.

Nothing needs restarting inside Correlix. When the path returns, polling
resumes on the next cycle and syslog, traps and flows start arriving again;
`deploy-qualify.sh` Q11 confirms it.

## What it does not cover

- An **NMS-only** install (no SNMP collectors): `NMSIngestSilent` is that
  page.
- A lane that dies **alone** (syslog stops, polling continues): that is a
  sender or forwarding problem; see `syslog-bad-frames.md` and
  `ingest-sender-address-masked.md`.
- A lab that has had no reachable device for more than a week: the guard
  only pages on a change, so an install that was never connected, or has been
  dark longer than the metric retention, stays quiet.
