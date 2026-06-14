# Active measurement architecture — the modern, standards-grade way

Status: **proposed** (research-backed, 2026-06-10). Unlocks RFC-compliant one-way
metrics (RFC 2679/2680/3393/5481) and the real Path Health, and is the path
toward the end goal: application ↔ network root-cause correlation.

## Why not just ICMP ping / traceroute
ICMP ping is RTT-only, deprioritized by devices, and not IPPM one-way. Modern
active measurement separates two concerns:
- **How good is the path?** → active SLA probing with timestamps → STAMP.
- **What is the path?** → hop-by-hop discovery → traceroute (TCP/UDP).

## The modern stack (researched)
1. **STAMP — Simple Two-Way Active Measurement Protocol (RFC 8762, ext RFC 8972).**
   The current IETF standard; standardizes/supersedes TWAMP-Light. Measures
   **one-way + round-trip delay, PDV/jitter (RFC 3393/5481), and loss (RFC 2680)**
   via sender→reflector test packets with T1..T4 timestamps. Vendor-supported
   (Cisco, Juniper, Nokia; SR perf via STAMP-SRPM). **This is the RFC-grade core.**
   - **Stdlib-friendly:** STAMP-Light is UDP with a defined test-packet payload
     (seq + timestamps). A sender is implementable in pure stdlib `net` (no raw
     sockets / TTL needed) → fits the zero-dep backend rule.
   - **Reflector:** lives on the device (capable routers), or we ship a small
     STAMP/TWAMP-Light **reflector** (stdlib UDP echo with timestamping) to run at
     sites/hosts that lack one. Unauthenticated STAMP ↔ TWAMP-Light interop.
2. **Traceroute (TCP/UDP)** — hop-by-hop path + per-hop latency (the reference
   Network Path view). **Needs TTL control / ICMP receipt**, which stdlib `net`
   does not expose → requires either `golang.org/x/net` (ipv4/icmp) added to the
   dependency allowlist, or a small privileged sidecar prober. **Decision needed.**
3. **eBPF + OpenTelemetry (later)** — host kernel RTT/TCP-state + app traces, to
   join application latency to the network path/flows. The app↔network RCA goal.

## Metrics emitted (RFC-aligned)
Per probe session (labels: src, dst, path/test):
- `probe_owd_ms` one-way delay (RFC 7679) · `probe_rtt_ms` round-trip
- `probe_loss_pct` one-way loss (RFC 2680)
- `probe_pdv_ms` packet delay variation (RFC 3393) · `probe_ipdv_ms` (RFC 5481)
- `probe_reorder`, `probe_route_changes` (route stability)
→ VictoriaMetrics → **Path Health becomes RFC-grade** (recompute the composite on
these instead of the tunnel proxy) → surfaces on Flow Trace / Network Path +
Quality boards.

## Build phases
- **P1 — STAMP/TWAMP-Light sender** (stdlib UDP, RFC 8762 packet format) +
  optional bundled reflector. Scheduled sessions (config: src→dst pairs, interval,
  packet size/rate). Emits the RFC metrics above. The modern, standards-grade core.
- **P2 — Traceroute path discovery** (pending the dependency decision) → the
  hop-by-hop Network Path / Flow Trace view.
- **P3 — Recompute Path Health on probe metrics**; wire NetPath/synthetics stubs.
- **P4 — eBPF/OTel app↔network correlation** (the end goal).

## Open decisions
1. **Reflector**: rely on device STAMP/TWAMP responders only, or also ship our
   own stdlib reflector for sites without one? (Shipping one = works anywhere.)
2. **Traceroute dependency**: add `golang.org/x/net` (icmp/ipv4) to the allowlist
   (CLAUDE.md §6 amend) vs a sidecar vs defer traceroute. STAMP itself does **not**
   need it.

See [[metrics-standards]] · [[build-order]].
