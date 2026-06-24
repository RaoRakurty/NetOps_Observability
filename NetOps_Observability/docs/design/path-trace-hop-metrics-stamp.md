# Path Trace hop-by-hop metrics (STAMP-valued) + the MTTR story

**Status:** DESIGN — captured 2026-06-24 from an owner discussion (owner heading
to bed; asked to keep going but could not approve interactively). NO speculative
code shipped — STAMP-per-hop is a real architecture decision and is held for owner
review. This doc grounds the feasibility in the actual code so the build, when
approved, is not surface-knowledge.

> Owner's words, in order:
> 1. "Path Trace should have path metric."
> 2. "We are already doing this in another place — Network Path and Synthetics."
> 3. "Every network observability talks about lower MTTR — where do we bring this idea?"
> 4. "Flow Trace is also using STAMP."
> 5. "We will need to see HOP-BY-HOP metrics somewhere based on STAMP in addition to traceroute."
> 6. "STAMP is more valued."

---

## 1. What we have today (verified in code, not assumed)

| Surface | Source | Granularity | Metrics | Where |
|---|---|---|---|---|
| **STAMP active probe** | `collectors/stamp.go` | **END-TO-END** (prober→reflector) | `probe_rtt_ms` / `probe_owd_ms` / `probe_pdv_ms` (jitter) / `probe_loss_pct` / `probe_sent` / `probe_recv`, all `{dst,probe="stamp"}` | live: `dst=10.70.245.120:8620` |
| **ICMP synthetic** | `collectors/synthetics.go` | END-TO-END | `synthetic_icmp_rtt_ms`, `synthetic_icmp_loss_pct` | live: `dst=10.70.245.120` |
| **Traceroute** | `collectors/traceroute.go` | **PER-HOP** | `probe_hop_rtt_ms` (per ttl), `probe_path_length`, `probe_path_reached`, `probe_path_changed` | `/api/probe/paths` (Flow Trace) — live: `lan-gw1 0.4ms → wan-edge2 2.6ms → dc-core1 6.2ms` |
| **Path Health SLA** | `path_health_api.go` `/api/paths/health` | END-TO-END, keyed `(agent,dst)` | p95 latency/jitter, 5-min loss + per-path baseline p50/p99 | **Network Path & Synthetics** board (`pages/NetworkPath.tsx`) |
| **NetworkPathView** (new, `c3603aa`) | `/api/topology/view?mode=path_trace` | per-hop *topology* | device health, link utilization, bottleneck (NO active latency/loss) | **Topology Canvas → Path Trace** |

**The key fact:** STAMP is **end-to-end by design** (RFC 8762 — a two-way active
measurement between a Session-Sender and a Session-Reflector). It yields a single
high-fidelity RTT/OWD/PDV/loss number **for the whole prober→reflector path** — it
does **not** natively produce per-hop numbers. The only **per-hop** latency we
have today is **traceroute** (`probe_hop_rtt_ms`), which is lower-fidelity (ICMP/TCP
TTL-expiry, rate-limited, no per-hop jitter/loss).

So the owner's two asks are in productive tension and must be reconciled honestly:
- "hop-by-hop metrics" → today only traceroute can do per-hop.
- "STAMP is more valued" → STAMP is the trustworthy number, but it's end-to-end.

---

## 2. The honest reconciliation — how you get STAMP-grade PER-HOP

Pure STAMP cannot see inside the path. Industry-correct ways to get per-hop /
per-segment STAMP-grade numbers, cheapest-to-richest:

1. **Segmented STAMP (reflectors at hops / segment boundaries)** — run a STAMP
   Session-Reflector at each measurement vantage (each PoP/edge/region), and a
   Session-Sender upstream. Adjacent-vantage sessions give **per-segment** RTT/OWD/
   PDV/loss of STAMP quality. This is exactly how SPs do per-segment TWAMP/STAMP.
   **In OUR architecture this maps directly to the planned vantage-point / cloud
   collector agents (#68 cloud-ingestion; parked ingest-isolation model C).** A
   path crossing N vantages decomposes into N-1 STAMP-measured segments → honest
   "STAMP per hop" at the *segment* granularity that actually matters for fault
   isolation (which OWNERSHIP DOMAIN / seam degraded — see #68 seam model).
2. **TTL-stepped STAMP / "STAMP-paris"** — send STAMP test packets with increasing
   TTL. Intermediate routers that don't run a Reflector just ICMP-TTL-exceed (=
   traceroute again, NOT STAMP quality); only nodes running a Reflector answer with
   true STAMP timestamps. Useful only where reflectors are sparse. Lower value.
3. **IOAM / in-situ OAM (RFC 9197)** — per-hop telemetry stamped into live data
   packets. Highest fidelity, needs device dataplane support (limited in lab).
   Roadmap-only.

**Verdict:** the credible path to "STAMP hop-by-hop" is **(1) segmented STAMP over
vantage agents**, delivered as #68's vantage agents land. **Until then, per-hop =
traceroute (`probe_hop_rtt_ms`), clearly labeled as such, with STAMP providing the
trusted END-TO-END envelope** the per-hop traceroute numbers must reconcile to.
This is honest and is the only design that doesn't fabricate per-hop STAMP we
cannot measure.

---

## 3. Where each thing renders (avoid the duplication the owner flagged)

The owner is right that **end-to-end path SLA already lives in Network Path &
Synthetics** — Path Trace must NOT re-show the same per-target SLA list. Division
of responsibility:

- **Network Path & Synthetics** (`NetworkPath.tsx`) = the **fleet SLA board**:
  every measured `(agent,dst)` path, e2e p95 latency/jitter/loss + baseline
  deviation. "Which of my monitored paths is out of SLA." STAYS as-is.
- **Flow Trace** = the **per-hop traceroute** view (path topology + hop RTT,
  path-change detection). Owner notes it "is also using STAMP" — reconcile in §5.
- **NetworkPathView / Path Trace** (new) = the **operator fault-isolation canvas**
  for ONE chosen src→dst: the L→R ribbon. This is where **per-hop metrics belong**
  — it's the "WHERE on this path did it break" view, which is the MTTR lever (§4).
  Its job is NOT a fleet SLA list; it's pinpointing the bad hop/segment on the one
  path the operator is investigating.

So Path Trace earns per-hop metrics precisely BECAUSE the board already owns e2e.

---

## 4. The MTTR story — where we "bring the idea"

MTTR = **detect → isolate → diagnose → repair**. Every vendor claims lower MTTR;
the differentiator is **time-to-ISOLATE** (the "WHERE"), because isolation is the
slowest human step in a NOC. Our moat is the evidence/RCA engine + the path view.
Concretely, surface the MTTR idea in three honest places:

1. **RCA verdict (time-to-isolate):** the engine already grounds a verdict to a
   `corr_object`. Add a **"time to isolate"** stat = first-signal → verdict-grounded.
   That is the literal MTTR contribution we can prove, per incident.
2. **Path Trace hop-by-hop (the visual WHERE):** the degraded HOP/SEGMENT lit on
   the ribbon IS fault isolation made visual — "the loss enters at segment 3
   (spine2→wan-r2), not in your LAN." This is the highest-leverage MTTR surface and
   the reason per-hop metrics matter here.
3. **Incident / dashboard rollup:** an explicit **MTTR / MTTI** trend (median
   time-to-isolate over resolved incidents) on the incident board — the executive
   number, computed from real incident timestamps, never fabricated.

Do NOT slap "MTTR -40%" marketing on the UI. Bring the idea as **a measured,
honest time-to-isolate stat + the visual WHERE** — consistent with the
evidence-engine-as-moat bar.

---

## 5. Open questions for owner (resolve before build)

1. **"Flow Trace is also using STAMP" — confirm.** `traceroute.go` methods are
   ICMP + TCP-SYN (`/api/probe/paths` shows `method=auto|icmp`, `via=tcp`). Is the
   intent that the traceroute probe should *timestamp with STAMP* for higher-
   fidelity per-hop RTT, or just that Flow Trace and STAMP share the prober? This
   determines whether §2-option-2 (TTL-stepped STAMP) is in scope.
2. **Per-hop granularity target:** true per-device-hop (needs reflectors at devices
   — unrealistic in most nets) vs **per-segment / per-vantage** (the #68 model,
   realistic and aligned with the seam-ownership story). Recommend per-segment.
3. **NetworkPathView per-hop NOW:** ship traceroute `probe_hop_rtt_ms` bound onto
   the ribbon as the interim per-hop metric (honest "traceroute" label), with the
   e2e STAMP number as the ribbon's header envelope (a small chip that LINKS to the
   board, not a duplicate list)? Binding caveat: device-path node ids
   (leaf1/spine1) must map to traceroute hop IPs/hostnames — needs an ip↔device
   resolve (the entity-resolver enrichment already exports iface-ip↔device, so this
   is feasible but must be built carefully, not guessed).
4. **STAMP reflector fan-out:** to get segmented STAMP we need reflectors at more
   than one vantage. Today there is one reflector (`.120:8620`). Confirm appetite
   to deploy reflectors per segment (ties to #68 collector-agent rollout).

---

## 6. Phased plan (proposed — pending §5 answers)

- **P0 (no new measurement, honest interim):** NetworkPathView gains a per-hop
  metric ROW sourced from traceroute `probe_hop_rtt_ms` when the traced path
  resolves to a measured traceroute (ip↔device via entity-resolver), + an e2e STAMP
  envelope chip in the header that links to Network Path & Synthetics (no
  duplication). Honest empty state when no probe covers the path. Reuses existing
  data only.
- **P1 (MTTR surfacing):** time-to-isolate stat on the RCA verdict banner +
  MTTI trend on the incident board. Pure computation over existing timestamps.
- **P2 (segmented STAMP):** as #68 vantage agents land, decompose a path into
  vantage-bounded segments and run STAMP per segment → true STAMP-grade per-segment
  latency/jitter/loss on the ribbon, superseding the traceroute interim where a
  segment is STAMP-covered (traceroute stays the fallback for un-instrumented
  segments). This is the headline differentiator.
- **P3 (IOAM):** per-hop in-situ telemetry where device support exists. Roadmap.

Cross-refs: #68 cloud-ingestion / seam model · #77 NetworkPathView (`c3603aa`) ·
Network Path & Synthetics board · the evidence-engine-as-moat bar.
