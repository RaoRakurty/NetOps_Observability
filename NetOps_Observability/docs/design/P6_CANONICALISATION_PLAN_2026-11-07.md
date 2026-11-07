# P6 — engine stage [1] canonicalisation: plan (2026-11-07)

Status: **PLAN.** Research: Fable `researcher` (read-only, main bf72bf4a); premises
spot-verified in the main session where marked ✔. Programme: `NMS_DEVICE_IDENTITY_2026-11-01.md`
§7b/§8. Out of scope: P4/371 identity resolver (blocked on the collector tier).

## Gates — P6 cannot ship alone

1. **E1 origin-observer ON** (`CORR_ORIGIN_OBSERVER`). Once syslog grounds to the
   device, a syslog-hostname vs SNMP-id pair would otherwise confirm on one box's word.
2. **Stage [2] series admission first** (`CORR_SERIES_ADMISSION`) — needed TODAY:
   - ✔ SNMP cumulative counters (octets/errors/discards/fcs, `bgp_fsm_transitions`)
     reach CUSUM RAW (`collectors/metric_events.go buildMetricEvent` → `main.handle_metric`
     → `episodes.observe`); a constant-rate counter opens an episode at sample 23 and
     NEVER clears (reproduced with `EpisodeDetector`). Tracked separately — fix first.
   - SNMP and controller samples already interleave in one series for cpu/mem and
     same-spelled interfaces (`nms/identity.go` rewrites the controller device id).
3. **Tenant-only resolver.** `entity_resolver_for` reads tenant ∪ global
   (`main.py ~1536`); a global row named like a tenant's device makes it ambiguous.

## Premise corrections

- `canonIface` is Go (`topology_view.go:789-847`), not UI → port to Python + drift test.
- D5 is real: `nms/identity.go:115-123` rewrites `PeerID` to an inventory id; the
  native IP stays in `correlation_hints.controller_peer_id`. `identity.yaml` defines a
  BGP session by the REMOTE ADDRESS → canonical peer = IP.
- Trap lane already binds `{device}:{peer}`; D1 is syslog only (`events.yaml ~352-388`).
- `_parse_ts` (`controller_events.py:93-107`): 7–9 fractional digits silently fall
  back to ingest time (uncounted); a numeric µs/ns epoch raises → quarantine. Fix:
  `producers.parse_event_ts(raw, reference=fallback) or fallback`.

## Design

- **Event lanes:** canonicalise once in `buffer_signal`, after `canon_tenant`, before
  `_stamp_origin_device` (where E1 stamps). NOT before `agg_admit` (INVARIANTS §10a:
  the plane's new_vantage/new_modality merge paths are unproven).
- **Metric lane:** series key in `handle_metric`, after `metric_identity`, before
  `feed_episode_detector`. **Flow lane:** `_FLOW_AGG` key in `handle_flow`.
- Rewrite only `entity_id` (+ raw-device tokens), never `native_id` → `signal_id`
  and the archive identity are unchanged. Stamp `attrs["canon"]={"raw","basis"}` on
  rewrite. Replay reads `corr_signals_archive` (canonical window) → flag-independent.
- New pure module `canon.py`: `canon_iface_key`, `canonical_peer`,
  `canonicalize(sig, resolver)`; idempotent, order-independent; `main.py` only wires.
- `EntityResolver`: per-device `(device,key)→ifName` index (collisions dropped),
  per-device ifName set, generic-hostname abstain (`localhost`, `router`, …).

| # | Rule |
|---|---|
| D2 | `host` → tenant-only `canonical_device`; ambiguous/unknown/generic → keep raw, count. Optional PR-G: `attrs.sender_ip` fallback (skip when `source_masked`). |
| D1 | BGP only: `<canon_device>:<compressed peer>`. OSPF syslog Nbr (router-id) ≠ ospfNbrTable (neighbour IP) — no change without evidence. Syslog peer regex is IPv4-only (residual row). |
| D5 | Controller session kinds: `entity_id=<device>:<controller_peer_id IP>`. Go cleanup waits for flag retirement (native_id embeds entity_id). |
| D4 | `<canon_device>:<canon_iface_key(name)>`: Go canonIface port + Cisco TwoGig/FiftyGig/400G/200G, XR MgmtEth, AppGigabitEthernet; Junos keeps units; Nokia ifDescr first comma field; SR Linux; Arista; NX-OS Eth; SONiC defaults (alias mode abstains); vEdge `ge0/0`. Digit-only → ifIndex only when the source declares an index (HP ProCurve ifNames are "1".."48"). IPv6-literal tokens abstain. |
| D3, D6 | Not P6 — own tracker rows (template audit; relayed severity). |

## Flags, ENGINE_SEMVER

- `CORR_SERIES_ADMISSION` (stage [2], default OFF): counters → per-second rate per
  (series, source) with reset handling; static unit/semantic table pinned to Go
  `rcaMetricFamilies` by a source-parsing test; one sample per (series, epoch bucket)
  across DIFFERENT sources, first wins, loser counted
  (`corr_series_cross_source_dropped_total`; bucket `CORR_SERIES_BUCKET_S`=60);
  honest observer: `EpisodeEvent.sources` → `attrs.series_sources`, multi-source →
  conservative authority path (downgrade only). State in `_SeriesState` (MAX_SERIES LRU).
- `CORR_IDENTITY_CANON` (stage [1], default OFF) REQUIRES E1 + series admission;
  otherwise stays OFF, logs, gauge `corr_identity_canon_enabled=0`. Flags in
  `signals.py` with `set_*` hooks. Counter `corr_identity_canon_total{lane,axis,outcome}`.
- **ENGINE_SEMVER 3.2.0 → 3.3.0** in the default-ON PR (node identity + episode
  semantics change; edges/scoring/gate do not). Bumping in a flag-OFF PR re-versions
  every open object (engine_ver is in content/material hash).

## Tests

Unit `test_canon_identity_p6.py` (per-vendor vectors, Go ifaceAlias drift test,
collisions, digit-only, generic guard, idempotence, hostile input, native_id unchanged);
§3a `test_identity_canon_isolation.py` (two tenants identical names → own ids; `""`
never resolves a tenant token); `test_series_admission_p6.py` (counter OFF stays stuck
— pins today; ON no spurious onset; reset/wrap; cross-source bucket; unit mismatch;
series_sources; E1 pairing); OFF byte-identical (golden wire, replay, p3_equivalence,
rank_memo); replay flag-independence; E7 ratchet split `KNOWN_DIVERGENCES` /
`_ON` with recorded cEDGE-81 syslog fixtures; mutation checks (canonicalize no-op,
resolver ∪ global, ambiguity drop removed, native_id canonicalised, flag default ON,
cross-source drop removed, observer = tripping path, E1 gate removed, canon before
agg_admit).

## PR order

A `_parse_ts` fix → B E7 extension (declarations only) → C1 counters→rates →
C2 cross-source bucket + semantics + honest observer → D `canon.py` + resolver (unwired)
→ E wiring (event lanes + metric key, §3a, OFF/replay tests, CLAUDE.md §1/§8) →
F flows + DIA seam endpoint fix (or defer to P5) → G optional sender_ip →
H owner-gated default ON + ENGINE_SEMVER 3.3.0 + rig run (scale-miniladder
t-storm-2.5k, specificity/FP/accuracy, INVARIANTS §10a).

## Risks

Splits at flip time (Jaccard 0.4 continuation; flip when quiet); ids changing over
time (renames, ifIndex TTL); false merges (generic hostnames, collisions, IPv6, digit
ifNames — guarded); metric re-warm (~20 samples); `_SeriesState` memory growth
(re-measure series_budget, 768 MiB OOM lesson); raw ids in `corr_signals` vs canonical
in RCA objects (document).

## Owner decisions (recommended defaults)

OD1 interface key form = table-free canonical key (`gi1`), raw name kept for display ·
OD2 tenant-only resolver (and move E1 onto it) · OD3 one-sample-per-bucket only across
sources, 60 s · OD4 counters→rates under its own flag · OD5 ENGINE_SEMVER at default-ON ·
OD6 default-ON order + rig run. Null0 KEPT / VPN ≥ 65528 DROPPED — decided 2026-11-07.
