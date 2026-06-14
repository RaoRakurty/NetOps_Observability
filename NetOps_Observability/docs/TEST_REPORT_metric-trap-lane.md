# Test Report — metric/trap correlation lane

Date: 2026-06-14 · Branch: `feat/observability-platform` · Stack: live lab (.122)

## Verdict

**PASS.** The finalized architecture is implemented and proven end-to-end on the
live stack. SNMP metrics now flow `Go collector → Vector :8690 → netops.metrics →
correlation → corr_signals` and produce `device_telemetry` signals with canonical
identity; SNMP traps produce normalized `control_plane` signals (high-value only);
syslog/flows/probes remain working; VictoriaMetrics stays the metric store, not
the live RCA path; Telegraf is not a bus producer.

| Suite | Result |
|-------|--------|
| Go collectors (metric-lane unit) | **9 / 9** pass |
| Correlation suite (incl. 12 intake + 11 trap) | **116 / 116** pass |
| Architecture contract (static) | **11 / 11** pass |
| gNMI fidelity conformance | **5 / 5** pass |
| Live regression smoke (real pipeline) | **6 / 6** pass |
| Full Go backend suite | **all packages ok** |
| SNMP/telemetry fidelity harness (Hop A–G) | **all PASS** |

48 new automated tests + a 6-check live regression smoke. New tests are CI-ready
(`go test ./...`, `pytest`).

## The 5 critical tests

| # | Critical test | Status | Where / evidence |
|---|---------------|--------|------------------|
| 1 | Go collector → Vector :8690 → `netops.metrics` → correlation | ✅ PROVEN live | smoke C1; `netops.metrics` 140→6630+ offsets, correlation LAG 0, `metrics_received=accepted, dropped=0` |
| 2 | Telegraf cannot produce canonical SNMP metrics | ✅ enforced | `test_telegraf_is_not_a_bus_producer`, `test_telegraf_keeps_only_its_vm_output` |
| 3 | MetricEvent → `device_telemetry` signal | ✅ PROVEN live | smoke C3 — signal `entity_id=smoke-…:eth-smoke0`, `observer=device`, `modality=device_telemetry`, `collection_path=snmp_poll`, `entity_type=interface`; unit `test_metric_intake.py` |
| 4 | Trap normalized before correlation | ✅ PROVEN live | smoke C4 — linkDown→`control_plane` bound to interface; unknown trap→no signal; `test_trap_classify.py` |
| 5 | gNMI fidelity / conformance harness | ✅ core enforced | `test_gnmi_fidelity.py` — doc_claimed/degraded ≠ supported; cEOS leaf-BGP pinned `degraded` (full fixture-replay = follow-up) |

## Layer-by-layer coverage

**Layer 1 — unit.** Go `MetricEvent` construction + RCA-filter allowlist
(interface/bgp/resource identity, NDJSON framing, sink disable) — 9 tests.
Correlation intake identity + timestamp validation + drop-counting — 12 tests.
Trap normalization (link/restart/BGP, identity binding, unknown→none) — 11 tests.

**Layer 2 — static/config contract.** Telegraf-not-a-producer, Go-collector-is,
Vector :8690 route, correlation 5-topic list, VM-not-live-path, source-enum
includes `trap` — 11 tests (`test_architecture_contract.py`).

**Layer 3/4/5 — bus + ingestion + regression (live).** `regression_correlation_smoke.py`
injects fresh uniquely-tagged events through the real pipeline and asserts the
downstream signal: metric anomaly→canonical device_telemetry, fresh-message (not
topic-existence), linkDown→control_plane, unknown-trap→none, malformed→dropped —
6/6 pass.

**Layer 6 — gNMI conformance.** Fidelity-status catalog + enforcement (status
semantics, cEOS degraded regression) — 5 tests. Fixture capture/replay = follow-up.

**Layer 7 — resilience.** Vector-unavailable → collector does not crash, 0 sent →
`collector_metric_events_failed` (`TestForwardMetricEvents_VectorUnavailable`);
rejected batch counted not crashed; malformed/bad-timestamp dropped (intake tests).

## Live evidence

- **Lane fed:** `netops.metrics` end-offset 140 → 6630+ (was effectively empty);
  correlation consumer LAG 0.
- **Canonical contract on the wire:** `{"observer_type":"device","modality_class":
  "device_telemetry","collection_path":"snmp_poll","device":"dmz-fw","signal_family":
  "device_resource","metric":"device_mem_percent","value":75,"unit":"percent",
  "vendor":"fortinet","ts":…}`.
- **Counters** (`/healthz.ingest`): `metrics_received 9206 / accepted 9205 /
  dropped 1`, `device_telemetry_signals` firing, `traps_received 15 / normalized 1
  / dropped 14` (guardrail: keepalive traps dropped, no false RCA).
- **Fidelity harness Hop G:** all PASS — lane fed, device_telemetry present,
  provenance never empty.

## Defect found + fixed during validation

`corr_signals.source` Enum8 lacked `'trap'` → normalized trap signals failed to
insert (ClickHouse Code 691). Fixed in `corr_schema.go` + `init.sql` (×2) and the
live tables ALTERed; guarded by `test_source_enum_includes_trap_everywhere` and
smoke C4. Without the live smoke this would have shipped silently.

## Known limitations / follow-ups

- gNMI metrics → `netops.metrics` (Phase 2) and the gNMI fixture-replay harness
  (Layer 6A) are not built — gNMI is explicitly **not** claimed as correlation-wired.
- Trap parser covers the standardized high-value families only; HA-failover /
  environmental / threshold-alarm traps deferred (vendor-specific OIDs).
- A ~2-min deploy-ordering window left 156 `entity_id='unknown'` device_telemetry
  signals (old image vs new lane); harmless, self-expire via 30-day TTL. Cleanup
  ALTER DELETE requires operator authorization.
- Telegraf placeholder still runs (times out harmlessly); retire/fix separately.

## How to run

```bash
cd src/backend && go test ./...                 # Go (incl. collectors metric lane)
cd src/correlation && python3 -m pytest -q      # correlation (116)
python3 -m pytest tests/ -q                      # contract + gNMI fidelity (16)
python3 scripts/regression_correlation_smoke.py  # live E2E (needs running stack)
python3 scripts/snmp_fidelity_harness.py         # live SNMP/telemetry fidelity
```
