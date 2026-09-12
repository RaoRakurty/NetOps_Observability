# Internal component topology — telemetry → correlation (agreed)

Status: **agreed + implemented + live-validated 2026-06-14.** This is the
authoritative wiring the architecture-contract tests (`tests/test_architecture_contract.py`)
enforce. Change the diagram and the tests together.

## The two metric paths (by purpose)

VictoriaMetrics and Redpanda are **not** competitors — they serve different
purposes and both are fed from the same collector:

| Path | Purpose | Producer → consumer |
|------|---------|---------------------|
| **VictoriaMetrics** | dashboard / PromQL / history (the metric store) | Go collector `emitMetrics` → VM `remote_write` (full sample set) |
| **Redpanda `netops.metrics`** | live RCA signal stream for correlation | Go collector `forwardMetricEvents` → Vector `:8690` → `netops.metrics` (RCA-filtered, canonical) |

Rules:
- **VM is NOT the live correlation path.** A VM-query bridge may be added later
  for replay/backfill/enrichment only — never for live RCA. (enforced:
  `test_correlation_live_path_does_not_query_victoriametrics`)
- **Redpanda is the live signal backbone.** Correlation consumes bus events.
- **Alert-driven-only is NOT the primary metric path.** Alerts may become a
  supplemental input later; correlation needs underlying per-sample signal context.

## Ownership

- **SNMP metrics are owned by the Go collector** (`src/backend/collectors/`),
  not Telegraf. Telegraf is a vestigial placeholder (polls `10.0.0.1/2`, times
  out) and must never become a second producer — that would double-produce the
  canonical series. (enforced: `test_telegraf_is_not_a_bus_producer`)
- **gNMI stays separate** (gnmic container → VM today). gNMI → `netops.metrics`
  is **Phase 2** (gnmic Kafka/canonical output); not claimed until validated by
  the fidelity catalog (`src/config/gnmi_fidelity.yaml`).
- One transport per (device, family). SNMP owns interface/cpu/temp; gNMI owns
  Nokia-SRL `device_mem_percent` + BGP/IS-IS state (the ownership gate,
  `gnmic.yaml`).

## Flow

```
SNMP device ─poll─► Go collector ─┬─ emitMetrics ───────────► VictoriaMetrics  (store/query/history)
                                  └─ forwardMetricEvents ─► Vector :8690 ─► netops.metrics ─┐
gNMI device ─sub─► gnmic ─────────► VictoriaMetrics  (Phase 2: ─► netops.metrics)           │
syslog ───────────► syslog-ng ────► Vector ─► netops.syslog ───────────────────────────────┤
traps  ───────────► API rcvr ─────► Vector :8688 ─► netops.snmptrap ────────────────────────┤
flows  ───────────► goflow2 ──────► Vector ─► netops.flows ─► ClickHouse + ─────────────────┤
probes ───────────► API ──────────► Vector :8689 ─► netops.probes ──────────────────────────┤
                                                                                            ▼
                                                                      CORRELATION ENGINE (consumes 5 topics)
                                                                        metric  → device_telemetry signal
                                                                        trap    → control_plane signal (high-value only)
                                                                        syslog  → control_plane signal
                                                                        flow    → passive_flow signal
                                                                        probe   → active_probe signal
                                                                                            │
                                                                      corr_signals / corr_objects (ClickHouse) ─► API ─► UI
```

## Canonical metric contract (`netops.metrics`)

Every MetricEvent the Go collector emits (and every event correlation accepts)
carries the single canonical contract — provenance + identity:

`observer_type` · `modality_class` · `collection_path` · `signal_family` ·
`device` · `if_name`/`peer`/`index` (where applicable) · `metric` · `value` ·
`unit` · `ts` · `vendor`.

RCA family allowlist (the bus filter — NOT a raw firehose; defined in
`collectors/metric_events.go`): interface state/counters/errors/discards, BGP
peer state, device CPU/memory/temperature. Noisy packet counters
(ucast/mcast/bcast) stay in VM only.

## Traps (event evidence plane)

Traps remain searchable in OpenSearch (history) **and** feed correlation as
normalized `control_plane` signals — but **only** the high-value, standardized
families (linkDown/Up, coldStart/warmStart, BGP transitions). Every other trap
returns no signal (the anti-noise guardrail). HA-failover / environmental /
threshold-alarm traps are vendor-specific and deferred to a fixture-driven
follow-up. (`producers.trap_control_signal`, enforced by
`test_trap_classifier_is_an_allowlist_not_a_firehose`)

## Observability

- Collector: `collector_metric_events_{built,sent,failed}` (VM gauges).
- Correlation `/healthz.ingest`: `metrics_{received,accepted,dropped}`,
  `device_telemetry_signals`, `traps_{received,normalized,dropped}`.

## Follow-ups (explicitly not in this work)

- gNMI metrics → `netops.metrics` (Phase 2, gnmic output).
- gNMI fixture-replay conformance harness (Layer 6A capture/replay).
- Trap parser expansion (HA failover, environmental/hardware, threshold alarms).
- Retire/fix the dead Telegraf container.
- VM-query bridge for replay/backfill (non-live).
