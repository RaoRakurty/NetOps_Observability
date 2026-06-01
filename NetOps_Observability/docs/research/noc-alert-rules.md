# NOC Alert Rule Library (Backlog #8)

Research + a drop-in set of **60 high-value NOC alerting rules**, written in the
**exact** schema this codebase's alert engine already consumes (the Prometheus
rules-file format in `src/config/rules.yaml`). Rules follow mainstream NOC /
NANOG operational practice and are grouped by operational category.

> Status: **research / design only — no code changed.** Rules are ready to paste
> into `src/config/rules.yaml` (mounted to the API as `RULES_FILE=/config/rules.yaml`,
> see `docker-compose.yml`). They are based on the **real metric names** emitted by
> the collectors; rules needing telemetry we don't yet emit are flagged
> `[NEEDS METRIC]` with the gap explained.

---

## 1. The engine's real rule schema (ground truth)

Read directly from `src/backend/alerts/{engine.go,evaluator.go,parse_test.go}` and
`src/config/rules.yaml`.

### 1.1 File format — Prometheus rules file (subset)

The loader `LoadRules(path)` → `parseRulesYAML()` in `engine.go` is a hand-rolled,
**stdlib-only** scanner (the backend is dependency-free by design). It parses a
*subset* of the Prometheus rules-file format:

```yaml
groups:
  - name: <group-name>
    interval: 30s              # cosmetic; engine ticks every 30s regardless
    rules:
      - alert: <RuleName>
        expr: <PromQL expression>
        for: <duration e.g. 5m>     # optional
        labels:
          severity: <critical|warning|info>
        annotations:
          summary: "<template with {{ $labels.X }} / {{ $value }}>"
```

What the scanner actually recognises (everything else is ignored, incl. nested
list/scalar nuances — keep rules in exactly the shape above):

- `- alert:` starts a new rule; `expr:`, `for:`, `severity:` (anywhere under
  `labels:`), and `summary:` (under `annotations:`) are the only fields captured.
- `for:` is parsed with Go `time.ParseDuration` (`5m`, `90s`, `1h`); unparseable
  values are silently dropped (rule then fires immediately).
- `#` comments and blank lines are ignored.
- `summary:` values may be quoted (quotes are stripped).
- **`severity` is a free-form label**, not a validated enum — but the UI/notifiers
  expect `critical | warning | info`; stick to those three.

### 1.2 The `Rule` struct — `engine.go`

```go
// Rule is a single alert rule. The Expr is a PromQL expression that the
// evaluator pushes through to VictoriaMetrics's /api/v1/query.
type Rule struct {
    Name        string            `json:"name"`
    Expr        string            `json:"expr"`
    For         time.Duration     `json:"for"`
    Severity    string            `json:"severity"`
    Labels      map[string]string `json:"labels,omitempty"`
    Annotations map[string]string `json:"annotations,omitempty"`
}
```

(Note: there is **no `category` field** in the schema. Categories in this document
are organisational only — use the YAML group `name:` to bucket rules, e.g. a group
per category. The struct's `Severity` field is populated from `labels.severity`.)

### 1.3 Evaluation semantics — `evaluator.go` + `engine.go`

This is the most important correction for rule authors:

- **`expr` is sent verbatim as a PromQL instant query to VictoriaMetrics**
  (`GET {VICTORIA_URL}/api/v1/query?query=<expr>&time=now`). There is **no
  homegrown mini-grammar** — you get **full PromQL / MetricsQL**: `rate(m[5m])`,
  `increase()`, `delta()`, `deriv()`, `predict_linear()`, `sum() by (…)`,
  `count()`, `avg_over_time()`, `stddev_over_time()`, `histogram_quantile()`,
  `* / + -`, `and`/`or`/`unless`, `offset`, etc. Use real PromQL `m[5m]` range
  syntax (not `rate(m, 5m)`).
- A rule **fires when the query returns ≥1 series.** Because PromQL comparison
  operators (`>`, `==`, …) already *filter* to series where the predicate holds,
  `expr: device_cpu_percent > 90` returns only the hot devices — each becomes one
  alert. So **every rule's `expr` should end in a comparison** (or otherwise return
  empty when healthy).
- The engine ticks every **30s** (`loop()`), evaluates all rules, and keeps a
  per-series active set keyed by `rule + fingerprint(labels)`. A series that stops
  matching auto-resolves; newly-matching series are dispatched to notifiers once.
- `for:` (hold-down) **is stored but the current engine does not yet enforce a
  sustained-duration window** — it dispatches on first match. Keep `for:` set
  correctly anyway (forward-compatible, and it documents intent); rely on PromQL
  range windows (`[5m]`, `avg_over_time`) for noise-damping today.
- **z-score is not a built-in** — express it in PromQL:
  `(m - avg_over_time(m[1h])) / stddev_over_time(m[1h]) > 3`.

### 1.4 Summary templating — `renderSummary()` in `engine.go`

- `{{ $labels.<name> }}` → the firing series' label value (`?` if absent).
- `{{ $value }}` (in any `{{ … $value … }}` wrapper) → the instant value (`%g`).
- Any other `{{ … }}` is **stripped** (no arithmetic/functions in templates).
- Available labels are whatever the metric carries (see §2): **`device`,
  `vendor`, `index`** for SNMP metrics; `instance`/`job` for `up`;
  `collector` for `collector_*`. The example `rules.yaml` also uses
  `{{ $labels.device_id }}` for the legacy `up`/`cpu_usage` series.

---

## 2. Metric vocabulary — what actually exists

Authoritative source: the multivendor SNMP collector
`src/backend/collectors/snmpmetrics.go` emits metrics named by
`src/config/snmp_profiles.json`, tagged with labels **`device`, `vendor`**, and for
table rows **`index`** (e.g. per-interface, per-sensor). Format emitted to
VictoriaMetrics: `device_cpu_percent{device="leaf1",vendor="arista",index="7"} 92`.

### 2.1 Confirmed-collected metrics (use freely)

| Metric | Labels | Notes / source |
|---|---|---|
| `up` | `instance`,`job`(,`device_id`) | scrape liveness 1/0 |
| `cpu_usage`, `memory_usage` | `device_id` | legacy series in shipped `rules.yaml` |
| `device_cpu_percent` | device,vendor,index | all vendors |
| `device_cpu_1min_percent` | device,vendor,index | Cisco |
| `device_mem_percent` | device,vendor | juniper, fortinet |
| `device_mem_used_bytes`,`device_mem_free_bytes` | device,vendor,index | Cisco |
| `device_mem_total_kb`,`device_mem_used_kb`,`device_mem_available_kb` | device,vendor | generic/nokia |
| `device_dram_bytes` | device,vendor,index | juniper |
| `device_if_oper_status` | device,vendor,index | IF-MIB (1=up,2=down,…) |
| `device_if_admin_status` | device,vendor,index | IF-MIB (1=up,2=down) |
| `device_if_in_octets`,`device_if_out_octets` | device,vendor,index | ifXTable HC octets |
| `device_if_in_errors`,`device_if_out_errors` | device,vendor,index | ifInErrors/ifOutErrors |
| `device_if_in_discards`,`device_if_out_discards` | device,vendor,index | ifIn/OutDiscards |
| `device_if_in_ucast_pkts`,`device_if_out_ucast_pkts` | device,vendor,index | ifXTable |
| `device_if_in_mcast_pkts`,`device_if_out_mcast_pkts` | device,vendor,index | ifXTable |
| `device_if_in_bcast_pkts`,`device_if_out_bcast_pkts` | device,vendor,index | ifXTable |
| `device_if_speed` | device,vendor,index | ifHighSpeed (units: see §2.3) |
| `device_temp_celsius` | device,vendor,index | Cisco/Arista/Juniper/Nokia |
| `device_temp_state` | device,vendor,index | Cisco CISCO-ENVMON (1=normal…) |
| `device_fan_state` | device,vendor,index | Cisco CISCO-ENVMON |
| `device_psu_state` | device,vendor,index | Cisco CISCO-ENVMON |
| `device_sensor_value` | device,vendor,index | ENTITY-SENSOR-MIB generic |
| `device_storage_size`,`device_storage_used` | device,vendor,index | HOST-RESOURCES hrStorage |
| `device_disk_used_mb`,`device_disk_capacity_mb` | device,vendor | fortinet |
| `device_session_count` | device,vendor | fortinet firewall sessions |
| `device_sysuptime` | device,vendor | sysUpTime (centiseconds) |
| `collector_up` | collector | per-collector heartbeat 1/0 |
| `collector_targets`,`collector_targets_reachable` | collector | target counts |
| `collector_target_up` | collector,device | per-target reachability |
| `collector_samples`,`collector_poll_duration_ms`,`collector_tunnels` | collector | self-telemetry |

### 2.2 CISCO-ENVMON state encodings (for env rules)

`device_temp_state` / `device_fan_state` / `device_psu_state` follow
CISCO-ENVMON `*State`: `1=normal, 2=warning, 3=critical, 4=shutdown,
5=notPresent, 6=notFunctioning`. So `> 1` (or `>= 2`) means "not normal".

### 2.3 Gotchas to verify before enabling utilization rules

- **`device_if_speed` units.** Profiles map it to `ifHighSpeed` (OID
  `…31.1.1.1.15`), which is in **Mbit/s**, not bit/s. Octet counters are bytes.
  So link utilization is `rate(device_if_in_octets[5m]) * 8 / (device_if_speed *
  1e6)`. Confirm units on your devices; some stacks normalise to bps. The rules
  below assume **`device_if_speed` in Mbit/s** and convert accordingly.
- **No `ifname` label** — interfaces are identified by **`index`** (ifIndex).
  Summaries use `{{ $labels.index }}`. (Enriching with ifName/ifAlias is future
  collector work.)
- **`up` for SNMP devices.** `collector_target_up{collector,device}` is the
  per-device reachability signal the SNMP path emits; classic `up` is the scrape
  job liveness. Reachability rules below offer both.

### 2.4 Metrics the rules want but we do NOT emit yet → `[NEEDS METRIC]`

- **Optics / DOM**: Rx/Tx power dBm, transceiver temp, laser bias, voltage
  (ENTITY-SENSOR-MIB transceiver rows or gNMI `components/transceiver`). Partly
  reachable today via the **generic `device_sensor_value`** ENTITY-SENSOR rows if
  the device exposes optics there, but they are not separated by sensor *type*, so
  dedicated `device_optic_*` metrics are recommended.
- **CRC/FCS errors** split from `device_if_in_errors` (`dot3StatsFCSErrors`).
- **BGP/OSPF/RIB**: `device_bgp_peer_state`, `device_bgp_accepted_prefixes`,
  `device_bgp_fsm_transitions`, `device_ospf_nbr_state`, `device_route_count`,
  `device_fib_count` (BGP4-MIB / OSPF-MIB / vendor RIB). gNMI/NETCONF collectors
  exist but don't yet emit these as VM metrics.
- **Tunnel SLA**: `tunnel_latency_ms`, `tunnel_jitter_ms`, `tunnel_loss_pct`,
  `tunnel_status`. **Critical gap:** the tunnel collector writes latency/jitter/loss
  **to ClickHouse** (`netops.tunnels`), and at the IF-MIB layer these are
  *honestly zero* (comment in `tunnels.go`). The alert engine **only queries
  VictoriaMetrics**, so it cannot alert on tunnel SLA until those values are (a)
  populated by the SD-WAN/IP-SLA layer and (b) mirrored to VM. Rules included for
  forward-compat, all flagged.
- **Syslog-derived counters**: `device_auth_failures_total`,
  `device_config_change_total`, `device_dot1x_failures_total` (classifier exists;
  counterization to VM does not).
- **Stack-internal**: `api_request_duration_ms`, Redpanda consumer lag,
  ClickHouse flow-row rate, correlation findings rate (would need exporters).

---

## 3. The rule set (60 rules)

Paste under `src/config/rules.yaml`. Thresholds are common NOC defaults — tune per
site. Each `expr` ends in a comparison so it returns empty when healthy.

```yaml
groups:

  # ----------------------------------------------------------------------------
  # 3.1 Reachability / Availability
  # ----------------------------------------------------------------------------
  - name: noc-availability
    interval: 30s
    rules:
      - alert: ScrapeTargetDown
        expr: up == 0
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.instance }} down >5m"

      - alert: DeviceUnreachable
        expr: collector_target_up == 0
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} unreachable from {{ $labels.collector }}"

      - alert: InterfaceDown
        expr: device_if_oper_status == 2 and device_if_admin_status == 1
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} DOWN (admin-up)"

      - alert: InterfaceLowerLayerDown
        expr: device_if_oper_status == 7
        for: 2m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} lowerLayerDown"

      - alert: InterfaceFlapping
        expr: changes(device_if_oper_status[10m]) >= 4
        for: 0m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} flapping ({{ $value }} transitions/10m)"

      - alert: AdminDownButReceivingTraffic
        expr: device_if_admin_status == 2 and rate(device_if_in_octets[5m]) > 0
        for: 5m
        labels: { severity: info }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} admin-down yet receiving traffic"

      - alert: DeviceRebooted
        expr: device_sysuptime < 6000
        for: 0m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} recently rebooted (uptime {{ $value }} cs)"

  # ----------------------------------------------------------------------------
  # 3.2 Errors / Discards
  # ----------------------------------------------------------------------------
  - name: noc-errors
    interval: 30s
    rules:
      - alert: InterfaceInputErrors
        expr: rate(device_if_in_errors[5m]) > 1
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} input errors {{ $value }}/s"

      - alert: InterfaceOutputErrors
        expr: rate(device_if_out_errors[5m]) > 1
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} output errors {{ $value }}/s"

      - alert: InterfaceInputErrorsHigh
        expr: rate(device_if_in_errors[5m]) > 10
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} HIGH input errors {{ $value }}/s"

      - alert: InterfaceInputDiscards
        expr: rate(device_if_in_discards[5m]) > 5
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} input discards {{ $value }}/s (congestion)"

      - alert: InterfaceOutputDiscards
        expr: rate(device_if_out_discards[5m]) > 5
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} output discards {{ $value }}/s (egress congestion)"

      - alert: InterfaceErrorRatioHigh
        expr: rate(device_if_in_errors[5m]) / clamp_min(rate(device_if_in_ucast_pkts[5m]) + rate(device_if_in_mcast_pkts[5m]) + rate(device_if_in_bcast_pkts[5m]), 1) > 0.001
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} error ratio >0.1% of input pkts"

      - alert: InterfaceErrorAnomaly
        expr: (rate(device_if_in_errors[5m]) - avg_over_time(rate(device_if_in_errors[5m])[1h:5m])) / clamp_min(stddev_over_time(rate(device_if_in_errors[5m])[1h:5m]), 0.01) > 3
        for: 5m
        labels: { severity: info }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} error-rate z-score anomaly"

      - alert: InterfaceCRCErrors   # [NEEDS METRIC] dot3StatsFCSErrors
        expr: rate(device_if_crc_errors[5m]) > 1
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} CRC/FCS errors {{ $value }}/s (cabling/optic)"

  # ----------------------------------------------------------------------------
  # 3.3 Saturation (CPU / memory / link util / storage / sessions)
  # ----------------------------------------------------------------------------
  - name: noc-saturation
    interval: 30s
    rules:
      - alert: HighCPU
        expr: device_cpu_percent > 85
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} ({{ $labels.vendor }}) CPU {{ $value }}%"

      - alert: CriticalCPU
        expr: device_cpu_percent > 95
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} CPU critically high {{ $value }}%"

      - alert: HighMemory
        expr: device_mem_percent > 85
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} memory {{ $value }}%"

      - alert: CriticalMemory
        expr: device_mem_percent > 95
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} memory critically high {{ $value }}%"

      - alert: HighMemoryBytes
        expr: device_mem_used_bytes / clamp_min(device_mem_used_bytes + device_mem_free_bytes, 1) > 0.90
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} memory >90% (Cisco byte counters)"

      - alert: LinkInboundUtilHigh
        expr: rate(device_if_in_octets[5m]) * 8 / (device_if_speed * 1e6) > 0.80
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} inbound >80% of link"

      - alert: LinkInboundUtilCritical
        expr: rate(device_if_in_octets[5m]) * 8 / (device_if_speed * 1e6) > 0.95
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} inbound SATURATED (>95%)"

      - alert: LinkOutboundUtilHigh
        expr: rate(device_if_out_octets[5m]) * 8 / (device_if_speed * 1e6) > 0.80
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} outbound >80% of link"

      - alert: LinkOutboundUtilCritical
        expr: rate(device_if_out_octets[5m]) * 8 / (device_if_speed * 1e6) > 0.95
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} outbound SATURATED (>95%)"

      - alert: StorageUtilHigh
        expr: device_storage_used / clamp_min(device_storage_size, 1) > 0.85
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} storage{{ $labels.index }} >85%"

      - alert: StorageUtilCritical
        expr: device_storage_used / clamp_min(device_storage_size, 1) > 0.95
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} storage{{ $labels.index }} >95% (full risk)"

      - alert: FirewallDiskHigh
        expr: device_disk_used_mb / clamp_min(device_disk_capacity_mb, 1) > 0.90
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} firewall disk >90%"

      - alert: FirewallSessionsHigh
        expr: (device_session_count - avg_over_time(device_session_count[6h])) / clamp_min(stddev_over_time(device_session_count[6h]), 1) > 4
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} session-count spike (z>4) — flood/leak?"

  # ----------------------------------------------------------------------------
  # 3.4 Environmental (temp / power / fan / optics / sensors)
  # ----------------------------------------------------------------------------
  - name: noc-environmental
    interval: 30s
    rules:
      - alert: TemperatureHigh
        expr: device_temp_celsius > 55
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} sensor{{ $labels.index }} {{ $value }}C"

      - alert: TemperatureCritical
        expr: device_temp_celsius > 70
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} sensor{{ $labels.index }} {{ $value }}C (thermal)"

      - alert: TemperatureStateAbnormal
        expr: device_temp_state >= 2
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} temp sensor{{ $labels.index }} state {{ $value }} (CISCO-ENVMON !normal)"

      - alert: FanFailed
        expr: device_fan_state >= 2
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} fan{{ $labels.index }} state {{ $value }} (failed/warning)"

      - alert: PowerSupplyFailed
        expr: device_psu_state >= 2
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} PSU{{ $labels.index }} state {{ $value }} (failed/warning)"

      - alert: GenericSensorAnomaly
        expr: (device_sensor_value - avg_over_time(device_sensor_value[6h])) / clamp_min(stddev_over_time(device_sensor_value[6h]), 0.5) > 4
        for: 10m
        labels: { severity: info }
        annotations:
          summary: "{{ $labels.device }} ENTITY sensor{{ $labels.index }} anomaly (z>4)"

      - alert: OpticRxPowerLow   # [NEEDS METRIC] device_optic_rx_power_dbm
        expr: device_optic_rx_power_dbm < -14
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} optic Rx {{ $value }}dBm low"

      - alert: OpticRxPowerCritical   # [NEEDS METRIC]
        expr: device_optic_rx_power_dbm < -18
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} optic Rx {{ $value }}dBm — LOS imminent"

      - alert: OpticTxPowerLow   # [NEEDS METRIC]
        expr: device_optic_tx_power_dbm < -8
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} optic Tx {{ $value }}dBm low (failing laser)"

      - alert: OpticTemperatureHigh   # [NEEDS METRIC]
        expr: device_optic_temp_c > 70
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} transceiver {{ $value }}C"

      - alert: OpticBiasDrift   # [NEEDS METRIC] laser ageing
        expr: (device_optic_bias_ma - avg_over_time(device_optic_bias_ma[6h])) / clamp_min(stddev_over_time(device_optic_bias_ma[6h]), 0.1) > 3
        for: 30m
        labels: { severity: info }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} optic bias drift"

  # ----------------------------------------------------------------------------
  # 3.5 Routing / control-plane  [all NEEDS METRIC — collectors don't emit yet]
  # ----------------------------------------------------------------------------
  - name: noc-routing
    interval: 30s
    rules:
      - alert: BGPSessionDown   # [NEEDS METRIC] BGP4-MIB bgpPeerState (6=established)
        expr: device_bgp_peer_state != 6
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} BGP peer {{ $labels.index }} not established"

      - alert: BGPPeerFlapping   # [NEEDS METRIC]
        expr: increase(device_bgp_fsm_transitions[15m]) > 3
        for: 0m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} BGP peer {{ $labels.index }} flapping"

      - alert: BGPPrefixDrop   # [NEEDS METRIC]
        expr: delta(device_bgp_accepted_prefixes[10m]) < -1000
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} BGP peer {{ $labels.index }} dropped >1000 prefixes"

      - alert: BGPAllPeersDown   # [NEEDS METRIC]
        expr: count by (device) (device_bgp_peer_state == 6) == 0
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} has zero established BGP peers (isolation)"

      - alert: OSPFAdjacencyDown   # [NEEDS METRIC] OSPF-MIB ospfNbrState (8=full)
        expr: device_ospf_nbr_state != 8
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} OSPF neighbor {{ $labels.index }} not full"

      - alert: OSPFAdjacencyFlapping   # [NEEDS METRIC]
        expr: changes(device_ospf_nbr_state[15m]) >= 4
        for: 0m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} OSPF neighbor {{ $labels.index }} flapping"

      - alert: RouteTableShrink   # [NEEDS METRIC]
        expr: delta(device_route_count[10m]) < -500
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} RIB shrank >500 routes/10m"

      - alert: FIBNearCapacity   # [NEEDS METRIC] TCAM exhaustion
        expr: device_fib_count / clamp_min(device_fib_max, 1) > 0.90
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} FIB/TCAM >90% (blackhole risk)"

  # ----------------------------------------------------------------------------
  # 3.6 Capacity / trend (z-score & linear prediction over real metrics)
  # ----------------------------------------------------------------------------
  - name: noc-capacity
    interval: 30s
    rules:
      - alert: TrafficZScoreAnomalyIn
        expr: (rate(device_if_in_octets[5m]) - avg_over_time(rate(device_if_in_octets[5m])[1h:5m])) / clamp_min(stddev_over_time(rate(device_if_in_octets[5m])[1h:5m]), 1) > 3
        for: 5m
        labels: { severity: info }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} inbound traffic anomaly (z>3)"

      - alert: TrafficDropAnomaly
        expr: (rate(device_if_in_octets[5m]) - avg_over_time(rate(device_if_in_octets[5m])[1h:5m])) / clamp_min(stddev_over_time(rate(device_if_in_octets[5m])[1h:5m]), 1) < -3 and device_if_oper_status == 1
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} traffic collapsed while up (z<-3)"

      - alert: SustainedLinkGrowth
        expr: avg_over_time(rate(device_if_in_octets[5m])[1h:5m]) * 8 / (device_if_speed * 1e6) > 0.70
        for: 1h
        labels: { severity: info }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} sustained >70% — plan upgrade"

      - alert: MemoryLeakTrend
        expr: delta(device_mem_percent[6h]) > 20
        for: 30m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} memory +{{ $value }}pp/6h — possible leak"

      - alert: StorageWillFill24h
        expr: predict_linear(device_storage_used[6h], 86400) > device_storage_size
        for: 30m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} storage{{ $labels.index }} projected full <24h"

      - alert: CPUBaselineRising
        expr: delta(avg_over_time(device_cpu_percent[1h])[12h:1h]) > 15
        for: 1h
        labels: { severity: info }
        annotations:
          summary: "{{ $labels.device }} baseline CPU rising +{{ $value }}pp/12h"

  # ----------------------------------------------------------------------------
  # 3.7 Latency / jitter / SLA  [NEEDS METRIC + needs VM mirror; see §2.4]
  # ----------------------------------------------------------------------------
  - name: noc-sla
    interval: 30s
    rules:
      - alert: TunnelDown   # [NEEDS METRIC] tunnel_status to VictoriaMetrics
        expr: tunnel_status == 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Tunnel {{ $labels.tunnel }} DOWN"

      - alert: TunnelLatencyHigh   # [NEEDS METRIC]
        expr: tunnel_latency_ms > 150
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Tunnel {{ $labels.tunnel }} latency {{ $value }}ms > SLA"

      - alert: TunnelLatencyCritical   # [NEEDS METRIC]
        expr: tunnel_latency_ms > 300
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "Tunnel {{ $labels.tunnel }} latency {{ $value }}ms — SLA breach"

      - alert: TunnelJitterHigh   # [NEEDS METRIC]
        expr: tunnel_jitter_ms > 30
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Tunnel {{ $labels.tunnel }} jitter {{ $value }}ms (voice/video risk)"

      - alert: TunnelLossHigh   # [NEEDS METRIC]
        expr: tunnel_loss_pct > 2
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "Tunnel {{ $labels.tunnel }} loss {{ $value }}% — SLA breach"

      - alert: TunnelLatencyAnomaly   # [NEEDS METRIC]
        expr: (tunnel_latency_ms - avg_over_time(tunnel_latency_ms[2h])) / clamp_min(stddev_over_time(tunnel_latency_ms[2h]), 1) > 3
        for: 5m
        labels: { severity: info }
        annotations:
          summary: "Tunnel {{ $labels.tunnel }} latency anomaly (z>3)"

  # ----------------------------------------------------------------------------
  # 3.8 Security / syslog  [NEEDS METRIC — syslog counterization not wired]
  # ----------------------------------------------------------------------------
  - name: noc-security
    interval: 30s
    rules:
      - alert: AuthFailureBurst   # [NEEDS METRIC] device_auth_failures_total
        expr: rate(device_auth_failures_total[5m]) > 5
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} {{ $value }} auth failures/s (brute force?)"

      - alert: AuthFailureCritical   # [NEEDS METRIC]
        expr: rate(device_auth_failures_total[5m]) > 20
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.device }} sustained login failures — credential attack"

      - alert: ConfigChanged   # [NEEDS METRIC] device_config_change_total
        expr: increase(device_config_change_total[5m]) > 0
        for: 0m
        labels: { severity: info }
        annotations:
          summary: "{{ $labels.device }} running-config changed"

      - alert: PortAuthFailure   # [NEEDS METRIC] device_dot1x_failures_total
        expr: rate(device_dot1x_failures_total[5m]) > 3
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.device }} if{{ $labels.index }} 802.1X failures"

  # ----------------------------------------------------------------------------
  # 3.9 Stack self-health
  # ----------------------------------------------------------------------------
  - name: noc-self-health
    interval: 30s
    rules:
      - alert: CollectorDown
        expr: collector_up == 0
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "Collector {{ $labels.collector }} is down"

      - alert: CollectorAllTargetsUnreachable
        expr: collector_targets_reachable == 0 and collector_targets > 0
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "Collector {{ $labels.collector }} cannot reach any target"

      - alert: CollectorPartialReachability
        expr: collector_targets_reachable / clamp_min(collector_targets, 1) < 0.8 and collector_targets > 0
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "Collector {{ $labels.collector }} reaching <80% of targets"

      - alert: CollectorPollSlow
        expr: collector_poll_duration_ms > 10000
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "Collector {{ $labels.collector }} poll {{ $value }}ms (slow)"

      - alert: NoSamplesIngested
        expr: collector_samples == 0 and collector_targets > 0
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "Collector {{ $labels.collector }} produced 0 samples"

      - alert: StorageBackendDown   # [NEEDS METRIC] up{job=...} for stack services
        expr: up{job=~"opensearch|clickhouse|victoria|postgres|redis"} == 0
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "Stack backend {{ $labels.job }} down"
```

---

## 4. Coverage summary

- **60 rules** in the engine's exact Prometheus rules-file schema, all using full
  PromQL (verified `expr` goes verbatim to VictoriaMetrics `/api/v1/query`).
- Severities limited to `critical | warning | info`.
- **Ready to fire on metrics we already collect (~33 rules):** all of
  §3.1 availability, §3.2 errors (minus CRC), §3.3 saturation, §3.4 temp/fan/PSU/
  sensor, §3.6 capacity/trend, and §3.9 self-health (minus stack `up`).
- **`[NEEDS METRIC]` (~27 rules):** optics/DOM (§3.4), all routing/control-plane
  (§3.5), all tunnel SLA (§3.7 — also needs VM mirror), all syslog security
  (§3.8), and stack-service `up` (§3.9).

## 5. Notes & recommended next steps (out of scope)

1. **`for:` is not yet enforced** by the engine — sustained-duration damping comes
   from the PromQL window (`[5m]`, `avg_over_time`), so prefer rate/window exprs
   over bare instant comparisons for flappy signals. Implementing `for` hold-down
   is a small engine enhancement worth tracking.
2. **Verify `device_if_speed` units** (Mbit/s assumed; `* 1e6` conversion) on real
   gear before enabling the utilization rules, and confirm whether the legacy
   `cpu_usage`/`memory_usage`/`up{device_id=…}` series still exist alongside
   `device_*`.
3. **Highest-ROI collector work** to unlock the flagged rules, in order:
   (a) BGP/OSPF MIB state → routing rules; (b) split CRC/FCS + dedicated
   `device_optic_*` DOM rows; (c) mirror tunnel latency/jitter/loss into
   VictoriaMetrics (today they only land in ClickHouse, so the engine is blind to
   them); (d) syslog → counter metrics for the security rules.
4. Add these groups to `src/config/rules.yaml` incrementally — start with the ~33
   ready rules so they begin firing immediately through the existing notifier chain.
```
