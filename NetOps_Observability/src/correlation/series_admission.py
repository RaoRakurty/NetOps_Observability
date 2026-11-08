# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Same semantics before samples meet — P6 PR-C2, engine stage [2].

Owner decision 2026-11-07 (NMS_DEVICE_IDENTITY_2026-11-01.md §8): SNMP and a
controller feeding one device keep ONE metric series. Interleaving two sources
in one CUSUM series is only sound when both mean the same thing by a sample —
the same unit and the same semantics (a running total vs a level, percent vs a
ratio). A sample that disagrees is not admitted; averaged in, the interleave
itself trips CUSUM.

`SERIES_SEMANTICS` is the canonical table for the RCA metric families: the
families every producer of `netops.metrics` may send (the SNMP allowlist
`rcaMetricFamilies` in `collectors/metric_events.go`, which the gNMI shaper and
vManage's realtime lane mirror). Each producer DECLARES the unit on the wire
(`MetricEvent.Unit` → `ev["unit"]`). `test_series_admission_p6.py` parses the
Go source — the SNMP allowlist AND every unit the vManage realtime transforms
stamp — and fails on any drift, so the table cannot silently disagree with the
producers it judges.

Semantics:
  * ``counter`` — a running total; `counter_rate.CounterRates` turns it into a
    per-second rate per (series, source) BEFORE admission, so both sources'
    samples meet as rates (tracker 379);
  * ``gauge``   — an instantaneous level;
  * ``state``   — an enumerated status (IF-MIB / BGP4-MIB / OSPF-MIB values).

Pure: no IO, no clock, no flag. `main.handle_metric` decides when it applies.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SeriesSemantics:
    """What one canonical metric means: its RCA family, unit and kind."""

    family: str
    unit: str
    semantics: str  # counter | gauge | state


COUNTER, GAUGE, STATE = "counter", "gauge", "state"

SERIES_SEMANTICS: dict[str, SeriesSemantics] = {
    # Interface (IF-MIB / EtherLike-MIB; vManage interface realtime).
    "device_if_oper_status": SeriesSemantics("interface", "state", STATE),
    "device_if_admin_status": SeriesSemantics("interface", "state", STATE),
    "device_if_in_octets": SeriesSemantics("interface", "bytes", COUNTER),
    "device_if_out_octets": SeriesSemantics("interface", "bytes", COUNTER),
    "device_if_in_errors": SeriesSemantics("interface", "errors", COUNTER),
    "device_if_out_errors": SeriesSemantics("interface", "errors", COUNTER),
    "device_if_in_discards": SeriesSemantics("interface", "discards", COUNTER),
    "device_if_out_discards": SeriesSemantics("interface", "discards", COUNTER),
    "device_if_fcs_errors": SeriesSemantics("interface", "fcs_errors", COUNTER),
    "device_if_speed": SeriesSemantics("interface", "mbps", GAUGE),
    # BGP (BGP4-MIB).
    "device_bgp_peer_state": SeriesSemantics("bgp", "state", STATE),
    "device_bgp_fsm_transitions": SeriesSemantics("bgp", "transitions", COUNTER),
    # IGP adjacency (OSPF-MIB; IS-IS via gNMI).
    "device_ospf_nbr_state": SeriesSemantics("igp", "state", STATE),
    "device_isis_adj_state": SeriesSemantics("igp", "state", STATE),
    # Device resource (HOST-RESOURCES / vendor MIBs; vManage system realtime).
    "device_cpu_percent": SeriesSemantics("device_resource", "percent", GAUGE),
    "device_mem_percent": SeriesSemantics("device_resource", "percent", GAUGE),
    "device_temp_celsius": SeriesSemantics("device_resource", "celsius", GAUGE),
}


def unit_contradicts(metric: str, unit: object) -> bool:
    """True when a sample DECLARES a unit that contradicts the canonical table.

    No opinion — False — when the metric is not an RCA family (it is judged by
    nothing here) or the sample declares no unit (a legacy producer cannot
    contradict what it never said). Comparison is case- and space-insensitive;
    a non-string unit is a contradiction (zero trust: a declared unit that is
    not even text is not a match)."""
    sem = SERIES_SEMANTICS.get(metric)
    if sem is None or unit is None:
        return False
    if not isinstance(unit, str):
        return True
    declared = unit.strip().lower()
    return bool(declared) and declared != sem.unit
