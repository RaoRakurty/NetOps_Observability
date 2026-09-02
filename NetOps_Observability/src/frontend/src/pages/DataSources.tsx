import { useEffect, useMemo, useState } from "react";
import { api, Device } from "../services/api";
import { StatStrip, Stat } from "../components/ui";
import DataTable, { Column } from "../components/DataTable";
import { Group, Panel } from "../components/board/panels";

// Data Sources — per-device collection coverage. The robustness view for
// onboarding a from-zero (no-telemetry) enterprise: for each device it shows
// which acquisition methods are actually delivering data right now — SNMP metrics,
// flows (NetFlow/IPFIX/sFlow), syslog, traps — so an operator can see coverage
// grow as they enable each (agentless) source and spot exactly what's missing.
// Derived from data already in the stores (VM metrics + ClickHouse flows +
// OpenSearch logs/traps + the device inventory) — no N×method queries.

// Tri — a coverage cell is three-state on purpose: true (receiving), false (the
// store answered and this device is absent) and null (the QUERY failed, so this
// device's coverage is UNKNOWN). Collapsing null into false reported a
// VictoriaMetrics / OpenSearch outage as "no telemetry from any device" — a
// definitive negative claim about the whole fleet that nothing supported.
type Tri = boolean | null;
type Cov = { device: Device; snmp: Tri; flows: Tri; syslog: Tri; traps: Tri };
const FRESH_MS = 15 * 60_000;

// A small status dot for a coverage cell.
function Dot({ on, label }: { on: Tri; label: string }) {
  if (on === null) {
    return (
      <span title={`${label}: query unavailable — coverage unknown`} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
        <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--warn)" }} />
        <span style={{ fontSize: 12, color: "var(--warn)" }}>?</span>
      </span>
    );
  }
  return (
    <span title={on ? `${label}: receiving` : `${label}: no data`} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <span style={{ width: 8, height: 8, borderRadius: "50%", background: on ? "var(--good)" : "var(--border-strong)" }} />
      <span style={{ fontSize: 12, color: on ? "var(--fg)" : "var(--fg-subtle)" }}>{on ? "yes" : "—"}</span>
    </span>
  );
}

export default function DataSources() {
  const [rows, setRows] = useState<Cov[]>([]);
  const [err, setErr] = useState<string | null>(null);
  // Which query PLANES failed this poll. Their columns render "unknown", and the
  // page says which read is down — an operator must never conclude "the fleet
  // sends nothing" from a broken query side.
  const [downPlanes, setDownPlanes] = useState<string[]>([]);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const fromIso = new Date(Date.now() - FRESH_MS).toISOString();
        const end = Math.floor(Date.now() / 1000);
        const settled = await Promise.all([
          api.devices(),
          Promise.allSettled([
            api.metricsQueryRange("device_sysuptime", end - 900, end, 300),
            api.flowsTopN("device", 900, 500),
            api.searchLogs({ query: "*", signal: "syslog", from: fromIso, size: 500 }),
            api.searchLogs({ query: "*", signal: "snmptrap", from: fromIso, size: 500 }),
          ]),
        ]);
        if (!alive) return;
        const devices = settled[0];
        const [snmpS, flowS, sysS, trapS] = settled[1];
        const ok = <T,>(r: PromiseSettledResult<T>): T | null => (r.status === "fulfilled" ? r.value : null);
        const snmpRes = ok(snmpS), flowRes = ok(flowS), sysRes = ok(sysS), trapRes = ok(trapS);
        const down: string[] = [];
        if (snmpS.status === "rejected") down.push("SNMP metrics");
        if (flowS.status === "rejected") down.push("flows");
        if (sysS.status === "rejected") down.push("syslog");
        if (trapS.status === "rejected") down.push("traps");
        setDownPlanes(down);

        // SNMP: device labels with a fresh device_sysuptime series.
        const snmpSet = new Set<string>();
        for (const s of snmpRes?.data?.result ?? []) if (s.metric?.device) snmpSet.add(s.metric.device);
        // Flows: exporter (sampler) IPs seen in recent flows.
        const flowSet = new Set<string>();
        for (const r of (flowRes?.data as any[]) ?? []) if (r.k) flowSet.add(String(r.k));
        // Syslog / traps: distinct host/agent identifiers in recent docs.
        const hostSet = (res: any): Set<string> => {
          const out = new Set<string>();
          for (const h of res?.hits?.hits ?? []) {
            const s = h._source || {};
            for (const k of ["host", "hostname", "device", "device.ip", "device_ip", "agent", "source"]) {
              const v = s[k];
              if (v) out.add(String(v).toLowerCase());
            }
          }
          return out;
        };
        const sysSet = hostSet(sysRes);
        const trapSet = hostSet(trapRes);

        const has = (set: Set<string>, d: Device) =>
          set.has((d.name || "").toLowerCase()) || set.has((d.address || "").toLowerCase());

        // A failed plane yields null (unknown), never false (definitively silent).
        const cov: Cov[] = (devices ?? []).map((d) => ({
          device: d,
          snmp: snmpRes === null ? null : snmpSet.has(d.id) || snmpSet.has(d.name),
          flows: flowRes === null ? null : flowSet.has(d.address),
          syslog: sysRes === null ? null : has(sysSet, d),
          traps: trapRes === null ? null : has(trapSet, d),
        }));
        setRows(cov);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const totals = useMemo(() => {
    const t = { devices: rows.length, snmp: 0, flows: 0, syslog: 0, full: 0, none: 0, unknown: 0 };
    for (const r of rows) {
      const cells = [r.snmp, r.flows, r.syslog, r.traps];
      if (r.snmp === true) t.snmp++;
      if (r.flows === true) t.flows++;
      if (r.syslog === true) t.syslog++;
      const n = cells.filter((c) => c === true).length;
      const u = cells.filter((c) => c === null).length;
      if (u > 0) t.unknown++;
      if (n === 4) t.full++;
      // "No data" is only true when every plane ANSWERED and said nothing.
      if (n === 0 && u === 0) t.none++;
    }
    return t;
  }, [rows]);

  const cols = useMemo<Column<Cov>[]>(() => [
    { key: "name", header: "Device", sortable: true, text: (r) => r.device.name, render: (r) => r.device.name },
    { key: "address", header: "Address", sortable: true, text: (r) => r.device.address, render: (r) => <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{r.device.address}</span> },
    { key: "snmp", header: "SNMP metrics", sortable: true, sortValue: (r) => (r.snmp ? 1 : 0), render: (r) => <Dot on={r.snmp} label="SNMP" /> },
    { key: "flows", header: "Flows", sortable: true, sortValue: (r) => (r.flows ? 1 : 0), render: (r) => <Dot on={r.flows} label="Flows" /> },
    { key: "syslog", header: "Syslog", sortable: true, sortValue: (r) => (r.syslog ? 1 : 0), render: (r) => <Dot on={r.syslog} label="Syslog" /> },
    { key: "traps", header: "Traps", sortable: true, sortValue: (r) => (r.traps ? 1 : 0), render: (r) => <Dot on={r.traps} label="Traps" /> },
    {
      key: "cov", header: "Coverage", sortable: true,
      sortValue: (r) => [r.snmp, r.flows, r.syslog, r.traps].filter((c) => c === true).length,
      render: (r) => {
        const cells = [r.snmp, r.flows, r.syslog, r.traps];
        const n = cells.filter((c) => c === true).length;
        const u = cells.filter((c) => c === null).length;
        // With an unknown cell the score is a floor, not a verdict — never "bad".
        const tone = u > 0 ? "warn" : n === 0 ? "bad" : n >= 3 ? "good" : "warn";
        return <span className={`badge ${tone}`} title={u > 0 ? `${u} source${u === 1 ? "" : "s"} could not be queried` : undefined}>{n}/4{u > 0 ? "?" : ""}</span>;
      },
    },
  ], []);

  return (
    <div className="dm-board">
      <Group title="Collection coverage" hue="#3B82F6">
        <StatStrip>
          <Stat label="Devices" value={totals.devices} />
          <Stat label="SNMP metrics" value={totals.snmp} tone={totals.snmp > 0 ? "good" : "bad"} />
          <Stat label="Flows" value={totals.flows} tone={totals.flows > 0 ? "good" : ""} />
          <Stat label="Syslog" value={totals.syslog} tone={totals.syslog > 0 ? "good" : ""} />
          <Stat label="Nothing arriving" value={totals.none} tone={totals.none > 0 ? "bad" : "good"} />
          {totals.unknown > 0 && <Stat label="Unknown" value={totals.unknown} tone="warn" />}
        </StatStrip>
        {downPlanes.length > 0 && (
          <p className="empty" role="alert" style={{ margin: 0, color: "var(--warn)" }}>
            <strong>Coverage is incomplete:</strong> {downPlanes.join(", ")} could not be queried.
            Those columns show “?” — the devices may well be sending data. This is a QUERY-side
            failure, not evidence that telemetry stopped.
          </p>
        )}
        <p className="mini-meta" style={{ margin: 0 }}>
          Coverage of agentless sources over the last 15 min. Start with <strong>SNMP</strong> (read-only v2c/v3) for device &amp; interface health,
          add <strong>NetFlow/IPFIX/sFlow</strong> for traffic, and forward <strong>syslog/traps</strong> for events. Streaming telemetry (gNMI/NETCONF) is an optional upgrade.
        </p>
        <Panel title={`Devices (${rows.length})`}>
          {err ? (
            <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
          ) : rows.length === 0 ? (
            <div className="empty">No devices discovered yet. Add devices under Infrastructure → Devices to begin.</div>
          ) : (
            <DataTable<Cov> rows={rows} columns={cols} rowKey={(r) => r.device.id} height={Math.min(520, 44 + rows.length * 30)} ariaLabel="Data source coverage" initialSort={{ key: "cov", dir: "asc" }} />
          )}
        </Panel>
      </Group>
    </div>
  );
}
