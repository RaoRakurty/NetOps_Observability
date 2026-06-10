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

type Cov = { device: Device; snmp: boolean; flows: boolean; syslog: boolean; traps: boolean };
const FRESH_MS = 15 * 60_000;

// A small status dot for a coverage cell.
function Dot({ on, label }: { on: boolean; label: string }) {
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

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const fromIso = new Date(Date.now() - FRESH_MS).toISOString();
        const end = Math.floor(Date.now() / 1000);
        const [devices, snmpRes, flowRes, sysRes, trapRes] = await Promise.all([
          api.devices(),
          api.metricsQueryRange("device_sysuptime", end - 900, end, 300).catch(() => null),
          api.flowsTopN("device", 900, 500).catch(() => null),
          api.searchLogs({ query: "*", signal: "syslog", from: fromIso, size: 500 }).catch(() => null),
          api.searchLogs({ query: "*", signal: "snmptrap", from: fromIso, size: 500 }).catch(() => null),
        ]);
        if (!alive) return;

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

        const cov: Cov[] = (devices ?? []).map((d) => ({
          device: d,
          snmp: snmpSet.has(d.id) || snmpSet.has(d.name),
          flows: flowSet.has(d.address),
          syslog: has(sysSet, d),
          traps: has(trapSet, d),
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
    const t = { devices: rows.length, snmp: 0, flows: 0, syslog: 0, full: 0, none: 0 };
    for (const r of rows) {
      if (r.snmp) t.snmp++;
      if (r.flows) t.flows++;
      if (r.syslog) t.syslog++;
      const n = [r.snmp, r.flows, r.syslog, r.traps].filter(Boolean).length;
      if (n === 4) t.full++;
      if (n === 0) t.none++;
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
      sortValue: (r) => [r.snmp, r.flows, r.syslog, r.traps].filter(Boolean).length,
      render: (r) => {
        const n = [r.snmp, r.flows, r.syslog, r.traps].filter(Boolean).length;
        const tone = n === 0 ? "bad" : n >= 3 ? "good" : "warn";
        return <span className={`badge ${tone}`}>{n}/4</span>;
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
          <Stat label="No data" value={totals.none} tone={totals.none > 0 ? "bad" : "good"} />
        </StatStrip>
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
