import { useEffect, useMemo, useState } from "react";
import { api, WanInterfaceRow } from "../services/api";
import DataTable, { Column, Sev } from "../components/DataTable";
import { latSev, lossSev } from "../tabs/Tunnels";

// WAN Circuit Utilization — one row per WAN-router interface = its circuit.
//
// The whole row is resolved server-side (GET /api/wan/interfaces): live
// utilization/oper status (device_if_*), the circuit far-end (remote WAN
// interface), and the SLA — latency/jitter/loss/QoE — resolved through the
// measurement-source ladder (STAMP → wan-echo → ICMP → traceroute) with a
// per-row SOURCE badge showing HOW it was measured. SLA cells show an honest
// "—" where no circuit exists yet (single hub/spoke not designated) or no probe
// has measured it — never a fabricated number.

const jitSev = (ms: number): Sev => (ms < 30 ? "ok" : ms < 60 ? "warn" : "crit");
const qoeSev = (q: number): Sev => (q >= 8 ? "ok" : q >= 5 ? "warn" : "crit");
const utilSev = (pct: number): Sev => (pct < 70 ? "ok" : pct < 90 ? "warn" : "crit");

function fmtBps(v: number): string {
  if (!isFinite(v) || v <= 0) return "0";
  const u = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
  let i = 0;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

const dash = <span className="mini-meta">—</span>;

export default function WanCircuits() {
  const [rows, setRows] = useState<WanInterfaceRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [q, setQ] = useState("");

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const res = await api.wanInterfaces();
        if (alive) { setRows(res?.interfaces ?? []); setErr(null); setLoaded(true); }
      } catch (e) {
        if (alive) { setErr((e as Error).message); setLoaded(true); }
      }
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((r) =>
      `${r.device} ${r.interface} ${r.remote_device ?? ""} ${r.source_label ?? ""}`.toLowerCase().includes(needle));
  }, [rows, q]);

  const rowKey = (r: WanInterfaceRow) => `${r.device}#${r.interface}`;

  const roleChip = (r: WanInterfaceRow) =>
    <span className={`badge ${r.role === "hub" ? "accent" : ""}`} title={`role: ${r.role} (${r.role_source})`}>{r.role}</span>;

  const utilCell = (r: WanInterfaceRow) => {
    if (!r.has_util) return dash;
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 8, justifyContent: "flex-end", width: "100%" }}>
        <span style={{ position: "relative", width: 52, height: 6, borderRadius: 3, background: "var(--panel-border)", overflow: "hidden" }}>
          <span style={{ position: "absolute", inset: 0, width: `${Math.min(100, r.util_pct)}%`, borderRadius: 3,
            background: r.util_pct < 70 ? "var(--ok, #22c55e)" : r.util_pct < 90 ? "var(--warn, #f59e0b)" : "var(--crit, #ef4444)" }} />
        </span>
        <span style={{ fontVariantNumeric: "tabular-nums", minWidth: 40, textAlign: "right" }}>{r.util_pct.toFixed(1)}%</span>
      </span>
    );
  };

  // SLA cell: honest dash when the field has no measurement.
  const sla = (has: (r: WanInterfaceRow) => boolean, val: (r: WanInterfaceRow) => number,
    fmt: (n: number) => string, sev: (n: number) => Sev) => ({
    sev: (r: WanInterfaceRow) => (has(r) ? sev(val(r)) : undefined),
    sortValue: (r: WanInterfaceRow) => (has(r) ? val(r) : -1),
    render: (r: WanInterfaceRow) => (has(r) ? fmt(val(r)) : dash),
  });

  const columns = useMemo<Column<WanInterfaceRow>[]>(() => [
    { key: "device", header: "Router", width: "13%", sortable: true,
      text: (r) => r.device, sortValue: (r) => r.device, render: (r) => <span title={r.device}>{r.device}</span> },
    { key: "iface", header: "Interface", width: "13%", sortable: true,
      text: (r) => r.interface, sortValue: (r) => r.interface,
      render: (r) => <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
        <span style={{ fontFamily: "var(--font-mono, monospace)" }}>{r.interface}</span>{roleChip(r)}</span> },
    { key: "util", header: "Utilization", width: 122, align: "right", sortable: true,
      sortValue: (r) => (r.has_util ? r.util_pct : -1), sev: (r) => (r.has_util ? utilSev(r.util_pct) : undefined), render: utilCell },
    { key: "in", header: "↓ In", width: 84, align: "right", sortable: true,
      sortValue: (r) => r.in_bps, render: (r) => (r.has_util ? fmtBps(r.in_bps) : dash) },
    { key: "out", header: "↑ Out", width: 84, align: "right", sortable: true,
      sortValue: (r) => r.out_bps, render: (r) => (r.has_util ? fmtBps(r.out_bps) : dash) },
    { key: "remote", header: "Circuit → far-end", width: "16%", sortable: true,
      text: (r) => `${r.remote_device ?? ""} ${r.remote_if ?? ""}`, sortValue: (r) => r.remote_device ?? "",
      render: (r) => r.has_circuit
        ? <span title={`${r.remote_device} · ${r.remote_if} · ${r.remote_addr}`}>{r.remote_device}
            <span className="mini-meta" style={{ marginLeft: 6, fontFamily: "var(--font-mono, monospace)" }}>{r.remote_if}</span></span>
        : dash },
    { key: "latency", header: "Latency", width: 90, align: "right", sortable: true,
      ...sla((r) => r.has_latency, (r) => r.latency_ms, (n) => `${n.toFixed(1)} ms`, latSev) },
    { key: "jitter", header: "Jitter", width: 84, align: "right", sortable: true,
      ...sla((r) => r.has_jitter, (r) => r.jitter_ms, (n) => `${n.toFixed(1)} ms`, jitSev) },
    { key: "loss", header: "Loss", width: 78, align: "right", sortable: true,
      ...sla((r) => r.has_loss, (r) => r.loss_pct, (n) => `${n.toFixed(2)} %`, lossSev) },
    { key: "qoe", header: "QoE", width: 64, align: "right", sortable: true,
      ...sla((r) => r.has_qoe, (r) => r.qoe, (n) => n.toFixed(1), qoeSev) },
    { key: "source", header: "Measured by", width: 110, sortable: true,
      text: (r) => r.source_label ?? "", sortValue: (r) => r.source_label ?? "",
      render: (r) => (r.source_label
        ? <span className="badge" title={`measurement source: ${r.source_label}`}>{r.source_label}</span> : dash) },
    { key: "status", header: "Status", width: 80, sortable: true,
      text: (r) => (r.has_oper ? (r.oper_up ? "up" : "down") : ""), sortValue: (r) => (r.has_oper ? (r.oper_up ? 1 : 0) : -1),
      render: (r) => (r.has_oper ? <span className={`badge ${r.oper_up ? "good" : "bad"}`}>{r.oper_up ? "up" : "down"}</span> : dash) },
  ], []);

  const down = rows.filter((r) => r.has_oper && !r.oper_up).length;
  const totIn = rows.reduce((a, r) => a + (r.has_util ? r.in_bps : 0), 0);
  const totOut = rows.reduce((a, r) => a + (r.has_util ? r.out_bps : 0), 0);
  const peak = rows.filter((r) => r.has_util).reduce((m, r) => Math.max(m, r.util_pct), 0);
  const measured = rows.filter((r) => r.has_latency || r.has_loss).length;

  return (
    <div className="card">
      <h2>WAN Circuit Utilization</h2>
      <p className="mini-meta" style={{ marginTop: -6, marginBottom: 14 }}>
        One row per WAN-router interface = its circuit to the remote interface.
        Utilization and status are live; latency / jitter / loss / QoE resolve
        through the active-measurement ladder (STAMP → echo → ICMP → traceroute),
        and the <b>Measured by</b> column shows which produced each row.
      </p>
      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className={`stat ${rows.length ? "s-good" : "s-muted"}`}>
          <span className="stat-label">WAN interfaces</span>
          <span className="stat-value">{rows.length}</span>
          <span className="stat-sub">{measured} with measured SLA</span>
        </div>
        <div className="stat s-muted">
          <span className="stat-label">Throughput</span>
          <span className="stat-value" style={{ fontSize: 26 }}>{fmtBps(totIn + totOut)}</span>
          <span className="stat-sub">↓ {fmtBps(totIn)} · ↑ {fmtBps(totOut)}</span>
        </div>
        <div className={`stat ${rows.length ? (peak < 70 ? "s-good" : peak < 90 ? "s-warn" : "s-bad") : "s-muted"}`}>
          <span className="stat-label">Peak utilization</span>
          <span className="stat-value">{rows.length ? peak.toFixed(1) : "—"}{rows.length ? <span style={{ fontSize: 20, color: "var(--muted)" }}> %</span> : null}</span>
          <span className="stat-sub">busiest interface</span>
        </div>
        <div className={`stat ${down ? "s-bad" : "s-muted"}`}>
          <span className="stat-label">Interfaces down</span>
          <span className="stat-value">{down}</span>
          <span className="stat-sub">{rows.length ? (down ? `${down} down` : "all up") : "none reported"}</span>
        </div>
      </div>

      <div className="dt-toolbar">
        <label className="dt-search">
          <span className="omni-icon">⌕</span>
          <input placeholder="Search routers, interfaces, far-ends…" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <span className="dt-count">{filtered.length} of {rows.length} interfaces</span>
      </div>

      {loaded && rows.length === 0 ? (
        <div className="empty">
          No WAN interfaces yet. WAN routers are the devices matched by the WAN
          topology policy (default name pattern <code>wan|edge|gw|dmz</code>);
          rows appear once they export <code>device_if_*</code> metrics. Designate
          a <b>hub</b> site to generate circuits and populate the SLA columns.
        </div>
      ) : (
        <DataTable<WanInterfaceRow>
          rows={filtered}
          columns={columns}
          rowKey={rowKey}
          height="60vh"
          ariaLabel="WAN circuits"
          initialSort={{ key: "util", dir: "desc" }}
          empty="No WAN interfaces match this filter."
        />
      )}
    </div>
  );
}
