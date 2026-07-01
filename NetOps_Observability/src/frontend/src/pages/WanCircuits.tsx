import { useEffect, useMemo, useState } from "react";
import { api, WanInterfaceRow } from "../services/api";
import DataTable, { Column, Sev } from "../components/DataTable";
import { latSev, lossSev } from "../tabs/Tunnels";

// WAN Interface Metrics — one row per WAN (or WAN-connected) interface.
//
// No hub/spoke. The whole row is resolved server-side (GET /api/wan/interfaces):
// live utilization/oper status (device_if_*), the interface's DERIVED measurement
// TARGET (directly-connected peer via LLDP in the lab; ISP next-hop or a public-DNS
// reachability anchor in prod), and the SLA — latency/jitter/loss/QoE/availability —
// resolved through the 5-tier measurement-source ranking with a per-row tier +
// method badge. SLA cells show an honest "—" where no target or no probe has
// measured it — never a fabricated number.

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
      `${r.device} ${r.interface} ${r.remote_device ?? ""} ${r.target ?? ""} ${r.target_label ?? ""} ${r.source_label ?? ""}`.toLowerCase().includes(needle));
  }, [rows, q]);

  const rowKey = (r: WanInterfaceRow) => `${r.device}#${r.interface}`;

  // How the measurement target was derived (provenance chip).
  const targetKindLabel: Record<string, string> = {
    direct_peer: "Peer", next_hop: "Next-hop", anchor: "Anchor",
  };
  const connectedChip = (r: WanInterfaceRow) =>
    r.connected_to_wan
      ? <span className="badge" title="This interface is directly connected to a WAN device (measured too).">linked</span>
      : null;

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
        <span style={{ fontFamily: "var(--font-mono, monospace)" }}>{r.interface}</span>{connectedChip(r)}</span> },
    { key: "util", header: "Utilization", width: 122, align: "right", sortable: true,
      sortValue: (r) => (r.has_util ? r.util_pct : -1), sev: (r) => (r.has_util ? utilSev(r.util_pct) : undefined), render: utilCell },
    { key: "in", header: "↓ In", width: 84, align: "right", sortable: true,
      sortValue: (r) => r.in_bps, render: (r) => (r.has_util ? fmtBps(r.in_bps) : dash) },
    { key: "out", header: "↑ Out", width: 84, align: "right", sortable: true,
      sortValue: (r) => r.out_bps, render: (r) => (r.has_util ? fmtBps(r.out_bps) : dash) },
    { key: "target", header: "Measured to", width: "18%", sortable: true,
      text: (r) => `${r.remote_device ?? ""} ${r.target ?? ""}`, sortValue: (r) => r.target_kind ?? "",
      render: (r) => r.has_target
        ? <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
            title={r.target_label ?? `${r.remote_device ?? ""} ${r.target ?? ""}`}>
            {r.target_kind ? <span className="badge" style={{ textTransform: "none" }}>{targetKindLabel[r.target_kind] ?? r.target_kind}</span> : null}
            <span>{r.remote_device || "—"}</span>
            {r.remote_if ? <span className="mini-meta" style={{ fontFamily: "var(--font-mono, monospace)" }}>{r.remote_if}</span> : null}
            <span className="mini-meta" style={{ fontFamily: "var(--font-mono, monospace)" }}>{r.target}</span>
          </span>
        : dash },
    { key: "latency", header: "Latency", width: 90, align: "right", sortable: true,
      ...sla((r) => r.has_latency, (r) => r.latency_ms, (n) => `${n.toFixed(1)} ms`, latSev) },
    { key: "jitter", header: "Jitter", width: 84, align: "right", sortable: true,
      ...sla((r) => r.has_jitter, (r) => r.jitter_ms, (n) => `${n.toFixed(1)} ms`, jitSev) },
    { key: "loss", header: "Loss", width: 78, align: "right", sortable: true,
      ...sla((r) => r.has_loss, (r) => r.loss_pct, (n) => `${n.toFixed(2)} %`, lossSev) },
    { key: "qoe", header: "QoE", width: 64, align: "right", sortable: true,
      ...sla((r) => r.has_qoe, (r) => r.qoe, (n) => n.toFixed(1), qoeSev) },
    { key: "avail", header: "Avail.", width: 78, align: "right", sortable: true,
      ...sla((r) => r.has_availability, (r) => r.availability_pct,
        (n) => `${n.toFixed(2)} %`, (n) => (n < 95 ? "crit" : n < 99 ? "warn" : undefined) as Sev) },
    { key: "source", header: "Measured by", width: 132, sortable: true,
      text: (r) => r.source_label ?? "", sortValue: (r) => (r.tier ?? 9) * 100 + (r.source_label?.length ?? 0),
      render: (r) => (r.source_label
        ? <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
            {r.tier ? <span className={`badge tier-t${r.tier}`} title={`Tier ${r.tier} — ${r.tier_label} (closer to Tier 1 = closer to user experience)`}>T{r.tier}</span> : null}
            <span className="badge" title={`method: ${r.source_label}${r.tier_label ? " · " + r.tier_label : ""}`}>{r.source_label}</span>
          </span>
        : dash) },
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
      <h2>WAN Interface Metrics</h2>
      <p className="mini-meta" style={{ marginTop: -6, marginBottom: 14 }}>
        One row per WAN interface — plus any interface directly connected to a WAN
        device (marked <span className="badge" style={{ verticalAlign: "middle" }}>linked</span>),
        so a lab WAN router <i>and</i> the Spine link to it are both measured. Each
        interface measures to a <b>derived target</b> (<b>Measured to</b>): a
        directly-connected peer (LLDP), an ISP next-hop, or a public-DNS reachability
        anchor. Utilization and status are live; latency / jitter / loss / QoE /
        availability resolve through the <b>5-tier measurement-source ranking</b> —
        closest to the user experience wins: <b>T1</b> application → <b>T2</b> active
        path probe → <b>T3</b> device-native (STAMP) → <b>T4</b> passive → <b>T5</b>
        flow. The <b>Measured by</b> column shows the winning tier + method per row.
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
          <input placeholder="Search devices, interfaces, targets…" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <span className="dt-count">{filtered.length} of {rows.length} interfaces</span>
      </div>

      {loaded && rows.length === 0 ? (
        <div className="empty">
          No WAN interfaces yet. WAN devices are matched by the measurement policy
          (default name pattern <code>wan|edge|gw|dmz</code>); their interfaces —
          plus any interface directly connected to them — appear once they export
          <code>device_if_*</code> metrics. SLA columns populate once a probe
          measures each interface's derived target.
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
