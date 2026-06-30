import { useEffect, useMemo, useState } from "react";
import { api, Tunnel, PromInstantResponse } from "../services/api";
import DataTable, { Column, Sev } from "../components/DataTable";
import { latSev, lossSev, fmtTunnelUptime, coerce } from "../tabs/Tunnels";

// WAN Circuit Utilization — one row per WAN-router interface.
//
// This is the physical-WAN view (deep-linked from the "WAN Circuit Utilization"
// dashboard card): per-interface load + oper status straight off SNMP
// (device_if_* in VictoriaMetrics), joined with the circuit SLA (latency /
// jitter / loss / QoE / uptime) measured by the active overlay riding that
// router (/api/tunnels). It is intentionally distinct from the overlay-centric
// Tunnels tab — that lists VPN/SD-WAN tunnels; this lists the WAN circuits the
// routers actually egress on. SLA cells show "—" when no active probe exists
// for that router yet (honest empty, never a fabricated number).

const WAN_PATTERN_KEY = "netops.overview.wanPattern"; // shared with the Operations Overview WAN panel

// Severity ramps — mirror the Tunnels page so colour reads identically.
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

// A WAN circuit = one WAN-facing interface on a router, enriched with the SLA of
// the overlay riding that router (if any).
type Circuit = {
  k: string;
  device: string;
  iface: string;
  inb: number;
  outb: number;
  util: number;     // %
  errs: number;     // errors+discards / s
  up: boolean;
  sla?: Tunnel;     // worst overlay on this device, if measured
};

const idx = (r?: PromInstantResponse): Record<string, number> => {
  const out: Record<string, number> = {};
  for (const x of r?.data?.result ?? []) out[`${x.metric.device}#${x.metric.index}`] = Number(x.value?.[1]);
  return out;
};

// Interface label: prefer a real name (Ethernet1/0), fall back to the index.
const ifaceLabel = (m: Record<string, string>): string =>
  m.ifName || m.ifAlias || m.name || (m.index ? `if ${m.index}` : "—");

export default function WanCircuits() {
  const [pattern, setPattern] = useState<string>(() => localStorage.getItem(WAN_PATTERN_KEY) || "wan|edge|dmz|gw");
  const [draft, setDraft] = useState(pattern);
  const [q, setQ] = useState("");
  const [rows, setRows] = useState<Circuit[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const sel = `{device=~"(?i).*(${pattern}).*"}`;

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const [inb, outb, speed, errs, oper, tun] = await Promise.all([
          api.metricsQuery(`rate(device_if_in_octets${sel}[2m])*8`).catch(() => undefined),
          api.metricsQuery(`rate(device_if_out_octets${sel}[2m])*8`).catch(() => undefined),
          api.metricsQuery(`device_if_speed${sel}`).catch(() => undefined),
          api.metricsQuery(`rate(device_if_in_errors${sel}[5m]) + rate(device_if_out_errors${sel}[5m]) + rate(device_if_in_discards${sel}[5m]) + rate(device_if_out_discards${sel}[5m])`).catch(() => undefined),
          api.metricsQuery(`device_if_oper_status${sel}`).catch(() => undefined),
          api.tunnels(500).catch(() => undefined),
        ]);
        if (!alive) return;

        // Per-device worst overlay SLA: highest loss, then highest latency.
        const slaByDevice: Record<string, Tunnel> = {};
        for (const raw of tun?.data ?? []) {
          const t = coerce(raw);
          for (const dev of [t.local_device, t.remote_device]) {
            if (!dev) continue;
            const cur = slaByDevice[dev.toLowerCase()];
            if (!cur || t.loss_pct > cur.loss_pct || (t.loss_pct === cur.loss_pct && t.latency_ms > cur.latency_ms)) {
              slaByDevice[dev.toLowerCase()] = t;
            }
          }
        }

        const inB = idx(inb), outB = idx(outb), spd = idx(speed), erR = idx(errs), opS = idx(oper);
        const next: Circuit[] = (inb?.data?.result ?? []).map((x) => {
          const k = `${x.metric.device}#${x.metric.index}`;
          const speedBps = (spd[k] || 0) * 1e6; // device_if_speed is ifHighSpeed (Mbps)
          const maxBps = Math.max(inB[k] || 0, outB[k] || 0);
          return {
            k,
            device: x.metric.device,
            iface: ifaceLabel(x.metric),
            inb: inB[k] || 0,
            outb: outB[k] || 0,
            util: speedBps > 0 ? (maxBps / speedBps) * 100 : 0,
            errs: erR[k] || 0,
            up: (opS[k] ?? 1) === 1,
            sla: slaByDevice[(x.metric.device || "").toLowerCase()],
          };
        }).sort((a, b) => b.util - a.util || (b.inb + b.outb) - (a.inb + a.outb));

        setRows(next);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => { alive = false; clearInterval(id); };
  }, [sel]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((r) => `${r.device} ${r.iface}`.toLowerCase().includes(needle));
  }, [rows, q]);

  const applyPattern = () => {
    const v = draft.trim() || "wan";
    setPattern(v); localStorage.setItem(WAN_PATTERN_KEY, v);
  };

  // Util cell — a slim load bar + the percentage, tinted by severity.
  const utilCell = (r: Circuit) => (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 8, justifyContent: "flex-end", width: "100%" }}>
      <span style={{ position: "relative", width: 56, height: 6, borderRadius: 3, background: "var(--panel-border)", overflow: "hidden" }}>
        <span style={{ position: "absolute", inset: 0, width: `${Math.min(100, r.util)}%`, borderRadius: 3,
          background: r.util < 70 ? "var(--ok, #22c55e)" : r.util < 90 ? "var(--warn, #f59e0b)" : "var(--crit, #ef4444)" }} />
      </span>
      <span style={{ fontVariantNumeric: "tabular-nums", minWidth: 42, textAlign: "right" }}>{r.util.toFixed(1)}%</span>
    </span>
  );

  // SLA cell renderer: honest dash when this circuit has no active measurement.
  const slaNum = (get: (t: Tunnel) => number, fmt: (n: number) => string, sevf: (n: number) => Sev) => ({
    sev: (r: Circuit) => (r.sla ? sevf(get(r.sla)) : undefined),
    sortValue: (r: Circuit) => (r.sla ? get(r.sla) : -1),
    render: (r: Circuit) => (r.sla ? fmt(get(r.sla)) : <span className="mini-meta">—</span>),
  });

  const columns = useMemo<Column<Circuit>[]>(() => [
    { key: "device", header: "Router", width: "16%", sortable: true,
      text: (r) => r.device, sortValue: (r) => r.device,
      render: (r) => <span title={r.device}>{r.device || "—"}</span> },
    { key: "iface", header: "Interface", width: "14%", sortable: true,
      text: (r) => r.iface, sortValue: (r) => r.iface,
      render: (r) => <span style={{ fontFamily: "var(--font-mono, monospace)" }}>{r.iface}</span> },
    { key: "util", header: "Utilization", width: 130, align: "right", sortable: true,
      sortValue: (r) => r.util, sev: (r) => utilSev(r.util), render: utilCell },
    { key: "in", header: "↓ In", width: 96, align: "right", sortable: true,
      sortValue: (r) => r.inb, render: (r) => fmtBps(r.inb) },
    { key: "out", header: "↑ Out", width: 96, align: "right", sortable: true,
      sortValue: (r) => r.outb, render: (r) => fmtBps(r.outb) },
    { key: "latency", header: "Latency", width: 92, align: "right", sortable: true,
      ...slaNum((t) => t.latency_ms, (n) => `${n.toFixed(1)} ms`, latSev) },
    { key: "jitter", header: "Jitter", width: 86, align: "right", sortable: true,
      ...slaNum((t) => t.jitter_ms, (n) => `${n.toFixed(1)} ms`, jitSev) },
    { key: "loss", header: "Loss", width: 80, align: "right", sortable: true,
      ...slaNum((t) => t.loss_pct, (n) => `${n.toFixed(2)} %`, lossSev) },
    { key: "qoe", header: "QoE", width: 66, align: "right", sortable: true,
      ...slaNum((t) => t.qoe, (n) => n.toFixed(1), qoeSev) },
    { key: "uptime", header: "Uptime", width: 90, align: "right", sortable: true,
      sortValue: (r) => (r.sla ? r.sla.uptime_s : -1),
      render: (r) => (r.sla ? fmtTunnelUptime(r.sla.uptime_s) : <span className="mini-meta">—</span>) },
    { key: "status", header: "Status", width: 84, sortable: true,
      text: (r) => (r.up ? "up" : "down"), sortValue: (r) => (r.up ? 1 : 0),
      render: (r) => <span className={`badge ${r.up ? "good" : "bad"}`}>{r.up ? "up" : "down"}</span> },
  ], []);

  const down = rows.filter((r) => !r.up).length;
  const totIn = rows.reduce((a, r) => a + r.inb, 0);
  const totOut = rows.reduce((a, r) => a + r.outb, 0);
  const peak = rows.length ? Math.max(...rows.map((r) => r.util)) : 0;
  const withSla = rows.filter((r) => r.sla);
  const avgLat = withSla.length ? withSla.reduce((n, r) => n + (r.sla!.latency_ms), 0) / withSla.length : 0;

  return (
    <div className="card">
      <h2>WAN Circuit Utilization</h2>
      <p className="mini-meta" style={{ marginTop: -6, marginBottom: 14 }}>
        WAN-router interface load and reachability SLA. Circuits are the WAN-facing
        ports matched by the pattern below; latency / jitter / loss / QoE come from
        the active overlay measured on that router.
      </p>
      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className={`stat ${rows.length ? "s-good" : "s-muted"}`}>
          <span className="stat-label">WAN circuits</span>
          <span className="stat-value">{rows.length}</span>
          <span className="stat-sub">{withSla.length} with active SLA</span>
        </div>
        <div className="stat s-muted">
          <span className="stat-label">Throughput</span>
          <span className="stat-value" style={{ fontSize: 26 }}>{fmtBps(totIn + totOut)}</span>
          <span className="stat-sub">↓ {fmtBps(totIn)} · ↑ {fmtBps(totOut)}</span>
        </div>
        <div className={`stat ${rows.length ? (peak < 70 ? "s-good" : peak < 90 ? "s-warn" : "s-bad") : "s-muted"}`}>
          <span className="stat-label">Peak utilization</span>
          <span className="stat-value">{rows.length ? peak.toFixed(1) : "—"}{rows.length ? <span style={{ fontSize: 20, color: "var(--muted)" }}> %</span> : null}</span>
          <span className="stat-sub">{withSla.length ? `avg latency ${avgLat.toFixed(0)} ms` : "busiest circuit"}</span>
        </div>
        <div className={`stat ${down ? "s-bad" : "s-muted"}`}>
          <span className="stat-label">Circuits down</span>
          <span className="stat-value">{down}</span>
          <span className="stat-sub">{rows.length ? (down ? `${down} unreachable` : "all up") : "none reported"}</span>
        </div>
      </div>

      <div className="dt-toolbar">
        <label className="dt-search">
          <span className="omni-icon">⌕</span>
          <input placeholder="Search routers, interfaces…" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <span style={{ marginLeft: "auto", display: "flex", gap: 4, alignItems: "center" }}>
          <span className="mini-meta">WAN match</span>
          <input value={draft} onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && applyPattern()}
            style={{ width: 150, fontFamily: "var(--font-mono, monospace)", fontSize: 12 }} />
          <button className="dash-btn" onClick={applyPattern} disabled={draft.trim() === pattern}>Apply</button>
        </span>
        <span className="dt-count">{filtered.length} of {rows.length} circuits</span>
      </div>

      {rows.length === 0 ? (
        <div className="empty">
          No WAN circuits matched <code>{pattern}</code>. Adjust the WAN-match
          pattern, or confirm the WAN routers are exporting <code>device_if_*</code>
          metrics. Interface load appears here once SNMP polling populates it.
        </div>
      ) : (
        <DataTable<Circuit>
          rows={filtered}
          columns={columns}
          rowKey={(r) => r.k}
          height="60vh"
          ariaLabel="WAN circuits"
          initialSort={{ key: "util", dir: "desc" }}
          empty="No WAN circuits match this filter."
        />
      )}
    </div>
  );
}
