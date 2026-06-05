import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api, Device, Alert, Tunnel } from "../services/api";
import { chartBase, hexToRgba } from "../theme/charts";
import { SEVERITY_COLOR, severityKey, SeverityKey } from "../theme/severity";

// Topology — a a "network-path"-style view. Devices are laid out in
// role tiers (core → distribution → access/edge → firewall) per site, drawn as
// health-colored node cards. Logical links connect adjacent tiers; if overlay
// tunnels exist they are drawn on top as latency-colored edges with ms labels.
// Clicking a node opens a detail panel. Edges/links are inferred from device
// role labels until LLDP/CDP/BGP-LS discovery lands (see discovery.go).

// Role → tier (lower = closer to the core). Unknown roles fall to the access tier.
const TIER: Record<string, number> = {
  core: 0,
  distribution: 1,
  dist: 1,
  aggregation: 1,
  agg: 1,
  firewall: 1,
  fw: 1,
  edge: 2,
  access: 2,
  leaf: 2,
};
const ROLE_GLYPH: Record<string, string> = {
  core: "◆", distribution: "▣", dist: "▣", aggregation: "▣", agg: "▣",
  firewall: "⛨", fw: "⛨", edge: "▲", access: "▲", leaf: "▲", router: "▲",
};

type Health = "ok" | "warning" | "critical";
const HEALTH_COLOR: Record<Health, string> = {
  ok: SEVERITY_COLOR.ok,
  warning: SEVERITY_COLOR.warning,
  critical: SEVERITY_COLOR.critical,
};
// Faint health wash for the node card fill — gives the map color at a glance
// (the reference platform tints node cards by status rather than leaving them flat white).
const HEALTH_TINT: Record<Health, string> = {
  ok: "#f0fdf7",
  warning: "#fffaf0",
  critical: "#fef2f3",
};

function roleOf(d: Device): string {
  return (d.labels?.role || d.labels?.tier || "access").toLowerCase();
}
function siteOf(d: Device): string {
  return d.labels?.site || d.labels?.location || "default";
}
function tierOf(d: Device): number {
  const t = TIER[roleOf(d)];
  return t === undefined ? 2 : t;
}

// Worst active-alert severity per device → node health.
function healthFor(id: string, alertsByDev: Record<string, SeverityKey>): Health {
  const sev = alertsByDev[id];
  if (sev === "critical" || sev === "error") return "critical";
  if (sev === "warning" || sev === "notice") return "warning";
  return "ok";
}

function latencyColor(ms: number): string {
  if (ms < 50) return SEVERITY_COLOR.ok;
  if (ms < 120) return SEVERITY_COLOR.warning;
  return SEVERITY_COLOR.critical;
}

// Per-vendor custom icons (operator-assigned). Persisted client-side so each
// operator can map their fleet's vendors to recognizable glyphs/logos. Keyed by
// a normalized vendor slug; value is an image URL or a data: URI.
const VENDOR_ICONS_KEY = "netops_vendor_icons";
const vendorKey = (v: string) => (v || "").toLowerCase().replace(/[^a-z0-9]/g, "");
function loadVendorIcons(): Record<string, string> {
  try {
    return JSON.parse(localStorage.getItem(VENDOR_ICONS_KEY) || "{}");
  } catch {
    return {};
  }
}

export default function Topology() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [vendorIcons, setVendorIcons] = useState<Record<string, string>>(loadVendorIcons);
  const [iconEditor, setIconEditor] = useState(false);

  useEffect(() => {
    api.devices().then((d) => setDevices(d ?? [])).catch((e) => setError((e as Error).message));
    api.alerts().then((a) => setAlerts(a ?? [])).catch(() => {});
    api.tunnels(200).then((r) => setTunnels((r?.data as Tunnel[]) ?? [])).catch(() => {});
  }, []);

  const alertsByDev = useMemo(() => {
    const m: Record<string, SeverityKey> = {};
    const rank: SeverityKey[] = ["critical", "error", "warning", "notice", "info", "debug", "ok"];
    for (const a of alerts) {
      const id = a.device_id || a.labels?.device;
      if (!id) continue;
      const k = severityKey(a.severity);
      if (!m[id] || rank.indexOf(k) < rank.indexOf(m[id])) m[id] = k;
    }
    return m;
  }, [alerts]);

  // Build laid-out nodes (role tiers per site) + inferred tier links.
  const { nodes, links, counts } = useMemo(() => {
    // Group by site, then tier, to assign x positions.
    const bySiteTier: Record<string, Record<number, Device[]>> = {};
    for (const d of devices) {
      const s = siteOf(d);
      const t = tierOf(d);
      (bySiteTier[s] ??= {})[t] ??= [];
      bySiteTier[s][t].push(d);
    }

    const X_GAP = 200, Y_GAP = 200, SITE_GAP = 120;
    const nodes: any[] = [];
    const links: any[] = [];
    const counts = { ok: 0, warning: 0, critical: 0 };
    let xCursor = 0;

    const sites = Object.keys(bySiteTier).sort();
    for (const site of sites) {
      const tiers = bySiteTier[site];
      const maxRow = Math.max(...Object.values(tiers).map((a) => a.length), 1);
      const siteWidth = maxRow * X_GAP;
      const byId: Record<string, { x: number; y: number; tier: number }> = {};

      for (const tStr of Object.keys(tiers)) {
        const t = Number(tStr);
        const row = tiers[t];
        row.forEach((d, i) => {
          // center each tier row within the site's allotted width
          const x = xCursor + (siteWidth / (row.length + 1)) * (i + 1);
          const y = t * Y_GAP;
          const h = healthFor(d.id, alertsByDev);
          counts[h]++;
          byId[d.id] = { x, y, tier: t };
          const color = HEALTH_COLOR[h];
          const role = roleOf(d);
          const vico = vendorIcons[vendorKey(d.vendor || "")];
          // First label line: health dot + (custom vendor icon | role glyph) + name.
          const head = vico ? `{dot|●} {vico|} {n|${d.name || d.id}}` : `{dot|●} {g|${ROLE_GLYPH[role] || "▤"}} {n|${d.name || d.id}}`;
          nodes.push({
            id: d.id,
            name: d.name || d.id,
            x, y,
            symbol: "roundRect",
            symbolSize: [134, 52],
            itemStyle: {
              color: HEALTH_TINT[h],
              borderColor: color,
              borderWidth: 2.5,
              shadowBlur: 14,
              shadowColor: hexToRgba(color, 0.28),
            },
            label: {
              show: true,
              formatter: [
                head,
                `{m|${role} · ${d.address || ""}}`,
              ].join("\n"),
              rich: {
                dot: { color, fontSize: 13, padding: [0, 2, 0, 0] },
                g: { color, fontSize: 15, fontWeight: 700 },
                vico: { height: 16, width: 16, backgroundColor: vico ? { image: vico } : undefined, padding: [0, 2, 0, 0] },
                n: { color: "#1a2230", fontSize: 13, fontWeight: 700 },
                m: { color: "#667085", fontSize: 11, padding: [4, 0, 0, 0] },
              },
            },
            _device: d,
            _health: h,
          });
        });
      }

      // Inferred logical links: connect every node in tier T to every node in
      // the next non-empty tier within the same site.
      const presentTiers = Object.keys(tiers).map(Number).sort((a, b) => a - b);
      for (let ti = 0; ti < presentTiers.length - 1; ti++) {
        const upper = tiers[presentTiers[ti]];
        const lower = tiers[presentTiers[ti + 1]];
        for (const u of upper) for (const l of lower) {
          links.push({
            source: u.id, target: l.id,
            lineStyle: { color: "rgba(100,116,139,0.45)", width: 1.5, curveness: 0 },
          });
        }
      }
      xCursor += siteWidth + SITE_GAP;
    }

    // Overlay tunnel edges (real latency/status) on top, if endpoints resolve.
    const idByName: Record<string, string> = {};
    for (const d of devices) {
      idByName[(d.name || "").toLowerCase()] = d.id;
      idByName[(d.address || "").toLowerCase()] = d.id;
      idByName[d.id.toLowerCase()] = d.id;
    }
    for (const t of tunnels) {
      const a = idByName[(t.local_device || t.local_addr || "").toLowerCase()];
      const b = idByName[(t.remote_device || t.remote_addr || "").toLowerCase()];
      if (!a || !b || a === b) continue;
      const ms = Number(t.latency_ms) || 0;
      const down = String(t.status).toLowerCase() === "down";
      links.push({
        source: a, target: b,
        label: { show: true, formatter: down ? "down" : `${ms.toFixed(0)}ms`, fontSize: 10, color: "#fff",
          backgroundColor: down ? SEVERITY_COLOR.critical : latencyColor(ms), padding: [2, 5], borderRadius: 4 },
        lineStyle: { color: down ? SEVERITY_COLOR.critical : latencyColor(ms), width: 2.5, curveness: 0.2,
          type: down ? "dashed" : "solid" },
      });
    }

    return { nodes, links, counts };
  }, [devices, alertsByDev, tunnels, vendorIcons]);

  // Distinct vendors present in the fleet — the rows of the icon editor.
  const vendors = useMemo(() => {
    const set = new Set<string>();
    for (const d of devices) if ((d.vendor || "").trim()) set.add(d.vendor!.trim());
    return [...set].sort();
  }, [devices]);

  const setVendorIcon = (vendor: string, url: string) => {
    setVendorIcons((cur) => {
      const next = { ...cur };
      const k = vendorKey(vendor);
      if (url.trim()) next[k] = url.trim();
      else delete next[k];
      try { localStorage.setItem(VENDOR_ICONS_KEY, JSON.stringify(next)); } catch { /* ignore quota */ }
      return next;
    });
  };

  const selDevice = selected ? devices.find((d) => d.id === selected) : null;

  return (
    <div className="card topo-card">
      <div className="topo-head">
        <div>
          <h2 style={{ margin: 0 }}>Network Topology</h2>
          <p className="topo-sub">
            Devices in role tiers; links inferred from role labels, tunnels drawn as
            latency-colored overlays. LLDP/CDP discovery will replace inferred links.
          </p>
        </div>
        <div className="topo-stats">
          <span className="topo-stat"><b style={{ color: HEALTH_COLOR.ok }}>{counts.ok}</b> healthy</span>
          <span className="topo-stat"><b style={{ color: HEALTH_COLOR.warning }}>{counts.warning}</b> warning</span>
          <span className="topo-stat"><b style={{ color: HEALTH_COLOR.critical }}>{counts.critical}</b> critical</span>
          <span className="topo-stat"><b>{links.length}</b> links</span>
          <button className="btn" onClick={() => setIconEditor((v) => !v)} title="Assign a custom icon per vendor">
            {iconEditor ? "Done" : "Vendor icons"}
          </button>
        </div>
      </div>

      {iconEditor && (
        <div className="card" style={{ margin: "0 0 10px", background: "var(--hover)" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <strong style={{ fontSize: 13 }}>Vendor icons</strong>
            <span style={{ color: "var(--muted)", fontSize: 12 }}>Paste an image URL or data: URI per vendor — shown on each device node.</span>
          </div>
          {vendors.length === 0 ? (
            <p className="empty">No vendors in the inventory yet.</p>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 8, marginTop: 8 }}>
              {vendors.map((v) => {
                const url = vendorIcons[vendorKey(v)] || "";
                return (
                  <div key={v} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ width: 22, height: 22, flex: "none", display: "inline-flex", alignItems: "center", justifyContent: "center", border: "1px solid var(--panel-border)", borderRadius: 4, overflow: "hidden", background: "#fff" }}>
                      {url ? <img src={url} alt={v} style={{ maxWidth: "100%", maxHeight: "100%" }} /> : <span style={{ fontSize: 10, color: "var(--muted)" }}>—</span>}
                    </span>
                    <span style={{ width: 90, fontSize: 12, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={v}>{v}</span>
                    <input
                      placeholder="https://… or data:image/…"
                      value={url}
                      onChange={(e) => setVendorIcon(v, e.target.value)}
                      style={{ flex: 1, fontSize: 12 }}
                    />
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      <div className="topo-legend">
        {(["ok", "warning", "critical"] as Health[]).map((h) => (
          <span className="topo-leg" key={h}><i style={{ background: HEALTH_COLOR[h] }} />{h}</span>
        ))}
        <span className="topo-leg-sep" />
        <span className="topo-leg-label">Edge color = latency:</span>
        <span className="topo-leg"><i style={{ background: SEVERITY_COLOR.ok }} />&lt;50ms</span>
        <span className="topo-leg"><i style={{ background: SEVERITY_COLOR.warning }} />&lt;120ms</span>
        <span className="topo-leg"><i style={{ background: SEVERITY_COLOR.critical }} />slow/down</span>
      </div>

      {error && <p style={{ color: "var(--bad)" }}>{error}</p>}

      <div className="topo-body">
        {nodes.length === 0 ? (
          <div className="empty">No devices to plot yet — add some on the Devices tab.</div>
        ) : (
          <ReactECharts
            style={{ height: 520, flex: 1, minWidth: 0 }}
            option={{
              ...chartBase,
              tooltip: {
                ...chartBase.tooltip,
                formatter: (p: any) =>
                  p.dataType === "node"
                    ? `<b>${p.data.name}</b><br/>${p.data._device?.vendor || "unknown vendor"} · ${roleOf(p.data._device)}<br/>${p.data._device?.address || ""} — <b style="color:${HEALTH_COLOR[p.data._health as Health]}">${p.data._health}</b>`
                    : "",
              },
              series: [{
                type: "graph",
                layout: "none",
                roam: true,
                draggable: true,
                label: { show: true, position: "inside" },
                edgeSymbol: ["none", "none"],
                data: nodes,
                links,
                emphasis: { focus: "adjacency", lineStyle: { width: 3 } },
              }],
            }}
            onEvents={{
              click: (p: any) => { if (p.dataType === "node") setSelected(p.data.id); },
            }}
          />
        )}

        {selDevice && (
          <div className="topo-detail">
            <div className="topo-detail-head">
              <h3 style={{ margin: 0 }}>{selDevice.name || selDevice.id}</h3>
              <button className="drawer-close" onClick={() => setSelected(null)}>✕</button>
            </div>
            <dl className="topo-kv">
              <dt>Status</dt>
              <dd><span className={`badge sev-${healthFor(selDevice.id, alertsByDev) === "ok" ? "ok" : healthFor(selDevice.id, alertsByDev) === "warning" ? "warning" : "critical"}`}>{healthFor(selDevice.id, alertsByDev)}</span></dd>
              <dt>Address</dt><dd className="mono">{selDevice.address || "—"}</dd>
              <dt>Vendor</dt><dd>{selDevice.vendor || "—"}</dd>
              <dt>Model</dt><dd>{selDevice.model || "—"}</dd>
              <dt>Role</dt><dd>{roleOf(selDevice)}</dd>
              <dt>Site</dt><dd>{siteOf(selDevice)}</dd>
              <dt>Source</dt><dd>{selDevice.source}</dd>
            </dl>
            <div className="topo-detail-section">Active alerts</div>
            {alerts.filter((a) => (a.device_id || a.labels?.device) === selDevice.id).slice(0, 6).map((a, i) => (
              <div className="mini-row" key={a.id ?? i}>
                <span className={`badge sev-${severityKey(a.severity)}`}>{a.severity}</span>
                <div className="mini-body"><div className="mini-title">{a.summary}</div></div>
              </div>
            ))}
            {alerts.filter((a) => (a.device_id || a.labels?.device) === selDevice.id).length === 0 && (
              <div className="panel-empty">No active alerts.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
