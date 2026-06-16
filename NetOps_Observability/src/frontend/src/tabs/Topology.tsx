import { useEffect, useMemo, useState } from "react";
import {
  ReactFlow, Background, BackgroundVariant, Controls, MiniMap, Handle, Position, MarkerType,
  type Node, type Edge, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api, Device, Alert, Tunnel } from "../services/api";
import { SEVERITY_COLOR, severityKey, SeverityKey } from "../theme/severity";
import VendorIcon from "../components/VendorIcon";
import { brandDataUri, vendorKey } from "../components/vendorBrands";
import { ShapeSVG, kindForRole } from "../components/graph/shapes";
import FlowEdge from "../components/graph/FlowEdge";

// Topology — a modern NOC device map (React Flow). Devices are drawn as real
// network SHAPES (router circle, switch hexagon, firewall shield, gateway diamond,
// cloud, host) coloured by health with a glossy glow, laid out in role tiers per
// site (core → distribution → access/edge). Links are TrafficFlowEdges: tier links
// flow gently; overlay tunnels animate and are coloured by latency / down state.
// Clicking a node opens a detail panel. Links are inferred from role tiers until
// LLDP/CDP/BGP-LS discovery lands (tracker #77).

const TIER: Record<string, number> = {
  core: 0, distribution: 1, dist: 1, aggregation: 1, agg: 1, firewall: 1, fw: 1,
  edge: 2, access: 2, leaf: 2,
};

type Health = "ok" | "warning" | "critical";
const HEALTH_COLOR: Record<Health, string> = {
  ok: SEVERITY_COLOR.ok, warning: SEVERITY_COLOR.warning, critical: SEVERITY_COLOR.critical,
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

const VENDOR_ICONS_KEY = "netops_vendor_icons";
function loadVendorIcons(): Record<string, string> {
  try { return JSON.parse(localStorage.getItem(VENDOR_ICONS_KEY) || "{}"); } catch { return {}; }
}

// ── custom device node ──────────────────────────────────────────────────────
const handleStyle = { width: 7, height: 7, background: "var(--border,#3a4252)", border: "none" } as const;
function DeviceNode({ data }: NodeProps) {
  const d = data as any;
  const size = 58;
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 134, gap: 2, cursor: "pointer" }}>
      <Handle type="target" position={Position.Top} id="t" style={{ ...handleStyle, left: "50%" }} />
      <Handle type="target" position={Position.Left} id="l" style={{ ...handleStyle, top: 30 }} />
      <div style={{ position: "relative", width: size, height: size, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <ShapeSVG kind={d.kind} tone={d.tone} size={size} glyph={!d.logo} />
        {d.logo && (
          <img src={d.logo} alt="" style={{ position: "absolute", width: size * 0.44, height: size * 0.44, objectFit: "contain", filter: "drop-shadow(0 1px 2px rgba(0,0,0,.5))" }} />
        )}
        {/* health LED */}
        <span style={{ position: "absolute", top: 1, right: 6, width: 9, height: 9, borderRadius: "50%", background: d.tone, boxShadow: `0 0 6px ${d.tone}, 0 0 0 1.5px var(--bg,#0e1320)` }} />
      </div>
      <div style={{ fontWeight: 700, fontSize: 12, color: "var(--fg,#e6edf3)", textAlign: "center", lineHeight: 1.15, overflowWrap: "anywhere", maxWidth: 134 }}>{d.name}</div>
      <div style={{ fontSize: 10.5, color: "var(--fg-muted,#6B7280)", textAlign: "center", lineHeight: 1.1 }}>
        {d.role}{d.addr ? ` · ${d.addr}` : ""}
      </div>
      <Handle type="source" position={Position.Bottom} id="b" style={{ ...handleStyle, left: "50%" }} />
      <Handle type="source" position={Position.Right} id="r" style={{ ...handleStyle, top: 30 }} />
    </div>
  );
}
const nodeTypes = { device: DeviceNode };
const edgeTypes = { flow: FlowEdge };

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

  const { rfNodes, rfEdges, counts } = useMemo(() => {
    const bySiteTier: Record<string, Record<number, Device[]>> = {};
    for (const d of devices) {
      const s = siteOf(d), t = tierOf(d);
      (bySiteTier[s] ??= {})[t] ??= [];
      bySiteTier[s][t].push(d);
    }
    const X_GAP = 180, Y_GAP = 165, SITE_GAP = 110;
    const rfNodes: Node[] = [];
    const rfEdges: Edge[] = [];
    const counts = { ok: 0, warning: 0, critical: 0 };
    let xCursor = 0;

    for (const site of Object.keys(bySiteTier).sort()) {
      const tiers = bySiteTier[site];
      const maxRow = Math.max(...Object.values(tiers).map((a) => a.length), 1);
      const siteWidth = maxRow * X_GAP;
      const present = Object.keys(tiers).map(Number).sort((a, b) => a - b);

      for (const t of present) {
        const row = tiers[t];
        row.forEach((d, i) => {
          const x = xCursor + (siteWidth / (row.length + 1)) * (i + 1);
          const y = t * Y_GAP;
          const h = healthFor(d.id, alertsByDev);
          counts[h]++;
          rfNodes.push({
            id: d.id, type: "device", position: { x, y }, draggable: true,
            data: {
              kind: kindForRole(roleOf(d)), tone: HEALTH_COLOR[h],
              name: d.name || d.id, role: roleOf(d), addr: d.address || "",
              logo: vendorIcons[vendorKey(d.vendor || "")] || brandDataUri(d.vendor || ""),
            },
          });
        });
      }
      // inferred tier links: each node → each node in the next non-empty tier.
      for (let ti = 0; ti < present.length - 1; ti++) {
        for (const u of tiers[present[ti]]) for (const l of tiers[present[ti + 1]]) {
          rfEdges.push({
            id: `tier-${u.id}-${l.id}`, source: u.id, sourceHandle: "b", target: l.id, targetHandle: "t",
            type: "flow", data: { flow: true, state: "healthy", particles: 1, speed: 4 },
            style: { stroke: "#3f4a5e", strokeWidth: 1.4, opacity: 0.7 },
          });
        }
      }
      xCursor += siteWidth + SITE_GAP;
    }

    // overlay tunnels (real latency/status) on top, if endpoints resolve.
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
      const color = down ? SEVERITY_COLOR.critical : latencyColor(ms);
      rfEdges.push({
        id: `tun-${a}-${b}`, source: a, sourceHandle: "r", target: b, targetHandle: "l",
        type: "flow", label: down ? "down" : `${ms.toFixed(0)} ms`,
        data: { flow: !down, state: down ? "confirmed_down" : ms >= 120 ? "degraded" : "healthy", particles: 3, speed: 2.2 },
        markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
        style: { stroke: color, strokeWidth: 2.4, opacity: 0.95 },
      });
    }
    return { rfNodes, rfEdges, counts };
  }, [devices, alertsByDev, tunnels, vendorIcons]);

  const vendors = useMemo(() => {
    const set = new Set<string>();
    for (const d of devices) if ((d.vendor || "").trim()) set.add(d.vendor!.trim());
    return [...set].sort();
  }, [devices]);

  const setVendorIcon = (vendor: string, url: string) => {
    setVendorIcons((cur) => {
      const next = { ...cur };
      const k = vendorKey(vendor);
      if (url.trim()) next[k] = url.trim(); else delete next[k];
      try { localStorage.setItem(VENDOR_ICONS_KEY, JSON.stringify(next)); } catch { /* quota */ }
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
            Devices as health-coloured network shapes in role tiers; tunnels drawn as
            latency-coloured traffic-flow overlays. LLDP/CDP/BGP-LS discovery will replace inferred links.
          </p>
        </div>
        <div className="topo-stats">
          <span className="topo-stat"><b style={{ color: HEALTH_COLOR.ok }}>{counts.ok}</b> healthy</span>
          <span className="topo-stat"><b style={{ color: HEALTH_COLOR.warning }}>{counts.warning}</b> warning</span>
          <span className="topo-stat"><b style={{ color: HEALTH_COLOR.critical }}>{counts.critical}</b> critical</span>
          <span className="topo-stat"><b>{rfEdges.length}</b> links</span>
          <button className={`btn${iconEditor ? "" : " accent"}`} onClick={() => setIconEditor((v) => !v)} title="Assign a custom icon per vendor">
            {iconEditor ? "Done" : "+ Vendor icons"}
          </button>
        </div>
      </div>

      {iconEditor && (
        <div className="vendor-editor">
          <div className="vendor-editor-head">
            <strong>Vendor icons</strong>
            <span className="vendor-editor-hint">Brand marks are detected automatically. Paste an image URL or data: URI to override one.</span>
          </div>
          {vendors.length === 0 ? (
            <p className="empty">No vendors in the inventory yet.</p>
          ) : (
            <div className="vendor-editor-grid">
              {vendors.map((v) => {
                const url = vendorIcons[vendorKey(v)] || "";
                const auto = !url && !!brandDataUri(v);
                return (
                  <div key={v} className="vendor-row">
                    <span className="vendor-tile">{url ? <img src={url} alt={v} /> : <VendorIcon vendor={v} size={22} />}</span>
                    <span className="vendor-name" title={v}>{v}{auto && <span className="vendor-auto">auto</span>}</span>
                    <input className="vendor-input" placeholder="override: https://… or data:image/…" value={url} onChange={(e) => setVendorIcon(v, e.target.value)} />
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
        <span className="topo-leg-label">Tunnel colour = latency:</span>
        <span className="topo-leg"><i style={{ background: SEVERITY_COLOR.ok }} />&lt;50ms</span>
        <span className="topo-leg"><i style={{ background: SEVERITY_COLOR.warning }} />&lt;120ms</span>
        <span className="topo-leg"><i style={{ background: SEVERITY_COLOR.critical }} />slow/down</span>
      </div>

      {error && <p style={{ color: "var(--bad)" }}>{error}</p>}

      <div className="topo-body">
        {rfNodes.length === 0 ? (
          <div className="empty">No devices to plot yet — add some on the Devices tab.</div>
        ) : (
          <div style={{ flex: 1, minWidth: 0, height: 560, borderRadius: 10, overflow: "hidden", border: "1px solid var(--border,#2a2f3a)", background: "radial-gradient(120% 120% at 0% 0%, rgba(40,52,74,0.35), var(--bg,#0e1320) 60%)" }}>
            <ReactFlow
              nodes={rfNodes} edges={rfEdges} nodeTypes={nodeTypes} edgeTypes={edgeTypes}
              fitView fitViewOptions={{ padding: 0.18 }} proOptions={{ hideAttribution: true }}
              nodesConnectable={false} minZoom={0.2} maxZoom={1.6}
              onNodeClick={(_, n) => setSelected(n.id)} onPaneClick={() => setSelected(null)}
            >
              <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="var(--border,#2a2f3a)" />
              <Controls showInteractive={false} position="bottom-right" />
              <MiniMap pannable zoomable nodeColor={(n) => (n.data as any)?.tone || "#5a6472"}
                style={{ background: "var(--panel,#151b2b)" }} maskColor="rgba(0,0,0,0.45)" />
            </ReactFlow>
          </div>
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
