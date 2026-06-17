import { useEffect, useMemo, useState } from "react";
import {
  ReactFlow, Background, BackgroundVariant, Controls, Handle, Position, MarkerType,
  type Node, type Edge, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api, Device, Alert, Tunnel, TopoLink } from "../services/api";
import { SEVERITY_COLOR, severityKey, SeverityKey } from "../theme/severity";
import VendorIcon from "../components/VendorIcon";
import { brandDataUri, vendorKey } from "../components/vendorBrands";
import { NetIcon, kindForDevice, type NetKind } from "../components/graph/NetIcon";
import FlowEdge from "../components/graph/FlowEdge";
import { layoutTopology, type TopoType } from "../components/graph/topologyLayout";
import { abbrevPortPair } from "../components/graph/ifname";

// Topology — a modern NOC device map (React Flow). Devices are drawn as real
// network SHAPES (router circle, switch hexagon, firewall shield, gateway diamond,
// cloud, host) coloured by health with a glossy glow, laid out in role tiers per
// site (core → distribution → access/edge). Links are TrafficFlowEdges: tier links
// flow gently; overlay tunnels animate and are coloured by latency / down state.
// Clicking a node opens a detail panel. Links are inferred from role tiers until
// LLDP/CDP/BGP-LS discovery lands (tracker #77).

// Human labels for the detected topology shape (from the layout engine).
const TOPO_TYPE_LABEL: Record<TopoType, string> = {
  star: "Star", ring: "Ring", bus: "Bus", tree: "Tree",
  clos: "Spine-leaf (CLOS)", mesh: "Mesh", hybrid: "Hybrid",
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

// Device Topology sub-objects: Physical = L2 adjacency (LLDP/CDP); Logical = the
// IGP link-state graph carried by BGP-LS (IS-IS OR OSPF — whichever the backend
// runs). A link confirmed by both protocols ("bgp_ls+lldp") appears in BOTH views.
type TopoView = "physical" | "logical";
const protoSet = (lk: TopoLink) => lk.source_protocol.split("+");
function isLogical(lk: TopoLink): boolean { return protoSet(lk).includes("bgp_ls"); }
function isPhysical(lk: TopoLink): boolean {
  const p = protoSet(lk);
  return p.includes("lldp") || p.includes("cdp");
}
// igpLabel collapses the wire IGP code to the protocol family shown to operators.
function igpLabel(igp?: string): string {
  if (!igp) return "";
  if (igp.startsWith("isis")) return "IS-IS";
  if (igp.startsWith("ospf")) return "OSPF";
  return igp.toUpperCase();
}

const VENDOR_ICONS_KEY = "netops_vendor_icons";
function loadVendorIcons(): Record<string, string> {
  try { return JSON.parse(localStorage.getItem(VENDOR_ICONS_KEY) || "{}"); } catch { return {}; }
}

// Per-device-type icon overrides (router/switch/firewall/…) — drop in any icon set
// (e.g. licensed Icons8 exports) and it renders inside the health-ringed tile.
const TYPE_ICONS_KEY = "netops_type_icons";
function loadTypeIcons(): Partial<Record<NetKind, string>> {
  try { return JSON.parse(localStorage.getItem(TYPE_ICONS_KEY) || "{}"); } catch { return {}; }
}
const TYPE_ROWS: { kind: NetKind; label: string }[] = [
  { kind: "router", label: "Router" }, { kind: "core", label: "Core router" },
  { kind: "switch", label: "Switch" }, { kind: "firewall", label: "Firewall" },
  { kind: "loadbalancer", label: "Load balancer" }, { kind: "gateway", label: "Gateway / WAN" },
  { kind: "server", label: "Server / host" }, { kind: "cloud", label: "Cloud / internet" },
];

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
        <NetIcon kind={d.kind} tone={d.tone} size={size} src={d.icon} alert={d.health !== "ok"} pulse={d.health === "critical"} />
        {/* vendor brand badge — bottom-right corner chip */}
        {d.logo && (
          <span style={{ position: "absolute", bottom: -2, right: 0, width: 20, height: 20, borderRadius: "50%", background: "var(--panel,#151b2b)", border: "1px solid var(--border,#2a2f3a)", display: "flex", alignItems: "center", justifyContent: "center", boxShadow: "0 1px 3px rgba(0,0,0,.5)" }}>
            <img src={d.logo} alt="" style={{ width: 13, height: 13, objectFit: "contain" }} />
          </span>
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
  const [links, setLinks] = useState<TopoLink[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [vendorIcons, setVendorIcons] = useState<Record<string, string>>(loadVendorIcons);
  const [typeIcons, setTypeIcons] = useState<Partial<Record<NetKind, string>>>(loadTypeIcons);
  const [iconEditor, setIconEditor] = useState(false);
  const [view, setView] = useState<TopoView>("physical"); // Device Topology sub-object

  useEffect(() => {
    api.devices().then((d) => setDevices(d ?? [])).catch((e) => setError((e as Error).message));
    api.alerts().then((a) => setAlerts(a ?? [])).catch(() => {});
    api.tunnels(200).then((r) => setTunnels((r?.data as Tunnel[]) ?? [])).catch(() => {});
    api.topologyLinks().then((r) => setLinks(r?.links ?? [])).catch(() => {});
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

  // Link availability per sub-object (drives the tab labels + honest empty states).
  const { physicalCount, logicalCount, igpName } = useMemo(() => {
    let p = 0, l = 0;
    const igs = new Set<string>();
    for (const lk of links) {
      if (isPhysical(lk)) p++;
      if (isLogical(lk)) { l++; const n = igpLabel(lk.igp); if (n) igs.add(n); }
    }
    return { physicalCount: p, logicalCount: l, igpName: [...igs].sort().join(" / ") };
  }, [links]);

  const { rfNodes, rfEdges, counts, topoType } = useMemo(() => {
    // Only the active sub-object's links are drawn. A "bgp_ls+lldp" link is both
    // physical and logical, so it shows in either view.
    const viewLinks = links.filter((lk) => (view === "logical" ? isLogical(lk) : isPhysical(lk)));
    const deviceById = new Map(devices.map((d) => [d.id, d]));

    // External (unmanaged) endpoints: a neighbour no managed device resolves to —
    // Internet / another domain. Drawn as a plain cloud so the edge of visibility
    // is explicit.
    const extNodes = new Map<string, string>(); // id → display name
    for (const lk of viewLinks) {
      if (lk.target.startsWith("ext:") && deviceById.has(lk.source) && !extNodes.has(lk.target)) {
        extNodes.set(lk.target, lk.target_name && lk.target_name !== "external" ? lk.target_name : "");
      }
    }
    const plottable = (id: string) => deviceById.has(id) || extNodes.has(id);

    // Classify + position from the OBSERVED adjacency (no fixed tier assumption).
    const layoutNodes = [
      ...devices.map((d) => ({ id: d.id, role: roleOf(d) })),
      ...[...extNodes.keys()].map((id) => ({ id, role: undefined as string | undefined })),
    ];
    const layoutEdges = viewLinks
      .filter((lk) => plottable(lk.source) && plottable(lk.target))
      .map((lk) => ({ source: lk.source, target: lk.target }));
    const { type: topoType, positions, layer } = layoutTopology(layoutNodes, layoutEdges);

    const counts = { ok: 0, warning: 0, critical: 0 };
    const rfNodes: Node[] = [];
    for (const d of devices) {
      const h = healthFor(d.id, alertsByDev);
      counts[h]++;
      rfNodes.push({
        id: d.id, type: "device", position: positions[d.id] ?? { x: 0, y: 0 }, draggable: true,
        data: {
          kind: kindForDevice(roleOf(d)), tone: HEALTH_COLOR[h], health: h,
          name: d.name || d.id, role: roleOf(d), addr: d.address || "",
          logo: vendorIcons[vendorKey(d.vendor || "")] || brandDataUri(d.vendor || ""),
          icon: typeIcons[kindForDevice(roleOf(d))],
        },
      });
    }
    for (const [id, name] of extNodes) {
      rfNodes.push({
        id, type: "device", position: positions[id] ?? { x: 0, y: 0 }, draggable: true,
        data: { kind: "cloud", tone: "#7c8aa5", health: "ok", name, role: "", addr: "" },
      });
    }

    // Edges follow real adjacency, oriented by layer: cross-layer links run
    // vertically (upper node's bottom → lower node's top = tree/CLOS look),
    // same-layer links run horizontally (siblings). No inferred/mesh edges.
    const rfEdges: Edge[] = [];
    const logicalView = view === "logical";
    for (const lk of viewLinks) {
      if (!positions[lk.source] || !positions[lk.target]) continue;
      const la = layer[lk.source] ?? 0, lb = layer[lk.target] ?? 0;
      let source = lk.source, target = lk.target, sourceHandle = "r", targetHandle = "l";
      if (la !== lb) {
        if (la > lb) { source = lk.target; target = lk.source; } // ensure upper→lower
        sourceHandle = "b"; targetHandle = "t";
      } else if (positions[lk.target].x < positions[lk.source].x) {
        source = lk.target; target = lk.source; // ensure left→right
      }
      const portLabel = abbrevPortPair(lk.local_port, lk.remote_port);
      const label = logicalView
        ? [igpLabel(lk.igp), lk.area ? `area ${lk.area}` : "", portLabel].filter(Boolean).join(" · ")
        : (portLabel || undefined);
      rfEdges.push({
        id: `${view}-${lk.source}-${lk.target}`, source, sourceHandle, target, targetHandle,
        type: "flow", label: label || undefined,
        data: { flow: true, state: "healthy", particles: logicalView ? 1 : 2, speed: 3.4 },
        style: {
          stroke: logicalView ? "#a78bfa" : (lk.resolved ? "#5a93c2" : "#6b7280"),
          strokeWidth: lk.bidirectional ? 2.2 : 1.6, opacity: 0.92,
          ...(logicalView ? { strokeDasharray: "6 3" } : {}),
        },
      });
    }

    // overlay tunnels (real latency/status) on top, if endpoints resolve.
    const idByName: Record<string, string> = {};
    for (const d of devices) {
      // NEVER index an empty key — a device with a blank name/address would make
      // idByName[""] resolve, and any tunnel with an unknown end (see below) would
      // then draw a bogus edge to it (this is what put a phantom DMZ-FW↔leaf link
      // on the map: the dmz-fw tunnel has no remote, so "" matched a leaf).
      if (d.name) idByName[d.name.toLowerCase()] = d.id;
      if (d.address) idByName[d.address.toLowerCase()] = d.id;
      idByName[d.id.toLowerCase()] = d.id;
    }
    for (const t of tunnels) {
      const lkey = (t.local_device || t.local_addr || "").toLowerCase();
      const rkey = (t.remote_device || t.remote_addr || "").toLowerCase();
      if (!lkey || !rkey) continue; // a tunnel with an unresolved end can't be drawn
      const a = idByName[lkey];
      const b = idByName[rkey];
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
    return { rfNodes, rfEdges, counts, topoType };
  }, [devices, alertsByDev, tunnels, vendorIcons, typeIcons, links, view]);

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

  const setTypeIcon = (kind: NetKind, url: string) => {
    setTypeIcons((cur) => {
      const next = { ...cur };
      if (url.trim()) next[kind] = url.trim(); else delete next[kind];
      try { localStorage.setItem(TYPE_ICONS_KEY, JSON.stringify(next)); } catch { /* quota */ }
      return next;
    });
  };

  const selDevice = selected ? devices.find((d) => d.id === selected) : null;

  return (
    <div className="card topo-card">
      <div className="topo-head">
        <div>
          <h2 style={{ margin: 0 }}>Device Topology</h2>
          {/* Sub-objects under Device Topology: Physical (L2) vs Logical (IGP). */}
          <div className="seg" style={{ display: "inline-flex", gap: 4, margin: "8px 0 6px" }}>
            <button className={`btn${view === "physical" ? " accent" : ""}`} onClick={() => setView("physical")}
              title="Layer-2 adjacency from LLDP/CDP">
              Physical{physicalCount > 0 ? ` · ${physicalCount}` : ""}
            </button>
            <button className={`btn${view === "logical" ? " accent" : ""}`} onClick={() => setView("logical")}
              title="IGP link-state topology carried by BGP-LS (IS-IS / OSPF)">
              Logical{igpName ? ` · ${igpName}` : " (IGP)"}{logicalCount > 0 ? ` · ${logicalCount}` : ""}
            </button>
          </div>
          <p className="topo-sub">
            {view === "logical"
              ? (logicalCount > 0
                ? `Logical topology — the ${igpName || "IGP"} link-state graph learned via BGP-LS. Violet dashed edges are IGP adjacencies labelled with protocol/area.`
                : "Logical topology — the IGP (IS-IS/OSPF) link-state graph. Enable BGP-LS discovery (ENABLE_BGPLS_DISCOVERY) with a peer running `distribute link-state` to populate it.")
              : (physicalCount > 0
                ? "Physical topology — real LLDP/CDP-discovered Layer-2 adjacencies, health-coloured; tunnels overlaid by latency."
                : "Physical topology — links inferred from role tiers (dashed) until LLDP/CDP discovery is enabled.")}
          </p>
        </div>
        <div className="topo-stats">
          {rfEdges.length > 0 && (
            <span className="topo-stat" title="Layout auto-detected from the discovered adjacency">
              <b>{TOPO_TYPE_LABEL[topoType]}</b> layout
            </span>
          )}
          <span className="topo-stat"><b style={{ color: HEALTH_COLOR.ok }}>{counts.ok}</b> healthy</span>
          <span className="topo-stat"><b style={{ color: HEALTH_COLOR.warning }}>{counts.warning}</b> warning</span>
          <span className="topo-stat"><b style={{ color: HEALTH_COLOR.critical }}>{counts.critical}</b> critical</span>
          <span className="topo-stat" title={view === "logical" ? "BGP-LS IGP adjacencies" : (physicalCount > 0 ? "LLDP/CDP-discovered adjacencies" : "inferred from role tiers")}>
            <b>{rfEdges.length}</b> {view === "logical" ? "IGP adjacencies" : (physicalCount > 0 ? "L2 links" : "inferred links")}
          </span>
          <button className={`btn${iconEditor ? "" : " accent"}`} onClick={() => setIconEditor((v) => !v)} title="Assign a custom icon per device type or vendor">
            {iconEditor ? "Done" : "+ Icons"}
          </button>
        </div>
      </div>

      {iconEditor && (
        <div className="vendor-editor">
          <div className="vendor-editor-head">
            <strong>Device-type icons</strong>
            <span className="vendor-editor-hint">Each type ships a built-in icon. Paste an image URL or data: URI (e.g. your licensed Icons8 export) to override one — it renders inside the health-ringed tile.</span>
          </div>
          <div className="vendor-editor-grid">
            {TYPE_ROWS.map((t) => {
              const url = typeIcons[t.kind] || "";
              return (
                <div key={t.kind} className="vendor-row">
                  <span className="vendor-tile" style={{ padding: 0, background: "transparent", border: "none" }}>
                    <NetIcon kind={t.kind} tone="#16A34A" size={26} src={url || undefined} />
                  </span>
                  <span className="vendor-name" title={t.label}>{t.label}{!url && <span className="vendor-auto">built-in</span>}</span>
                  <input className="vendor-input" placeholder="override: https://… or data:image/…" value={url} onChange={(e) => setTypeIcon(t.kind, e.target.value)} />
                </div>
              );
            })}
          </div>
          <div className="vendor-editor-head" style={{ marginTop: 12 }}>
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
              nodesConnectable={false} minZoom={0.2} maxZoom={1.6} zoomOnScroll={false} preventScrolling={false}
              onNodeClick={(_, n) => setSelected(n.id)} onPaneClick={() => setSelected(null)}
            >
              <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="var(--border,#2a2f3a)" />
              <Controls showInteractive={false} position="bottom-right" />
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
