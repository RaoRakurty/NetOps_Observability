import { useEffect, useMemo, useState } from "react";
import { api, PortRow } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { operatorError } from "../lib/errors";
// PortsWorkbench — the service-provider-grade Interfaces / Ports / Optics / DDM
// workbench (#94 P6). Fleet-wide table over /api/infrastructure/interfaces with
// six column presets (NOC / Troubleshooting / Optics-DDM / 400G-800G Lane /
// Carrier Handoff / Inventory), filter chips, and a right-side detail drawer.
// Enhances the Infrastructure surface — no new nav tree (owner constraint).
// Separates logical interface state from physical port/transceiver state but
// presents them together. Data lights up when the collectors run on real optics
// hardware; until then the shell + presets + honest empty state render.

type PresetKey = "noc" | "troubleshoot" | "optics" | "lanes" | "carrier" | "inventory";

const PRESETS: { key: PresetKey; label: string }[] = [
  { key: "noc", label: "NOC" },
  { key: "troubleshoot", label: "Troubleshooting" },
  { key: "optics", label: "Optics / DDM" },
  { key: "lanes", label: "400G / 800G Lane" },
  { key: "carrier", label: "Carrier Handoff" },
  { key: "inventory", label: "Inventory" },
];

const fmtSpeed = (bps: number) => (bps >= 1e9 ? `${(bps / 1e9).toFixed(0)}G` : bps >= 1e6 ? `${(bps / 1e6).toFixed(0)}M` : bps ? `${bps}` : "—");
const dash = (s?: string) => (s && s.trim() ? s : "—");

// Health chip: the sacred ok/watch/degraded/critical ramp.
function Health({ score, state }: { score: number; state: string }) {
  const color = state === "critical" ? "var(--crit,#e5484d)" : state === "degraded" ? "var(--warn,#f5a623)"
    : state === "watch" ? "var(--info,#e2b714)" : "var(--ok,#30a46c)";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <span style={{ width: 8, height: 8, borderRadius: "50%", background: color }} />
      <span style={{ fontVariantNumeric: "tabular-nums" }}>{score}</span>
    </span>
  );
}

function statusCell(v: string) {
  const up = v === "up";
  return <span style={{ color: up ? "var(--ok,#30a46c)" : v === "down" ? "var(--crit,#e5484d)" : "var(--muted)" }}>{dash(v)}</span>;
}

// Column presets — the owner's per-view column lists (subset present in PortRow;
// lane/FEC/coherent columns render from the row when the collectors supply them).
function columnsFor(preset: PresetKey): Column<PortRow>[] {
  const health: Column<PortRow> = { key: "health", header: "Health", width: 70, align: "right", sortable: true, sortValue: (r) => r.health, render: (r) => <Health score={r.health} state={r.health_state} /> };
  const device: Column<PortRow> = { key: "device", header: "Device", width: 120, sortable: true, text: (r) => r.device, render: (r) => r.device };
  const port: Column<PortRow> = { key: "port", header: "Port", width: 130, sortable: true, text: (r) => r.port_name, render: (r) => r.port_name };
  const alias: Column<PortRow> = { key: "alias", header: "Description", render: (r) => dash(r.if_alias) };
  const admin: Column<PortRow> = { key: "admin", header: "Admin", width: 70, render: (r) => statusCell(r.admin_status) };
  const oper: Column<PortRow> = { key: "oper", header: "Oper", width: 70, render: (r) => statusCell(r.oper_status) };
  const speed: Column<PortRow> = { key: "speed", header: "Speed", width: 70, align: "right", sortable: true, sortValue: (r) => r.speed_bps, render: (r) => fmtSpeed(r.speed_bps) };
  const seam: Column<PortRow> = { key: "seam", header: "Seam", width: 90, render: (r) => dash(r.seam) };
  const role: Column<PortRow> = { key: "role", header: "Role", width: 90, render: (r) => dash(r.role) };
  const dominant: Column<PortRow> = { key: "issue", header: "Dominant issue", render: (r) => dash(r.dominant_issue) };
  const form: Column<PortRow> = { key: "form", header: "Form factor", width: 100, render: (r) => dash(r.form_factor) };
  const media: Column<PortRow> = { key: "media", header: "Media", width: 130, render: (r) => dash(r.media_type) };
  const vendor: Column<PortRow> = { key: "vendor", header: "Vendor", width: 100, render: (r) => dash(r.vendor_name) };
  const part: Column<PortRow> = { key: "part", header: "Part #", width: 120, render: (r) => dash(r.part_number) };
  const serial: Column<PortRow> = { key: "serial", header: "Serial", width: 130, render: (r) => dash(r.serial_number) };
  const supported: Column<PortRow> = { key: "supported", header: "Supported", width: 100, render: (r) => dash(r.supported_status) };

  switch (preset) {
    case "noc":
      return [health, device, port, alias, role, seam, admin, oper, speed, dominant];
    case "troubleshoot":
      return [health, device, port, admin, oper, speed, dominant];
    case "optics":
      return [health, device, port, form, media, vendor, part, serial, supported];
    case "lanes":
      return [health, device, port, form, speed, dominant];
    case "carrier":
      return [health, device, port, seam, role, admin, oper, speed, media, dominant];
    case "inventory":
      return [device, port, form, media, vendor, part, serial, supported];
  }
}

function Drawer({ row, onClose }: { row: PortRow; onClose: () => void }) {
  const Section = ({ title, children }: { title: string; children: React.ReactNode }) => (
    <div style={{ borderTop: "1px solid var(--line)", padding: "10px 0" }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: "var(--muted)", textTransform: "uppercase", letterSpacing: 0.4, marginBottom: 6 }}>{title}</div>
      {children}
    </div>
  );
  const Row = ({ k, v }: { k: string; v?: string | number }) => (
    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, padding: "2px 0" }}>
      <span style={{ color: "var(--muted)" }}>{k}</span><span style={{ fontVariantNumeric: "tabular-nums" }}>{v === "" || v === undefined ? "—" : v}</span>
    </div>
  );
  return (
    <div style={{ position: "fixed", top: 0, right: 0, bottom: 0, width: 420, maxWidth: "90vw", background: "var(--panel,#14161a)", borderLeft: "1px solid var(--line)", boxShadow: "-8px 0 24px rgba(0,0,0,0.3)", overflowY: "auto", zIndex: 50, padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div style={{ fontWeight: 600 }}>{row.device} · {row.port_name}</div>
          <div style={{ fontSize: 11, color: "var(--muted)" }}>{dash(row.if_alias)}</div>
        </div>
        <button className="op-hd-btn" onClick={onClose} title="Close" style={{ fontSize: 14 }}>×</button>
      </div>
      <Section title="Interface State">
        <Row k="Admin" v={row.admin_status} /><Row k="Oper" v={row.oper_status} />
        <Row k="Speed" v={fmtSpeed(row.speed_bps)} /><Row k="Role" v={dash(row.role)} />
        <Row k="Seam" v={dash(row.seam)} /><Row k="LAG" v={dash(row.lag_id)} />
        <Row k="Breakout group" v={dash(row.breakout_group_id)} /><Row k="Last change" v={dash(row.last_change)} />
      </Section>
      <Section title="Transceiver Inventory">
        <Row k="Form factor" v={dash(row.form_factor)} /><Row k="Media" v={dash(row.media_type)} />
        <Row k="Vendor" v={dash(row.vendor_name)} /><Row k="Part #" v={dash(row.part_number)} />
        <Row k="Serial" v={dash(row.serial_number)} /><Row k="Supported" v={dash(row.supported_status)} />
      </Section>
      <Section title="DDM / DOM">
        <div style={{ fontSize: 12, color: "var(--muted)" }}>Optical power / temperature / bias stream from the metrics plane once the collectors run on real optics hardware.</div>
      </Section>
      <Section title="RCA Evidence">
        {row.matched_signature ? (
          <>
            <Row k="Matched signature" v={row.matched_signature} />
            <Row k="Dominant issue" v={dash(row.dominant_issue)} />
            <Row k="Health" v={`${row.health} (${row.health_state})`} />
          </>
        ) : (
          <div style={{ fontSize: 12, color: "var(--muted)" }}>No physical-layer signature attached. Health {row.health} ({row.health_state}).</div>
        )}
      </Section>
    </div>
  );
}

export default function PortsWorkbench() {
  const [preset, setPreset] = useState<PresetKey>("noc");
  const [rows, setRows] = useState<PortRow[]>([]);
  const [total, setTotal] = useState(0);
  const [summary, setSummary] = useState<{ total_ports: number; by_state: Record<string, number>; rca_attached: number } | null>(null);
  const [filter, setFilter] = useState("");
  const [seamFilter, setSeamFilter] = useState("");
  const [rcaOnly, setRcaOnly] = useState(false);
  const [selected, setSelected] = useState<PortRow | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const qs = new URLSearchParams();
    if (seamFilter) qs.set("seam", seamFilter);
    if (rcaOnly) qs.set("rca_attached", "true");
    qs.set("limit", "500");
    api.portInterfaces(qs.toString()).then((r) => { setRows(r.interfaces ?? []); setTotal(r.total); setErr(null); }).catch((e) => setErr(operatorError(e, "Interface data could not be loaded.")));
    api.portSummary().then(setSummary).catch(() => {});
  }, [seamFilter, rcaOnly]);

  const columns = useMemo(() => columnsFor(preset), [preset]);
  const seams = useMemo(() => Array.from(new Set(rows.map((r) => r.seam).filter(Boolean))) as string[], [rows]);

  return (
    <div style={{ padding: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
        <h2 style={{ margin: 0, fontSize: 16 }}>Interfaces · Ports · Optics</h2>
        {summary && (
          <div style={{ display: "flex", gap: 12, fontSize: 12, color: "var(--muted)" }}>
            <span>{summary.total_ports} ports</span>
            <span style={{ color: "var(--warn,#f5a623)" }}>{summary.by_state.degraded ?? 0} degraded</span>
            <span style={{ color: "var(--crit,#e5484d)" }}>{summary.by_state.critical ?? 0} critical</span>
            <span>{summary.rca_attached} RCA-attached</span>
          </div>
        )}
      </div>

      {/* View presets */}
      <div style={{ display: "flex", gap: 4, margin: "12px 0" }}>
        {PRESETS.map((p) => (
          <button key={p.key} onClick={() => setPreset(p.key)}
            className={`dash-btn${preset === p.key ? " accent" : ""}`} style={{ fontSize: 12 }}>{p.label}</button>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10, flexWrap: "wrap" }}>
        <input placeholder="Search device / port / vendor…" value={filter} onChange={(e) => setFilter(e.target.value)}
          style={{ flex: "1 1 240px", minWidth: 200 }} />
        <select value={seamFilter} onChange={(e) => setSeamFilter(e.target.value)} style={{ fontSize: 12 }}>
          <option value="">All seams</option>
          {seams.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <label style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 12, color: "var(--muted)" }}>
          <input type="checkbox" checked={rcaOnly} onChange={(e) => setRcaOnly(e.target.checked)} /> RCA attached
        </label>
      </div>

      {err && <div style={{ color: "var(--crit,#e5484d)", fontSize: 12, marginBottom: 8 }}>{err}</div>}

      <DataTable
        rows={rows}
        columns={columns}
        rowKey={(r) => r.device + "|" + r.port_id}
        filter={filter}
        onRowClick={setSelected}
        ariaLabel="Interfaces and ports"
        empty={
          <div style={{ padding: 40, textAlign: "center", color: "var(--muted)", fontSize: 13 }}>
            No interface/optics data yet. Ports populate as the collectors poll devices with SNMP/gNMI;
            optics (DDM) require transceivers that expose ENTITY-SENSOR-MIB or a vendor DOM MIB.
            {total > 0 && ` (${total} ports match the current filter but not the search.)`}
          </div>
        }
      />

      {selected && <Drawer row={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
