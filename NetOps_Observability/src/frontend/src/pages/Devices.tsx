import { useEffect, useMemo, useState } from "react";
import { api, Device, Alert } from "../services/api";
import { takeDrill } from "../theme/drill";
import DeviceDetail, { DeviceDetailBody } from "./DeviceDetail";
import DeviceTerminal from "./DeviceTerminal";
import Logs from "../tabs/Logs";
import Wizard from "../components/Wizard";
import DataTable, { Column, Sev } from "../components/DataTable";
import { useWorkspace } from "../context/workspace";

const Req = () => <span style={{ color: "var(--bad)", marginLeft: 2 }} title="required">*</span>;

// Device health is 3-state (#20 follow-up). Thresholds are heartbeat ages on
// last_seen; "amber" also folds in active alerts so a reachable-but-sick device
// reads as degraded, not healthy.
const FRESH_MS = 5 * 60 * 1000; // fresher than this = healthy heartbeat
const DOWN_MS = 15 * 60 * 1000; // staler than this = down
type Health = "up" | "degraded" | "down";

const HEALTH_META: Record<Health, { label: string; color: string }> = {
  up: { label: "Up", color: "var(--good, #16a34a)" },
  degraded: { label: "Degraded", color: "var(--warn, #d97706)" },
  down: { label: "Down", color: "var(--bad, #dc2626)" },
};

function deviceHealth(d: Device, alertedDevices: Set<string>): Health {
  const seen = new Date(d.last_seen).getTime();
  const age = seen ? Date.now() - seen : Infinity;
  if (age > DOWN_MS) return "down";
  if (alertedDevices.has(d.id) || age > FRESH_MS) return "degraded";
  return "up";
}

// A compact status dot shown inline, just before the device name. Tooltip
// carries the label so we don't spend a column on it.
function StatusDot({ health }: { health: Health }) {
  const m = HEALTH_META[health];
  return (
    <span
      title={m.label}
      aria-label={m.label}
      style={{
        display: "inline-block", width: 8, height: 8, borderRadius: 999,
        background: m.color, boxShadow: `0 0 0 2px color-mix(in srgb, ${m.color} 25%, transparent)`,
        flex: "none", marginRight: 8, verticalAlign: "middle",
      }}
    />
  );
}

// Stable accent per vendor so each group header reads as one product family.
const VENDOR_HUE: Record<string, number> = {
  cisco: 200, juniper: 150, arista: 280, fortinet: 0,
  paloalto: 25, nokia: 220, huawei: 345, mikrotik: 35,
};
function vendorColor(vendor: string): string {
  const key = vendor.toLowerCase().replace(/[^a-z]/g, "");
  let hue = VENDOR_HUE[key];
  if (hue === undefined) {
    if (vendor === "Unknown") return "var(--muted)";
    let h = 0;
    for (let i = 0; i < vendor.length; i++) h = (h * 31 + vendor.charCodeAt(i)) % 360;
    hue = h;
  }
  return `hsl(${hue} 65% 55%)`;
}

const SOURCE_META: Record<string, { label: string; tone: string }> = {
  static: { label: "Static", tone: "" },
  snmp: { label: "SNMP", tone: "good" },
  netbox: { label: "NetBox", tone: "accent" },
  manual: { label: "Manual", tone: "warn" },
};
const sourceLabel = (s: string) => SOURCE_META[s]?.label ?? (s || "—");
const sourceTone = (s: string) => SOURCE_META[s]?.tone ?? "";

type Filter = "all" | Health;

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [sshEnabled, setSshEnabled] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [draft, setDraft] = useState({ id: "", name: "", address: "", vendor: "" });
  const [filter, setFilter] = useState<Filter>("all");
  const [q, setQ] = useState("");
  const [detail, setDetail] = useState<Device | null>(null);
  const [term, setTerm] = useState<Device | null>(null);
  const ws = useWorkspace();

  // Selecting a device pivots into the dockable Inspector (shell-v2) with its
  // context + actions (Connect, and a "View logs" NOC pivot that opens the
  // device's logs in the bottom drawer). In v1 it falls back to the modal.
  const openDevice = (d: Device) => {
    if (!ws.enabled) { setDetail(d); return; }
    ws.openInspector(
      <DeviceDetailBody
        device={d}
        actions={
          <>
            {sshEnabled && <button className="btn" onClick={() => setTerm(d)}>Connect</button>}
            <button
              className="btn"
              onClick={() => ws.openDrawer(<Logs initialQuery={d.name || d.id} rangeMinutes={60} />, { title: `Logs · ${d.id}` })}
            >
              View logs
            </button>
          </>
        }
      />,
      { title: d.name || d.id, subtitle: d.address },
    );
  };

  useEffect(() => {
    const d = takeDrill().devices;
    if (d === "down") setFilter("down");
  }, []);

  const load = async () => {
    try {
      const [list, al] = await Promise.all([api.devices(), api.alerts().catch(() => [])]);
      setDevices(list ?? []);
      setAlerts(al ?? []);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    load();
    api.credentials().then((c) => setSshEnabled(!!c.device_ssh)).catch(() => {});
    const t = setInterval(load, 30_000); // live-ish; status is time-sensitive
    return () => clearInterval(t);
  }, []);

  const addDevice = async () => {
    if (!draft.id.trim() || !draft.address.trim()) return;
    await api.upsertDevice(draft);
    setDraft({ id: "", name: "", address: "", vendor: "" });
    setShowAdd(false);
    await load();
  };

  const remove = async (id: string) => {
    if (!confirm(`Delete ${id}?`)) return;
    await api.deleteDevice(id);
    await load();
  };

  // Active (unresolved) warning/critical alerts → set of affected device ids.
  const alertedDevices = useMemo(() => {
    const s = new Set<string>();
    for (const a of alerts) {
      if (a.resolved_at) continue;
      const sev = (a.severity || "").toLowerCase();
      if ((sev === "warning" || sev === "critical" || sev === "error") && a.device_id) s.add(a.device_id);
    }
    return s;
  }, [alerts]);

  const health = useMemo(() => new Map(devices.map((d) => [d.id, deviceHealth(d, alertedDevices)])), [devices, alertedDevices]);
  const counts = useMemo(() => {
    const c = { up: 0, degraded: 0, down: 0 };
    for (const h of health.values()) c[h]++;
    return c;
  }, [health]);

  // Health-filtered flat list; the text filter (q) + sort run inside DataTable.
  const rows = useMemo(
    () => devices.filter((d) => filter === "all" || health.get(d.id) === filter),
    [devices, filter, health],
  );

  // Map device health → the sacred severity ramp so a stale/down heartbeat tints
  // its "Last seen" cell (warn = degraded, crit = down).
  const healthSev = (h: Health): Sev | undefined =>
    h === "down" ? "crit" : h === "degraded" ? "warn" : undefined;

  // Column defs for the telemetry table primitive. `text` feeds the inline
  // filter, `sortValue` the header sort, `sev` the conditional cell tint.
  const columns = useMemo<Column<Device>[]>(() => [
    {
      key: "id", header: "Device", width: "16%", sortable: true,
      text: (d) => d.id, sortValue: (d) => d.id,
      render: (d) => (
        <>
          <StatusDot health={health.get(d.id) ?? "up"} />
          <a className="dtv-link" title="View device details"
            onClick={(e) => { e.stopPropagation(); openDevice(d); }}>{d.id}</a>
        </>
      ),
    },
    {
      key: "name", header: "Name", width: "16%", sortable: true,
      text: (d) => d.name ?? "", render: (d) => <span title={d.name || ""}>{d.name || "—"}</span>,
    },
    {
      key: "address", header: "Address", width: 160,
      text: (d) => d.address,
      render: (d) => <span title={d.address} style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{d.address}</span>,
    },
    {
      key: "vendor", header: "Vendor", width: "13%", sortable: true,
      text: (d) => d.vendor ?? "", sortValue: (d) => (d.vendor || "~").toLowerCase(),
      render: (d) => {
        const v = (d.vendor || "").trim() || "Unknown";
        return (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }} title={v}>
            <span style={{ width: 8, height: 8, borderRadius: 3, background: vendorColor(v), flex: "none" }} />
            <span style={{ textTransform: "capitalize" }}>{v}</span>
          </span>
        );
      },
    },
    {
      key: "model", header: "Model", width: "12%",
      text: (d) => d.model ?? "", render: (d) => <span title={d.model || ""}>{d.model || "—"}</span>,
    },
    {
      key: "source", header: "Source", width: 96,
      text: (d) => sourceLabel(d.source),
      render: (d) => <span className={`badge ${sourceTone(d.source)}`} title={`Discovery source: ${d.source || "unknown"}`}>{sourceLabel(d.source)}</span>,
    },
    {
      key: "last_seen", header: "Last seen", width: 110, sortable: true,
      sortValue: (d) => new Date(d.last_seen).getTime() || 0,
      sev: (d) => healthSev(health.get(d.id) ?? "up"),
      render: (d) => <span title={new Date(d.last_seen).toLocaleString()}>{relTime(d.last_seen)}</span>,
    },
  ], [health]);

  const chip = (key: Filter, label: string, n: number, color?: string) => (
    <button
      className={filter === key ? "btn accent" : "btn"}
      onClick={() => setFilter(key)}
      style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
    >
      {color && <span style={{ width: 8, height: 8, borderRadius: 999, background: color }} />}
      {label} {n}
    </button>
  );

  return (
    <>
      <div className="card" style={{ paddingBottom: 10 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {chip("all", "All", devices.length)}
            {chip("up", "Up", counts.up, HEALTH_META.up.color)}
            {chip("degraded", "Degraded", counts.degraded, HEALTH_META.degraded.color)}
            {chip("down", "Down", counts.down, HEALTH_META.down.color)}
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input
              placeholder="Filter devices…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              style={{ width: 200 }}
            />
            <button className="btn" onClick={() => setShowAdd((v) => !v)}>{showAdd ? "Cancel" : "+ Add device"}</button>
          </div>
        </div>

        {showAdd && (
          <div style={{ marginTop: 12, borderTop: "1px solid var(--panel-border, #e2e6ee)", paddingTop: 12 }}>
            <Wizard
              finishLabel="Add device"
              onCancel={() => { setShowAdd(false); setDraft({ id: "", name: "", address: "", vendor: "" }); }}
              onFinish={addDevice}
              steps={[
                {
                  id: "identity",
                  title: "Identity",
                  hint: "How the platform reaches and refers to this device. Both are required.",
                  isValid: () => !!draft.id.trim() && !!draft.address.trim(),
                  render: () => (
                    <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                      <label style={{ display: "grid", gap: 4 }}>
                        <span style={{ fontSize: 12 }}>Device ID <Req /></span>
                        <input placeholder="e.g. leaf1" value={draft.id} autoFocus onChange={(e) => setDraft({ ...draft, id: e.target.value })} />
                      </label>
                      <label style={{ display: "grid", gap: 4 }}>
                        <span style={{ fontSize: 12 }}>Address <Req /></span>
                        <input placeholder="IP or hostname" value={draft.address} onChange={(e) => setDraft({ ...draft, address: e.target.value })} />
                      </label>
                    </div>
                  ),
                },
                {
                  id: "classify",
                  title: "Classification",
                  hint: "Optional — helps grouping and vendor profiles. You can change these later.",
                  isValid: () => true,
                  render: () => (
                    <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                      <label style={{ display: "grid", gap: 4 }}>
                        <span style={{ fontSize: 12 }}>Display name</span>
                        <input placeholder="optional" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
                      </label>
                      <label style={{ display: "grid", gap: 4 }}>
                        <span style={{ fontSize: 12 }}>Vendor</span>
                        <input placeholder="optional" value={draft.vendor} onChange={(e) => setDraft({ ...draft, vendor: e.target.value })} />
                      </label>
                    </div>
                  ),
                },
              ]}
            />
          </div>
        )}
        {error && <p style={{ color: "var(--bad)", marginBottom: 0 }}>{error}</p>}
      </div>

      <div className="card">
        {devices.length === 0 ? (
          <div className="empty">No devices yet — discovery hasn't returned anything.</div>
        ) : (
          <DataTable<Device>
            rows={rows}
            columns={columns}
            rowKey={(d) => d.id}
            filter={q}
            height="62vh"
            ariaLabel="Devices"
            initialSort={{ key: "vendor", dir: "asc" }}
            onRowClick={(d) => openDevice(d)}
            empty="No devices match this filter."
            rowActions={(d) => (
              <>
                {sshEnabled && (
                  <button className="btn" title="SSH to device" onClick={() => setTerm(d)}>Connect</button>
                )}
                <button className="btn" onClick={() => remove(d.id)}>Delete</button>
              </>
            )}
          />
        )}
      </div>

      {detail && <DeviceDetail device={detail} onClose={() => setDetail(null)} />}
      {term && <DeviceTerminal device={term} onClose={() => setTerm(null)} />}
    </>
  );
}

// relTime renders a compact "3m ago" / "2h ago" age for the last-seen column.
function relTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (!t) return "—";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
