import { useEffect, useMemo, useState } from "react";
import { api, Device, Alert } from "../services/api";
import { takeDrill } from "../theme/drill";
import DeviceDetail from "./DeviceDetail";
import DeviceTerminal from "./DeviceTerminal";

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

function StatusDot({ health }: { health: Health }) {
  const m = HEALTH_META[health];
  return (
    <span title={m.label} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <span style={{ width: 9, height: 9, borderRadius: 999, background: m.color, boxShadow: `0 0 0 3px color-mix(in srgb, ${m.color} 22%, transparent)`, flex: "none" }} />
      <span style={{ fontSize: 12, color: "var(--muted)" }}>{m.label}</span>
    </span>
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
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [draft, setDraft] = useState({ id: "", name: "", address: "", vendor: "" });
  const [filter, setFilter] = useState<Filter>("all");
  const [q, setQ] = useState("");
  const [detail, setDetail] = useState<Device | null>(null);
  const [term, setTerm] = useState<Device | null>(null);

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

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!draft.id || !draft.address) return;
    setBusy(true);
    try {
      await api.upsertDevice(draft);
      setDraft({ id: "", name: "", address: "", vendor: "" });
      setShowAdd(false);
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
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

  const groups = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const by = new Map<string, Device[]>();
    for (const d of devices) {
      if (filter !== "all" && health.get(d.id) !== filter) continue;
      if (needle) {
        const hay = `${d.id} ${d.name} ${d.address} ${d.vendor ?? ""} ${d.model ?? ""}`.toLowerCase();
        if (!hay.includes(needle)) continue;
      }
      const v = (d.vendor || "").trim() || "Unknown";
      (by.get(v) ?? by.set(v, []).get(v)!).push(d);
    }
    return [...by.entries()].sort(([a], [b]) =>
      a === "Unknown" ? 1 : b === "Unknown" ? -1 : a.localeCompare(b));
  }, [devices, filter, q, health]);

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
          <form onSubmit={submit} style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
            <input placeholder="id" value={draft.id} onChange={(e) => setDraft({ ...draft, id: e.target.value })} />
            <input placeholder="name" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            <input placeholder="address" value={draft.address} onChange={(e) => setDraft({ ...draft, address: e.target.value })} />
            <input placeholder="vendor (optional)" value={draft.vendor} onChange={(e) => setDraft({ ...draft, vendor: e.target.value })} />
            <button className="btn accent" disabled={busy} type="submit">{busy ? "Saving…" : "Save"}</button>
          </form>
        )}
        {error && <p style={{ color: "var(--bad)", marginBottom: 0 }}>{error}</p>}
      </div>

      <div className="card">
        {devices.length === 0 ? (
          <div className="empty">No devices yet — discovery hasn't returned anything.</div>
        ) : groups.length === 0 ? (
          <div className="empty">No devices match this filter.</div>
        ) : (
          // One unified, column-aligned grid: a single <table> with a fixed
          // colgroup so every row lines up; vendors are section header rows
          // (multiple <tbody> in one table is valid HTML and keeps alignment).
          <table className="device-table" style={{ tableLayout: "fixed", width: "100%" }}>
            <colgroup>
              <col style={{ width: 96 }} />
              <col style={{ width: "16%" }} />
              <col style={{ width: "18%" }} />
              <col style={{ width: 150 }} />
              <col style={{ width: "14%" }} />
              <col style={{ width: 88 }} />
              <col style={{ width: 96 }} />
              <col style={{ width: sshEnabled ? 170 : 90 }} />
            </colgroup>
            <thead>
              <tr>
                <th>Status</th>
                <th>ID</th>
                <th>Name</th>
                <th>Address</th>
                <th>Model</th>
                <th>Source</th>
                <th>Last seen</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            {groups.map(([vendor, list]) => (
              <tbody key={vendor}>
                <tr className="group-row">
                  <td colSpan={8} style={{ background: "var(--hover)", padding: "6px 10px", fontWeight: 600 }}>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                      <span style={{ width: 9, height: 9, borderRadius: 999, background: vendorColor(vendor) }} />
                      {vendor}
                      <span style={{ color: "var(--muted)", fontWeight: 400, fontSize: 12 }}>· {list.length}</span>
                    </span>
                  </td>
                </tr>
                {list.map((d) => (
                  <tr key={d.id}>
                    <td><StatusDot health={health.get(d.id) ?? "up"} /></td>
                    <td style={ellipsis}>
                      <a style={{ cursor: "pointer", color: "var(--accent)", fontWeight: 600 }}
                        title="View device details" onClick={() => setDetail(d)}>{d.id}</a>
                    </td>
                    <td style={ellipsis} title={d.name || ""}>{d.name || "—"}</td>
                    <td style={{ ...ellipsis, fontFamily: "var(--font-mono, monospace)", fontSize: 12 }} title={d.address}>{d.address}</td>
                    <td style={ellipsis} title={d.model || ""}>{d.model || "—"}</td>
                    <td><span className={`badge ${sourceTone(d.source)}`} title={`Discovery source: ${d.source || "unknown"}`}>{sourceLabel(d.source)}</span></td>
                    <td title={new Date(d.last_seen).toLocaleString()} style={{ fontSize: 12, color: "var(--muted)" }}>{relTime(d.last_seen)}</td>
                    <td style={{ whiteSpace: "nowrap", textAlign: "right" }}>
                      {sshEnabled && (
                        <button className="btn" title="SSH to device" onClick={() => setTerm(d)} style={{ marginRight: 6 }}>Connect</button>
                      )}
                      <button className="btn" onClick={() => remove(d.id)}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            ))}
          </table>
        )}
      </div>

      {detail && <DeviceDetail device={detail} onClose={() => setDetail(null)} />}
      {term && <DeviceTerminal device={term} onClose={() => setTerm(null)} />}
    </>
  );
}

const ellipsis: React.CSSProperties = { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" };

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
