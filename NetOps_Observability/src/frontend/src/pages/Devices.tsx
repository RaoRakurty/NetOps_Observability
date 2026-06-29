import { useEffect, useMemo, useState } from "react";
import { api, Device, Alert, DeviceLocationRow, SiteRow } from "../services/api";
import { takeDrill } from "../theme/drill";
import DeviceDetailPage from "./DeviceDetailPage";
import DeviceTerminal from "./DeviceTerminal";
import Wizard from "../components/Wizard";
import DataTable, { Column, Sev } from "../components/DataTable";
import { NocHeader, NocKpis, NocKpi, Chip, LiveChip } from "../components/noc";

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

// Functional device type (SNMP-inferred, backend) → label + colour. Distinct hues
// so the column scans at a glance; "generic" stays muted (unclassified).
const TYPE_META: Record<string, { label: string; color: string }> = {
  router: { label: "Router", color: "#3b82f6" },
  switch: { label: "Switch", color: "#22c55e" },
  firewall: { label: "Firewall", color: "#ef4444" },
  "load-balancer": { label: "Load balancer", color: "#a855f7" },
  ap: { label: "Access point", color: "#06b6d4" },
  wlc: { label: "WLC", color: "#14b8a6" },
  "cloud-gw": { label: "Cloud GW", color: "#f59e0b" },
  generic: { label: "Generic", color: "var(--muted)" },
};
const typeMeta = (t?: string) => TYPE_META[(t || "generic")] ?? { label: t || "—", color: "var(--muted)" };

type Filter = "all" | Health;

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [locs, setLocs] = useState<Map<string, DeviceLocationRow>>(new Map()); // device id → resolved placement
  const [siteOptions, setSiteOptions] = useState<SiteRow[]>([]); // declared SoT sites (assignable)
  const [sotProvider, setSotProvider] = useState<string>("internal"); // active SoT authority
  const [sshEnabled, setSshEnabled] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [draft, setDraft] = useState({ id: "", name: "", address: "", vendor: "" });
  const [filter, setFilter] = useState<Filter>("all");
  const [q, setQ] = useState("");
  const [detail, setDetail] = useState<Device | null>(null);
  const [term, setTerm] = useState<Device | null>(null);

  // Selecting a device opens the full-page detail view (Overview · Interfaces ·
  // Routing) — the reference design's graph rows need full width, which the narrow
  // inspector couldn't carry.
  const openDevice = (d: Device) => setDetail(d);

  useEffect(() => {
    const d = takeDrill().devices;
    if (d === "down") setFilter("down");
    // Deep link from Command Center "Impacted entities" → pre-filter to that
    // entity so its status row is shown immediately (#/infrastructure/devices?q=…).
    const qs = (typeof location !== "undefined" ? location.hash : "").split("?")[1] || "";
    const dq = new URLSearchParams(qs).get("q");
    if (dq) setQ(dq);
  }, []);

  const load = async () => {
    try {
      const [list, al, locRes, siteRes] = await Promise.all([
        api.devices(),
        api.alerts().catch(() => []),
        api.deviceLocations().catch(() => ({ devices: [] as DeviceLocationRow[] })),
        api.sites().catch(() => ({ sites: [] as SiteRow[], active: "internal" })),
      ]);
      setDevices(list ?? []);
      setAlerts(al ?? []);
      setLocs(new Map((locRes?.devices ?? []).map((r) => [r.id, r])));
      setSiteOptions([...(siteRes?.sites ?? [])].sort((a, b) => a.name.localeCompare(b.name)));
      setSotProvider(siteRes?.active ?? "internal");
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  // Assign / clear a device's declared site (operator intent). Coordinates resolve
  // live from the site definition; an empty slug clears the binding.
  const assignSite = async (id: string, slug: string) => {
    try {
      if (slug) await api.setDeviceSite(id, slug);
      else await api.clearDeviceSite(id);
      await load();
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

  // Declared-site lookup (slug → display name) + whether the site column is
  // editable. Only the INTERNAL SoT provider's sites are editable here; when an
  // external CMDB (NetBox) is the authority, placement is read-only.
  const siteName = useMemo(() => new Map(siteOptions.map((s) => [s.slug, s.name])), [siteOptions]);
  const editableSites = sotProvider === "internal" && siteOptions.length > 0;

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
      key: "address", header: "IP address", width: 148,
      text: (d) => d.address,
      render: (d) => <span title={d.address} style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{d.address}</span>,
    },
    {
      key: "type", header: "Type", width: "12%", sortable: true,
      text: (d) => typeMeta(d.type).label, sortValue: (d) => d.type || "~",
      render: (d) => {
        const m = typeMeta(d.type);
        return (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }} title={`Device type: ${m.label} (SNMP-inferred)`}>
            <span style={{ width: 8, height: 8, borderRadius: 999, background: m.color, flex: "none" }} />
            <span>{m.label}</span>
          </span>
        );
      },
    },
    {
      key: "vendor", header: "Manufacturer", width: "12%", sortable: true,
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
      key: "location", header: "Site", width: "15%", sortable: true,
      text: (d) => siteText(locs.get(d.id), siteName),
      sortValue: (d) => siteText(locs.get(d.id), siteName) || "~",
      render: (d) => (
        <SiteCell
          row={locs.get(d.id)}
          options={siteOptions}
          editable={editableSites}
          siteName={siteName}
          onAssign={(slug) => assignSite(d.id, slug)}
        />
      ),
    },
    {
      key: "model", header: "Description", width: "14%",
      text: (d) => d.model ?? d.os ?? "", render: (d) => <span title={d.model || d.os || ""} style={{ color: "var(--fg-muted)" }}>{d.model || d.os || "—"}</span>,
    },
    {
      key: "source", header: "Source", width: 88,
      text: (d) => sourceLabel(d.source),
      render: (d) => <span className={`badge ${sourceTone(d.source)}`} title={`Discovery source: ${d.source || "unknown"}`}>{sourceLabel(d.source)}</span>,
    },
    {
      key: "last_seen", header: "Polled", width: 100, sortable: true,
      sortValue: (d) => new Date(d.last_seen).getTime() || 0,
      sev: (d) => healthSev(health.get(d.id) ?? "up"),
      render: (d) => <span title={new Date(d.last_seen).toLocaleString()}>{relTime(d.last_seen)}</span>,
    },
  ], [health, locs, siteOptions, editableSites, siteName]);

  const chip = (key: Filter, label: string, n: number, color?: string) => (
    <button
      className={filter === key ? "chip chip-active" : "chip"}
      onClick={() => setFilter(key)}
      style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
    >
      {color && <span style={{ width: 8, height: 8, borderRadius: 999, background: color, flex: "none" }} />}
      {label} <span style={{ opacity: 0.65, fontVariantNumeric: "tabular-nums" }}>{n}</span>
    </button>
  );

  return (
    <div className="dm-board">
      <NocHeader
        title="Inventory & Devices"
        subtitle="Every discovered and declared device, with live reachability health, type and source — click any row to drill into its telemetry."
        chips={<><Chip label={`${devices.length} devices`} /><LiveChip detail="30s poll" /></>}
      >
        <NocKpis cols={4}>
          <NocKpi n={devices.length} label="Inventory" interp="devices tracked" />
          <NocKpi n={counts.up} label="Up" interp="fresh heartbeat" tone={counts.up ? "var(--ok)" : undefined} />
          <NocKpi n={counts.degraded} label="Degraded" interp="stale or alerting" tone={counts.degraded ? "var(--warn)" : undefined} />
          <NocKpi n={counts.down} label="Down" interp="no heartbeat" tone={counts.down ? "var(--crit)" : undefined} />
        </NocKpis>
      </NocHeader>

      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Device inventory</h3>
          <span className="cc-panel-meta">{rows.length} shown · click a row for the device workspace</span>
        </div>
        <div style={{ padding: "11px 13px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap", marginBottom: 11 }}>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {chip("all", "All", devices.length)}
              {chip("up", "Up", counts.up, HEALTH_META.up.color)}
              {chip("degraded", "Degraded", counts.degraded, HEALTH_META.degraded.color)}
              {chip("down", "Down", counts.down, HEALTH_META.down.color)}
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <input
                className="form-input"
                placeholder="Filter devices…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                style={{ width: 200, height: 32 }}
              />
              <button className="btn" onClick={() => setShowAdd((v) => !v)}>{showAdd ? "Cancel" : "+ Add device"}</button>
            </div>
          </div>

        {showAdd && (
          <div style={{ marginBottom: 12, borderBottom: "1px solid var(--panel-border, #e2e6ee)", paddingBottom: 12 }}>
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
                    <div className="form-grid">
                      <div className="form-field">
                        <label className="form-label" htmlFor="dev-id">Device ID <Req /></label>
                        <input id="dev-id" className="form-input" placeholder="e.g. leaf1" value={draft.id} autoFocus onChange={(e) => setDraft({ ...draft, id: e.target.value })} />
                      </div>
                      <div className="form-field">
                        <label className="form-label" htmlFor="dev-addr">Address <Req /></label>
                        <input id="dev-addr" className="form-input" placeholder="IP or hostname" value={draft.address} onChange={(e) => setDraft({ ...draft, address: e.target.value })} />
                      </div>
                    </div>
                  ),
                },
                {
                  id: "classify",
                  title: "Classification",
                  hint: "Optional — helps grouping and vendor profiles. You can change these later.",
                  isValid: () => true,
                  render: () => (
                    <div className="form-grid">
                      <div className="form-field">
                        <label className="form-label" htmlFor="dev-name">Display name</label>
                        <input id="dev-name" className="form-input" placeholder="optional" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
                      </div>
                      <div className="form-field">
                        <label className="form-label" htmlFor="dev-vendor">Vendor</label>
                        <input id="dev-vendor" className="form-input" placeholder="optional" value={draft.vendor} onChange={(e) => setDraft({ ...draft, vendor: e.target.value })} />
                      </div>
                    </div>
                  ),
                },
              ]}
            />
          </div>
        )}
        {error && <p style={{ color: "var(--bad)", margin: "0 0 10px" }}>{error}</p>}

          {devices.length === 0 ? (
            <div className="empty">No devices yet — discovery hasn't returned anything.</div>
          ) : (
            <DataTable<Device>
              rows={rows}
              columns={columns}
              rowKey={(d) => d.id}
              filter={q}
              height="58vh"
              ariaLabel="Devices"
              initialSort={{ key: "vendor", dir: "asc" }}
              onRowClick={(d) => openDevice(d)}
              empty="No devices match this filter."
              rowActions={(d) => (
                <>
                  {sshEnabled && (
                    <button className="btn" title="SSH to device" onClick={() => setTerm(d)}>Connect</button>
                  )}
                  <button className="btn danger" onClick={() => remove(d.id)}>Delete</button>
                </>
              )}
            />
          )}
        </div>
      </div>

      {detail && <DeviceDetailPage device={detail} onClose={() => setDetail(null)} />}
      {term && <DeviceTerminal device={term} onClose={() => setTerm(null)} />}
    </div>
  );
}

// siteText is the device's resolved site as plain text (for filtering / sorting):
// a declared site's display name, else the raw label, else empty.
function siteText(row: DeviceLocationRow | undefined, siteName: Map<string, string>): string {
  const slug = row?.site ?? "";
  if (!slug) return "";
  return siteName.get(slug) ?? slug;
}

// SiteCell renders the device→site assignment: an inline declared-site picker
// when the internal SoT provider is the authority, otherwise read-only text.
// `row.source` distinguishes a declared-site placement ("sot") from a free-form
// manual location ("manual"); the picker binds to a declared site by slug.
function SiteCell({
  row, options, editable, siteName, onAssign,
}: {
  row: DeviceLocationRow | undefined;
  options: SiteRow[];
  editable: boolean;
  siteName: Map<string, string>;
  onAssign: (slug: string) => void;
}) {
  const slug = row?.site ?? "";
  const isDeclared = !!slug && siteName.has(slug);
  const label = siteText(row, siteName);

  if (!editable) {
    return label
      ? <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }} title={label}><span aria-hidden style={{ color: "var(--muted)" }}>◍</span>{label}</span>
      : <span style={{ color: "var(--fg-subtle, var(--muted))" }}>—</span>;
  }

  // A manual (non-declared) location is shown as a hint after the picker so the
  // operator can see existing placement without it masquerading as a declared site.
  const manualHint = !isDeclared && row?.source === "manual" && label;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }} onClick={(e) => e.stopPropagation()}>
      <span aria-hidden style={{ color: isDeclared ? "var(--accent, var(--muted))" : "var(--muted)" }}>◍</span>
      <select
        className="form-input"
        aria-label="Assign site"
        title={isDeclared ? `Site: ${label}` : "Assign this device to a site"}
        value={isDeclared ? slug : ""}
        onChange={(e) => onAssign(e.target.value)}
        style={{ height: 28, padding: "2px 6px", fontSize: 12, maxWidth: 150 }}
      >
        <option value="">— Unassigned —</option>
        {options.map((s) => (
          <option key={s.slug} value={s.slug}>{s.name}</option>
        ))}
      </select>
      {manualHint && <span style={{ color: "var(--fg-subtle, var(--muted))", fontSize: 11 }} title={`Manual location: ${label}`}>· {label}</span>}
    </span>
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
