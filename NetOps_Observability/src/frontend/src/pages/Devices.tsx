// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { fmtDateTime } from "../lib/time";
import { Suspense, lazy, startTransition, useDeferredValue, useEffect, useMemo, useState } from "react";
import { api, Device, Alert, DeviceLocationRow, SiteRow, type LicenceView, type ConfigDriftRow } from "../services/api";
import { deviceHealth, DEVICE_HEALTH_META, type DeviceHealth } from "./device/deviceHealth";
import { classifyError, statusBadge } from "./config/configModel";
import { takeDrill } from "../theme/drill";
import DeviceDetailPage from "./DeviceDetailPage";

// xterm.js (~290 KB) rides only in the terminal chunk: the SSH console is an
// opt-in feature (FEATURE_DEVICE_SSH, dormant by default) most users never
// open, so it loads on first "Connect" click, not with the Devices page.
const DeviceTerminal = lazy(() => import("./DeviceTerminal"));
import Wizard from "../components/Wizard";
import DataTable, { Column, Sev } from "../components/DataTable";
import { NocHeader, NocKpis, NocKpi, Chip, LiveChip } from "../components/noc";
import AskIris from "../components/AskIris";
import { overageSummary } from "./licence.model";
import { operatorError } from "../lib/errors";
import { deviceSerial } from "./device/serial";

const Req = () => <span style={{ color: "var(--bad)", marginLeft: 2 }} title="required">*</span>;

// Device status: ONE helper (./device/deviceHealth) over the server's live
// reachability, shared with the detail popup and the monitoring page.
type Health = DeviceHealth;
const HEALTH_META = DEVICE_HEALTH_META;

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
  netbox: { label: "Source of Truth", tone: "accent" },
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
  ap: { label: "AP", color: "#06b6d4" },
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
  // FEATURE_CONFIG_BACKUP (configuration backup + drift). Its columns stay
  // visible and say "Off" when it is disabled, so an operator sees what is
  // switched off rather than a column that silently vanished.
  const [configOn, setConfigOn] = useState(false);
  // Per-device "Back up now" state: device id → "running" | error text.
  const [backupState, setBackupState] = useState<Map<string, string>>(new Map());
  const [error, setError] = useState<string | null>(null);
  // Separate from `error`: the inventory loaded, but the alert correlation that
  // feeds "degraded" did not — so "Up" cannot be read as "healthy".
  const [alertsErr, setAlertsErr] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [draft, setDraft] = useState({ id: "", name: "", address: "", vendor: "" });
  const [filter, setFilter] = useState<Filter>("all");
  const [q, setQ] = useState("");
  // The box keeps the typed value; the TABLE filters against the deferred one,
  // so typing stays responsive on a fleet-sized list (DataTable's filter runs
  // every column's text accessor over every row).
  const deferredQ = useDeferredValue(q);
  // The popup holds the device ID and renders the LIVE row from the 30 s
  // refresh: a captured row froze its status at click time (owner report
  // 2026-10-10: the popup said down while the list said up).
  const [detailId, setDetailId] = useState<string | null>(null);
  const detail = useMemo(() => (detailId ? devices.find((d) => d.id === detailId) ?? null : null), [detailId, devices]);
  // Config drift per device (the Config Drift page, as inventory columns).
  // null = the config backup feature is off on this deployment.
  const [drift, setDrift] = useState<Map<string, ConfigDriftRow> | null>(new Map());
  const [term, setTerm] = useState<Device | null>(null);
  // The licence view, BEST EFFORT. This page is not an admin page and most of
  // the people who open it cannot read /api/system/licence at all; a 403 here
  // must therefore leave the fleet table exactly as it was, with no banner and
  // no error. What it buys when it does load is the soft-overage banner below —
  // an operator enabling their 260th device should learn it is being recorded
  // here, where they are doing it, and not only on a page they never visit.
  const [licence, setLicence] = useState<LicenceView | null>(null);

  // Selecting a device opens the full-page detail view (Overview · Interfaces ·
  // Routing) — the reference design's graph rows need full width, which the narrow
  // inspector couldn't carry.
  const openDevice = (d: Device) => setDetailId(d.id);

  useEffect(() => {
    const d = takeDrill().devices;
    if (d === "down") setFilter("down");
    // Deep link from Command Center "Impacted entities" → pre-filter to that
    // entity so its status row is shown immediately (#/infrastructure/devices?q=…).
    const qs = (typeof location !== "undefined" ? location.hash : "").split("?")[1] || "";
    const dq = new URLSearchParams(qs).get("q");
    if (dq) setQ(dq);
  }, []);

  // "Back up now": queue one capture; the drift columns refresh shortly after.
  const backupNow = async (id: string) => {
    setBackupState((m) => new Map(m).set(id, "running"));
    try {
      await api.configBackup(id);
      setBackupState((m) => { const n = new Map(m); n.delete(id); return n; });
      setTimeout(() => { void loadDrift(); }, 5000);
    } catch (e) {
      setBackupState((m) => new Map(m).set(id, operatorError(e, "The backup could not be started.")));
    }
  };

  // Config drift for the whole visible fleet, paged and bounded (§9: at most
  // 40 pages of 500). A deployment with config backup off answers "off" and the
  // config columns are hidden rather than shown empty.
  const loadDrift = async () => {
    try {
      const m = new Map<string, ConfigDriftRow>();
      let cursor: string | undefined;
      for (let page = 0; page < 40; page++) {
        const res = await api.configDriftList({ cursor, limit: 500 });
        for (const r of res.items ?? []) m.set(r.device_id, r);
        if (!res.next_cursor) break;
        cursor = res.next_cursor;
      }
      setDrift(m);
    } catch (e) {
      // "off" hides the columns; any other failure keeps the last good read
      // (the cells then show it rather than a false "never captured").
      if (classifyError(e) === "off") setDrift(null);
    }
  };

  const load = async () => {
    try {
      // Alerts are the amber "reachable-but-sick" input. Swallowing their failure
      // into [] made every device render GREEN during an alerts outage — a
      // fabricated all-healthy fleet. Track the failure and say so instead.
      const [list, alRes, locRes, siteRes] = await Promise.all([
        api.devices(),
        api.alerts().then((v) => ({ ok: true as const, v })).catch((e) => ({ ok: false as const, e })),
        api.deviceLocations().catch(() => ({ devices: [] as DeviceLocationRow[] })),
        api.sites().catch(() => ({ sites: [] as SiteRow[], active: "internal" })),
      ]);
      // The 30s refresh replaces the whole fleet. As a transition the re-render
      // yields to whatever the operator is doing rather than blocking on it.
      startTransition(() => {
        setDevices(list ?? []);
        setAlerts(alRes.ok ? alRes.v ?? [] : []);
      });
      setAlertsErr(alRes.ok ? null : (alRes.e instanceof Error ? alRes.e.message : String(alRes.e)));
      setLocs(new Map((locRes?.devices ?? []).map((r) => [r.id, r])));
      setSiteOptions([...(siteRes?.sites ?? [])].sort((a, b) => a.name.localeCompare(b.name)));
      setSotProvider(siteRes?.active ?? "internal");
      setError(null);
      void loadDrift();
    } catch (e) {
      setError(operatorError(e, "The device inventory could not be loaded."));
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
      setError(operatorError(e, "The site could not be assigned."));
    }
  };

  useEffect(() => {
    load();
    api.features().then((c) => { setSshEnabled(!!c.device_ssh); setConfigOn(!!c.config_backup); }).catch(() => {});
    // Deliberately swallowed: not being allowed to read the licence is the
    // normal case for an operator, not an error worth showing them.
    api.getLicence().then(setLicence).catch(() => setLicence(null));
    const t = setInterval(load, 30_000); // live-ish; status is time-sensitive
    return () => clearInterval(t);
  }, []);

  const addDevice = async () => {
    if (!draft.id.trim() || !draft.address.trim()) return;
    try {
      // Every device with an address is monitored, up to the licence limit.
      // The server never refuses one for the licence: past the limit it is
      // added and marked over the limit, and the banner below says so.
      await api.upsertDevice(draft);
      setError(null);
    } catch (e) {
      setError(operatorError(e, "The device could not be added."));
      return;
    }
    setDraft({ id: "", name: "", address: "", vendor: "" });
    setShowAdd(false);
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

  // MONITORED is what Correlix collects from: every device with an address, up
  // to the licence limit, first found first (owner decision 2026-10-03). It is
  // shown beside the inventory size so the gap — devices over the limit, or
  // with no address — is visible.
  const monitoredCount = useMemo(() => devices.filter((d) => d.monitored).length, [devices]);

  // Devices past the licence limit: in the inventory, NOT collected from. The
  // rows come from /api/devices, which is already scoped to the caller's
  // tenant, so a tenant's banner counts only its own devices. The limit rides
  // on each over-limit row, so this needs no licence read.
  const overLimit = useMemo(() => devices.filter((d) => d.monitor_state === "over_limit"), [devices]);
  const overLimitCap = overLimit.find((d) => d.monitor_limit !== undefined)?.monitor_limit;

  // The SOFT overage (Team/Enterprise), if the licence view loaded: a billing
  // fact — every device is still collected from and the excess is recorded for
  // true-up (owner decision, 2026-09-05). The HARD case is the banner above,
  // built from the device rows themselves.
  const deviceOverage = useMemo(
    () => (licence?.overages ?? []).filter((o) => o.ceiling === "devices" && o.soft),
    [licence],
  );

  const health = useMemo(() => new Map(devices.map((d) => [d.id, deviceHealth(d, alertedDevices.has(d.id))])), [devices, alertedDevices]);
  const counts = useMemo(() => {
    const c = { up: 0, degraded: 0, down: 0, unknown: 0 };
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
  const columns = useMemo<Column<Device>[]>(() => {
    const cols: Column<Device>[] = [
      {
        // ONE glyph: the circle says whether Correlix monitors it, the arrow says
        // whether it is answering (owner spec 2026-10-10).
        key: "status", header: "Status", width: 78, sortable: true,
        text: (d) => `${monitoringLabel(d)} ${HEALTH_META[health.get(d.id) ?? "unknown"].label}`,
        sortValue: (d) => ["down", "degraded", "unknown", "up"].indexOf(health.get(d.id) ?? "unknown"),
        sev: (d) => healthSev(health.get(d.id) ?? "unknown"),
        render: (d) => <StatusGlyph device={d} health={health.get(d.id) ?? "unknown"} />,
      },
      {
        // The hostname. The internal id is identity plumbing, not something an
        // operator reads — it stays in the tooltip and in search.
        key: "name", header: "Device", width: "17%", sortable: true,
        text: (d) => `${d.name || ""} ${d.id}`, sortValue: (d) => (d.name || d.id).toLowerCase(),
        render: (d) => (
          <a className="dtv-link" title={`Open ${d.name || d.id} (id ${d.id})`}
            onClick={(e) => { e.stopPropagation(); openDevice(d); }}><span className="device-name">{d.name || d.id}</span></a>
        ),
      },
      {
        key: "address", header: "IP", width: 128,
        text: (d) => d.address,
        render: (d) => <span title={d.address} style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 14 }}>{d.address}</span>,
      },
      {
        key: "vendor", header: "Manufacturer", width: "11%", sortable: true,
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
        key: "software", header: "Version", width: "11%", sortable: true,
        text: (d) => d.software_version ?? "", sortValue: (d) => d.software_version || "~",
        render: (d) => d.software_version
          ? <span title={d.os || d.software_version} style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 14 }}>{d.software_version}</span>
          : <span style={{ color: "var(--fg-subtle, var(--muted))" }} title={d.os || "The device's description carries no version"}>—</span>,
      },
      {
        key: "serial", header: "Serial", width: 140, sortable: true,
        text: (d) => deviceSerial(d)?.serial ?? "", sortValue: (d) => deviceSerial(d)?.serial || "~",
        render: (d) => {
          const sv = deviceSerial(d);
          return sv
            ? <span title={sv.from} style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 14 }}>{sv.serial}</span>
            : <span style={{ color: "var(--fg-subtle, var(--muted))" }} title="The device has not reported a serial number yet">—</span>;
        },
      },
      {
        key: "location", header: "Site", width: "14%", sortable: true,
        text: (d) => siteText(locs.get(d.id), siteName) || d.configured_location || "",
        sortValue: (d) => siteText(locs.get(d.id), siteName) || d.configured_location || "~",
        render: (d) => (
          <SiteCell
            row={locs.get(d.id)}
            options={siteOptions}
            editable={editableSites}
            siteName={siteName}
            configured={d.configured_location}
            onAssign={(slug) => assignSite(d.id, slug)}
          />
        ),
      },
    ];
    const off = <span style={{ color: "var(--fg-subtle, var(--muted))" }}>Off</span>;
    const configOffTip = "Configuration backup is turned off on this deployment (FEATURE_CONFIG_BACKUP). An administrator can enable it.";
    const configLive = configOn && drift !== null;
    cols.push(
      {
        // Sync = is the running config the approved (golden) one?
        key: "sync", header: "Sync", width: 128, sortable: true,
        text: (d) => (configLive ? syncLabel(drift?.get(d.id)).label : "Off"),
        sortValue: (d) => (configLive ? syncLabel(drift?.get(d.id)).label : "~"),
        render: (d) => {
          if (!configLive) return <span title={configOffTip}>{off}</span>;
          const b = syncLabel(drift?.get(d.id));
          return <span className={`badge ${b.tone}`} title={b.help}>{b.label}</span>;
        },
      },
      {
        key: "backup", header: "Config backup", width: 168, sortable: true,
        sortValue: (d) => new Date(drift?.get(d.id)?.last_capture_at ?? 0).getTime() || 0,
        render: (d) => {
          if (!configLive) return <span title={configOffTip}>{off}</span>;
          const at = drift?.get(d.id)?.last_capture_at;
          const st = backupState.get(d.id);
          return (
            <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }} onClick={(e) => e.stopPropagation()}>
              {at ? <span title={fmtDateTime(at)}>{relTime(at)}</span> : <span style={{ color: "var(--fg-subtle, var(--muted))" }}>never</span>}
              <button className="btn" style={{ padding: "2px 8px" }} disabled={st === "running"}
                title={st && st !== "running" ? st : "Capture the running configuration now"}
                onClick={() => { void backupNow(d.id); }}>
                {st === "running" ? "Backing up…" : "Back up now"}
              </button>
            </span>
          );
        },
      },
      {
        key: "ssh", header: "SSH", width: 104,
        text: () => (sshEnabled ? "Connect" : "Off"),
        render: (d) => sshEnabled
          ? <button className="btn" title="Open an SSH session to the device" onClick={(e) => { e.stopPropagation(); setTerm(d); }}>Connect</button>
          : <span title="Device SSH is turned off on this deployment (FEATURE_DEVICE_SSH). An administrator can enable it.">{off}</span>,
      },
    );
    cols.push({
      key: "source", header: "Source", width: 96,
      text: (d) => sourceLabel(d.source),
      render: (d) => <span className={`badge ${sourceTone(d.source)}`} title={`Discovery source: ${d.source || "unknown"}`}>{sourceLabel(d.source)}</span>,
    });
    return cols;
  }, [health, locs, siteOptions, editableSites, siteName, drift, configOn, sshEnabled, backupState]);

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
        topic="page.devices"
        chips={<>
          <Chip label={`Discovered ${devices.length}`} />
          <Chip label={`Monitored ${monitoredCount}`} />
          <LiveChip detail="30s poll" />
        </>}
      >
        <NocKpis cols={5}>
          <NocKpi n={devices.length} label="Discovered devices" topic="devices.discovered" />
          <NocKpi n={monitoredCount} label="Monitored devices" topic="devices.monitored" />
          <NocKpi
            n={counts.up}
            label="Up"
            topic={alertsErr ? "devices.heartbeat-only" : "devices.up"}
            tone={alertsErr ? "var(--warn)" : counts.up ? "var(--ok)" : undefined}
          />
          <NocKpi n={counts.degraded} label="Degraded" topic="devices.degraded" tone={counts.degraded ? "var(--warn)" : undefined} />
          <NocKpi n={counts.down} label="Down" topic="devices.down" tone={counts.down ? "var(--crit)" : undefined} />
        </NocKpis>
      </NocHeader>

      {alertsErr && (
        <p className="empty" role="alert" style={{ color: "var(--warn)", margin: "0 0 10px" }}>
          <strong>Alert correlation unavailable</strong> — health below is heartbeat only. ({alertsErr})
          <AskIris topic="devices.heartbeat-only" label="heartbeat-only health" />
        </p>
      )}

      {overLimit.length > 0 && (
        <p className="empty" role="status" style={{ color: "var(--warn)", margin: "0 0 10px", fontSize: 14 }}>
          <strong>{overLimitSentence(overLimit.length, overLimitCap)}</strong>
          <AskIris topic="devices.allowance" label="the license limit" />
        </p>
      )}

      {deviceOverage.length > 0 && (
        <p className="empty" role="note" style={{ color: "var(--warn)", margin: "0 0 10px", fontSize: 14 }}>
          <strong>Above your monitored-device allowance</strong>{" "}
          — {overageSummary(deviceOverage)}<AskIris topic="devices.allowance" label="the monitored-device allowance" />
        </p>
      )}

      {devices.length > 0 && <FleetComposition devices={devices} locs={locs} siteName={siteName} />}

      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Device inventory</h3>
          <span style={{ color: "var(--fg-muted)", fontSize: 12.5 }}>
            Discovered {devices.length} · Monitored {monitoredCount}
          </span>
        </div>
        <div style={{ padding: "11px 13px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap", marginBottom: 11 }}>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {chip("all", "All", devices.length)}
              {chip("up", "Up", counts.up, HEALTH_META.up.color)}
              {chip("degraded", "Degraded", counts.degraded, HEALTH_META.degraded.color)}
              {chip("down", "Down", counts.down, HEALTH_META.down.color)}
              {counts.unknown > 0 && chip("unknown", "Not polled", counts.unknown, HEALTH_META.unknown.color)}
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
              filter={deferredQ}
              height="58vh"
              ariaLabel="Devices"
              initialSort={{ key: "vendor", dir: "asc" }}
              onRowClick={(d) => openDevice(d)}
              empty="No devices match this filter."
            />
          )}
        </div>
      </div>

      {detail && <DeviceDetailPage device={detail} onClose={() => setDetailId(null)} />}
      {term && (
        <Suspense fallback={<div style={{ padding: 40, color: "var(--muted)" }}>Loading…</div>}>
          <DeviceTerminal device={term} onClose={() => setTerm(null)} />
        </Suspense>
      )}
    </div>
  );
}

// overLimitSentence is the banner: how many of the caller's devices are not
// collected from because the licence limit is reached. Plain words, one line.
export function overLimitSentence(n: number, limit?: number): string {
  const subject = n === 1 ? "1 device is" : `${n} devices are`;
  const cap = limit !== undefined ? `license limit of ${limit} reached` : "license limit reached";
  return `${subject} not monitored: ${cap}`;
}

// monitoringLabel is the row's state in words, for the filter and the badge.
export function monitoringLabel(d: Device): string {
  if (d.monitored) return "Monitored";
  if (d.monitor_state === "over_limit") return "Over license limit";
  return "Not monitored";
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
  row, options, editable, siteName, configured, onAssign,
}: {
  row: DeviceLocationRow | undefined;
  options: SiteRow[];
  editable: boolean;
  siteName: Map<string, string>;
  /** The location configured ON the device (SNMP sysLocation), used when no
   *  site is assigned; empty when the device has none configured. */
  configured?: string;
  onAssign: (slug: string) => void;
}) {
  const slug = row?.site ?? "";
  const isDeclared = !!slug && siteName.has(slug);
  const label = siteText(row, siteName);
  const fromDevice = !label && configured
    ? <span style={{ color: "var(--fg-muted)" }} title={`Configured on the device: ${configured}`}>{configured}</span>
    : null;

  if (!editable) {
    return label
      ? <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }} title={label}><span aria-hidden style={{ color: "var(--muted)" }}>◍</span>{label}</span>
      : fromDevice ?? <span style={{ color: "var(--fg-subtle, var(--muted))" }}>—</span>;
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
      {manualHint && <span style={{ color: "var(--fg-subtle, var(--muted))", fontSize: 14 }} title={`Manual location: ${label}`}>· {label}</span>}
      {!slug && fromDevice}
    </span>
  );
}

// syncLabel: the drift state in the operator's words — is the running config
// the approved (golden) one? "Changed" (differs from the previous capture) and
// "Drifted" (differs from golden) are both "Not in sync" here; the detail
// panel keeps the distinction.
function syncLabel(r: ConfigDriftRow | undefined): { label: string; tone: string; help: string } {
  const b = statusBadge(r);
  if (!r || !r.last_capture_at) return { label: "Not captured", tone: "", help: b.help };
  if (String(r.state) === "failed") return { label: "Capture failed", tone: "bad", help: b.help };
  switch (String(r.state)) {
    case "in_sync": return { label: "In sync", tone: "good", help: b.help };
    case "changed":
    case "drifted": return { label: "Not in sync", tone: String(r.state) === "drifted" ? "bad" : "warn", help: b.help };
    default: return { label: "Unknown", tone: "", help: b.help };
  }
}

// StatusGlyph: the circle is monitoring (green = Correlix collects from it,
// amber = past the licence limit, grey = not monitored); the arrow is the live
// status from the collectors (↑ up, ↓ down, ↕ degraded, – not polled recently).
function StatusGlyph({ device, health }: { device: Device; health: Health }) {
  const ring = device.monitored ? "var(--good, #16a34a)" : device.monitor_state === "over_limit" ? "var(--warn, #d97706)" : "var(--muted, #94a3b8)";
  const m = HEALTH_META[health];
  const label = `${monitoringLabel(device)} · ${m.label}`;
  const methods = device.monitored ? (device.monitor_methods ?? []).join(" · ") : "";
  const title = [label, methods && `telemetry: ${methods}`, device.monitor_reason].filter(Boolean).join(" — ");
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }} title={title} aria-label={label}>
      <span style={{ width: 12, height: 12, borderRadius: 999, background: ring, flex: "none" }} />
      <span aria-hidden style={{ color: m.color, fontWeight: 700, fontSize: 16, lineHeight: 1 }}>{m.arrow}</span>
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

// ── Fleet composition ────────────────────────────────────────────────────────
// A compact, evidence-only read on the SHAPE of the fleet — derived entirely
// from the already-loaded inventory (no extra fetch, no mock data). It turns the
// empty space below the KPIs into an at-a-glance operator briefing: what kinds of
// devices, from which vendors, via which discovery source, and how much of the
// fleet is placed at a known site.

type Slice = { key: string; label: string; n: number; color: string };

// tally groups rows by a key accessor, returns the top slices (rest folded into
// "Other"), each carrying a stable colour from `color`. Empty keys → "Unknown".
function tally(
  devices: Device[],
  keyOf: (d: Device) => string,
  label: (k: string) => string,
  color: (k: string) => string,
  top = 5,
): Slice[] {
  const counts = new Map<string, number>();
  for (const d of devices) {
    const k = keyOf(d) || "unknown";
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const head = sorted.slice(0, top).map(([k, n]) => ({ key: k, label: label(k), n, color: color(k) }));
  const rest = sorted.slice(top).reduce((s, [, n]) => s + n, 0);
  if (rest > 0) head.push({ key: "__other", label: "Other", n: rest, color: "var(--muted)" });
  return head;
}

// A labelled distribution: a thin stacked bar + a legend of the slices. Honest
// empty state when there's nothing to show for this dimension.
function DistroBar({ title, slices, total }: { title: string; slices: Slice[]; total: number }) {
  return (
    <div className="fc-distro">
      <div className="fc-distro-h">
        <span className="fc-distro-t">{title}</span>
        <span className="fc-distro-n">{slices.length} {slices.length === 1 ? "kind" : "kinds"}</span>
      </div>
      {total === 0 ? (
        <div className="fc-distro-empty">Nothing collected yet</div>
      ) : (
        <>
          <div className="fc-bar" role="img" aria-label={`${title} distribution`}>
            {slices.map((s) => (
              <span key={s.key} className="fc-bar-seg" title={`${s.label}: ${s.n}`}
                style={{ width: `${(s.n / total) * 100}%`, background: s.color }} />
            ))}
          </div>
          <ul className="fc-legend">
            {slices.map((s) => (
              <li key={s.key} className="fc-legend-i" title={`${s.label}: ${s.n} of ${total}`}>
                <span className="fc-legend-dot" style={{ background: s.color }} />
                <span className="fc-legend-l">{s.label}</span>
                <span className="fc-legend-n">{s.n}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

function FleetComposition({
  devices, locs, siteName,
}: {
  devices: Device[];
  locs: Map<string, DeviceLocationRow>;
  siteName: Map<string, string>;
}) {
  const byType = useMemo(
    () => tally(devices, (d) => d.type || "generic", (k) => typeMeta(k).label, (k) => typeMeta(k).color),
    [devices],
  );
  const byVendor = useMemo(
    () => tally(devices, (d) => (d.vendor || "").trim() || "Unknown",
      (k) => k.charAt(0).toUpperCase() + k.slice(1), (k) => vendorColor(k)),
    [devices],
  );
  const bySource = useMemo(
    () => tally(devices, (d) => d.source || "unknown", (k) => sourceLabel(k),
      (k) => SOURCE_META[k]?.tone === "good" ? "var(--good)" : SOURCE_META[k]?.tone === "accent" ? "var(--accent)" : SOURCE_META[k]?.tone === "warn" ? "var(--warn)" : "var(--muted)"),
    [devices],
  );
  // Site placement coverage — declared site vs. unplaced. Directly actionable:
  // unplaced devices won't roll up into any site view.
  const placed = useMemo(
    () => devices.filter((d) => { const sl = locs.get(d.id)?.site; return !!sl && siteName.has(sl); }).length,
    [devices, locs, siteName],
  );
  const placement: Slice[] = [
    { key: "placed", label: "Placed at a site", n: placed, color: "var(--good, #16a34a)" },
    { key: "unplaced", label: "Unplaced", n: devices.length - placed, color: "var(--muted)" },
  ];

  return (
    <div className="cc-panel fc-panel">
      <div className="cc-panel-h">
        <h3 className="cc-panel-t">Fleet composition</h3>
        <span className="cc-panel-meta">{devices.length} devices · derived live from inventory</span>
      </div>
      <div className="fc-grid">
        <DistroBar title="By type" slices={byType} total={devices.length} />
        <DistroBar title="By manufacturer" slices={byVendor} total={devices.length} />
        <DistroBar title="By discovery source" slices={bySource} total={devices.length} />
        <DistroBar title="Site placement" slices={placement} total={devices.length} />
      </div>
    </div>
  );
}
