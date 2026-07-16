import { fmtDateTime } from "../lib/time";
import { useEffect, useState } from "react";
import { api, Device, Alert } from "../services/api";

// DeviceDetail — a per-device drill-down drawer opened from the Devices
// inventory: device metadata, labels, up/down status, and the device's active
// alerts (reusing existing endpoints; no backend change).

const DOWN_AFTER_MS = 5 * 60 * 1000;
function isDown(d: Device): boolean {
  const seen = new Date(d.last_seen).getTime();
  return !!seen && Date.now() - seen > DOWN_AFTER_MS;
}

// DeviceDetailBody — the device metadata/labels/alerts content, factored out of
// the modal so it can also be hosted in the dockable Inspector (shell-v2). The
// optional `actions` slot renders a row of buttons under the status header.
// LocationSection — the inspector's slice of the geomap annotation layer:
// shows where this device is placed (SoT site wins) and lets the operator set
// site label + decimal lat/lng for devices the Source of Truth doesn't place.
function LocationSection({ device }: { device: Device }) {
  const [sotSite, setSotSite] = useState("");
  const [cur, setCur] = useState<{ set: boolean; site?: string; lat?: number; lng?: number } | null>(null);
  const [form, setForm] = useState({ site: "", lat: "", lng: "" });
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api.deviceLocation(device.id)
      .then((r) => {
        if (!alive) return;
        setSotSite(r.sot_site ?? ""); // locked only when the SoT actually places this device
        setCur({ set: r.set, ...r.location });
        if (r.set && r.location) setForm({ site: r.location.site ?? "", lat: String(r.location.lat), lng: String(r.location.lng) });
        else setForm({ site: "", lat: "", lng: "" });
      })
      .catch(() => setCur(null));
    return () => { alive = false; };
  }, [device.id]);

  if (sotSite) {
    return (
      <>
        <div className="mini-meta" style={{ fontWeight: 700, marginTop: 14 }}>Location</div>
        <p className="mini-meta" style={{ marginTop: 4 }}>
          Placed by the Source of Truth (site <b>{sotSite}</b>) — coordinates are managed on the site record.
        </p>
      </>
    );
  }
  const save = async () => {
    const lat = parseFloat(form.lat), lng = parseFloat(form.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) { setMsg("latitude and longitude are required (decimal WGS 84)"); return; }
    try { await api.setDeviceLocation(device.id, { site: form.site.trim(), lat, lng }); setMsg("saved — shown on the Geomap"); setCur({ set: true, site: form.site, lat, lng }); }
    catch (e) { setMsg(e instanceof Error ? e.message : String(e)); }
  };
  const clear = async () => {
    try { await api.clearDeviceLocation(device.id); setMsg("cleared"); setCur({ set: false }); setForm({ site: "", lat: "", lng: "" }); }
    catch (e) { setMsg(e instanceof Error ? e.message : String(e)); }
  };
  return (
    <>
      <div className="mini-meta" style={{ fontWeight: 700, marginTop: 14 }}>Location</div>
      <div style={{ display: "flex", gap: 6, marginTop: 6, flexWrap: "wrap" }}>
        <input placeholder="Site label" value={form.site} style={{ flex: "1 1 120px" }}
          onChange={(e) => setForm({ ...form, site: e.target.value })} />
        <input placeholder="Lat" inputMode="decimal" value={form.lat} style={{ width: 90 }}
          onChange={(e) => setForm({ ...form, lat: e.target.value })} />
        <input placeholder="Lng" inputMode="decimal" value={form.lng} style={{ width: 90 }}
          onChange={(e) => setForm({ ...form, lng: e.target.value })} />
        <button className="dash-btn accent" onClick={save}>Save</button>
        {cur?.set && <button className="dash-btn" onClick={clear}>Clear</button>}
      </div>
      {msg && <p className="mini-meta" style={{ marginTop: 4 }}>{msg}</p>}
    </>
  );
}

export function DeviceDetailBody({ device, actions }: { device: Device; actions?: React.ReactNode }) {
  const [alerts, setAlerts] = useState<Alert[] | null>(null);

  useEffect(() => {
    api
      .alerts()
      .then((all) => setAlerts((all ?? []).filter((a) => a.device_id === device.id)))
      .catch(() => setAlerts([]));
  }, [device.id]);

  const rows: [string, string][] = [
    ["ID", device.id],
    ["Name", device.name || "—"],
    ["Address", device.address],
    ["Vendor", device.vendor || "—"],
    ["Model", device.model || "—"],
    ["OS", device.os || "—"],
    ["Preferred protocol", device.preferred_protocol || "—"],
    ["Source", device.source || "—"],
    ["Last seen", fmtDateTime(device.last_seen)],
  ];

  return (
    <>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
        <h3 style={{ margin: 0 }}>
          {device.name || device.id}
          {isDown(device) ? (
            <span className="badge" style={{ marginLeft: 8, background: "var(--bad)", color: "#fff" }}>Down</span>
          ) : (
            <span className="badge good" style={{ marginLeft: 8 }}>Up</span>
          )}
        </h3>
      </div>

      {actions && <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>{actions}</div>}

      <table style={{ marginTop: 10 }}>
        <tbody>
          {rows.map(([k, v]) => (
            <tr key={k}>
              <td style={{ color: "var(--muted)", width: 180 }}>{k}</td>
              <td>{v}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <LocationSection device={device} />

      {device.labels && Object.keys(device.labels).length > 0 && (
        <>
          <div className="mini-meta" style={{ fontWeight: 700, marginTop: 14 }}>Labels</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
            {Object.entries(device.labels).map(([k, v]) => (
              <span key={k} className="badge">{k}={v}</span>
            ))}
          </div>
        </>
      )}

      <div className="mini-meta" style={{ fontWeight: 700, marginTop: 16 }}>Active alerts</div>
      {alerts === null ? (
        <div className="empty">Loading…</div>
      ) : alerts.length === 0 ? (
        <p className="mini-meta">No active alerts for this device.</p>
      ) : (
        <table style={{ marginTop: 6 }}>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule</th>
              <th>Summary</th>
              <th>Fired</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td><span className={`badge sev-${a.severity}`}>{a.severity}</span></td>
                <td>{a.rule}</td>
                <td>{a.summary}</td>
                <td className="mini-meta">{fmtDateTime(a.fired_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

export default function DeviceDetail({ device, onClose }: { device: Device; onClose: () => void }) {
  return (
    <div
      className="modal-backdrop"
      style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.45)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}
      onClick={onClose}
    >
      <div className="card" style={{ width: "min(640px, 94vw)", maxHeight: "88vh", overflow: "auto" }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <button className="btn" onClick={onClose}>Close</button>
        </div>
        <DeviceDetailBody device={device} />
      </div>
    </div>
  );
}
