import { useEffect, useMemo, useState } from "react";
import { api, Device } from "../services/api";
import { takeDrill } from "../theme/drill";

// A device is considered "down" when discovery hasn't refreshed it within the
// staleness window (no recent SNMP/telemetry response). This mirrors the
// Overview "Devices Down" tile so the drilldown lands on the same set.
const DOWN_AFTER_MS = 5 * 60 * 1000;
function isDown(d: Device): boolean {
  const seen = new Date(d.last_seen).getTime();
  return !!seen && Date.now() - seen > DOWN_AFTER_MS;
}

// Stable accent per vendor so each group header reads as one product family.
// Known vendors get a fixed hue; unknowns hash to a consistent color.
const VENDOR_HUE: Record<string, number> = {
  cisco: 200,
  juniper: 150,
  arista: 280,
  fortinet: 0,
  paloalto: 25,
  nokia: 220,
  huawei: 345,
  mikrotik: 35,
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

// Map the backend discovery-source id to an operator-friendly label + badge
// tone, so the Source column reads as "how this device was learned" rather than
// a bare slug. Backend sets these in discovery.go (StaticSource.Name() etc.);
// unknown values fall through to the raw id with a neutral badge.
const SOURCE_META: Record<string, { label: string; tone: string }> = {
  static: { label: "Static (seed file)", tone: "" },
  snmp: { label: "SNMP discovery", tone: "good" },
  netbox: { label: "NetBox", tone: "accent" },
  manual: { label: "Manual", tone: "warn" },
};
function sourceLabel(s: string): string {
  return SOURCE_META[s]?.label ?? (s || "—");
}
function sourceTone(s: string): string {
  return SOURCE_META[s]?.tone ?? "";
}

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState({ id: "", name: "", address: "", vendor: "" });
  // "down" when arriving from the Overview "Devices Down" tile (one-shot drill).
  const [statusFilter, setStatusFilter] = useState<"all" | "down">("all");

  useEffect(() => {
    if (takeDrill().devices === "down") setStatusFilter("down");
  }, []);

  const load = async () => {
    try {
      const list = await api.devices();
      setDevices(list ?? []);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!draft.id || !draft.address) return;
    setBusy(true);
    try {
      await api.upsertDevice(draft);
      setDraft({ id: "", name: "", address: "", vendor: "" });
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

  // Group the inventory by vendor: alphabetical, with "Unknown" pinned last.
  const downCount = useMemo(() => devices.filter(isDown).length, [devices]);
  const groups = useMemo(() => {
    const by = new Map<string, Device[]>();
    for (const d of devices) {
      if (statusFilter === "down" && !isDown(d)) continue;
      const v = (d.vendor || "").trim() || "Unknown";
      (by.get(v) ?? by.set(v, []).get(v)!).push(d);
    }
    return [...by.entries()].sort(([a], [b]) => {
      if (a === "Unknown") return 1;
      if (b === "Unknown") return -1;
      return a.localeCompare(b);
    });
  }, [devices, statusFilter]);

  return (
    <>
      <div className="card">
        <h2>Add device</h2>
        <form onSubmit={submit} style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input
            placeholder="id"
            value={draft.id}
            onChange={(e) => setDraft({ ...draft, id: e.target.value })}
          />
          <input
            placeholder="name"
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          />
          <input
            placeholder="address"
            value={draft.address}
            onChange={(e) => setDraft({ ...draft, address: e.target.value })}
          />
          <input
            placeholder="vendor (optional)"
            value={draft.vendor}
            onChange={(e) => setDraft({ ...draft, vendor: e.target.value })}
          />
          <button disabled={busy} type="submit">
            {busy ? "Saving…" : "Save"}
          </button>
        </form>
      </div>

      <div className="card">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
          <h2 style={{ margin: 0 }}>
            Inventory ({devices.length}) · {groups.length} vendor
            {groups.length === 1 ? "" : "s"}
          </h2>
          <div style={{ display: "flex", gap: 6 }}>
            <button
              className={statusFilter === "all" ? "btn accent" : "btn"}
              onClick={() => setStatusFilter("all")}
            >
              All ({devices.length})
            </button>
            <button
              className={statusFilter === "down" ? "btn accent" : "btn"}
              onClick={() => setStatusFilter("down")}
            >
              Down ({downCount})
            </button>
          </div>
        </div>
        {statusFilter === "down" && (
          <p style={{ color: "var(--muted)", fontSize: 13 }}>
            Showing devices with no telemetry in the last 5 minutes.
          </p>
        )}
        {error && <p style={{ color: "var(--bad)" }}>{error}</p>}
        {devices.length === 0 ? (
          <div className="empty">No devices yet — discovery hasn't returned anything.</div>
        ) : (
          groups.map(([vendor, list]) => (
            <div key={vendor} className="vendor-group">
              <div className="vendor-head">
                <span className="vendor-dot" style={{ background: vendorColor(vendor) }} />
                <span className="vendor-name">{vendor}</span>
                <span className="vendor-count">{list.length}</span>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Address</th>
                    <th>Model</th>
                    <th>OS</th>
                    <th>Source</th>
                    <th>Status</th>
                    <th>Last seen</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((d) => (
                    <tr key={d.id}>
                      <td>{d.id}</td>
                      <td>{d.name || "—"}</td>
                      <td>{d.address}</td>
                      <td>{d.model || "—"}</td>
                      <td>{d.os || "—"}</td>
                      <td>
                        <span
                          className={`badge ${sourceTone(d.source)}`}
                          title={`Discovery source: ${d.source || "unknown"}`}
                        >
                          {sourceLabel(d.source)}
                        </span>
                      </td>
                      <td>
                        {isDown(d) ? (
                          <span
                            className="badge"
                            style={{ background: "var(--bad)", color: "#fff" }}
                            title={`No telemetry since ${new Date(d.last_seen).toLocaleString()}`}
                          >
                            Down
                          </span>
                        ) : (
                          <span className="badge good" title="Responding">Up</span>
                        )}
                      </td>
                      <td>{new Date(d.last_seen).toLocaleString()}</td>
                      <td>
                        <button onClick={() => remove(d.id)}>Delete</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))
        )}
      </div>
    </>
  );
}
