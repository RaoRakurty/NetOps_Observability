import { useEffect, useState } from "react";
import { api, NetboxConfig } from "../services/api";
import Icon from "../components/Icon";

// Automation → Source of Truth. The system-of-record integrations that feed the
// device inventory. NetBox is the first connector; discovery refresh and the
// poll status live here (moved out of Administration → Settings).

type Status = { label: string; tone: "good" | "warn" | "" };

function netboxStatus(c: NetboxConfig | null): Status {
  if (!c || (!c.token_set && !c.url)) return { label: "Not configured", tone: "" };
  if (c.enabled && c.token_set && c.url) return { label: "Connected", tone: "good" };
  return { label: "Disabled", tone: "warn" };
}

export default function SourceOfTruth() {
  const [cfg, setCfg] = useState<NetboxConfig | null>(null);
  const [form, setForm] = useState<{ enabled: boolean; url: string; token: string; interval: number }>({
    enabled: false,
    url: "",
    token: "",
    interval: 60,
  });
  const [saving, setSaving] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [poll, setPoll] = useState<{ last_poll?: string; devices?: number; last_error?: string } | null>(null);

  const load = async () => {
    try {
      const r = await api.netboxConfig();
      setCfg(r.config);
      setForm({ enabled: r.config.enabled, url: r.config.url, token: "", interval: r.config.interval_sec || 60 });
    } catch (e) {
      setErr((e as Error).message);
    }
    // Poll status is part of the platform-owner health payload.
    try {
      const h = await api.health();
      const d = (h.discovery || {}) as Record<string, { last_poll?: string; devices?: number; last_error?: string }>;
      if (d.netbox) setPoll(d.netbox);
    } catch {
      /* health detail is platform-owner-only; ignore otherwise */
    }
  };

  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    setSaving(true);
    setMsg(null);
    setErr(null);
    try {
      const payload: Partial<NetboxConfig> = {
        enabled: form.enabled,
        url: form.url.trim(),
        interval_sec: Number(form.interval) || 60,
      };
      if (form.token.trim()) payload.token = form.token.trim();
      const r = await api.saveNetboxConfig(payload);
      setCfg(r.config);
      setForm((f) => ({ ...f, token: "" }));
      setMsg("Saved. The collector picks up changes on its next poll.");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const refresh = async () => {
    setRefreshing(true);
    setMsg(null);
    setErr(null);
    try {
      await api.refreshDiscovery();
      setMsg("Discovery refresh requested.");
      setTimeout(load, 1500);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setRefreshing(false);
    }
  };

  const st = netboxStatus(cfg);
  const lbl = { display: "block", fontSize: 12, color: "var(--muted)", margin: "10px 0 4px" } as const;
  const req = <span style={{ color: "#c0392b" }}> *</span>;

  return (
    <>
      <div className="card">
        <h2 style={{ margin: 0 }}>Source of Truth</h2>
        <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 6 }}>
          Systems of record that feed the device inventory. Discovered devices are tagged with their
          source and reconciled into Infrastructure → Devices.
        </p>
      </div>

      <div className="card">
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            style={{
              width: 34,
              height: 34,
              borderRadius: 8,
              background: "var(--panel-2, #f4f4f8)",
              display: "grid",
              placeItems: "center",
            }}
          >
            <Icon name="directory" size={20} />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 700 }}>NetBox</div>
            <div style={{ fontSize: 12, color: "var(--muted)" }}>
              DCIM/IPAM source of truth — polls <code>/dcim/devices/</code> for the device inventory.
            </div>
          </div>
          <span className={`badge ${st.tone}`}>{st.label}</span>
        </div>

        <div style={{ marginTop: 14, maxWidth: 560 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            />
            Enable NetBox discovery
          </label>

          <label style={lbl}>NetBox URL{form.enabled ? req : null}</label>
          <input
            className="input"
            style={{ width: "100%" }}
            placeholder="https://netbox.example.com"
            value={form.url}
            onChange={(e) => setForm({ ...form, url: e.target.value })}
          />

          <label style={lbl}>API token{cfg?.token_set ? " (leave blank to keep current)" : form.enabled ? req : null}</label>
          <input
            className="input"
            style={{ width: "100%" }}
            type="password"
            placeholder={cfg?.token_set ? "•••••••• (stored, encrypted at rest)" : "paste a NetBox API token"}
            value={form.token}
            onChange={(e) => setForm({ ...form, token: e.target.value })}
          />

          <label style={lbl}>Poll interval (seconds)</label>
          <input
            className="input"
            style={{ width: 160 }}
            type="number"
            min={15}
            value={form.interval}
            onChange={(e) => setForm({ ...form, interval: Number(e.target.value) })}
          />

          <div style={{ display: "flex", gap: 10, marginTop: 16, alignItems: "center" }}>
            <button className="btn primary" disabled={saving} onClick={save}>
              {saving ? "Saving…" : "Save"}
            </button>
            <button className="btn" disabled={refreshing} onClick={refresh}>
              <Icon name="refresh" size={14} /> {refreshing ? "Refreshing…" : "Refresh now"}
            </button>
          </div>
          <p style={{ fontSize: 11, color: "var(--muted)", marginTop: 8 }}>
            The API token is encrypted at rest by the secret-custody Vault and is never shown again.
          </p>

          {poll && (
            <div style={{ marginTop: 12, fontSize: 12, color: "var(--muted)" }}>
              Last poll: {poll.last_poll ? new Date(poll.last_poll).toLocaleString() : "—"} ·{" "}
              {poll.devices ?? 0} device(s)
              {poll.last_error ? (
                <span style={{ color: "#c0392b" }}> · error: {poll.last_error}</span>
              ) : null}
            </div>
          )}
          {msg && <p style={{ marginTop: 10, color: "var(--accent, #2e7d32)" }}>{msg}</p>}
          {err && <p style={{ marginTop: 10, color: "#c0392b" }}>{err}</p>}
        </div>
      </div>
    </>
  );
}
