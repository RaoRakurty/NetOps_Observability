import { useEffect, useState } from "react";
import { api, NetboxConfig } from "../services/api";
import Icon from "../components/Icon";
import Wizard, { WizardStep } from "../components/Wizard";

// Automation → Source of Truth. Systems of record that feed the device
// inventory. NetBox is bundled with the platform (managed): it's wired
// automatically, so setup is just "turn it on" — no URL/token to paste. An
// external NetBox can be connected instead via the guided flow.

type Status = { label: string; tone: "good" | "warn" | "" };

function netboxStatus(c: NetboxConfig | null): Status {
  if (!c) return { label: "…", tone: "" };
  if (c.enabled && (c.managed || (c.url && c.token_set))) return { label: "Connected", tone: "good" };
  if (c.managed) return { label: "Bundled · off", tone: "warn" };
  if (c.url || c.token_set) return { label: "Disabled", tone: "warn" };
  return { label: "Not set up", tone: "" };
}

const labelStyle = { display: "block", fontSize: 12, color: "var(--muted)", margin: "10px 0 4px" } as const;

export default function SourceOfTruth() {
  const [cfg, setCfg] = useState<NetboxConfig | null>(null);
  const [wizard, setWizard] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [poll, setPoll] = useState<{ last_poll?: string; devices?: number; last_error?: string } | null>(null);

  // Wizard working state.
  const [mode, setMode] = useState<"managed" | "external">("managed");
  const [enabled, setEnabled] = useState(true);
  const [urlV, setUrlV] = useState("");
  const [tokenV, setTokenV] = useState("");
  const [interval, setIntervalV] = useState(60);

  const load = async () => {
    try {
      const r = await api.netboxConfig();
      setCfg(r.config);
      setMode(r.config.url && !r.config.managed ? "external" : "managed");
      setEnabled(r.config.enabled);
      setUrlV(r.config.managed ? "" : r.config.url);
      setIntervalV(r.config.interval_sec || 60);
    } catch (e) {
      setErr((e as Error).message);
    }
    try {
      const h = await api.health();
      const d = (h.discovery || {}) as Record<string, { last_poll?: string; devices?: number; last_error?: string }>;
      if (d.netbox) setPoll(d.netbox);
    } catch {
      /* discovery detail is platform-owner-only */
    }
  };

  useEffect(() => {
    load();
  }, []);

  const validURL = (u: string) => /^https?:\/\/.+/.test(u.trim());

  const save = async () => {
    const payload: Partial<NetboxConfig> = { enabled, interval_sec: Number(interval) || 60 };
    if (mode === "external") {
      payload.url = urlV.trim();
      if (tokenV.trim()) payload.token = tokenV.trim();
    } else {
      payload.url = ""; // managed → no URL/token (auto-wired)
    }
    const r = await api.saveNetboxConfig(payload);
    setCfg(r.config);
    setTokenV("");
    setWizard(false);
    setMsg("Saved. The collector picks up changes on its next poll.");
    setTimeout(load, 1200);
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

  // Guided steps differ by mode. Managed = one "turn it on" step (+ switch to
  // external); external = URL → token → activate.
  const managedStep: WizardStep = {
    id: "managed",
    title: "Bundled NetBox",
    hint: "NetBox ships with the platform — it's already wired. Just turn it on.",
    isValid: () => true,
    render: () => (
      <div>
        <p style={{ fontSize: 13, color: "var(--muted)" }}>
          The platform runs and manages NetBox internally; the connection (URL + API token) is
          configured automatically. You don't need to paste anything.
        </p>
        <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, marginTop: 8 }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enable NetBox discovery
        </label>
        <label style={labelStyle}>Poll interval (seconds)</label>
        <input className="input" style={{ width: 160 }} type="number" min={15} value={interval} onChange={(e) => setIntervalV(Number(e.target.value))} />
        <p style={{ marginTop: 14 }}>
          <button className="btn" onClick={() => setMode("external")}>
            Connect an external NetBox instead →
          </button>
        </p>
      </div>
    ),
  };

  const externalSteps: WizardStep[] = [
    {
      id: "url",
      title: "Connect",
      hint: "Point at your existing NetBox instance.",
      isValid: () => validURL(urlV),
      render: () => (
        <div>
          {cfg?.managed && (
            <p style={{ marginBottom: 8 }}>
              <button className="btn" onClick={() => setMode("managed")}>
                ← Use the bundled NetBox
              </button>
            </p>
          )}
          <label style={labelStyle}>
            NetBox URL <span style={{ color: "#c0392b" }}>*</span>
          </label>
          <input className="input" style={{ width: "100%" }} placeholder="https://netbox.example.com" value={urlV} onChange={(e) => setUrlV(e.target.value)} />
        </div>
      ),
    },
    {
      id: "token",
      title: "Authenticate",
      hint: "An API token with read access to DCIM.",
      isValid: () => tokenV.trim().length > 0 || !!cfg?.token_set,
      render: () => (
        <div>
          <label style={labelStyle}>
            API token {cfg?.token_set ? "(leave blank to keep current)" : <span style={{ color: "#c0392b" }}>*</span>}
          </label>
          <input
            className="input"
            style={{ width: "100%" }}
            type="password"
            placeholder={cfg?.token_set ? "•••••••• (stored, encrypted)" : "paste a NetBox API token"}
            value={tokenV}
            onChange={(e) => setTokenV(e.target.value)}
          />
          <p style={{ fontSize: 11, color: "var(--muted)", marginTop: 6 }}>Encrypted at rest by the secret-custody Vault; never shown again.</p>
        </div>
      ),
    },
    {
      id: "activate",
      title: "Activate",
      hint: "Turn discovery on and set the cadence.",
      isValid: () => true,
      render: () => (
        <div>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            Enable NetBox discovery
          </label>
          <label style={labelStyle}>Poll interval (seconds)</label>
          <input className="input" style={{ width: 160 }} type="number" min={15} value={interval} onChange={(e) => setIntervalV(Number(e.target.value))} />
        </div>
      ),
    },
  ];

  const steps = mode === "managed" ? [managedStep] : externalSteps;
  const st = netboxStatus(cfg);

  return (
    <>
      <div className="card">
        <h2 style={{ margin: 0 }}>Source of Truth</h2>
        <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 6 }}>
          Systems of record that feed the device inventory. Discovered devices are tagged with their
          source and reconciled into Infrastructure → Devices.
        </p>
      </div>

      {/* NetBox connector tile → guided setup */}
      <div className="card" style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 40, height: 40, borderRadius: 8, background: "var(--panel-2, #f4f4f8)", display: "grid", placeItems: "center" }}>
          <Icon name="directory" size={22} />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, display: "flex", gap: 8, alignItems: "center" }}>
            NetBox
            {cfg?.managed && (
              <span className="badge" style={{ fontSize: 10 }}>
                Bundled
              </span>
            )}
          </div>
          <div style={{ fontSize: 12, color: "var(--muted)" }}>
            DCIM/IPAM source of truth — feeds the device inventory.
          </div>
        </div>
        <span className={`badge ${st.tone}`}>{st.label}</span>
        <button
          className="btn primary"
          onClick={() => {
            setMode(cfg?.url && !cfg.managed ? "external" : "managed");
            setWizard(true);
          }}
        >
          {st.label === "Not set up" || st.label === "Bundled · off" ? "Set up" : "Manage"}
        </button>
        <button className="btn" disabled={refreshing} onClick={refresh}>
          <Icon name="refresh" size={14} /> {refreshing ? "…" : "Refresh"}
        </button>
      </div>

      {poll && (
        <div className="card" style={{ fontSize: 12, color: "var(--muted)" }}>
          Last poll: {poll.last_poll ? new Date(poll.last_poll).toLocaleString() : "—"} · {poll.devices ?? 0} device(s)
          {poll.last_error ? <span style={{ color: "#c0392b" }}> · error: {poll.last_error}</span> : null}
        </div>
      )}
      {msg && <p style={{ color: "var(--accent, #2e7d32)", padding: "0 4px" }}>{msg}</p>}
      {err && <p style={{ color: "#c0392b", padding: "0 4px" }}>{err}</p>}

      {wizard && (
        <div
          onClick={() => setWizard(false)}
          style={{ position: "fixed", inset: 0, background: "rgba(10,10,20,.45)", display: "grid", placeItems: "center", zIndex: 50, padding: 16 }}
        >
          <div onClick={(e) => e.stopPropagation()} className="card" style={{ maxWidth: 560, width: "100%" }}>
            <h3 style={{ marginTop: 0 }}>Set up NetBox</h3>
            <Wizard key={mode} steps={steps} onFinish={save} onCancel={() => setWizard(false)} finishLabel="Save" />
          </div>
        </div>
      )}
    </>
  );
}
