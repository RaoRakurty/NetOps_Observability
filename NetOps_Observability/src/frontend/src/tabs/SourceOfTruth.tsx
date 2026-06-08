import { useEffect, useRef, useState } from "react";
import { api, NetboxConfig } from "../services/api";
import Icon from "../components/Icon";
import Wizard, { WizardStep } from "../components/Wizard";

// Automation → Source of Truth. The system of record that feeds the device
// inventory is bundled with and managed by the platform — it's embedded right
// here (auto-logged-in, no separate console, no vendor branding). Operators
// create sites/devices/IPs inline and discovery reconciles them into
// Infrastructure → Devices. An external instance can be connected instead.

type Status = { label: string; tone: "good" | "warn" | "" };

function sotStatus(c: NetboxConfig | null): Status {
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
  const [full, setFull] = useState(false);
  const frameRef = useRef<HTMLIFrameElement | null>(null);

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
    title: "Bundled inventory",
    hint: "The inventory service ships with the platform — it's already wired. Just turn it on.",
    isValid: () => true,
    render: () => (
      <div>
        <p style={{ fontSize: 13, color: "var(--muted)" }}>
          The platform runs and manages the inventory service internally; the connection is configured
          automatically. You don't need to paste anything.
        </p>
        <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, marginTop: 8 }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enable inventory discovery
        </label>
        <label style={labelStyle}>Poll interval (seconds)</label>
        <input className="input" style={{ width: 160 }} type="number" min={15} value={interval} onChange={(e) => setIntervalV(Number(e.target.value))} />
        <p style={{ marginTop: 14 }}>
          <button className="btn" onClick={() => setMode("external")}>
            Connect an external inventory instead →
          </button>
        </p>
      </div>
    ),
  };

  const externalSteps: WizardStep[] = [
    {
      id: "url",
      title: "Connect",
      hint: "Point at your existing inventory instance.",
      isValid: () => validURL(urlV),
      render: () => (
        <div>
          {cfg?.managed && (
            <p style={{ marginBottom: 8 }}>
              <button className="btn" onClick={() => setMode("managed")}>
                ← Use the bundled inventory
              </button>
            </p>
          )}
          <label style={labelStyle}>
            Inventory URL <span style={{ color: "#c0392b" }}>*</span>
          </label>
          <input className="input" style={{ width: "100%" }} placeholder="https://inventory.example.com" value={urlV} onChange={(e) => setUrlV(e.target.value)} />
        </div>
      ),
    },
    {
      id: "token",
      title: "Authenticate",
      hint: "An API token with read access to the device inventory.",
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
            placeholder={cfg?.token_set ? "•••••••• (stored, encrypted)" : "paste an API token"}
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
            Enable inventory discovery
          </label>
          <label style={labelStyle}>Poll interval (seconds)</label>
          <input className="input" style={{ width: 160 }} type="number" min={15} value={interval} onChange={(e) => setIntervalV(Number(e.target.value))} />
        </div>
      ),
    },
  ];

  const steps = mode === "managed" ? [managedStep] : externalSteps;
  const st = sotStatus(cfg);
  // The bundled inventory is embedded (auto-logged-in via the platform gate); an
  // external instance can't be framed (its own origin/login), so we link out.
  const embeddable = !!cfg?.managed && cfg.enabled;
  const externalConnected = !cfg?.managed && cfg?.enabled && !!cfg?.url;

  const reloadFrame = () => {
    if (frameRef.current) frameRef.current.src = "/netbox/";
  };

  return (
    <>
      {/* Toolbar: title · status · inline controls. No vendor name, no new tab. */}
      <div className="card sot-head">
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <div style={{ width: 34, height: 34, borderRadius: 8, background: "var(--panel-2, #f4f4f8)", display: "grid", placeItems: "center" }}>
            <Icon name="directory" size={20} />
          </div>
          <div style={{ flex: 1, minWidth: 180 }}>
            <div style={{ fontWeight: 700, display: "flex", gap: 8, alignItems: "center" }}>
              Source of Truth
              {cfg?.managed && <span className="badge" style={{ fontSize: 10 }}>Built-in</span>}
            </div>
            <div style={{ fontSize: 12, color: "var(--muted)" }}>
              System of record for the device inventory — discovery reconciles it into Infrastructure → Devices.
            </div>
          </div>
          <span className={`badge ${st.tone}`}>{st.label}</span>
          {embeddable && (
            <>
              <button className="btn" onClick={reloadFrame} title="Reload the inventory view">
                <Icon name="refresh" size={14} /> Reload
              </button>
              <button className="btn" onClick={() => setFull((f) => !f)} title={full ? "Exit full screen" : "Full screen"}>
                <Icon name={full ? "close" : "maximize"} size={14} /> {full ? "Exit full screen" : "Full screen"}
              </button>
            </>
          )}
          <button
            className="btn"
            onClick={() => {
              setMode(cfg?.url && !cfg.managed ? "external" : "managed");
              setWizard(true);
            }}
          >
            <Icon name="settings" size={14} /> {st.label === "Not set up" || st.label === "Bundled · off" ? "Set up" : "Manage"}
          </button>
          <button className="btn" disabled={refreshing} onClick={refresh} title="Run discovery now">
            <Icon name="refresh" size={14} /> {refreshing ? "…" : "Sync devices"}
          </button>
        </div>
        {poll && (
          <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 8 }}>
            Last sync: {poll.last_poll ? new Date(poll.last_poll).toLocaleString() : "—"} · {poll.devices ?? 0} device(s)
            {poll.last_error ? <span style={{ color: "#c0392b" }}> · error: {poll.last_error}</span> : null}
          </div>
        )}
        {msg && <p style={{ color: "var(--accent, #2e7d32)", margin: "8px 0 0" }}>{msg}</p>}
        {err && <p style={{ color: "#c0392b", margin: "8px 0 0" }}>{err}</p>}
      </div>

      {/* Embedded, auto-logged-in inventory dashboard — the hero of the page. */}
      {embeddable ? (
        <div className={`sot-frame-wrap${full ? " full" : ""}`}>
          {full && (
            <button className="btn sot-exit" onClick={() => setFull(false)}>
              <Icon name="close" size={14} /> Exit full screen
            </button>
          )}
          <iframe
            ref={frameRef}
            title="Source of Truth"
            src="/netbox/"
            className="sot-frame"
          />
        </div>
      ) : externalConnected ? (
        <div className="card" style={{ fontSize: 13, color: "var(--muted)" }}>
          Connected to an external inventory instance. It's managed in its own console; discovery pulls its
          devices into <b>Infrastructure → Devices</b>. Use <b>Manage</b> to change the connection.
        </div>
      ) : (
        <div className="card" style={{ textAlign: "center", padding: "40px 20px" }}>
          <div style={{ fontWeight: 600, fontSize: 15 }}>The inventory service is off</div>
          <p style={{ color: "var(--muted)", fontSize: 13, maxWidth: 460, margin: "8px auto 16px" }}>
            Turn on the built-in Source of Truth to create sites, devices and IPs right here — it's wired
            automatically, no URL or token to paste.
          </p>
          <button
            className="btn primary"
            onClick={() => {
              setMode("managed");
              setWizard(true);
            }}
          >
            Turn on inventory
          </button>
        </div>
      )}

      {wizard && (
        <div
          onClick={() => setWizard(false)}
          style={{ position: "fixed", inset: 0, background: "rgba(10,10,20,.45)", display: "grid", placeItems: "center", zIndex: 50, padding: 16 }}
        >
          <div onClick={(e) => e.stopPropagation()} className="card" style={{ maxWidth: 560, width: "100%" }}>
            <h3 style={{ marginTop: 0 }}>Set up the Source of Truth</h3>
            <Wizard key={mode} steps={steps} onFinish={save} onCancel={() => setWizard(false)} finishLabel="Save" />
          </div>
        </div>
      )}
    </>
  );
}
