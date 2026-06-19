import { useEffect, useRef, useState } from "react";
import { api, NetboxConfig, NetboxSyncStatus } from "../services/api";
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

// DirectionPicker controls how devices flow between the platform and the
// inventory. Default "write" keeps it one-directional (platform → inventory),
// so synced devices never reappear in Infrastructure → Devices as duplicates.
type Direction = "write" | "read" | "both" | "none";

const DIRECTIONS: { v: Direction; label: string; help: string }[] = [
  { v: "write", label: "Devices → Inventory", help: "One-way: discovered devices are pushed to the inventory. The inventory is a downstream record and is never read back, so nothing is duplicated. Best when you're building inventory from scratch — SNMP discovery seeds it. (Recommended)" },
  { v: "read", label: "Inventory → Devices", help: "One-way: the inventory is the source of truth; its devices appear in Infrastructure. Discovery does not push anything up." },
  { v: "both", label: "Two-way sync", help: "Read inventory devices in AND push discovered devices up. Records are de-duplicated by IP / serial / name." },
  { v: "none", label: "No automatic sync", help: "The inventory stays available (browse it here, use its site/geo intent) but discovery neither pushes nor pulls devices. Use this when you already run an external source of truth and will sync it through its own API." },
];

function DirectionPicker({ value, onChange }: { value: Direction; onChange: (v: Direction) => void }) {
  const cur = DIRECTIONS.find((d) => d.v === value) ?? DIRECTIONS[0];
  return (
    <div style={{ marginTop: 12 }}>
      <label style={labelStyle}>Sync direction</label>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {DIRECTIONS.map((d) => (
          <button
            key={d.v}
            className={`btn${d.v === value ? " btn-primary" : ""}`}
            style={{ fontSize: 12 }}
            onClick={() => onChange(d.v)}
            type="button"
          >
            {d.label}
          </button>
        ))}
      </div>
      <p style={{ fontSize: 11, color: "var(--muted)", marginTop: 6 }}>{cur.help}</p>
    </div>
  );
}

export default function SourceOfTruth() {
  const [cfg, setCfg] = useState<NetboxConfig | null>(null);
  const [wizard, setWizard] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [poll, setPoll] = useState<{ last_poll?: string; devices?: number; last_error?: string } | null>(null);
  const [syncStat, setSyncStat] = useState<NetboxSyncStatus | null>(null);
  const [pushing, setPushing] = useState(false);
  const [full, setFull] = useState(false);
  const [gateReady, setGateReady] = useState(false);
  const frameRef = useRef<HTMLIFrameElement | null>(null);

  // Wizard working state.
  const [mode, setMode] = useState<"managed" | "external">("managed");
  const [enabled, setEnabled] = useState(true);
  const [urlV, setUrlV] = useState("");
  const [tokenV, setTokenV] = useState("");
  const [interval, setIntervalV] = useState(60);
  const [direction, setDirection] = useState<Direction>("write");

  const load = async () => {
    try {
      const r = await api.netboxConfig();
      setCfg(r.config);
      setMode(r.config.url && !r.config.managed ? "external" : "managed");
      setEnabled(r.config.enabled);
      setUrlV(r.config.managed ? "" : r.config.url);
      setIntervalV(r.config.interval_sec || 60);
      setDirection(r.config.direction || "write");
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
    try {
      setSyncStat(await api.netboxSyncStatus());
    } catch {
      /* platform-owner-only */
    }
  };

  // Push discovered devices INTO NetBox (write-through reconcile). Distinct from
  // "Sync devices" above, which polls the inventory INTO Infrastructure → Devices.
  const pushToNetbox = async () => {
    setPushing(true);
    setMsg(null);
    setErr(null);
    try {
      const s = await api.netboxSyncNow();
      setSyncStat(s);
      setMsg(`Pushed to inventory: ${s.created} created, ${s.present} already present.`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setPushing(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  // The embedded console is a raw iframe that doesn't pass through the SPA's
  // Bearer/refresh path, so its gate cookie can be stale/missing. Re-mint it
  // before showing the frame so /netbox/ always authenticates (no 403 wall).
  useEffect(() => {
    if (!(cfg?.managed && cfg.enabled)) return;
    let alive = true;
    api.ensureConsoleGate().finally(() => {
      if (alive) setGateReady(true);
    });
    return () => {
      alive = false;
    };
  }, [cfg?.managed, cfg?.enabled]);

  const validURL = (u: string) => /^https?:\/\/.+/.test(u.trim());

  const save = async () => {
    const payload: Partial<NetboxConfig> = { enabled, interval_sec: Number(interval) || 60, direction };
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
        <DirectionPicker value={direction} onChange={setDirection} />
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
            Inventory URL <span style={{ color: "var(--bad)" }}>*</span>
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
            API token {cfg?.token_set ? "(leave blank to keep current)" : <span style={{ color: "var(--bad)" }}>*</span>}
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
          <DirectionPicker value={direction} onChange={setDirection} />
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
    // Re-mint the gate cookie first in case it expired during a long session.
    api.ensureConsoleGate().finally(() => {
      if (frameRef.current) frameRef.current.src = "/netbox/";
    });
  };

  return (
    <>
      {/* Toolbar: title · status · inline controls. No vendor name, no new tab. */}
      <div className="card sot-head">
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <div style={{ width: 34, height: 34, borderRadius: 8, background: "var(--surface-2)", display: "grid", placeItems: "center" }}>
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
          <button className="btn" disabled={refreshing} onClick={refresh} title="Poll the inventory now (inventory → Infrastructure → Devices)">
            <Icon name="refresh" size={14} /> {refreshing ? "…" : "Sync devices"}
          </button>
          {cfg?.enabled && (cfg.direction === "write" || cfg.direction === "both") && (
            <button className="btn" disabled={pushing} onClick={pushToNetbox} title="Push discovered devices INTO the inventory (runs automatically every 5 min)">
              <Icon name="arrow-up-right" size={14} /> {pushing ? "…" : "Push to inventory"}
            </button>
          )}
        </div>
        {poll && (
          <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 8 }}>
            Inventory → Devices (poll): {poll.last_poll ? new Date(poll.last_poll).toLocaleString() : "—"} · {poll.devices ?? 0} device(s)
            {poll.last_error ? <span style={{ color: "var(--bad)" }}> · error: {poll.last_error}</span> : null}
          </div>
        )}
        {syncStat?.enabled && (
          <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 4 }}>
            Devices → NetBox (write-through): {syncStat.last_run ? new Date(syncStat.last_run).toLocaleString() : "not run yet"}
            {syncStat.last_run ? <> · {syncStat.created} created · {syncStat.present} already present</> : null}
            {syncStat.last_error ? <span style={{ color: "var(--bad)" }}> · error: {syncStat.last_error}</span> : null}
          </div>
        )}
        {msg && <p style={{ color: "var(--good)", margin: "8px 0 0" }}>{msg}</p>}
        {err && <p style={{ color: "var(--bad)", margin: "8px 0 0" }}>{err}</p>}
      </div>

      {/* Embedded, auto-logged-in inventory dashboard — the hero of the page. */}
      {embeddable ? (
        <div className={`sot-frame-wrap${full ? " full" : ""}`}>
          {full && (
            <button className="btn sot-exit" onClick={() => setFull(false)}>
              <Icon name="close" size={14} /> Exit full screen
            </button>
          )}
          {gateReady ? (
            <iframe
              ref={frameRef}
              title="Source of Truth"
              src="/netbox/"
              className="sot-frame"
            />
          ) : (
            <div className="sot-frame" style={{ display: "grid", placeItems: "center", color: "var(--muted)", fontSize: 13 }}>
              Connecting to the inventory…
            </div>
          )}
        </div>
      ) : externalConnected ? (
        <div className="card" style={{ fontSize: 13, color: "var(--muted)" }}>
          Connected to an external inventory instance. It's managed in its own console; discovery pulls its
          devices into <b>Infrastructure → Devices</b>. Use <b>Manage</b> to change the connection.
        </div>
      ) : (
        <div className="card" style={{ textAlign: "center", padding: "40px 20px" }}>
          <div style={{ fontWeight: 600, fontSize: 14 }}>The inventory service is off</div>
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
