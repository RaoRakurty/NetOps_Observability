import { useEffect, useState } from "react";
import { ExportPolicyForm, LANDING_OPTIONS } from "./admin";
import { api } from "../services/api";
import Icon from "../components/Icon";

// Default landing page — the platform-wide page users land on after sign-in.
// Stored on the global tenant (the platform default); individual tenants can
// override it in Identity & Access → (org) → Tenants. Discoverable home: here.
function DefaultLandingCard() {
  const [current, setCurrent] = useState<string>("");
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);

  useEffect(() => {
    api.listTenants()
      .then((ts) => setCurrent(ts.find((t) => t.id === "global")?.default_landing || ""))
      .catch((e) => setErr((e as Error).message))
      .finally(() => setBusy(false));
  }, []);

  const onChange = async (route: string) => {
    setErr(null); setSaved(false);
    const prev = current;
    setCurrent(route); // optimistic
    try {
      await api.setTenantLanding("global", route);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setCurrent(prev);
      setErr((e as Error).message);
    }
  };

  return (
    <div className="card" style={{ display: "flex", alignItems: "center", gap: 12 }}>
      <div style={{ width: 34, height: 34, borderRadius: 8, background: "var(--surface-2)", display: "grid", placeItems: "center" }}>
        <Icon name="overview" size={20} />
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 700 }}>Default landing page</div>
        <div style={{ fontSize: 12, color: "var(--muted)" }}>
          The page everyone lands on after sign-in. Tenants can override this in Identity &amp; Access.
          {err && <span style={{ color: "var(--crit)" }}> · {err}</span>}
          {saved && <span style={{ color: "var(--ok)" }}> · saved</span>}
        </div>
      </div>
      <select
        className="app-select"
        value={current}
        disabled={busy}
        onChange={(e) => onChange(e.target.value)}
        aria-label="Default landing page"
        style={{ minWidth: 200 }}
      >
        <option value="">Built-in (Dashboards · Home)</option>
        {LANDING_OPTIONS.map((o) => <option key={o.route} value={o.route}>{o.label}</option>)}
      </select>
    </div>
  );
}

// Administration → Settings. Trimmed (C1/C2/C3):
//   - the redundant per-integration credentials table is gone — each connector
//     shows its own status under Integrations / Notifications;
//   - discovery refresh moved to Automation → Source of Truth;
//   - log-export limits are now a tile that opens a guided setup modal.
export default function Settings() {
  const [showExport, setShowExport] = useState(false);

  return (
    <>
      <div className="card">
        <h2 style={{ margin: 0 }}>Settings</h2>
        <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 6 }}>
          Platform configuration. Integration credentials live with their connectors
          (Administration → Integrations and Notifications); discovery sources are under
          Automation → Source of Truth.
        </p>
      </div>

      {/* Default landing page — the platform-wide post-login page. */}
      <DefaultLandingCard />

      {/* Log export limits — tile + guided setup (C3). */}
      <div className="card" style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div
          style={{
            width: 34,
            height: 34,
            borderRadius: 8,
            background: "var(--surface-2)",
            display: "grid",
            placeItems: "center",
          }}
        >
          <Icon name="external" size={20} />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700 }}>Log export limits</div>
          <div style={{ fontSize: 12, color: "var(--muted)" }}>
            Anti-exfiltration guardrails for log exports — rate, row/size caps, runtime, link TTL.
          </div>
        </div>
        <button className="btn" onClick={() => setShowExport(true)}>
          Configure
        </button>
      </div>

      {showExport && (
        <div
          onClick={() => setShowExport(false)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(10,10,20,.45)",
            display: "grid",
            placeItems: "center",
            zIndex: 50,
            padding: 16,
          }}
        >
          <div onClick={(e) => e.stopPropagation()} style={{ maxWidth: 640, width: "100%", maxHeight: "86vh", overflow: "auto" }}>
            <ExportPolicyForm />
            <div style={{ textAlign: "right", marginTop: 8 }}>
              <button className="btn" onClick={() => setShowExport(false)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
