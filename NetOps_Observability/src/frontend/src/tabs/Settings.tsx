import { useEffect, useState } from "react";
import { ExportPolicyForm, LANDING_OPTIONS } from "./admin";
import { api } from "../services/api";
import Icon from "../components/Icon";
import { setTzMode, tzLabel } from "../lib/time";
import { useAuth } from "../hooks/useAuth";
import SystemNetworkCard from "../pages/SystemNetwork";
import DataProtection from "../pages/DataProtection";
import { Modal } from "../components/ui";

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
        <h3 style={{ fontWeight: 700, fontSize: "inherit", margin: 0 }}>Default landing page</h3>
        <div style={{ fontSize: 12, color: "var(--muted)" }}>
          The page everyone lands on after sign-in. Tenants can override this in Identity &amp; Access.
          {err && <span role="alert" style={{ color: "var(--crit)" }}> · {err}</span>}
          <span role="status">{saved ? " · saved" : ""}</span>
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

// Time display — the Local/UTC rendering mode, moved here off the top bar
// (owner 2026-07-17): a per-TENANT persisted, audited preference. Every user
// of the tenant reads timestamps in the zone chosen here; storage stays UTC.
// Applies immediately (setTzMode) — no reload, every rendered time re-labels.
function TimeDisplayCard() {
  const [mode, setMode] = useState<"local" | "utc">("local");
  const [saved, setSaved] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);

  useEffect(() => {
    api.getDisplaySettings()
      .then((r) => setMode(r.time_display === "utc" ? "utc" : "local"))
      .catch((e) => setErr((e as Error).message))
      .finally(() => setBusy(false));
  }, []);

  const onChange = async (next: "local" | "utc") => {
    setErr(null); setSaved(false);
    const prev = mode;
    setMode(next); // optimistic
    try {
      await api.setDisplaySettings(next);
      setTzMode(next); // re-render every timestamp now
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setMode(prev);
      setErr((e as Error).message);
    }
  };

  return (
    <div className="card" style={{ display: "flex", alignItems: "center", gap: 12 }}>
      <div style={{ width: 34, height: 34, borderRadius: 8, background: "var(--surface-2)", display: "grid", placeItems: "center" }}>
        <Icon name="sliders" size={20} />
      </div>
      <div style={{ flex: 1 }}>
        <h3 style={{ fontWeight: 700, fontSize: "inherit", margin: 0 }}>Time display</h3>
        <div style={{ fontSize: 12, color: "var(--muted)" }}>
          How every timestamp renders for this tenant — your local zone ({tzLabel("local")}) or UTC.
          Storage is always UTC; only display changes. Admin-set, applies to all of the tenant&apos;s users.
          {err && <span role="alert" style={{ color: "var(--crit)" }}> · {err}</span>}
          <span role="status">{saved ? " · saved" : ""}</span>
        </div>
      </div>
      <select
        className="app-select"
        value={mode}
        disabled={busy}
        onChange={(e) => onChange(e.target.value as "local" | "utc")}
        aria-label="Time display"
        style={{ minWidth: 200 }}
      >
        <option value="local">Local — {tzLabel("local")}</option>
        <option value="utc">UTC</option>
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
  const { user } = useAuth();
  const platformAdmin = !!user?.platform_admin;

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

      {/* Time display (Local/UTC) — per-tenant, persisted, audited. */}
      <TimeDisplayCard />

      {/* DNS + NTP — two boxes (Configure → popup), platform-owner only. */}
      {platformAdmin && <SystemNetworkCard />}

      {/* Data Protection — backup destination + DR status, platform-owner only. */}
      {platformAdmin && <DataProtection />}

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
          <h3 style={{ fontWeight: 700, fontSize: "inherit", margin: 0 }}>Log export limits</h3>
          <div style={{ fontSize: 12, color: "var(--muted)" }}>
            Anti-exfiltration guardrails for log exports — rate, row/size caps, runtime, link TTL.
          </div>
        </div>
        <button className="btn" onClick={() => setShowExport(true)}>
          Configure
        </button>
      </div>

      {/* Shared Modal (a11y): role=dialog + aria-modal, Escape close, focus
          moved in / restored and trapped — the hand-rolled overlay had none. */}
      {showExport && (
        <Modal title="Log export limits" onClose={() => setShowExport(false)}>
          <ExportPolicyForm />
          <div style={{ textAlign: "right", marginTop: 8 }}>
            <button className="btn" onClick={() => setShowExport(false)}>
              Close
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
