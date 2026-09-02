// Transport Security (SEC-021.1) — the read-only posture inventory: every
// internal transport path (edge), its declared vs target TLS tier, live probe
// observations and owner-accepted exceptions. The platform owner sees the full
// inventory + validator findings and can export the HTML report; a tenant
// admin sees only its device lanes. The backend enforces both scopes
// independently (403 below administration:admin, scope picked by principal).

import { useCallback, useEffect, useState } from "react";
import { api, PostureRow } from "../services/api";
import { fmtDate, fmtDateTime } from "../lib/time";
import { StatStrip, Stat } from "../components/ui";

// ---- shared chrome (admin.tsx keeps these private; replicated, not imported) --

function AdminHead({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="admin-head">
      <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>{title}</h2>
      <p className="admin-sub">{sub}</p>
    </div>
  );
}

// role=alert announces the failure to assistive tech when it appears (WCAG
// 3.3.1/4.1.3) — same contract as the admin forms' ErrLine.
function ErrLine({ msg }: { msg: string | null }) {
  if (!msg) return null;
  return <p role="alert" style={{ color: "var(--bad)", fontSize: "var(--fs-meta)", margin: "0 0 var(--sp-2)" }}>{msg}</p>;
}

// useReload gives a [data, error, reload, setError] tuple over an async loader.
function useReload<T>(loader: () => Promise<T>): [T | undefined, string | null, () => void, (e: string | null) => void] {
  const [data, setData] = useState<T>();
  const [err, setErr] = useState<string | null>(null);
  const reload = useCallback(() => {
    loader().then(setData).catch((e) => setErr((e as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(reload, [reload]);
  return [data, err, reload, setErr];
}

// ---- rendering helpers ------------------------------------------------------

// The probe verdict for one path. Honest three-state: unprobed paths say so —
// they are never rendered as either good or bad.
export function observedText(r: PostureRow): string {
  if (!r.observed) return "not probed";
  if (r.observed.probe_ok && r.observed.cert_not_after) return `cert ok, expires ${fmtDate(r.observed.cert_not_after)}`;
  return "No certificate presented";
}

// Drift is a warning (declared ≠ current); an accepted exception is disclosed
// with its owner, date, age and reason — never hidden behind a checkmark.
function DriftCell({ r }: { r: PostureRow }) {
  if (r.drift) return <span className="badge warn">{r.drift}</span>;
  if (r.exception) {
    return (
      <span className="mini-meta">
        {r.exception.owner}, accepted {fmtDate(r.exception.accepted)}
        {r.exception_age_days !== undefined ? `, ${r.exception_age_days}d` : ""}, {r.exception.reason}
      </span>
    );
  }
  return <span className="mini-meta">—</span>;
}

// One posture table. `identity` adds the Peer identity column (platform scope
// only — tenant lanes carry no platform identities).
function PostureTable({ rows, identity }: { rows: PostureRow[]; identity: boolean }) {
  return (
    <table className="ds-table" style={{ width: "100%" }}>
      <thead>
        <tr>
          <th>Edge</th>
          <th>Channel</th>
          <th>Declared</th>
          <th>Target</th>
          {identity && <th>Peer identity</th>}
          <th>Observed</th>
          <th>Drift / Exception</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={`${r.edge}:${r.channel}`}>
            <td style={{ fontWeight: 600 }}>
              {r.edge}
              {r.trust_domain === "device" && <span className="badge" style={{ marginLeft: 6 }}>device lane</span>}
            </td>
            <td>
              {r.channel}{" "}
              <span className="mini-meta">({r.protocol}{r.port ? `:${r.port}` : ""})</span>
            </td>
            <td>{r.declared_tier}</td>
            <td>{r.target_tier}</td>
            {identity && <td className="mono">{r.identity || "—"}</td>}
            <td>{observedText(r)}</td>
            <td><DriftCell r={r} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ---- the view ---------------------------------------------------------------

export function TransportSecurity() {
  const [data, err, , setErr] = useReload(() => api.transportPosture());
  const [exporting, setExporting] = useState(false);

  // Blob → browser download named transport-posture.html (the api layer's
  // downloadResponse helper is private, so the createObjectURL idiom lives here).
  const doExport = async () => {
    setErr(null);
    setExporting(true);
    try {
      const blob = await api.exportTransportPosture();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "transport-posture.html";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setExporting(false);
    }
  };

  if (!data) {
    return (
      <>
        <AdminHead title="Transport Security" sub="Read-only TLS posture of every internal transport path: declared vs target tier, live probe results, drift and accepted exceptions." />
        <ErrLine msg={err} />
        {!err && <div className="empty">Loading transport posture…</div>}
      </>
    );
  }

  if (data.scope === "tenant") {
    const lanes = data.device_lanes ?? [];
    return (
      <>
        <AdminHead title="Transport Security" sub="Read-only TLS posture of the transport lanes carrying your devices' telemetry." />
        <ErrLine msg={err} />
        <div className="card" style={{ paddingTop: 8 }}>
          <h3 style={{ margin: "0 0 var(--sp-2)" }}>Your fleet: {data.device_count ?? 0} devices</h3>
          <PostureTable rows={lanes} identity={false} />
          {lanes.length === 0 && <div className="empty">No device lanes in the inventory.</div>}
          <p className="mini-meta" style={{ marginTop: 8 }}>
            Platform-internal transport paths are visible to platform administrators only.
          </p>
        </div>
      </>
    );
  }

  const rows = data.rows ?? [];
  const drifting = rows.filter((r) => r.drift).length;
  const exceptions = rows.filter((r) => r.exception).length;
  const v = data.validator;
  return (
    <>
      <AdminHead title="Transport Security" sub="Read-only TLS posture of every internal transport path: declared vs target tier, live probe results, drift and accepted exceptions." />
      <ErrLine msg={err} />
      <StatStrip>
        <Stat label="Paths" value={rows.length} />
        <Stat label="Drifting" value={drifting} tone={drifting > 0 ? "warn" : ""} />
        <Stat label="Exceptions" value={exceptions} tone={exceptions > 0 ? "accent" : ""} />
        <Stat label="Critical problems" value={v?.fatal ?? "—"} tone={v && v.fatal > 0 ? "bad" : ""} />
        <Stat label="Warnings" value={v?.warn ?? "—"} tone={v && v.warn > 0 ? "warn" : ""} />
      </StatStrip>
      <div className="ds-toolbar">
        <span className="mini-meta">Generated {fmtDateTime(data.generated)}{v ? ` · profile ${v.profile}` : ""}</span>
        <button className="btn" disabled={exporting} onClick={() => { void doExport(); }}>
          {exporting ? "Exporting…" : "Export report (HTML)"}
        </button>
      </div>
      <div className="card" style={{ paddingTop: 8 }}>
        <PostureTable rows={rows} identity />
        {rows.length === 0 && <div className="empty">No transport paths in the inventory.</div>}
      </div>
    </>
  );
}

export default TransportSecurity;
