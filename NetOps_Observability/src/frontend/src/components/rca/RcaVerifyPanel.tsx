// RcaVerifyPanel — the "Verify now" card for the RCA workspace (Active
// Verification, RCA spec item 8). When a case sits at SUSPECTED, the engine
// can interrogate the implicated devices with a bounded READ-ONLY check
// battery; results come back as an independent evidence modality. This panel
// shows the latest run + per-check results in an evidence disclosure, and lets
// an operator with infrastructure:write trigger a run manually.
//
// Self-contained slot like RcaTicketCard: fetches its own data, renders
// nothing when the feature is dormant or the tenant has not opted in, and
// never invents a result that is not there.

import { useEffect, useState } from "react";
import { fmtDateTime } from "../../lib/time";
import { api, type VerificationCheckResult } from "../../services/api";
import { useVerification } from "./useVerification";

const STATUS_LABEL: Record<string, string> = {
  pass: "healthy", fail: "fault found", unreachable: "unreachable", skipped: "skipped",
};
const STATUS_COLOR: Record<string, string> = {
  pass: "var(--ok, #2e9e5b)", fail: "var(--bad, #d64545)",
  unreachable: "var(--warn, #d6883f)", skipped: "var(--muted, #8a8f98)",
};

function fmtWhen(iso?: string): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  return Number.isNaN(t) ? "—" : fmtDateTime(t);
}

function ResultRow({ r }: { r: VerificationCheckResult }) {
  return (
    <tr>
      <td style={{ whiteSpace: "nowrap" }}>{r.check}</td>
      <td style={{ whiteSpace: "nowrap" }}>{r.device_name || r.device_id}</td>
      <td style={{ whiteSpace: "nowrap", color: STATUS_COLOR[r.status] }}>
        {STATUS_LABEL[r.status] ?? r.status}
      </td>
      <td title={r.command ? `command: ${r.command}` : undefined}>{r.observed || "—"}</td>
    </tr>
  );
}

export default function RcaVerifyPanel({ correlationId, suspected }: {
  correlationId: string;
  suspected?: boolean; // case sits at the suspected tier → verification is the closer
}) {
  const { status, available, busy, message, trigger } = useVerification(correlationId);
  const [canWrite, setCanWrite] = useState(false);

  useEffect(() => {
    api.permissions()
      .then((p) => setCanWrite((p.permissions?.infrastructure ?? 0) >= 2))
      .catch(() => setCanWrite(false));
  }, [correlationId]);

  // Dormant feature, tenant not opted in, or case not visible → no panel.
  if (!available || !status?.enabled) return null;

  const run = status.run;
  const results = run?.results ?? [];
  const counts = results.reduce<Record<string, number>>((m, r) => {
    m[r.status] = (m[r.status] ?? 0) + 1;
    return m;
  }, {});
  const summary = run
    ? run.status === "running"
      ? `Run in progress (${run.trigger}) — started ${fmtWhen(run.started_at)}`
      : `Last run ${fmtWhen(run.finished_at || run.started_at)} (${run.trigger}) — ` +
        `${counts.fail ?? 0} fault, ${counts.unreachable ?? 0} unreachable, ` +
        `${counts.pass ?? 0} healthy, ${counts.skipped ?? 0} skipped`
    : suspected
      ? "No verification run yet — the case needs a second independent source."
      : "No verification run yet.";

  return (
    <div className="rw-verify" style={{ display: "grid", gap: 8 }}>
      <h3 className="rw-section-title">Active verification</h3>
      <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
        {/* Live region (4.1.3): announces run start/finish after "Verify now". */}
        <span style={{ flex: 1, minWidth: 220 }} role="status" aria-live="polite">{summary}</span>
        {canWrite && (
          <button className="rw-btn" onClick={trigger}
            disabled={busy || run?.status === "running"}
            aria-busy={busy || run?.status === "running"}
            title="Run the bounded read-only check battery (ping / SNMP / show commands) against the implicated devices">
            {run?.status === "running" ? "Verifying…" : "Verify now"}
          </button>
        )}
      </div>
      {message && <div className="rw-note" role="status" aria-live="polite">{message}</div>}
      {results.length > 0 && (
        <details>
          <summary style={{ cursor: "pointer" }}>
            Per-check results ({results.length}) — read-only battery, every command allowlisted &amp; audited
          </summary>
          <div style={{ overflowX: "auto", marginTop: 6 }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ textAlign: "left", opacity: 0.7 }}>
                  <th scope="col">Check</th><th scope="col">Device</th><th scope="col">Result</th><th scope="col">Device response</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => <ResultRow key={`${r.device_id}/${r.check}/${i}`} r={r} />)}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  );
}
