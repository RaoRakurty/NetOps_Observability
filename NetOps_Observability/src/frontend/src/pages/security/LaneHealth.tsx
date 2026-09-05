// LaneHealth — the security PRODUCER lane's own health, on Security Overview.
//
// WHY THIS EXISTS. Every number on this page is downstream of one process: the
// lane that assesses devices and publishes evidence onto the bus. Until now
// nothing in the console said whether that process was running, when it last
// ran, or whether what it produced was actually grounded — the exact class of
// failure the 2026-09-02 outage was (every container read healthy while the
// engine consumed nothing for three hours). A page that renders a funnel out of
// a lane it cannot see is reporting a measurement it has no evidence for.
//
// HONESTY RULES, in the order they bite:
//   · 404 means the lane is NOT ENABLED on this deployment. It is not an idle
//     lane and not an empty result — the routes are not registered at all while
//     FEATURE_SECURITY_LANE is off, and the panel says exactly that.
//   · `findings_emitted: 0` is read next to `devices_assessed`. A run that
//     assessed nothing measured nothing; it is never rendered as "clear".
//   · `outcome: skipped` keeps the PREVIOUS run's numbers (the lane refuses to
//     blank a row it did not re-measure), so the row is labelled as carrying
//     the last real result rather than a fresh one.
//   · A queued scan whose result has not appeared is reported as still queued,
//     never as a completed scan with no findings.
//
// §3a: the status read is tenant-filtered server-side — a tenant administrator
// sees only its own row, the platform owner sees one row per tenant. The scan
// is refused (400) for a cross-tenant caller, because a scan writes
// tenant-attributed evidence and the attribution must be unambiguous.

import { useCallback, useEffect, useRef, useState } from "react";
import { api, SecLaneScanStatus, SecLaneStatus } from "../../services/api";
import { Panel } from "../../components/board/panels";
import { fmtDateTime } from "../../lib/time";
import { httpFailure, operatorError } from "../../lib/errors";

/** How the lane read ended. `off` is a deployment fact, not a failure. */
type LoadState =
  | { kind: "loading" }
  | { kind: "off" }
  | { kind: "denied" }
  | { kind: "error"; message: string }
  | { kind: "ready"; status: SecLaneStatus };

/** What the operator's own "Scan now" is doing right now. */
type ScanState =
  | { kind: "idle" }
  | { kind: "queued"; seg: string; since: number }
  | { kind: "done"; row: SecLaneScanStatus }
  | { kind: "pending"; seg: string }
  | { kind: "refused"; message: string };

const OUTCOME_TONE: Record<string, string> = {
  ok: "chip-ok",
  partial: "chip-warn",
  error: "chip-crit",
  skipped: "",
};

/** The counters an operator reads to judge whether evidence reached the engine. */
const COUNTERS: { key: string; label: string; bad?: boolean }[] = [
  { key: "scan_runs_total", label: "Scan runs" },
  { key: "emitted_posture", label: "Hardening evidence published" },
  { key: "emitted_exposure", label: "Exposure evidence published" },
  { key: "emitted_signal", label: "Threat evidence published" },
  { key: "ungroundable_total", label: "Refused grounding", bad: true },
  { key: "findings_truncated_total", label: "Dropped by the per-run cap", bad: true },
  { key: "emit_failures_total", label: "Publish attempts exhausted", bad: true },
  { key: "dead_lettered_total", label: "Held in the dead-letter lane", bad: true },
  { key: "lost_total", label: "No durable copy anywhere", bad: true },
];

function secs(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "not stated";
  if (n % 60 === 0) return `${n / 60} min`;
  return `${n} s`;
}

function TenantRow({ row }: { row: SecLaneScanStatus }) {
  const skipped = row.outcome === "skipped";
  return (
    <tr>
      <th scope="row" style={{ fontWeight: 500, textAlign: "left" }}>{row.tenant_seg || row.tenant_id}</th>
      <td>
        <span className={`chip ${OUTCOME_TONE[row.outcome] ?? ""}`}>{row.outcome || "not stated"}</span>
        {skipped && <span className="mini-meta"> · a run was already in flight, so this row still carries the last real result</span>}
      </td>
      <td>{row.trigger || "not stated"}</td>
      <td>{row.last_scan_at ? fmtDateTime(row.last_scan_at) : "never"}</td>
      <td>{row.duration_ms > 0 ? `${row.duration_ms.toLocaleString()} ms` : "not measured"}</td>
      <td>{row.devices_assessed.toLocaleString()}</td>
      <td>
        {row.findings_emitted.toLocaleString()}
        {row.findings_truncated > 0 && <span className="mini-meta"> · {row.findings_truncated.toLocaleString()} over the cap</span>}
      </td>
    </tr>
  );
}

export default function LaneHealth({ pollMs = 4000, maxPolls = 15 }: { pollMs?: number; maxPolls?: number }) {
  const [load, setLoad] = useState<LoadState>({ kind: "loading" });
  const [scan, setScan] = useState<ScanState>({ kind: "idle" });
  const [busy, setBusy] = useState(false);
  const polls = useRef(0);

  const read = useCallback(async (): Promise<SecLaneStatus | null> => {
    try {
      const st = await api.securityLaneStatus();
      setLoad({ kind: "ready", status: st });
      return st;
    } catch (e) {
      const f = httpFailure(e);
      if (f?.status === 404) setLoad({ kind: "off" });
      else if (f?.status === 403) setLoad({ kind: "denied" });
      else setLoad({ kind: "error", message: operatorError(e, "The security lane status could not be read.") });
      return null;
    }
  }, []);

  useEffect(() => { void read(); }, [read]);

  // While a scan the operator started is in flight, re-read the lane until the
  // tenant's row carries a run that started after the request. Bounded: a scan
  // whose result never appears is reported as still queued, not as finished.
  useEffect(() => {
    if (scan.kind !== "queued") return;
    polls.current = 0;
    const id = setInterval(() => {
      polls.current += 1;
      void read().then((st) => {
        if (!st) return;
        const row = st.tenants.find((t) => t.tenant_seg === scan.seg);
        const at = row?.last_scan_at ? Date.parse(row.last_scan_at) : NaN;
        if (row && Number.isFinite(at) && at >= scan.since) {
          setScan({ kind: "done", row });
        } else if (polls.current >= maxPolls) {
          setScan({ kind: "pending", seg: scan.seg });
        }
      });
    }, pollMs);
    return () => clearInterval(id);
  }, [scan, read, pollMs, maxPolls]);

  const startScan = useCallback(async () => {
    setBusy(true);
    setScan({ kind: "idle" });
    // The clock the run is compared against is taken BEFORE the request, so a
    // run already recorded cannot be mistaken for the one just asked for.
    const since = Date.now() - 1000;
    try {
      const res = await api.securityScan();
      const row = await read();
      const seg = res.tenant_seg;
      const fresh = row?.tenants.find((t) => t.tenant_seg === seg);
      const at = fresh?.last_scan_at ? Date.parse(fresh.last_scan_at) : NaN;
      if (fresh && Number.isFinite(at) && at >= since) setScan({ kind: "done", row: fresh });
      else setScan({ kind: "queued", seg, since });
    } catch (e) {
      const f = httpFailure(e);
      if (f?.status === 429) {
        setScan({ kind: "refused", message: "A scan is already queued or running for this tenant. Its result appears on the row below when it finishes." });
      } else if (f?.status === 400) {
        setScan({ kind: "refused", message: operatorError(e, "A scan writes tenant-attributed evidence — select a tenant before starting one.") });
      } else {
        setScan({ kind: "refused", message: operatorError(e, "The scan could not be started.") });
      }
    } finally {
      setBusy(false);
    }
  }, [read]);

  if (load.kind === "loading") {
    return <Panel title="Security lane"><div className="empty" role="status">Reading the lane status…</div></Panel>;
  }
  if (load.kind === "off") {
    return (
      <Panel title="Security lane">
        <div className="empty">
          The security lane is not enabled on this deployment, so nothing assesses this estate on a
          schedule and no scan can be started here. Everything above was produced by other sources.
          The lane is switched on with <code>FEATURE_SECURITY_LANE</code>.
        </div>
      </Panel>
    );
  }
  if (load.kind === "denied") {
    return (
      <Panel title="Security lane">
        <div className="empty">Reading the lane status needs administration access — the same permission that enables a detection rule.</div>
      </Panel>
    );
  }
  if (load.kind === "error") {
    return (
      <Panel title="Security lane">
        <div className="empty" role="alert" style={{ color: "var(--bad)" }}>
          {load.message} The lane's state is unknown, not idle.
        </div>
      </Panel>
    );
  }

  const st = load.status;
  const scanAction = (
    <button
      type="button"
      className="btn accent"
      onClick={() => void startScan()}
      disabled={busy || scan.kind === "queued"}
    >
      {busy ? "Starting…" : scan.kind === "queued" ? "Scan running…" : "Scan now"}
    </button>
  );

  return (
    <Panel title="Security lane" action={scanAction}>
      <p className="mini-meta" style={{ marginTop: 0 }}>
        The lane assesses every device in scope every {secs(st.interval_seconds)} and publishes what it
        finds onto <code>{st.topic}</code>, up to {st.max_findings_per_tenant.toLocaleString()} findings
        per tenant per run. A scan you start here assesses your own tenant now instead of waiting.
      </p>

      {scan.kind === "refused" && (
        <p className="mini-meta" role="alert" style={{ color: "var(--bad)" }}>{scan.message}</p>
      )}
      {scan.kind === "queued" && (
        <p className="mini-meta" role="status">
          Scan queued for {scan.seg}. Waiting for the run to be recorded — the row below updates when it is.
        </p>
      )}
      {scan.kind === "pending" && (
        <p className="mini-meta" role="status">
          The scan was accepted for {scan.seg} but no completed run has been recorded yet. It has not
          failed; the result has not arrived. Read the row below again in a moment.
        </p>
      )}
      {scan.kind === "done" && (
        <p className="mini-meta" role="status">
          Scan finished {scan.row.outcome === "ok" ? "cleanly" : `with outcome ${scan.row.outcome}`} —{" "}
          {scan.row.findings_emitted.toLocaleString()} finding{scan.row.findings_emitted === 1 ? "" : "s"} published
          from {scan.row.devices_assessed.toLocaleString()} device{scan.row.devices_assessed === 1 ? "" : "s"} assessed.
          {scan.row.devices_assessed === 0 && " A scan that assessed no device measured nothing — this is not a clear estate."}
        </p>
      )}

      {st.tenants.length === 0 ? (
        <div className="empty">
          The lane is enabled but has recorded no run yet. Nothing has been assessed — that is different
          from having been assessed and found clean.
        </div>
      ) : (
        <table className="ds-table" aria-label="Security lane, last run per tenant">
          <thead>
            <tr>
              <th scope="col">Tenant</th>
              <th scope="col">Outcome</th>
              <th scope="col">Started by</th>
              <th scope="col">Last run</th>
              <th scope="col">Duration</th>
              <th scope="col">Devices assessed</th>
              <th scope="col">Findings published</th>
            </tr>
          </thead>
          <tbody>
            {st.tenants.map((t) => <TenantRow key={t.tenant_id || t.tenant_seg} row={t} />)}
          </tbody>
        </table>
      )}

      {st.tenants.some((t) => (t.errors?.length ?? 0) > 0) && (
        <div style={{ marginTop: "var(--sp-2)" }}>
          {st.tenants.filter((t) => (t.errors?.length ?? 0) > 0).map((t) => (
            <div key={`err-${t.tenant_id || t.tenant_seg}`} className="mini-meta">
              <b>{t.tenant_seg || t.tenant_id}</b> — the checks below reported UNASSESSED rather than clear:
              <ul>{(t.errors ?? []).map((e, i) => <li key={i}>{e}</li>)}</ul>
            </div>
          ))}
        </div>
      )}

      <table className="ds-table" aria-label="Security lane counters" style={{ marginTop: "var(--sp-2)" }}>
        <thead>
          <tr><th scope="col">Counter</th><th scope="col">Total since start</th></tr>
        </thead>
        <tbody>
          {COUNTERS.map((c) => {
            const v = st.metrics?.[c.key] ?? 0;
            return (
              <tr key={c.key}>
                <th scope="row" style={{ fontWeight: 500, textAlign: "left" }}>{c.label}</th>
                <td style={c.bad && v > 0 ? { color: "var(--bad)" } : undefined}>{v.toLocaleString()}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="mini-meta" style={{ marginBottom: 0 }}>
        Counters are totals for this process since it started, not for the last run. Anything counted on
        the last five rows is evidence that never reached the engine, so a story that would have used it
        was never built.
      </p>
    </Panel>
  );
}
