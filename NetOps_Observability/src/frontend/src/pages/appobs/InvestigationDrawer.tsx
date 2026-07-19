// InvestigationDrawer (#7 Wave 2) — the correlation object embedded INSIDE
// Service View: the full RCA Inspector componentry (CorrelationDetail — reused,
// not re-implemented) topped by the close/verification loop. Everything shown is
// real, tenant-scoped engine data:
//   - the recovery verification state comes from the canonical RCA report JSON
//     (the same RecoveryReconciler output the PDF renders from) — never derived
//     client-side from row colors;
//   - a manual close is recorded through the audited time-events endpoint: the
//     server stamps WHO from the token and labels the verification state; an
//     override (closing while the signal is present / recovery unobserved) is
//     explicit and labeled, never silent;
//   - when recovery is not observable we say exactly that — never "verified".

import { useEffect, useMemo, useState } from "react";
import { api, RcaReportJson, TimeEventRow } from "../../services/api";
import { CorrelationDetail } from "../../tabs/Correlations";
import { friendlyProblemId } from "../../components/rca/labels";
import ResolutionActions from "./ResolutionActions";
import InvestigationChanges from "./InvestigationChanges";
import CostContext from "./CostContext";

// ── recovery-verification derivation (pure — unit-tested) ────────────────────

export type VerifyKind =
  | "verified_clear"     // incident-level recovery gate passed
  | "component_only"     // component recovered; end-to-end not confirmed
  | "signal_present"     // recovery validation failed — anomalies continued
  | "inferred"           // recovery inferred, not confirmed by evidence
  | "not_observable"     // no recovery evidence captured
  | "unavailable";       // report could not be loaded — say so, never imply clear

export interface VerifyState {
  kind: VerifyKind;
  basis: string;          // the engine's own sentence for WHY (never invented)
  clearSince?: Date;      // verified_clear only: when the signal went clear
  monitoringUntil?: Date; // stability window end, when the engine set one
  monitoring?: string;    // not_started | active | completed
  engineClosed: boolean;  // the engine itself already closed the object
}

// report times render as "2006-01-02 15:04:05 UTC" (fmtUTC) — parse safely.
export function parseReportTime(s?: string): Date | undefined {
  if (!s) return undefined;
  const d = new Date(s.replace(" UTC", "").replace(" ", "T") + "Z");
  return Number.isNaN(d.getTime()) ? undefined : d;
}

export function deriveVerify(rep: RcaReportJson | null): VerifyState {
  if (!rep || !rep.states) {
    return {
      kind: "unavailable", engineClosed: false,
      basis: "The recovery assessment could not be loaded for this investigation.",
    };
  }
  const st = rep.states;
  const times = rep.times ?? {};
  const engineClosed = st.lifecycle === "closed" || st.incident === "closed";
  const basis = st.recovery_basis || "";
  switch (st.recovery) {
    case "explicitly_confirmed":
      return {
        kind: "verified_clear", basis, engineClosed,
        clearSince: parseReportTime(times.recovered_at),
        monitoringUntil: parseReportTime(times.monitoring_until),
        monitoring: st.monitoring,
      };
    case "component_only":
      return { kind: "component_only", basis, engineClosed };
    case "failed_validation":
      return { kind: "signal_present", basis, engineClosed };
    case "inferred":
      return { kind: "inferred", basis, engineClosed };
    default:
      return {
        kind: "not_observable", engineClosed,
        basis: basis || "No recovery evidence has been captured for this investigation yet.",
      };
  }
}

// the allowlisted verification value a close records for each observed state —
// anything short of verified-clear is an EXPLICIT override (server-labeled).
export const CLOSE_VERIFICATION: Record<Exclude<VerifyKind, "verified_clear">, string> = {
  component_only: "override_partial_recovery",
  signal_present: "override_signal_present",
  inferred: "override_recovery_unobserved",
  not_observable: "override_recovery_unobserved",
  unavailable: "override_recovery_unobserved",
};

export function fmtClearFor(clearSince: Date, now: Date): string {
  const min = Math.max(0, Math.floor((now.getTime() - clearSince.getTime()) / 60000));
  if (min < 60) return `${min} min`;
  return `${Math.floor(min / 60)} h ${min % 60} min`;
}

// ── the verification / close panel ───────────────────────────────────────────

const KIND_TITLE: Record<VerifyKind, string> = {
  verified_clear: "Recovered — signal verified clear",
  component_only: "Partially recovered",
  signal_present: "Signal still present",
  inferred: "Recovery inferred — not confirmed",
  not_observable: "Recovery not yet observable",
  unavailable: "Recovery status unavailable",
};
const KIND_TONE: Record<VerifyKind, string> = {
  verified_clear: "ok", component_only: "warn", signal_present: "crit",
  inferred: "warn", not_observable: "muted", unavailable: "muted",
};

export function InvestigationVerification({ id }: { id: string }) {
  const [rep, setRep] = useState<RcaReportJson | null>(null);
  const [repLoaded, setRepLoaded] = useState(false);
  const [events, setEvents] = useState<TimeEventRow[]>([]);
  const [override, setOverride] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [now, setNow] = useState(() => new Date());
  const [tick, setTick] = useState(0);

  // live loop: the "signal clear for N min" progress is real elapsed time over
  // real recovery evidence — refresh both every 30 s while the drawer is open.
  useEffect(() => {
    const t = setInterval(() => { setNow(new Date()); setTick((n) => n + 1); }, 30_000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    let alive = true;
    api.rcaReportJson(id)
      .then((r) => { if (alive) { setRep(r); setRepLoaded(true); } })
      .catch(() => { if (alive) { setRep(null); setRepLoaded(true); } });
    api.correlationTimeEvents(id)
      .then((r) => { if (alive) setEvents(r?.events ?? []); })
      .catch(() => { /* read-back is best-effort; the panel still renders */ });
    return () => { alive = false; };
  }, [id, tick]);

  const v = useMemo(() => deriveVerify(rep), [rep]);
  const closedEvent = useMemo(
    () => [...events].reverse().find((e) => e.event_type === "closed"),
    [events],
  );

  const close = async () => {
    setBusy(true); setErr("");
    const verification = v.kind === "verified_clear"
      ? "verified_clear"
      : CLOSE_VERIFICATION[v.kind];
    try {
      const ev = await api.correlationTimeEventSet(id, {
        event_type: "closed",
        event_time: new Date().toISOString(),
        verification,
      });
      setEvents((prev) => [...prev.filter((e) => e.event_type !== "closed"), ev]);
    } catch (e) {
      setErr(String((e as Error)?.message ?? e));
    } finally {
      setBusy(false);
    }
  };

  if (!repLoaded) return <div className="inv-verify inv-verify--muted">Checking recovery status…</div>;

  const needsOverride = v.kind !== "verified_clear";
  return (
    <div className={`inv-verify inv-verify--${KIND_TONE[v.kind]}`}>
      {/* recovery banner / honest state */}
      <div className="inv-verify-h" role={v.kind === "verified_clear" ? "status" : undefined}>
        <strong>{KIND_TITLE[v.kind]}</strong>
        {v.kind === "verified_clear" && v.clearSince && (
          <span className="inv-verify-clearfor">signal clear for {fmtClearFor(v.clearSince, now)}</span>
        )}
      </div>
      {v.basis && <div className="inv-verify-basis">{v.basis}</div>}
      {v.kind === "verified_clear" && v.monitoring === "active" && v.monitoringUntil && v.clearSince && (
        <StabilityProgress from={v.clearSince} until={v.monitoringUntil} now={now} />
      )}
      {v.kind === "verified_clear" && v.monitoring === "completed" && (
        <div className="inv-verify-basis">Post-recovery stability window complete.</div>
      )}

      {/* close state / action */}
      {closedEvent ? (
        <div className="inv-verify-closed">
          Closed by <strong>{closedEvent.created_by}</strong>
          {" "}at {new Date(closedEvent.event_time).toLocaleString()}
          {closedEvent.note && <div className="inv-verify-note">{closedEvent.note}</div>}
        </div>
      ) : v.engineClosed ? (
        <div className="inv-verify-closed">This investigation is already closed.</div>
      ) : (
        <div className="inv-verify-close">
          {needsOverride && (
            <label className="inv-verify-override">
              <input type="checkbox" checked={override}
                onChange={(e) => setOverride(e.target.checked)} />
              Close anyway — recovery is not verified. This is recorded as an explicit override.
            </label>
          )}
          <button className="ao-btn ao-btn--primary" disabled={busy || (needsOverride && !override)}
            onClick={close}>
            {busy ? "Recording…" : needsOverride ? "Close with override" : "Close investigation — verified clear"}
          </button>
          {err && <div className="inv-verify-err">{err}</div>}
        </div>
      )}
    </div>
  );
}

function StabilityProgress({ from, until, now }: { from: Date; until: Date; now: Date }) {
  const total = Math.max(1, until.getTime() - from.getTime());
  const pct = Math.min(100, Math.max(0, Math.round(((now.getTime() - from.getTime()) / total) * 100)));
  const totalMin = Math.round(total / 60000);
  return (
    <div className="inv-verify-progress" title={`stability window: ${totalMin} min`}>
      <div className="inv-verify-bar" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
        <div className="inv-verify-fill" style={{ width: `${pct}%` }} />
      </div>
      <span className="inv-verify-pct">stability window {pct}% ({totalMin} min)</span>
    </div>
  );
}

// ── the drawer content ────────────────────────────────────────────────────────

export default function InvestigationDrawer({ id }: { id: string }) {
  return (
    <div className="inv-drawer">
      <div className="inv-drawer-top">
        <span className="inv-drawer-id" title={id}>{friendlyProblemId(id)}</span>
        {/* deep work still has its page — the drawer never traps the analysis */}
        <a className="ao-rowaction" href={`#/monitoring/correlations?id=${encodeURIComponent(id)}`}>
          Open full analysis
        </a>
      </div>
      <InvestigationVerification id={id} />
      <ResolutionActions id={id} />
      <InvestigationChanges id={id} />
      <CostContext id={id} />
      <CorrelationDetail id={id} />
    </div>
  );
}
