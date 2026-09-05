// ExperienceDataHealth.tsx — the Data Health tab.
//
// This is the tab that says whether the other six are worth reading.
//
// `can_confirm` and its explanation are rendered FIRST and largest, because a
// tenant with fewer than two independent kinds of instrument can never reach a
// confirmed verdict, whatever else is true. Discovering that at the bottom of
// an incident, at 03:00, is exactly the failure this panel exists to prevent.
//
// Every state comes from the payload. There is no hard-coded green anywhere in
// this file: "flowing" is a claim the server makes on evidence, and a source
// that is off, stale, refused, misconfigured or unsupported says which of those
// it is, with the sentence explaining it and the amount of confidence its
// current state is costing.

import { api } from "../../services/api";
import type { DemSourceHealth, DemDataHealthResponse, DemWindow } from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { Loading, LoadError, NotMeasured, Panel, pct, reasonText } from "./honest";
import { useDemRead } from "./state";

const STATE_WORDS: Record<string, string> = {
  flowing: "Reporting",
  stale: "Last reported longer ago than its own cadence allows",
  off: "Not configured",
  permission_denied: "Refused — the credential it uses is not permitted",
  misconfigured: "Configured wrongly",
  no_data: "Configured, but produced nothing in this window",
  not_supported: "Cannot be collected in this deployment",
};

export default function ExperienceDataHealth({ window: win }: { window: DemWindow }) {
  const res = useDemRead<DemDataHealthResponse>(() => api.demDataHealth(win), [win]);

  if (res.status === "loading") return <Loading what="the telemetry health" />;
  if (res.status === "error" || !res.data) {
    return <LoadError what="The telemetry health" error={res.error} onRetry={res.reload} />;
  }
  const dh = res.data.data_health;
  const sources = dh?.sources ?? [];

  return (
    <div className="dx-section">
      <Panel title="Can a cause be confirmed?" label="Confirmation capability">
        <p className={dh?.can_confirm ? "dx-note" : "dx-error"} role="note">
          <b style={{ fontSize: "var(--fs-md)" }}>
            {dh?.can_confirm
              ? "Yes — a cause can be confirmed."
              : "No — no cause can be confirmed in this deployment right now."}
          </b>
        </p>
        <p className="dx-note">{dh?.explanation}</p>
        <p className="dx-cap">
          {dh?.anchor_sources_flowing ?? 0} anchor-capable source(s) reporting.
          {" "}Two independent kinds of instrument are the minimum: one instrument agreeing
          with itself is one opinion, however many times it says it.
        </p>
        {!res.data.enabled && (
          <p className="dx-error" role="alert">
            Experience collection is switched off, so these states describe a system that is
            not being asked to produce anything.
          </p>
        )}
      </Panel>

      <Panel title="Sources" label="Experience telemetry sources"
        actions={<span className="dx-chip">{sources.filter((s) => s.state === "flowing").length} of {sources.length} reporting</span>}>
        <div className="dx-src-grid">
          {sources.map((s) => <SourceCard key={s.source} s={s} />)}
        </div>
      </Panel>

      <p className="dx-cap">
        Window {res.data.window} · score policy version {res.data.policy_version}
      </p>
    </div>
  );
}

function SourceCard({ s }: { s: DemSourceHealth }) {
  const influence = Math.round(s.confidence_influence * 100);
  const influenceClass = influence >= 50 ? "dx-meter-fill--crit"
    : influence > 0 ? "dx-meter-fill--warn" : "";
  return (
    <section className={`dx-src dx-src--${s.state}`} aria-label={`${s.label} telemetry source`}>
      <div className="dx-src-head">
        <h3 className="dx-h3">{s.label}</h3>
        <span className="dx-chip">{STATE_WORDS[s.state] ?? s.state}</span>
      </div>

      <p className="dx-cap">{s.detail || reasonText(s.state)}</p>

      <p className="dx-cap">
        Kind of instrument: {s.independence_group.replace(/_/g, " ")}.
        {" "}{s.anchor_capable
          ? "It can anchor a confirmed verdict."
          : "It cannot anchor a confirmed verdict on its own."}
      </p>

      <div>
        <span className="dx-card-label">Coverage</span>
        {s.coverage === undefined ? (
          // Not knowable is stated, never rendered as full coverage.
          <NotMeasured compact reason="not_supported"
            detail="Coverage is not knowable for this source." />
        ) : (
          <>
            <span className="dx-mono"> {pct(s.coverage * 100, 0)} </span>
            <span className="dx-cap">({s.coverage_covered} of {s.coverage_total} subjects)</span>
            <span className="dx-meter" aria-hidden="true">
              <span className="dx-meter-fill" style={{ width: `${Math.min(100, s.coverage * 100)}%` }} />
            </span>
          </>
        )}
      </div>

      <div>
        <span className="dx-card-label">Freshness</span>
        {s.last_seen ? (
          <span className="dx-cap">
            {" "}last reported {fmtDateTime(s.last_seen)}
            {s.freshness_seconds !== undefined ? ` (${s.freshness_seconds}s ago` : ""}
            {s.expected_interval_sec ? `, expected every ${s.expected_interval_sec}s)` : s.freshness_seconds !== undefined ? ")" : ""}
          </span>
        ) : (
          <NotMeasured compact reason={s.configured ? "no_data" : "not_configured"}
            detail="This source has not reported at all, so there is no freshness to state." />
        )}
      </div>

      <p className="dx-cap">
        {s.events_in_window} event{s.events_in_window === 1 ? "" : "s"} in this window
        {s.errors ? ` · ${s.errors} error(s)` : ""}
        {s.lag_seconds !== undefined ? ` · lagging ${s.lag_seconds}s` : ""}
      </p>
      {s.last_error && <p className="dx-cap">Last error: {s.last_error}</p>}

      <div>
        <span className="dx-card-label">Effect on confidence</span>
        <span className="dx-cap">
          {" "}{influence === 0
            ? "not lowering diagnostic confidence"
            : `lowering diagnostic confidence by ${influence}%`}
        </span>
        <span className="dx-meter" aria-hidden="true">
          <span className={`dx-meter-fill ${influenceClass}`} style={{ width: `${influence}%` }} />
        </span>
      </div>
    </section>
  );
}
