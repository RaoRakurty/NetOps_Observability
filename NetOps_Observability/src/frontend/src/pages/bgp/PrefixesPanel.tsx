// PrefixesPanel — the Prefixes tab (BGP ops tracker #5).
//
// This IS the watchlist view, extended with the incident class and its
// evidence. There is deliberately NO second prefix list: the class shown here
// and the class that pages someone come from ONE classifier, so the page and
// the pager can never disagree.
//
// Honesty rules the panel enforces:
//   * "not measured" is its own chip and is never green.
//   * a verdict names the vantage points that support it; a near-miss (a class
//     that lacked corroboration) is SHOWN as a shortfall, not hidden.
//   * a LEARNED origin baseline is labelled as learned — it is weaker evidence
//     than a declared one.

import { Chip } from "../../components/noc";
import type { BgpAlert, BgpAlertStatus, BgpIncident, BgpWatchEntry } from "../../services/api";
import { alertStatusLine, incidentSummary, incidentTone, pathLabel } from "./bgpAlerts.model";
import { Section, ShowAll, SubBlock, useCap } from "./Section";

/** Rows shown before the operator asks for the rest (one-page view, 2026-09-03). */
const FIRST_WATCHED = 8;
const FIRST_ALERTS = 8;

const ORDER = ["origin_change", "rpki_invalid", "bogon", "route_leak", "visibility_loss", "unknown", "none"] as const;

export function PrefixesPanel({
  watch, incidents, incidentsNote, status, alerts, onInvestigate, active, updatedAt,
}: {
  watch: BgpWatchEntry[];
  incidents: Record<string, BgpIncident>;
  incidentsNote?: string;
  status?: BgpAlertStatus;
  alerts: BgpAlert[];
  onInvestigate: (resource: string) => void;
  active: string;
  /** When the page last read the watchlist + alert history. */
  updatedAt?: string | number | null;
}) {
  const list = Object.values(incidents);
  const summary = incidentSummary(list);
  const statusLine = alertStatusLine(status);
  const watchCap = useCap(watch, FIRST_WATCHED);
  const alertCap = useCap(alerts, FIRST_ALERTS);

  return (
    <Section id="incidents" title="Incidents — watched prefixes" updatedAt={updatedAt}>
      <SubBlock title="Watched prefixes">

        {incidentsNote && <p className="mini-meta" style={{ color: "var(--warn)" }}>{incidentsNote}</p>}
        {statusLine && <p className="mini-meta" style={{ color: "var(--warn)" }}>{statusLine}</p>}

        {list.length > 0 && (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
            {ORDER.filter((c) => summary[c] > 0).map((c) => {
              const t = incidentTone(c);
              return <Chip key={c} label={`${summary[c]} ${t.label}`} tone={t.tone} title={t.detail} />;
            })}
          </div>
        )}

        {watch.length === 0 && (
          <div className="empty">
            Nothing is watched yet. Investigate a prefix and press “Watch this prefix” — the evaluator classifies what
            this list holds, and nothing else.
          </div>
        )}

        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {watchCap.rows.map((wentry) => {
            const inc = incidents[wentry.resource];
            const t = incidentTone(inc?.class);
            return (
              <div key={wentry.resource} style={{
                display: "flex", flexDirection: "column", gap: 4,
                padding: "8px 10px", borderRadius: 6,
                border: `1px solid ${wentry.resource === active ? "var(--accent)" : "var(--border)"}`,
              }}>
                <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                  <button className="btn-ghost mono" style={{ fontSize: 13, padding: 0 }}
                    onClick={() => onInvestigate(wentry.resource)}>
                    {wentry.resource}
                  </button>
                  {inc ? <Chip label={t.label} tone={t.tone} title={t.detail} />
                       : <Chip label="NOT EVALUATED" tone="var(--muted)" title="The evaluator has not classified this prefix yet — this is not a clean verdict." />}
                  {inc?.also?.map((c) => {
                    const at = incidentTone(c);
                    return <Chip key={c} label={`also ${at.label}`} tone={at.tone} title={at.detail} />;
                  })}
                  {inc?.learned_origin && (
                    <Chip label="learned baseline" tone="var(--muted)"
                      title="No expected origin is declared for this prefix, so the baseline was learned from the first observation. Declare one to make the verdict stronger." />
                  )}
                  {wentry.note && <span className="mini-meta">{wentry.note}</span>}
                  {inc && (
                    <span className="mini-meta" style={{ marginLeft: "auto" }} title="When this class started">
                      since {new Date(inc.since).toLocaleString()}
                    </span>
                  )}
                </div>

                {inc && <p className="mini-meta" style={{ margin: 0 }}>{inc.summary}</p>}
                {inc?.evidence?.detail && (
                  <p className="mini-meta" style={{ margin: 0, color: "var(--muted)" }}>{inc.evidence.detail}</p>
                )}
                {inc?.evidence?.vantages?.length ? (
                  <p className="mini-meta" style={{ margin: 0 }}>
                    Corroborated by {inc.evidence.vantages.length} vantage point(s):{" "}
                    <span className="mono">{inc.evidence.vantages.join(", ")}</span>
                  </p>
                ) : null}
                {inc?.evidence?.paths?.length ? (
                  <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                    {inc.evidence.paths.slice(0, 4).map((p, i) => (
                      <span key={i} className="mono mini-meta">{pathLabel(p)}</span>
                    ))}
                  </div>
                ) : null}
                {inc?.evidence?.peers_total ? (
                  <p className="mini-meta" style={{ margin: 0 }}>
                    Seen by {inc.evidence.peers_seeing} of {inc.evidence.peers_total} route-collector peers.
                  </p>
                ) : null}
                {inc?.corroboration_shortfall && (
                  <p className="mini-meta" style={{ margin: 0, color: "var(--warn)" }}>
                    Observed but NOT asserted: {inc.corroboration_shortfall}.
                  </p>
                )}
                {inc?.error && (
                  <p className="mini-meta" style={{ margin: 0, color: "var(--warn)" }}>{inc.error}</p>
                )}
              </div>
            );
          })}
          <ShowAll cap={watchCap} noun="watched resources" />
        </div>
      </SubBlock>

      <SubBlock title="Alert history">
        {alerts.length === 0 ? (
          <div className="empty">
            {status?.enabled
              ? "No BGP alert has fired for this tenant. The evaluator is running — this is a measured quiet, not an unwatched one."
              : (status?.note || "BGP alerting is off, so nothing has been evaluated.")}
          </div>
        ) : (
          <div className="bgp-scroll">
            <table className="tbl bgp-tbl" style={{ width: "100%" }}>
              <thead>
                <tr><th>When</th><th>Resource</th><th>Class</th><th>Severity</th><th>Summary</th></tr>
              </thead>
              <tbody>
                {alertCap.rows.map((a, i) => {
                  const t = incidentTone(a.class);
                  return (
                    <tr key={`${a.id}-${a.fired_at}-${i}`}>
                      <td className="mini-meta">{new Date(a.resolved_at || a.fired_at).toLocaleString()}</td>
                      <td className="mono">{a.resource}</td>
                      <td>
                        {a.resolved
                          ? <Chip label="CLEARED" tone="var(--ok)" title="The condition no longer holds." />
                          : <Chip label={t.label} tone={t.tone} title={t.detail} />}
                      </td>
                      <td className="mini-meta">{a.severity}</td>
                      <td className="mini-meta">{a.summary}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <ShowAll cap={alertCap} noun="alerts" />
        {status?.enabled && (
          <p className="mini-meta" style={{ marginBottom: 0 }}>
            Evaluated every {status.interval}; a repeat of the same incident is held for {status.cooldown} before it
            pages again (suppressed alerts are counted, not lost).
          </p>
        )}
      </SubBlock>
    </Section>
  );
}

export default PrefixesPanel;
