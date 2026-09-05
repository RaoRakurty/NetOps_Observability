// incidentTable.tsx — the Active Experience Incidents table.
//
// The owner's column set, in the owner's order: Severity · Incident ·
// Journey/App · Impact · Business impact · Likely layer · Leading cause ·
// Confidence · Owner · Duration. Shared by the Experience overview and the
// Incidents tab so the two can never show a different incident differently.
//
// Three columns are honest-by-construction:
//   - Impact renders `impact_not_measured` when the server could not measure a
//     dimension, instead of a 0% that reads as "nothing was affected".
//   - Business impact is absent unless a value per success was declared. There
//     is no default currency and no zero.
//   - Owner is blank-with-a-sentence when no owner was determined; it never
//     falls back to a default team, which would send the wrong shift a page.
//
// CONFIDENCE IS DECOMPOSED IN THE ROW. The server carries the leading
// hypothesis's `confidence_factors` and, when the verdict is not confirmed, its
// `gate_reasons` on the LIST row as well as on the incident. So the table shows
// the same breakdown the incident view does: a number an operator cannot take
// apart is one they can only take on trust, and "not confirmed" with no reason
// teaches them to stop reading the distinction at all.

import type { DemIncidentSummary } from "../../services/api";
import { ownerLabel } from "../../components/rca/labels";
import {
  ConfidenceChip, Money, NotMeasured, SeverityChip, fmtDuration, pct,
} from "./honest";

export function IncidentTable({ rows, onOpen, caption }: {
  rows: DemIncidentSummary[];
  onOpen: (id: string) => void;
  caption?: string;
}) {
  if (rows.length === 0) {
    return (
      <p className="dx-note">
        No experience incident is open in this window. That is a real result only if the
        telemetry behind it is flowing — the Data Health tab says whether it is.
      </p>
    );
  }
  return (
    <div className="dx-scroll">
      <table className="dx-table">
        {caption && <caption className="dx-cap" style={{ captionSide: "bottom", textAlign: "left" }}>{caption}</caption>}
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Incident</th>
            <th scope="col">Journey / App</th>
            <th scope="col">Impact</th>
            <th scope="col">Business impact</th>
            <th scope="col">Likely layer</th>
            <th scope="col">Leading cause</th>
            <th scope="col">Confidence</th>
            <th scope="col">Owner</th>
            <th scope="col">Duration</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td><SeverityChip severity={r.severity} /></td>
              <td>
                <button type="button" className="dx-row-btn" onClick={() => onOpen(r.id)}>
                  {r.title}
                </button>
                <div className="dx-cap">{r.status}</div>
              </td>
              <td>
                {r.journey || r.app
                  ? <>{r.journey || "—"}{r.app ? <div className="dx-cap">{r.app}</div> : null}</>
                  : <span className="dx-subtle">Not attributed to a declared journey</span>}
              </td>
              <td>
                {r.journey_success_pct !== undefined
                  ? <span className="dx-mono">{pct(r.journey_success_pct)} succeeded</span>
                  : <NotMeasured compact reason="no_samples"
                      detail={(r.impact_not_measured ?? []).join("; ")} />}
                {r.impact_not_measured && r.impact_not_measured.length > 0 && (
                  <div className="dx-cap">Not measured: {r.impact_not_measured.join(", ")}</div>
                )}
              </td>
              <td><Money value={r.business_impact} currency={r.currency} /></td>
              <td>{r.likely_layer || <span className="dx-subtle">Not placed on the path</span>}</td>
              <td>
                {r.leading_cause
                  ? <span>{r.leading_cause}</span>
                  : <span className="dx-subtle">No cause has enough evidence yet</span>}
              </td>
              <td>
                <ConfidenceChip confidence={r.confidence} tier={r.verdict_tier}
                  factors={r.confidence_factors} gateReasons={r.gate_reasons} />
                <div className="dx-cap">
                  {r.evidence_count} supporting · {r.contradiction_count} contradicting ·
                  {" "}{r.missing_evidence_count} missing
                </div>
              </td>
              <td>
                {r.owner
                  ? ownerLabel(r.owner) || r.owner
                  : <span className="dx-subtle">Owner not determined</span>}
                {r.seam && <div className="dx-cap">{r.seam}</div>}
              </td>
              <td className="dx-mono">{fmtDuration(r.duration_sec) || <span className="dx-subtle">Not timed</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
