// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// PresentationPlanRenderer — draws one Iris answer from a ResultSet and a
// PresentationPlan (tracker 337 N-E1/N-E3, design §4.1 decision 7).
//
// Contract:
//   · Both inputs are untrusted. The result goes through normalizeResult, the
//     plan through validatePlan (or defaultPlanFor when the server sent none).
//   · The view switch covers the CLOSED enum only. There is no default branch
//     that renders anything the enum does not name; an unknown view has already
//     become SUMMARY, which is escaped text.
//   · Honest states: an empty result says "Nothing found in this window" (never a
//     blank chart); a truncated one says it is partial; every bound the
//     validator tightened is stated.
//   · No dead ends: a chart click opens the rows behind it; a table row opens
//     its detail; every answer has "Why am I seeing this?".
//
// No dangerouslySetInnerHTML anywhere in this tree (§15 LLM02); every link is
// built by links.tsx through safeCiteHref.

import { useCallback, useMemo, useState, type ReactNode } from "react";
import { fmtDateTime } from "../lib/time";
import { ConfigDiffView } from "../components/ConfigDiffView";
import {
  cellText,
  defaultPlanFor,
  entityLabel,
  hasBeforeAfter,
  highlightFor,
  humanize,
  isEmptyResult,
  normalizeResult,
  rowId,
  validatePlan,
  type PresentationPlan,
  type QueryHint,
  type ResultSet,
  type Row,
  type ValidatedPlan,
  type ViewType,
} from "./presentation";
import { changeTitle, str } from "./changes";
import { SafeLink } from "./links";
import IrisTimeline, { accentForHighlight, type TimelineEvent } from "./IrisTimeline";
import ChangeTable from "./ChangeTable";
import ChangeDrawer from "./ChangeDrawer";
import ResultTable from "./ResultTable";
import JsonDiff from "./JsonDiff";
import EvidenceDrawer from "./EvidenceDrawer";
import { BarView, TimeSeriesView, type DrillDown } from "./charts";
import { ChangeCard, IncidentCard, RecommendationCard, incidentEvidence } from "./cards";

/** Views that draw the result's rows/series — these honour the empty state. */
const DATA_VIEWS: ReadonlySet<ViewType> = new Set<ViewType>([
  "TABLE",
  "TIME_SERIES",
  "TIMELINE",
  "BAR",
  "DIFF",
  "EVIDENCE_LIST",
  "CHANGE_CARD",
  "TOPOLOGY",
  "PATH",
]);

function unreachable(v: never): null {
  void v;
  return null;
}

function isChangeRow(r: Row): boolean {
  return typeof r.change_id === "string";
}

export function timelineEvents(result: ResultSet, plan: PresentationPlan): TimelineEvent[] {
  return result.rows.map((r, i) => {
    const id = rowId(r, i);
    if (isChangeRow(r)) {
      return {
        id,
        ts: str(r, "time"),
        label: changeTitle(r),
        detail: str(r, "actor") || undefined,
        accent: accentForHighlight(highlightFor(plan, [str(r, "change_id")])),
        link: { kind: "change", id: str(r, "change_id") },
      };
    }
    const incident = str(r, "incident_id");
    const title = [str(r, "display_id"), str(r, "title")].filter(Boolean).join(" · ") || entityLabel(r);
    return {
      id,
      ts: str(r, "created_at") || str(r, "time"),
      label: title,
      detail: cellText(r.state) ?? undefined,
      accent: accentForHighlight(highlightFor(plan, [incident, id])),
      link: incident ? { kind: "incident", id: incident } : undefined,
    };
  });
}

function windowText(r: ResultSet): string {
  if (!r.window.from && !r.window.to) return "";
  return `${fmtDateTime(r.window.from)} → ${fmtDateTime(r.window.to)}`;
}

function SummaryView({ result, plan }: { result: ResultSet; plan: ValidatedPlan }) {
  const n = result.rows.length;
  const s = result.series.length;
  return (
    <div className="iris-summary">
      {plan.fallback === "unknown_view" && (
        <p className="iris-notice" role="status">
          This answer is shown as a plain summary because its layout was not recognised.
        </p>
      )}
      <p className="iris-text">
        {n > 0 && `${n} row${n === 1 ? "" : "s"} found`}
        {n > 0 && s > 0 && " · "}
        {s > 0 && `${s} series found`}
        {n === 0 && s === 0 && "Nothing found in this window."}
      </p>
    </div>
  );
}

function NoGraph({ what, result }: { what: string; result: ResultSet }) {
  const ents = result.provenance.entities;
  return (
    <div className="iris-summary">
      <p className="iris-note">A {what} is not available for this answer. The entities it covers:</p>
      {ents.length === 0 ? (
        <p className="iris-muted">None named.</p>
      ) : (
        <ul className="iris-inline-list">
          {ents.map((e, i) => (
            <li key={`${e.type}-${e.id}-${i}`}>
              {humanize(e.type)}:{" "}
              <SafeLink kind={e.type} id={e.id}>
                {e.id}
              </SafeLink>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function PresentationPlanRenderer({
  result: rawResult,
  plan: rawPlan,
  hint,
  onDrill,
}: {
  /** The server's ResultSet — untrusted. */
  result: unknown;
  /** The server's PresentationPlan — untrusted; omitted → chosen from the result. */
  plan?: unknown;
  hint?: QueryHint;
  /** Told whenever the operator drills into a chart (the renderer also shows the rows). */
  onDrill?: (d: DrillDown) => void;
}) {
  const norm = useMemo(() => normalizeResult(rawResult), [rawResult]);
  const plan = useMemo<ValidatedPlan | null>(() => {
    if (!norm.ok) return null;
    return rawPlan === undefined ? defaultPlanFor(norm.result, hint) : validatePlan(rawPlan);
  }, [norm, rawPlan, hint]);
  const [drill, setDrill] = useState<DrillDown | null>(null);
  const [evidence, setEvidence] = useState<{ row?: Row } | null>(null);
  const [openChange, setOpenChange] = useState<Row | null>(null);

  const handleDrill = useCallback(
    (d: DrillDown) => {
      setDrill(d);
      onDrill?.(d);
    },
    [onDrill],
  );

  if (!norm.ok || !plan) {
    return (
      <section className="iris-answer" aria-label="Answer">
        <p className="iris-notice" role="alert">
          {norm.ok ? "This answer could not be displayed." : norm.reason}
        </p>
      </section>
    );
  }
  const result = norm.result;
  const empty = isEmptyResult(result);
  const groupField = hint?.group_by?.[0];

  const renderView = (view: ViewType): ReactNode => {
    if (empty && DATA_VIEWS.has(view)) return null;
    switch (view) {
      case "SUMMARY":
        return <SummaryView result={result} plan={plan} />;
      case "TABLE":
        return result.rows.some(isChangeRow) ? (
          <ChangeTable rows={result.rows} result={result} plan={plan} />
        ) : (
          <ResultTable rows={result.rows} unit={result.unit} columns={plan.table_columns} onRowClick={(row) => setEvidence({ row })} />
        );
      case "TIME_SERIES":
        return <TimeSeriesView result={result} onDrill={handleDrill} />;
      case "TIMELINE":
        return (
          <IrisTimeline
            events={timelineEvents(result, plan)}
            ariaLabel={plan.title}
            onSelect={
              result.rows.some(isChangeRow)
                ? (e) => {
                    const row = result.rows.find((r, i) => rowId(r, i) === e.id);
                    if (row) setOpenChange(row);
                  }
                : undefined
            }
          />
        );
      case "BAR":
        return <BarView result={result} groupField={groupField} onDrill={handleDrill} />;
      case "TOPOLOGY":
        return <NoGraph what="network map" result={result} />;
      case "PATH":
        return <NoGraph what="path view" result={result} />;
      case "DIFF": {
        const row = result.rows.find((r) => hasBeforeAfter(r) || typeof r.unified === "string");
        if (!row) return <p className="iris-note">No before/after was recorded for this change.</p>;
        if (typeof row.unified === "string") {
          return (
            <ConfigDiffView
              title={changeTitle(row)}
              diff={{
                unified: row.unified,
                added: typeof row.added === "number" ? row.added : NaN,
                removed: typeof row.removed === "number" ? row.removed : NaN,
                truncated: row.truncated === true,
              }}
            />
          );
        }
        return <JsonDiff before={row.before} after={row.after} title={changeTitle(row)} />;
      }
      case "EVIDENCE_LIST": {
        if (result.query_type === "incident_explain") {
          const ev = incidentEvidence(result.detail);
          if (ev.known.length === 0 && ev.missing.length === 0) {
            return <p className="iris-empty">No evidence lines recorded for this incident.</p>;
          }
          return (
            <div className="iris-evidence">
              {ev.known.length > 0 && (
                <>
                  <h4 className="iris-h4">Evidence found</h4>
                  <ul className="iris-plain-list">
                    {ev.known.map((k, i) => (
                      <li key={i}>{k}</li>
                    ))}
                  </ul>
                </>
              )}
              {ev.missing.length > 0 && (
                <>
                  <h4 className="iris-h4">Evidence still needed</h4>
                  <ul className="iris-plain-list">
                    {ev.missing.map((k, i) => (
                      <li key={i}>{k}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          );
        }
        return (
          <ul className="iris-evidence-list">
            {result.rows.slice(0, 50).map((r, i) => (
              <li key={`${rowId(r, i)}#${i}`}>
                <span>{isChangeRow(r) ? changeTitle(r) : entityLabel(r)}</span>
                <button type="button" className="iris-linkbtn" onClick={() => setEvidence({ row: r })}>
                  Why am I seeing this?
                </button>
              </li>
            ))}
          </ul>
        );
      }
      case "INCIDENT_CARD":
        return <IncidentCard row={result.rows[0]} detail={result.detail} />;
      case "CHANGE_CARD": {
        const row = result.rows[0];
        return <ChangeCard row={row} critical={row ? highlightFor(plan, [str(row, "change_id")]) === "critical_change" : false} />;
      }
      case "RECOMMENDATION_CARD":
        return <RecommendationCard recommendation={result.detail} />;
      default:
        // Unreachable: validatePlan only yields enum members. The `never` makes a
        // new enum member a compile error here instead of a silent blank.
        return unreachable(view);
    }
  };

  const wtext = windowText(result);
  return (
    <section className="iris-answer" aria-label={plan.title}>
      <header className="iris-answer-head">
        <h3 className="iris-title">{plan.title}</h3>
        {wtext && <span className="iris-muted">{wtext}</span>}
      </header>

      {result.truncated && (
        <p className="iris-notice" role="status">
          Partial answer — more matched than could be shown. Narrow the time window or add a filter to see everything.
        </p>
      )}
      {result.constraints_applied.length > 0 && (
        <ul className="iris-notes" aria-label="Adjustments">
          {result.constraints_applied.map((c, i) => (
            <li key={i}>
              Adjusted {humanize(c.path) || "a limit"} from {c.from || "none"} to {c.to || "none"}
              {c.reason && ` — ${c.reason}`}
            </li>
          ))}
        </ul>
      )}
      {result.notes.length > 0 && (
        <ul className="iris-notes" aria-label="Notes">
          {result.notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      )}

      {empty && DATA_VIEWS.has(plan.primary_view) ? (
        <p className="iris-empty" role="status">
          Nothing found in this window{wtext ? ` (${wtext})` : ""}.
        </p>
      ) : drill ? (
        <div className="iris-drill">
          <div className="iris-drill-head">
            <span>
              {drill.rows.length} row{drill.rows.length === 1 ? "" : "s"} for <b>{drill.label}</b>
            </span>
            <button type="button" className="iris-linkbtn" onClick={() => setDrill(null)}>
              Back to the chart
            </button>
          </div>
          {drill.rows.some(isChangeRow) ? (
            <ChangeTable rows={drill.rows} result={result} plan={plan} ariaLabel={`Rows for ${drill.label}`} />
          ) : (
            <ResultTable rows={drill.rows} unit={result.unit} ariaLabel={`Rows for ${drill.label}`} onRowClick={(row) => setEvidence({ row })} />
          )}
        </div>
      ) : (
        <>
          <div className="iris-view">{renderView(plan.primary_view)}</div>
          {plan.secondary_view && !(empty && DATA_VIEWS.has(plan.secondary_view)) && (
            <div className="iris-view iris-view-secondary">{renderView(plan.secondary_view)}</div>
          )}
        </>
      )}

      <footer className="iris-answer-foot">
        <button type="button" className="iris-linkbtn" onClick={() => setEvidence({})}>
          Why am I seeing this?
        </button>
      </footer>

      {evidence && <EvidenceDrawer result={result} row={evidence.row} onClose={() => setEvidence(null)} />}
      {openChange && <ChangeDrawer row={openChange} result={result} onClose={() => setOpenChange(null)} />}
    </section>
  );
}
