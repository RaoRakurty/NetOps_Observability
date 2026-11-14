// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ChangeTable — the clickable change drill-down table (tracker 337 N-E3,
// design Part 2 §28), on the shared DataTable (sortable, filterable, keyboard
// operable). Clicking a row opens ChangeDrawer. The Before/After column appears
// only when at least one row carries a before/after pair; the Relation column
// always states "temporal" as "Happened before — not proven cause".
//
// "What changed before every X incident" (N-S3): when every row names the
// incident it was found near, the table is grouped — one section per incident,
// headed by the incident and a link to its root-cause analysis, with a "Before
// onset" column. A row whose kind matches a step of that incident's causal
// chain says so, and still says "not proven cause".
//
// Every cell is escaped text; entity references are safe links.

import { useMemo, useState } from "react";
import DataTable, { type Column } from "../components/DataTable";
import { fmtDateTime, parseTs } from "../lib/time";
import { cellText, highlightFor, rowId, type PresentationPlan, type ResultSet, type Row } from "./presentation";
import { automationText, beforeAfterShort, beforeOnsetText, changeSourceText, isPerIncidentRow, relationText, str } from "./changes";
import { accentForHighlight } from "./IrisTimeline";
import { SafeLink } from "./links";
import ChangeDrawer from "./ChangeDrawer";

type Keyed = { key: string; row: Row };

interface IncidentGroup {
  id: string;
  display: string;
  title: string;
  rows: Keyed[];
}

function textCell(v: unknown) {
  const t = cellText(v);
  return t ?? <span className="iris-muted">Not recorded</span>;
}

export default function ChangeTable({
  rows,
  result,
  plan,
  ariaLabel = "Changes",
}: {
  rows: Row[];
  result?: ResultSet;
  plan?: PresentationPlan;
  ariaLabel?: string;
}) {
  const [open, setOpen] = useState<Row | null>(null);
  const keyed = useMemo<Keyed[]>(() => rows.map((row, i) => ({ key: `${rowId(row, i)}#${i}`, row })), [rows]);
  const anyDiff = useMemo(() => rows.some((r) => r.before !== undefined || r.after !== undefined), [rows]);
  const perIncident = useMemo(() => rows.length > 0 && rows.every(isPerIncidentRow), [rows]);

  // Groups keep the order the server sent (newest change first within the
  // result); an incident appears where its first change does.
  const groups = useMemo<IncidentGroup[]>(() => {
    if (!perIncident) return [];
    const byId = new Map<string, IncidentGroup>();
    const order: IncidentGroup[] = [];
    for (const k of keyed) {
      const id = str(k.row, "incident_id");
      let g = byId.get(id);
      if (!g) {
        g = { id, display: str(k.row, "incident_display_id") || id, title: str(k.row, "incident_title"), rows: [] };
        byId.set(id, g);
        order.push(g);
      }
      g.rows.push(k);
    }
    return order;
  }, [keyed, perIncident]);

  const columns = useMemo<Column<Keyed>[]>(() => {
    const cols: Column<Keyed>[] = [
      {
        key: "time",
        header: "Time",
        width: 170,
        sortable: true,
        sortValue: ({ row }) => parseTs(str(row, "time"))?.getTime() ?? 0,
        text: ({ row }) => str(row, "time"),
        render: ({ row }) => (str(row, "time") ? fmtDateTime(str(row, "time")) : <span className="iris-muted">Not recorded</span>),
      },
    ];
    if (perIncident) {
      cols.push({
        key: "before_onset",
        header: "Before onset",
        width: 150,
        sortable: true,
        sortValue: ({ row }) => (typeof row.minutes_before_incident === "number" ? row.minutes_before_incident : 0),
        text: ({ row }) => beforeOnsetText(row) ?? "",
        render: ({ row }) => beforeOnsetText(row) ?? <span className="iris-muted">Not recorded</span>,
      });
    }
    cols.push(
      { key: "actor", header: "Actor", sortable: true, text: ({ row }) => str(row, "actor"), render: ({ row }) => textCell(row.actor) },
      { key: "source", header: "Source", text: ({ row }) => changeSourceText(row), render: ({ row }) => changeSourceText(row) },
      { key: "type", header: "Change type", sortable: true, text: ({ row }) => str(row, "type"), render: ({ row }) => textCell(row.type) },
      {
        key: "site",
        header: "Site",
        sortable: true,
        text: ({ row }) => str(row, "site"),
        render: ({ row }) =>
          str(row, "site") ? (
            <SafeLink kind="site" id={str(row, "site")}>
              {str(row, "site")}
            </SafeLink>
          ) : (
            <span className="iris-muted">Not recorded</span>
          ),
      },
      { key: "object", header: "Object", sortable: true, text: ({ row }) => str(row, "object"), render: ({ row }) => textCell(row.object) },
    );
    if (anyDiff) {
      cols.push({
        key: "before_after",
        header: "Before / After",
        text: ({ row }) => beforeAfterShort(row) ?? "",
        render: ({ row }) => beforeAfterShort(row) ?? <span className="iris-muted">Not recorded</span>,
      });
    }
    cols.push(
      { key: "ticket", header: "Ticket", text: ({ row }) => str(row, "ticket"), render: ({ row }) => textCell(row.ticket) },
      { key: "automation", header: "Automation / manual", text: ({ row }) => automationText(row), render: ({ row }) => automationText(row) },
      {
        key: "relation",
        header: "Relation",
        width: 260,
        text: ({ row }) => relationText(row),
        render: ({ row }) => {
          const accent = plan ? accentForHighlight(highlightFor(plan, [str(row, "change_id")])) : undefined;
          return (
            <span className={accent ? `iris-accent accent-${accent}` : undefined}>
              {accent === "critical" && "Critical change · "}
              {relationText(row)}
            </span>
          );
        },
      },
    );
    return cols;
  }, [anyDiff, plan, perIncident]);

  if (rows.length === 0) {
    return <p className="iris-empty" role="status">No changes in this window.</p>;
  }

  const height = (n: number) => Math.min(40 + n * 28, 380);

  return (
    <>
      {perIncident ? (
        <div className="iris-incident-groups">
          {groups.map((g) => (
            <section key={g.id} className="iris-incident-group" aria-label={`Changes before ${g.display}`}>
              <h4 className="iris-incident-group-head">
                <SafeLink kind="incident" id={g.id}>
                  {g.display}
                </SafeLink>
                {g.title && <span className="iris-incident-group-title"> {g.title}</span>}
                <span className="iris-muted">
                  {" "}
                  · {g.rows.length} {g.rows.length === 1 ? "change" : "changes"} before it · open the incident for its root-cause analysis
                </span>
              </h4>
              <DataTable<Keyed>
                rows={g.rows}
                columns={columns}
                rowKey={(k) => k.key}
                ariaLabel={`${ariaLabel} before ${g.display}`}
                height={height(g.rows.length)}
                onRowClick={(k) => setOpen(k.row)}
                empty="No changes before this incident."
              />
            </section>
          ))}
        </div>
      ) : (
        <DataTable<Keyed>
          rows={keyed}
          columns={columns}
          rowKey={(k) => k.key}
          ariaLabel={ariaLabel}
          height={height(keyed.length)}
          onRowClick={(k) => setOpen(k.row)}
          empty="No changes in this window."
        />
      )}
      {open && <ChangeDrawer row={open} result={result} onClose={() => setOpen(null)} />}
    </>
  );
}
