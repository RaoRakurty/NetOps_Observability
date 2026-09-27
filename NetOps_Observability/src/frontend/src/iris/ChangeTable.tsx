// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ChangeTable — the clickable change drill-down table (tracker 337 N-E3,
// design Part 2 §28), on the shared DataTable (sortable, filterable, keyboard
// operable). Clicking a row opens ChangeDrawer. The Before/After column appears
// only when at least one row carries a before/after pair; the Relation column
// always states "temporal" as "Happened before — not proven cause".
//
// Every cell is escaped text; entity references are safe links.

import { useMemo, useState } from "react";
import DataTable, { type Column } from "../components/DataTable";
import { fmtDateTime, parseTs } from "../lib/time";
import { cellText, highlightFor, rowId, type PresentationPlan, type ResultSet, type Row } from "./presentation";
import { automationText, beforeAfterShort, changeSourceText, relationText, str } from "./changes";
import { accentForHighlight } from "./IrisTimeline";
import { SafeLink } from "./links";
import ChangeDrawer from "./ChangeDrawer";

type Keyed = { key: string; row: Row };

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
    ];
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
        width: 240,
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
  }, [anyDiff, plan]);

  if (rows.length === 0) {
    return <p className="iris-empty" role="status">No changes in this window.</p>;
  }

  return (
    <>
      <DataTable<Keyed>
        rows={keyed}
        columns={columns}
        rowKey={(k) => k.key}
        ariaLabel={ariaLabel}
        height={Math.min(40 + keyed.length * 28, 380)}
        onRowClick={(k) => setOpen(k.row)}
        empty="No changes in this window."
      />
      {open && <ChangeDrawer row={open} result={result} onClose={() => setOpen(null)} />}
    </>
  );
}
