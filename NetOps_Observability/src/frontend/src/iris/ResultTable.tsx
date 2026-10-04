// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ResultTable — the generic TABLE view for any ResultSet rows, on the shared
// DataTable. Columns come from the plan's validated `table_columns` when given,
// else from the rows themselves (bounded). A measure the server did not send is
// "Not measured", never 0; any other missing value is "Not recorded". Id fields
// are safe links. Selecting a row opens "Why am I seeing this?" for it.

import { useMemo } from "react";
import DataTable, { type Column } from "../components/DataTable";
import { fmtDateTime, parseTs } from "../lib/time";
import { cellText, fmtNumber, humanize, lookup, MEASURE_FIELDS, rowId, type Row } from "./presentation";
import { SafeLink } from "./links";

const MAX_COLS = 12;
const TIME_FIELDS = new Set(["time", "created_at", "executed_at", "at"]);
const LINK_FIELDS: Record<string, string> = {
  incident_id: "incident",
  change_id: "change",
  device: "device",
  site: "site",
};

type Keyed = { key: string; row: Row };

export function columnsFor(rows: Row[], preferred?: string[]): string[] {
  const present = new Set<string>();
  const order: string[] = [];
  for (const r of rows.slice(0, 50)) {
    for (const k of Object.keys(r)) {
      if (!present.has(k)) {
        present.add(k);
        order.push(k);
      }
    }
  }
  if (preferred && preferred.length > 0) {
    const cols = preferred.filter((c) => present.has(c));
    if (cols.length > 0) return cols.slice(0, MAX_COLS);
  }
  return order.slice(0, MAX_COLS);
}

function renderCell(field: string, v: unknown, unit: string) {
  if (MEASURE_FIELDS.has(field)) {
    const n = fmtNumber(v, field === "count" ? "" : unit);
    return n ?? <span className="iris-muted">Not measured</span>;
  }
  if (TIME_FIELDS.has(field) && typeof v === "string" && parseTs(v)) return fmtDateTime(v);
  const t = cellText(v);
  if (t === null) return <span className="iris-muted">Not recorded</span>;
  const kind = lookup(LINK_FIELDS, field);
  if (kind && typeof v === "string") {
    return (
      <SafeLink kind={kind} id={v}>
        {t}
      </SafeLink>
    );
  }
  return t;
}

export default function ResultTable({
  rows,
  unit = "",
  columns: preferred,
  onRowClick,
  ariaLabel = "Answer rows",
}: {
  rows: Row[];
  unit?: string;
  columns?: string[];
  onRowClick?: (row: Row) => void;
  ariaLabel?: string;
}) {
  const fields = useMemo(() => columnsFor(rows, preferred), [rows, preferred]);
  const keyed = useMemo<Keyed[]>(() => rows.map((row, i) => ({ key: `${rowId(row, i)}#${i}`, row })), [rows]);
  const columns = useMemo<Column<Keyed>[]>(
    () =>
      fields.map((f) => ({
        key: f,
        header: humanize(f),
        sortable: true,
        align: MEASURE_FIELDS.has(f) ? "right" : "left",
        sortValue: ({ row }) => {
          const v = row[f];
          if (typeof v === "number" && Number.isFinite(v)) return v;
          if (TIME_FIELDS.has(f) && typeof v === "string") return parseTs(v)?.getTime() ?? 0;
          // Unmeasured sorts below every measured number, never as 0.
          // (-MAX_VALUE, not -Infinity: DataTable subtracts, and -Inf - -Inf is NaN.)
          if (MEASURE_FIELDS.has(f)) return -Number.MAX_VALUE;
          return cellText(v) ?? "";
        },
        text: ({ row }) => cellText(row[f]) ?? "",
        render: ({ row }) => renderCell(f, row[f], unit),
      })),
    [fields, unit],
  );
  if (rows.length === 0) return <p className="iris-empty" role="status">Nothing found in this window.</p>;
  return (
    <DataTable<Keyed>
      rows={keyed}
      columns={columns}
      rowKey={(k) => k.key}
      ariaLabel={ariaLabel}
      height={Math.min(40 + keyed.length * 28, 380)}
      onRowClick={onRowClick ? (k) => onRowClick(k.row) : undefined}
      empty="Nothing found in this window."
    />
  );
}
