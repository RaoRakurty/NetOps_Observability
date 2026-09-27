// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// FilterChipBar — the editable filters of an answer (tracker 337 N-E3 / N-C7,
// design Part 2 §34). Each chip is one AST filter the server resolved. A chip
// can be REMOVED, or CHANGED to another value from the closed list the server
// offered — there is no free-text box, so an edit can only ever produce a value
// the catalog already knows. The bar emits a typed change event; the caller
// regenerates the AST deterministically from it (no model in the loop).
//
// Chip text is untrusted and rendered as escaped React text.

import { useId, useState } from "react";
import { clip, isFieldName } from "./presentation";

export interface ChipOption {
  value: string;
  label: string;
}

export interface FilterChip {
  id: string;
  /** Catalog field name, e.g. "site". */
  field: string;
  /** What the field is called for the operator, e.g. "Site". */
  label: string;
  value: string;
  valueLabel?: string;
  /** Values this chip may be changed to. Absent/empty → not editable. */
  options?: ChipOption[];
  /** Default true. A required filter (e.g. the time window) is not removable. */
  removable?: boolean;
}

export type FilterChipChange =
  | { kind: "remove"; id: string; field: string }
  | { kind: "set"; id: string; field: string; value: string };

const MAX_CHIPS = 12;
const MAX_OPTIONS = 50;

/** Keep only chips that are well-formed; bound lengths and counts. */
export function sanitizeChips(chips: unknown): FilterChip[] {
  if (!Array.isArray(chips)) return [];
  const out: FilterChip[] = [];
  const seen = new Set<string>();
  for (const c of chips) {
    if (out.length >= MAX_CHIPS) break;
    if (typeof c !== "object" || c === null) continue;
    const o = c as Record<string, unknown>;
    if (typeof o.id !== "string" || o.id === "" || seen.has(o.id)) continue;
    if (!isFieldName(o.field)) continue;
    if (typeof o.value !== "string") continue;
    const options: ChipOption[] = Array.isArray(o.options)
      ? (o.options as unknown[])
          .filter((x): x is ChipOption => typeof x === "object" && x !== null && typeof (x as ChipOption).value === "string" && typeof (x as ChipOption).label === "string")
          .slice(0, MAX_OPTIONS)
          .map((x) => ({ value: clip(x.value, 128), label: clip(x.label, 80) }))
      : [];
    seen.add(o.id);
    out.push({
      id: clip(o.id, 64),
      field: o.field,
      label: typeof o.label === "string" && o.label.trim() ? clip(o.label, 40) : o.field,
      value: clip(o.value, 128),
      valueLabel: typeof o.valueLabel === "string" ? clip(o.valueLabel, 80) : undefined,
      options,
      removable: o.removable !== false,
    });
  }
  return out;
}

function Chip({ chip, onChange }: { chip: FilterChip; onChange: (e: FilterChipChange) => void }) {
  const [editing, setEditing] = useState(false);
  const selectId = useId();
  const options = chip.options ?? [];
  const shown = chip.valueLabel || options.find((o) => o.value === chip.value)?.label || chip.value;
  return (
    <li className="iris-chip">
      <span className="iris-chip-k">{chip.label}:</span>
      {editing ? (
        <>
          <label className="sr-only" htmlFor={selectId}>
            Change {chip.label}
          </label>
          <select
            id={selectId}
            className="iris-chip-select"
            value={chip.value}
            autoFocus
            onChange={(e) => {
              const v = e.target.value;
              setEditing(false);
              // Closed list: only a value the server offered can be emitted.
              if (v !== chip.value && options.some((o) => o.value === v)) {
                onChange({ kind: "set", id: chip.id, field: chip.field, value: v });
              }
            }}
            onBlur={() => setEditing(false)}
            onKeyDown={(e) => {
              if (e.key === "Escape") setEditing(false);
            }}
          >
            {!options.some((o) => o.value === chip.value) && <option value={chip.value}>{shown}</option>}
            {options.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </>
      ) : options.length > 0 ? (
        <button type="button" className="iris-chip-v" onClick={() => setEditing(true)} aria-label={`${chip.label}: ${shown}. Change`}>
          {shown}
        </button>
      ) : (
        <span className="iris-chip-v">{shown}</span>
      )}
      {chip.removable !== false && (
        <button
          type="button"
          className="iris-chip-x"
          aria-label={`Remove ${chip.label} filter`}
          onClick={() => onChange({ kind: "remove", id: chip.id, field: chip.field })}
        >
          ×
        </button>
      )}
    </li>
  );
}

export default function FilterChipBar({
  chips,
  onChange,
}: {
  chips: unknown;
  onChange: (e: FilterChipChange) => void;
}) {
  const safe = sanitizeChips(chips);
  if (safe.length === 0) return null;
  return (
    <ul className="iris-chips" aria-label="Filters on this answer">
      {safe.map((c) => (
        <Chip key={c.id} chip={c} onChange={onChange} />
      ))}
    </ul>
  );
}
