// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// FilterSection — one collapsible filter group: a header with its chevron on
// the LEFT, then rows of checkbox + label + a quiet right-aligned count. The
// only coloured things are the checked boxes and the optional action link
// ("Clear"), both in the accent. docs/design/visual-language.md › Components.

import { useId, useState } from "react";
import Icon from "../Icon";
import "./kit.css";

export interface FilterOption {
  value: string;
  label: string;
  count?: number;
}

export interface FilterSectionProps {
  title: string;
  options: FilterOption[];
  /** The checked values. */
  selected: ReadonlySet<string>;
  onToggle: (value: string, checked: boolean) => void;
  defaultOpen?: boolean;
  /** An optional accent link in the header (e.g. "Clear"). */
  action?: { label: string; onClick: () => void };
}

export default function FilterSection({ title, options, selected, onToggle, defaultOpen = true, action }: FilterSectionProps) {
  const [open, setOpen] = useState(defaultOpen);
  const bodyId = useId();
  return (
    <section className="kit-fs" aria-label={title}>
      <div style={{ display: "flex", alignItems: "center" }}>
        <button type="button" className="kit-fs-head" aria-expanded={open} aria-controls={bodyId} onClick={() => setOpen((o) => !o)}>
          <Icon name="chevron-down" size={14} />
          <span>{title}</span>
        </button>
        {action && <button type="button" className="kit-fs-action" onClick={action.onClick}>{action.label}</button>}
      </div>
      <div id={bodyId} hidden={!open}>
        {options.map((o) => (
          <label key={o.value} className="kit-fs-row">
            <input type="checkbox" checked={selected.has(o.value)} onChange={(e) => onToggle(o.value, e.target.checked)} />
            <span className="kit-fs-label">{o.label}</span>
            {o.count !== undefined && <span className="kit-fs-count">{o.count}</span>}
          </label>
        ))}
      </div>
    </section>
  );
}
