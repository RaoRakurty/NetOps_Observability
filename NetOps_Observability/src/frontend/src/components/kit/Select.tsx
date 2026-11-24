// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// The dropdown family — both are the app's native <select> (keyboard, screen
// reader and mobile pickers for free), dressed per the visual language:
//
//   PillSelect   compact, neutral, outlined: "Health ⌄", "Site ⌄" in a toolbar.
//   FieldSelect  full width, borderless until hovered: "All sites ⌄" in a panel.
//
// Neither is ever coloured: a dropdown is a control, not a state.

import Icon from "../Icon";
import "./kit.css";

export interface SelectOption {
  value: string;
  label: string;
}

interface BaseProps {
  /** Accessible name (also the visible lead word on a pill when `lead` is unset). */
  label: string;
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  /** A leading glyph from Icon.tsx. */
  icon?: string;
  id?: string;
  testId?: string;
}

export interface PillSelectProps extends BaseProps {
  /** A muted word before the value ("Health"); omit to show only the value. */
  lead?: string;
}

export function PillSelect({ label, value, options, onChange, icon, lead, id, testId }: PillSelectProps) {
  return (
    <label className="kit-select kit-pill" data-testid={testId}>
      {icon && <Icon name={icon} size={15} />}
      {lead && <span className="kit-lead">{lead}</span>}
      <select id={id} aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <Icon name="chevron-down" size={14} className="kit-chev" />
    </label>
  );
}

export function FieldSelect({ label, value, options, onChange, icon, id, testId }: BaseProps) {
  return (
    <label className="kit-select kit-field" data-testid={testId}>
      {icon && <Icon name={icon} size={16} />}
      <select id={id} aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
      <Icon name="chevron-down" size={14} className="kit-chev" />
    </label>
  );
}

/** "Sort by ⇅" — the quiet label in front of a sort PillSelect. */
export function SortLabel({ children = "Sort by" }: { children?: string }) {
  return <span className="kit-sortlabel">{children}<Icon name="arrow-up-down" size={14} /></span>;
}
