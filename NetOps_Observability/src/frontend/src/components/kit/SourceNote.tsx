// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// SourceNote — a quiet marker beside a value whose sources disagree (tracker
// 389). The value shown is the one the workspace's source order picks — the
// same one Iris cites — and the marker carries the sentence Iris states:
// which source won, why, and what every other source said. It is information,
// not an alarm: neutral colour, an "i" glyph, never a status colour
// (docs/design/visual-language.md, rule 4).

import Icon from "../Icon";
import type { DeviceFactDisagreement } from "../../services/api";
import "./kit.css";

export interface SourceNoteProps {
  /** The disagreements on the facts this cell shows (empty → nothing renders). */
  notes: DeviceFactDisagreement[];
  testId?: string;
}

export default function SourceNote({ notes, testId }: SourceNoteProps) {
  if (!notes.length) return null;
  const text = notes.map((n) => n.text).join(" ");
  const short = notes.length === 1 ? `Sources disagree on the ${notes[0].label}` : "Sources disagree";
  return (
    <span className="kit-srcnote" role="img" aria-label={`${short}. ${text}`} title={text} data-testid={testId}>
      <Icon name="info" size={14} />
    </span>
  );
}

/** The disagreements of a device on any of `facts`. */
export function notesFor(d: { source_disagreements?: DeviceFactDisagreement[] }, ...facts: string[]): DeviceFactDisagreement[] {
  return (d.source_disagreements ?? []).filter((n) => facts.includes(n.fact));
}
