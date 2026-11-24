// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// StatusChip — THE way a state is shown (docs/design/visual-language.md, rule 3).
// A state always carries an icon AND a word AND its semantic colour, so it reads
// the same for a colour-blind operator, on a greyscale print and on a phone in
// sunlight. Colour comes only from the semantic tokens (--ok, --warn, --crit,
// --info) via kit.css; descriptive values (vendor, site, type) never use this.

import Icon from "../Icon";
import "./kit.css";

/** The five tones. Every kind below maps to exactly one. */
export type StatusTone = "ok" | "warn" | "bad" | "info" | "neutral";

/** The words a caller may pass for a state; each resolves to one tone. */
export type StatusKind =
  | "ok" | "up" | "allow" | "healthy" | "confirmed" | "resolved" | "in-sync"
  | "warn" | "degraded" | "warning" | "suspected" | "partial"
  | "bad" | "down" | "deny" | "critical" | "failed" | "error"
  | "info"
  | "neutral" | "unknown" | "off" | "not-polled";

export const STATUS_TONE: Record<StatusKind, StatusTone> = {
  ok: "ok", up: "ok", allow: "ok", healthy: "ok", confirmed: "ok", resolved: "ok", "in-sync": "ok",
  warn: "warn", degraded: "warn", warning: "warn", suspected: "warn", partial: "warn",
  bad: "bad", down: "bad", deny: "bad", critical: "bad", failed: "bad", error: "bad",
  info: "info",
  neutral: "neutral", unknown: "neutral", off: "neutral", "not-polled": "neutral",
};

/** One glyph per tone: ✓ ok, ⓘ-style "!" warn, ⊘ bad, "i" info, ring neutral. */
export const TONE_ICON: Record<StatusTone, string> = {
  ok: "check",
  warn: "alert-circle",
  bad: "ban",
  info: "info",
  neutral: "circle",
};

export interface StatusChipProps {
  kind: StatusKind;
  /** The word shown. Required: a chip without a word would be colour-only. */
  label: string;
  /** Extra detail for the tooltip (why this state). */
  title?: string;
}

export default function StatusChip({ kind, label, title }: StatusChipProps) {
  const tone = STATUS_TONE[kind] ?? "neutral";
  return (
    // No role="status": a table of chips would be a wall of live regions. The
    // visible word is the accessible text; the glyph is decorative (aria-hidden).
    <span className="kit-status" data-tone={tone} data-kind={kind} title={title ?? label}>
      <Icon name={TONE_ICON[tone]} size={14} />
      <span>{label}</span>
    </span>
  );
}
