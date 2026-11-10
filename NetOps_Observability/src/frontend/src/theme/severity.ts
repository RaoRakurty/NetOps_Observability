// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Canonical severity model shared by Logs, Alerts, and Findings so the same
// level is always the same color everywhere. Accepts syslog words, numeric
// syslog severities (0–7), and common app log levels.

export type SeverityKey =
  | "critical"
  | "error"
  | "warning"
  | "notice"
  | "info"
  | "debug"
  | "ok";

const WORDS: Record<string, SeverityKey> = {
  emerg: "critical", emergency: "critical", alert: "critical", crit: "critical",
  critical: "critical", fatal: "critical", panic: "critical",
  err: "error", error: "error",
  warn: "warning", warning: "warning",
  notice: "notice",
  info: "info", information: "info", informational: "info",
  debug: "debug", trace: "debug", verbose: "debug",
  ok: "ok", up: "ok", success: "ok", resolved: "ok", healthy: "ok",
  // Alarm vocabularies (X.733 / NETCONF notification severities) and lifecycle words.
  major: "error", minor: "warning", indeterminate: "info",
  clear: "ok", cleared: "ok", recovered: "ok", normal: "ok",
};

export function severityKey(raw: string | number | null | undefined): SeverityKey {
  if (raw === null || raw === undefined || raw === "") return "info";
  const s = String(raw).toLowerCase().trim();
  if (WORDS[s]) return WORDS[s];

  // Numeric syslog severity (0 emerg … 7 debug).
  const n = Number(s);
  if (!Number.isNaN(n) && /^\d+$/.test(s)) {
    if (n <= 2) return "critical";
    if (n === 3) return "error";
    if (n === 4) return "warning";
    if (n === 5) return "notice";
    if (n === 6) return "info";
    return "debug";
  }

  // Fuzzy fallback for compound strings (e.g. "err-major", "critical (1)").
  if (/(crit|emerg|fatal|panic)/.test(s)) return "critical";
  if (/major/.test(s)) return "error";
  if (/minor/.test(s)) return "warning";
  if (/clear|recover/.test(s)) return "ok";
  if (/err/.test(s)) return "error";
  if (/warn/.test(s)) return "warning";
  if (/(debug|trace)/.test(s)) return "debug";
  return "info";
}

// CSS class for the severity badge, e.g. "sev-critical".
export function severityClass(raw: string | number | null | undefined): string {
  return `sev-${severityKey(raw)}`;
}

// Sort rank (critical=0 … ok=6) for ordering by severity — ascending puts the
// most severe first. Shared by the DataTable Level/Severity columns.
const SEV_RANK: Record<SeverityKey, number> = {
  critical: 0, error: 1, warning: 2, notice: 3, info: 4, debug: 5, ok: 6,
};
export function severityRank(raw: string | number | null | undefined): number {
  return SEV_RANK[severityKey(raw)];
}

// Class for a table row to get a colored left accent by severity.
export function severityRowClass(raw: string | number | null | undefined): string {
  return `sevrow-${severityKey(raw)}`;
}

// THE severity → tone map (owner, 2026-11-10). Every severity accent in the product
// reads one of these seven tones, so a whole surface re-tints from one key: the Logs
// rows and facets, and every part of the event panel (icon tile, pill, ring, bar,
// lifecycle chip, timeline dot). The CSS carries the same hues as --sev-<tone> (the
// accent for the active theme), --sev-<tone>-bg (a translucent fill), --sev-<tone>-solid
// and --sev-<tone>-on (a solid pill and the text that holds AA on it). Dark values are
// the owner's palette; the light theme uses deeper cuts of the same hues so text in
// the accent colour still clears 4.5:1 on white.
export interface SeverityTone {
  key: SeverityKey;
  /** The accent on a dark canvas (the owner's palette). */
  dark: string;
  /** The same hue, deep enough for AA text on a light canvas. */
  light: string;
  /** A solid pill fill, and the text colour that clears AA on it. */
  solid: string;
  on: string;
  /** The glyph that goes with the word, so severity never rests on colour alone. */
  icon: "octagon" | "triangle" | "info" | "bug" | "check";
}

export const SEVERITY_TONES: Record<SeverityKey, SeverityTone> = {
  critical: { key: "critical", dark: "#EF4444", light: "#DC2626", solid: "#DC2626", on: "#FFFFFF", icon: "triangle" },
  error:    { key: "error",    dark: "#F97316", light: "#C2410C", solid: "#C2410C", on: "#FFFFFF", icon: "octagon" },
  warning:  { key: "warning",  dark: "#F59E0B", light: "#B45309", solid: "#F59E0B", on: "#1A1203", icon: "triangle" },
  notice:   { key: "notice",   dark: "#38BDF8", light: "#0369A1", solid: "#38BDF8", on: "#04141D", icon: "info" },
  info:     { key: "info",     dark: "#5FB3B3", light: "#2F7A7A", solid: "#5FB3B3", on: "#061515", icon: "info" },
  debug:    { key: "debug",    dark: "#94A3B8", light: "#5B6779", solid: "#94A3B8", on: "#0B1220", icon: "bug" },
  ok:       { key: "ok",       dark: "#22C55E", light: "#15803D", solid: "#22C55E", on: "#04140A", icon: "check" },
};

export function severityTone(raw: string | number | null | undefined): SeverityTone {
  return SEVERITY_TONES[severityKey(raw)];
}

// Hex colors per severity — the dark accents of the tone map above. Use in charts
// (ECharts) where a concrete color is needed rather than a class.
export const SEVERITY_COLOR: Record<SeverityKey, string> = {
  critical: SEVERITY_TONES.critical.dark,
  error: SEVERITY_TONES.error.dark,
  warning: SEVERITY_TONES.warning.dark,
  notice: SEVERITY_TONES.notice.dark,
  info: SEVERITY_TONES.info.dark,
  debug: SEVERITY_TONES.debug.dark,
  ok: SEVERITY_TONES.ok.dark,
};

export function severityColor(raw: string | number | null | undefined): string {
  return SEVERITY_COLOR[severityKey(raw)];
}

// The CSS token for a severity: what DOM surfaces use, so a level follows the
// active theme. Logs reads every row accent and chip through this and severityKey,
// which keeps one level from ever showing two colours.
export function severityVar(raw: string | number | null | undefined): string {
  return `var(--sev-${severityKey(raw)})`;
}

const SYSLOG_NUMERIC = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"];
const LABELS: Record<string, string> = {
  emerg: "Emergency", emergency: "Emergency", alert: "Alert", crit: "Critical", critical: "Critical",
  fatal: "Fatal", panic: "Panic", err: "Error", error: "Error", warn: "Warning", warning: "Warning",
  notice: "Notice", info: "Info", information: "Info", informational: "Info", debug: "Debug",
  trace: "Trace", verbose: "Verbose", ok: "OK",
  major: "Major", minor: "Minor", clear: "Clear", cleared: "Cleared", recovered: "Recovered",
};

// The word an operator reads for a level. It keeps the record's own distinction
// (emergency and alert both colour as critical, and still say which they were)
// and shows a spelling it does not know exactly as the record gave it.
export function severityLabel(raw: string | number | null | undefined): string {
  if (raw === null || raw === undefined) return "";
  const s = String(raw).trim();
  if (/^[0-7]$/.test(s)) return SYSLOG_NUMERIC[Number(s)];
  return LABELS[s.toLowerCase()] ?? s;
}
