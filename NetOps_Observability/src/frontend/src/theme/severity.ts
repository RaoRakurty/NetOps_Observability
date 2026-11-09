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

  // Fuzzy fallback for compound strings (e.g. "err-major").
  if (/(crit|emerg|fatal|panic)/.test(s)) return "critical";
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

// Hex colors per severity — kept in sync with the --sev-* CSS tokens. Use in
// charts (ECharts) where a concrete color is needed rather than a class.
export const SEVERITY_COLOR: Record<SeverityKey, string> = {
  critical: "#f43f5e",
  error: "#f97316",
  warning: "#d97706",
  notice: "#8b5cf6",
  info: "#2563eb",
  debug: "#64748b",
  ok: "#059669",
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
