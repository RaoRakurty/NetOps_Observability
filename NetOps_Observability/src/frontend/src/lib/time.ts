// time.ts — the ONE time authority for the SPA (docs/design/log-time-standard.md).
//
// Rules this module enforces:
//   1. PARSE: every timestamp the platform stores/serves is UTC. Strings that
//      carry no zone designator (ClickHouse `toString(DateTime64)` →
//      "2026-07-16 21:56:03.562") are UTC BY PLATFORM CONTRACT and must NEVER
//      fall into `new Date(...)`'s "no zone ⇒ browser-local" trap — that
//      shifted every ClickHouse-backed view by the viewer's UTC offset.
//   2. RENDER: viewer's choice of local time or UTC (top-bar toggle, persisted
//      in localStorage "netops.tzmode"), and every rendered time is LABELED
//      with the zone it is displayed in ("PDT", "IST", "UTC" — customer
//      language, never "browser TZ").
//   3. Epoch numbers are auto-ranged (s / ms / µs / ns) so raw fields like
//      goflow2 `time_received_ns` can never render as "Invalid Date".
//
// Every view formats times through this module — no scattered
// ad-hoc Date-toLocaleString one-offs.

import { useSyncExternalStore } from "react";

export type TzMode = "local" | "utc";

const TZ_KEY = "netops.tzmode";

function readMode(): TzMode {
  try {
    return localStorage.getItem(TZ_KEY) === "utc" ? "utc" : "local";
  } catch {
    return "local";
  }
}

let mode: TzMode = readMode();
const listeners = new Set<() => void>();

export function tzMode(): TzMode {
  return mode;
}

export function setTzMode(m: TzMode): void {
  mode = m;
  try {
    localStorage.setItem(TZ_KEY, m);
  } catch {
    /* private-mode storage failure — in-memory mode still applies */
  }
  listeners.forEach((fn) => fn());
}

function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// useTzMode — components that render times subscribe so the top-bar toggle
// re-renders them immediately.
export function useTzMode(): TzMode {
  return useSyncExternalStore(subscribe, tzMode, tzMode);
}

// ── Parsing ───────────────────────────────────────────────────────────────────

// Zone-less "YYYY-MM-DD HH:MM:SS[.fff]" / "YYYY-MM-DDTHH:MM:SS[.fff]" —
// ClickHouse toString(), correlation-service strings. UTC by contract.
const NAIVE_RE = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)$/;

function fromEpoch(n: number): Date {
  // Auto-range: seconds (~1.7e9 today), millis (~1.7e12), micros (~1.7e15),
  // nanos (~1.7e18). Boundaries leave headroom to year ~5138 for seconds.
  const abs = Math.abs(n);
  if (abs < 1e11) return new Date(n * 1000); // seconds
  if (abs < 1e14) return new Date(n); // milliseconds
  if (abs < 1e17) return new Date(n / 1e3); // microseconds
  return new Date(n / 1e6); // nanoseconds
}

// parseTs — a stored/served timestamp → Date, or null when absent/unparseable.
// Accepts Date, epoch number (any unit), numeric string, RFC 3339/ISO 8601
// (offset preserved), and zone-less datetime strings (interpreted as UTC —
// the platform storage contract — never as browser-local).
export function parseTs(v: string | number | Date | null | undefined): Date | null {
  if (v == null || v === "") return null;
  if (v instanceof Date) return isNaN(v.getTime()) ? null : v;
  if (typeof v === "number") {
    if (!isFinite(v) || v === 0) return null;
    const d = fromEpoch(v);
    return isNaN(d.getTime()) ? null : d;
  }
  const s = v.trim();
  if (!s) return null;
  if (/^-?\d+(\.\d+)?$/.test(s)) return parseTs(Number(s));
  const m = NAIVE_RE.exec(s);
  const d = m ? new Date(`${m[1]}T${m[2]}Z`) : new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

// ── Zone labels (customer language: "PDT", "IST", "UTC" — never "browser") ────

// Short zone token for an instant in the viewer's zone ("PDT", "IST", "GMT+5:30"
// when the locale has no abbreviation). Instant-sensitive so DST is honest.
function localZoneToken(d: Date): string {
  try {
    const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" }).formatToParts(d);
    const tz = parts.find((p) => p.type === "timeZoneName");
    if (tz && tz.value) return tz.value;
  } catch {
    /* fall through to offset form */
  }
  return offsetToken(d);
}

// "UTC−7" / "UTC+5:30" for an instant (handles half-hour offsets, DST).
function offsetToken(d: Date): string {
  const mins = -d.getTimezoneOffset(); // JS sign is inverted
  if (mins === 0) return "UTC";
  const sign = mins > 0 ? "+" : "−";
  const abs = Math.abs(mins);
  const h = Math.floor(abs / 60);
  const mm = abs % 60;
  return `UTC${sign}${h}${mm ? ":" + String(mm).padStart(2, "0") : ""}`;
}

// tzToken — the short label appended to rendered times ("UTC" | "PDT" | …).
export function tzToken(d: Date = new Date(), m: TzMode = mode): string {
  return m === "utc" ? "UTC" : localZoneToken(d);
}

// tzLabel — the explicit toggle/legend label: "PDT (UTC−7)" or "UTC".
export function tzLabel(m: TzMode = mode, d: Date = new Date()): string {
  if (m === "utc") return "UTC";
  const zone = localZoneToken(d);
  const off = offsetToken(d);
  return zone === off ? zone : `${zone} (${off})`;
}

// ── Formatting ────────────────────────────────────────────────────────────────

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const p2 = (n: number) => String(n).padStart(2, "0");

type Fields = {
  year: number;
  month: number;
  day: number;
  h: number;
  m: number;
  s: number;
  ms: number;
};

function fields(d: Date, m: TzMode): Fields {
  return m === "utc"
    ? { year: d.getUTCFullYear(), month: d.getUTCMonth(), day: d.getUTCDate(), h: d.getUTCHours(), m: d.getUTCMinutes(), s: d.getUTCSeconds(), ms: d.getUTCMilliseconds() }
    : { year: d.getFullYear(), month: d.getMonth(), day: d.getDate(), h: d.getHours(), m: d.getMinutes(), s: d.getSeconds(), ms: d.getMilliseconds() };
}

export type FmtOpts = {
  mode?: TzMode; // override the global toggle (rare — exports, tooltips)
  ms?: boolean; // include milliseconds
  label?: boolean; // append the zone token (default true — labeled everywhere)
  year?: boolean; // include the year (default: only when ≠ current year)
};

// fmtDateTime — the standard table/detail form: "Jul 16, 14:56:03 PDT"
// (or "Jul 16 2025, …" when the year differs from the current one).
export function fmtDateTime(v: string | number | Date | null | undefined, opts: FmtOpts = {}): string {
  const d = parseTs(v);
  if (!d) return "—";
  const m = opts.mode ?? mode;
  const f = fields(d, m);
  const nowYear = m === "utc" ? new Date().getUTCFullYear() : new Date().getFullYear();
  const yr = (opts.year ?? f.year !== nowYear) ? ` ${f.year}` : "";
  const msPart = opts.ms ? `.${String(f.ms).padStart(3, "0")}` : "";
  const label = opts.label === false ? "" : ` ${tzToken(d, m)}`;
  return `${MONTHS[f.month]} ${p2(f.day)}${yr}, ${p2(f.h)}:${p2(f.m)}:${p2(f.s)}${msPart}${label}`;
}

// fmtTime — clock only: "14:56:03 PDT".
export function fmtTime(v: string | number | Date | null | undefined, opts: FmtOpts = {}): string {
  const d = parseTs(v);
  if (!d) return "—";
  const m = opts.mode ?? mode;
  const f = fields(d, m);
  const msPart = opts.ms ? `.${String(f.ms).padStart(3, "0")}` : "";
  const label = opts.label === false ? "" : ` ${tzToken(d, m)}`;
  return `${p2(f.h)}:${p2(f.m)}:${p2(f.s)}${msPart}${label}`;
}

// fmtDate — date only: "Jul 16, 2026".
export function fmtDate(v: string | number | Date | null | undefined, opts: FmtOpts = {}): string {
  const d = parseTs(v);
  if (!d) return "—";
  const m = opts.mode ?? mode;
  const f = fields(d, m);
  return `${MONTHS[f.month]} ${p2(f.day)}, ${f.year}`;
}

// isoUTC — canonical RFC 3339 UTC string (tooltips, exports, copy/paste).
export function isoUTC(v: string | number | Date | null | undefined): string {
  const d = parseTs(v);
  return d ? d.toISOString() : "—";
}

// fmtTooltip — the disambiguation tooltip: both renderings, fully labeled.
// "2026-07-16T21:56:03.562Z · Jul 16, 14:56:03 PDT (UTC−7)"
export function fmtTooltip(v: string | number | Date | null | undefined): string {
  const d = parseTs(v);
  if (!d) return "";
  return `${d.toISOString()} · ${fmtDateTime(d, { mode: "local", label: false, ms: true })} ${tzLabel("local", d)}`;
}
