// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// logfmt — shared, reusable log-field renderers (the "extensible objects": Time,
// Source, Level, Message). One token vocabulary, used identically in the Logs
// table, the Events table, and the detail/inspector — so a field looks the same
// wherever it appears (Dynatrace/ThousandEyes-style: muted time, accented source,
// severity-coded level, and a message with mildly-colored significant tokens —
// numbers, IPs/MACs, key=value keys, quoted strings, state words).

import React from "react";
import { parseTs, useTzMode, fmtTooltip, tzToken } from "./time";

// ── Time ──────────────────────────────────────────────────────────────────────
// date dimmed, clock emphasized, milliseconds whispered — tabular figures so
// columns never jitter. Parsing and the Local/UTC display mode come from
// lib/time.ts (the shared time authority): zone-less strings are UTC by
// contract, epoch numbers are auto-ranged, and the rendered zone is labeled
// (whispered token after the ms) so an operator always knows which clock a
// time is shown in.
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export function LogTime({ ts, withDate = true }: { ts: string | number; withDate?: boolean }) {
  const mode = useTzMode();
  const d = parseTs(ts);
  if (!d) return <span className="lf-time">—</span>;
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  const utc = mode === "utc";
  const month = utc ? d.getUTCMonth() : d.getMonth();
  const day = utc ? d.getUTCDate() : d.getDate();
  const hh = utc ? d.getUTCHours() : d.getHours();
  const mm = utc ? d.getUTCMinutes() : d.getMinutes();
  const ss = utc ? d.getUTCSeconds() : d.getSeconds();
  const ms = utc ? d.getUTCMilliseconds() : d.getMilliseconds();
  return (
    <span className="lf-time" title={fmtTooltip(d)}>
      {withDate && <span className="lf-time-date">{MONTHS[month]} {p(day)} </span>}
      <span className="lf-time-clock">{p(hh)}:{p(mm)}:{p(ss)}</span>
      <span className="lf-time-ms">.{p(ms, 3)} {tzToken(d, mode)}</span>
    </span>
  );
}

// ── Source ──────────────────────────────────────────────────────────────────────
export function LogSource({ source }: { source: string }) {
  return <span className="lf-source" title={source}>{source || "—"}</span>;
}

// ── Level / severity ────────────────────────────────────────────────────────────
// normalize the many spellings to one tone so the dot+label colour is consistent.
export function levelTone(level: string): "crit" | "err" | "warn" | "notice" | "info" | "debug" {
  const x = (level || "").toLowerCase();
  if (["emergency", "emerg", "alert", "critical", "crit", "fatal", "0", "1", "2"].includes(x)) return "crit";
  if (["error", "err", "3"].includes(x)) return "err";
  if (["warning", "warn", "4"].includes(x)) return "warn";
  if (["notice", "5"].includes(x)) return "notice";
  if (["debug", "trace", "7"].includes(x)) return "debug";
  return "info";
}
export function LogLevel({ level }: { level: string }) {
  const tone = levelTone(level);
  return (
    <span className={`lf-level lf-${tone}`}>
      <span className="lf-level-dot" />
      {level || "—"}
    </span>
  );
}

// ── Message tokenizer ─────────────────────────────────────────────────────────
// One pass, mild colouring of the *significant* spans only — everything else stays
// neutral so the eye lands on the data. Order matters (most specific first).
const TOKEN_RE = new RegExp(
  [
    "(?<str>\"[^\"]*\"|'[^']*')", // quoted strings
    "(?<mac>\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b)", // MAC
    "(?<ip>\\b\\d{1,3}(?:\\.\\d{1,3}){3}(?::\\d+)?\\b)", // IPv4(:port)
    "(?<key>\\b[A-Za-z_][\\w.\\-]*(?==))", // key in key=value
    "(?<oid>\\b\\d+(?:\\.\\d+){3,}\\b)", // dotted OID
    "(?<hex>\\b0x[0-9A-Fa-f]+\\b)", // hex
    "(?<num>\\b\\d+(?:\\.\\d+)?(?:%|ms|s|m|h|d|b|kb|mb|gb|bps|fps)?\\b)", // numbers (+ units)
    "(?<state>\\b(?:up|down|fail(?:ed|ure)?|error|denied|drop(?:ped)?|timeout|unreachable|established|recovered|cleared|flap)\\b)",
  ].join("|"),
  "gi",
);
const CLASS: Record<string, string> = {
  str: "lf-str", mac: "lf-mac", ip: "lf-ip", key: "lf-key",
  oid: "lf-oid", hex: "lf-num", num: "lf-num", state: "lf-state",
};
export function LogMessage({ text, clamp = true }: { text: string; clamp?: boolean }) {
  return <span className={clamp ? "lf-msg lf-clamp" : "lf-msg"} title={clamp ? text : undefined}>{tokenize(text)}</span>;
}
function tokenize(text: string): React.ReactNode[] {
  if (!text) return ["—"];
  const out: React.ReactNode[] = [];
  let last = 0, i = 0;
  for (const m of text.matchAll(TOKEN_RE)) {
    const start = m.index ?? 0;
    if (start > last) out.push(text.slice(last, start));
    const g = m.groups || {};
    const kind = Object.keys(g).find((k) => g[k] != null);
    out.push(<span key={i++} className={kind ? CLASS[kind] : undefined}>{m[0]}</span>);
    last = start + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

// ── JSON document highlighter (detail view) ─────────────────────────────────────
// Same palette as the inline tokens so the expanded document reads continuously.
export function LogJson({ value }: { value: unknown }) {
  let pretty = "";
  try { pretty = JSON.stringify(value ?? {}, null, 2); } catch { pretty = String(value); }
  const nodes: React.ReactNode[] = [];
  let last = 0, i = 0;
  // keys, strings, numbers, literals
  const re = /("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|-?\b\d+(?:\.\d+)?\b/g;
  for (const m of pretty.matchAll(re)) {
    const start = m.index ?? 0;
    if (start > last) nodes.push(pretty.slice(last, start));
    if (m[1] && m[2]) { nodes.push(<span key={i++} className="lf-key">{m[1]}</span>, m[2]); }
    else if (m[1]) nodes.push(<span key={i++} className="lf-str">{m[1]}</span>);
    else if (m[3]) nodes.push(<span key={i++} className="lf-state">{m[3]}</span>);
    else nodes.push(<span key={i++} className="lf-num">{m[0]}</span>);
    last = start + m[0].length;
  }
  if (last < pretty.length) nodes.push(pretty.slice(last));
  return <pre className="lf-json">{nodes}</pre>;
}
