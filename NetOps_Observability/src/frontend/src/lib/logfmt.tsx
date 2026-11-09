// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// logfmt — shared, reusable log-field renderers (the "extensible objects": Time,
// Source, Level, Message). One token vocabulary, used identically in the Logs
// table, the Events table, and the detail/inspector — so a field looks the same
// wherever it appears. Severity colour comes from theme/severity.ts alone, and a
// clamped stream message only tints IPs and state words, so a page of rows stays
// calm; an unclamped detail view keeps the fuller highlighting.

import React from "react";
import { parseTs, useTzMode, fmtTooltip, tzToken } from "./time";
import { severityKey, severityLabel } from "../theme/severity";
import { redactSecrets } from "./logEvent";

// ── Time ──────────────────────────────────────────────────────────────────────
// date dimmed, clock emphasized, milliseconds whispered — tabular figures so
// columns never jitter. Parsing and the Local/UTC display mode come from
// lib/time.ts (the shared time authority): zone-less strings are UTC by
// contract, epoch numbers are auto-ranged, and the rendered zone is labeled
// (whispered token after the ms) so an operator always knows which clock a
// time is shown in.
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export function LogTime({ ts, withDate = true, stacked = false }: { ts: string | number; withDate?: boolean; stacked?: boolean }) {
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
  // Two-line form for tall rows: the clock leads, the date and zone sit under it.
  if (stacked) {
    return (
      <span className="lf-time lf-time-stacked" title={fmtTooltip(d)}>
        <span className="lf-time-clock">{p(hh)}:{p(mm)}:{p(ss)}<span className="lf-time-ms">.{p(ms, 3)}</span></span>
        <span className="lf-time-date">{MONTHS[month]} {p(day)} {tzToken(d, mode)}</span>
      </span>
    );
  }
  return (
    <span className="lf-time" title={fmtTooltip(d)}>
      {withDate && <span className="lf-time-date">{MONTHS[month]} {p(day)} </span>}
      <span className="lf-time-clock">{p(hh)}:{p(mm)}:{p(ss)}</span>
      <span className="lf-time-ms">.{p(ms, 3)}</span>
      <span className="lf-time-zone"> {tzToken(d, mode)}</span>
    </span>
  );
}

// ── Source ──────────────────────────────────────────────────────────────────────
export function LogSource({ source }: { source: string }) {
  return <span className="lf-source" title={source}>{source || "—"}</span>;
}

// ── Level / severity ────────────────────────────────────────────────────────────
// Text and colour together, never colour alone. theme/severity.ts decides both.
export function LogLevel({ level }: { level: string }) {
  const tone = level ? `lf-sev-${severityKey(level)}` : "lf-sev-none";
  return (
    <span className={`lf-level ${tone}`}>
      <span className="lf-level-dot" />
      {severityLabel(level) || "—"}
    </span>
  );
}

// ── Message tokenizer ─────────────────────────────────────────────────────────
// One pass, most specific first. "full" colours the significant spans for a detail
// view; "stream" tints only IPs and state words so a page of rows stays calm, and
// sets an OID in mono without colouring it. The IP pattern refuses a dotted run that
// keeps going, or the head of every OID would read as an address.
const STATE_BAD = "fail(?:ed|ure)?|error|denied|drop(?:ped)?|timeout|unreachable|down|flap";
const STATE_GOOD = "up|established|recovered|cleared";
const IP = "(?<ip>(?<![\\d.])\\d{1,3}(?:\\.\\d{1,3}){3}(?!\\.?\\d)(?::\\d+)?\\b)";
const OID = "(?<oid>(?<![\\d.])\\d+(?:\\.\\d+){3,}\\b)";
const STATE = `(?<state>\\b(?:${STATE_BAD})\\b)|(?<good>\\b(?:${STATE_GOOD})\\b)`;
const STREAM_RE = new RegExp([IP, OID, STATE].join("|"), "gi");
const FULL_RE = new RegExp(
  [
    "(?<str>\"[^\"]*\"|'[^']*')", // quoted strings
    "(?<mac>\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b)", // MAC
    IP, // IPv4(:port)
    "(?<key>\\b[A-Za-z_][\\w.\\-]*(?==))", // key in key=value
    OID, // dotted OID
    "(?<hex>\\b0x[0-9A-Fa-f]+\\b)", // hex
    "(?<num>\\b\\d+(?:\\.\\d+)?(?:%|ms|s|m|h|d|b|kb|mb|gb|bps|fps)?\\b)", // numbers (+ units)
    STATE,
  ].join("|"),
  "gi",
);
const STREAM_CLASS: Record<string, string> = { ip: "lf-ip", oid: "lf-mono", state: "lf-state", good: "lf-state-good" };
const FULL_CLASS: Record<string, string> = {
  str: "lf-str", mac: "lf-mac", ip: "lf-ip", key: "lf-key",
  oid: "lf-oid", hex: "lf-num", num: "lf-num", state: "lf-state", good: "lf-state-good",
};
export function LogMessage({ text, clamp = true, highlight }: { text: string; clamp?: boolean; highlight?: "stream" | "full" }) {
  const mode = highlight ?? (clamp ? "stream" : "full");
  return <span className={clamp ? "lf-msg lf-clamp" : "lf-msg"} title={clamp ? text : undefined}>{tokenize(text, mode)}</span>;
}
function tokenize(text: string, mode: "stream" | "full"): React.ReactNode[] {
  if (!text) return ["—"];
  const re = mode === "full" ? FULL_RE : STREAM_RE;
  const classes = mode === "full" ? FULL_CLASS : STREAM_CLASS;
  const out: React.ReactNode[] = [];
  let last = 0, i = 0;
  for (const m of text.matchAll(re)) {
    const start = m.index ?? 0;
    if (start > last) out.push(text.slice(last, start));
    const g = m.groups || {};
    const kind = Object.keys(g).find((k) => g[k] != null);
    out.push(<span key={i++} className={kind ? classes[kind] : undefined}>{m[0]}</span>);
    last = start + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

// ── JSON document highlighter (detail view) ─────────────────────────────────────
// Same palette as the inline tokens so the expanded document reads continuously.
// Secrets are replaced here as well as in the presenter: this is the renderer every
// raw view shares, so no caller can forget it.
export function LogJson({ value }: { value: unknown }) {
  let pretty = "";
  try { pretty = JSON.stringify(redactSecrets(value ?? {}), null, 2); } catch { pretty = "Could not display this record."; }
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
