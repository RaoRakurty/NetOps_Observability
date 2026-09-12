// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// text.ts — small display-only string helpers.
//
// capitalize is for the RENDER layer only: it upper-cases the first character
// of a value for human display (e.g. a vendor id "arista" → "Arista"). It must
// never be used to mutate ids/values that feed lookups or API calls — those
// stay verbatim; only what the user reads changes.
export function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

// escapeHtml is the canonical HTML-context escaper. Use it for ANY value that
// reaches an HTML sink — most importantly ECharts tooltip/label `formatter`
// return strings, which ECharts inserts via innerHTML. Chart labels come from
// device-controlled data (ifName / ifAlias / sysName / seam + site names), so an
// unescaped `<img src=x onerror=…>` in a device field executed in the operator's
// authenticated browser (stored XSS). Escaping, not stripping: real names carry
// `/`, `(`, `+` that an allowlist-strip would eat; the operator must see the
// true name. Ampersand first so the escape is not itself re-interpretable.
export function escapeHtml(v: unknown): string {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
