// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// adminTheme — the one colour per Administration group (owner, 2026-10-18:
// "mild modern colours", sections told apart at a glance).
//
// Colour lives in ONE scope (App.tsx wraps every Administration leaf in
// `.adm-scope`), which re-points --accent and friends, so buttons, tabs,
// focus rings and stat accents follow without per-page CSS. Each group has
// three shades, because one hue cannot do every job on both themes:
//   hue   — the existing --mod-* token: borders, icon chips, tints, and text
//           on the dark themes;
//   ink   — a darker shade for text and icons on the light theme (the --mod-*
//           hues reach only 2.4–4.5:1 on white);
//   solid — the background behind white button text.
// adminTheme.test.ts holds every ink and solid to WCAG AA.
//
// Themes are keyed by LEAF id, not group label, so a group rename (Phase 4)
// cannot silently recolour a page; every Administration leaf must be listed
// (the test fails on a new, unlisted one).

export type AdminTheme = {
  key: string;
  hue: string; // CSS value (a --mod-* token)
  ink: string;
  solid: string;
};

export const ADMIN_THEMES: Record<string, AdminTheme> = {
  sources: { key: "sources", hue: "var(--mod-fleet)", ink: "#0f766e", solid: "#0f766e" },
  response: { key: "response", hue: "var(--mod-incidents)", ink: "#7e22ce", solid: "#7e22ce" },
  handling: { key: "handling", hue: "var(--mod-logs)", ink: "#4338ca", solid: "#4338ca" },
  iris: { key: "iris", hue: "var(--mod-copilot)", ink: "#6d28d9", solid: "#6d28d9" },
  people: { key: "people", hue: "var(--mod-network)", ink: "#1d4ed8", solid: "#1d4ed8" },
  audit: { key: "audit", hue: "var(--mod-stack)", ink: "#155e75", solid: "#155e75" },
  workspace: { key: "workspace", hue: "var(--mod-reports)", ink: "#4f46e5", solid: "#4f46e5" },
};

// Administration leaf id → theme key.
export const ADMIN_LEAF_THEME: Record<string, keyof typeof ADMIN_THEMES> = {
  discovery: "sources",
  integrations: "response",
  notifications: "response",
  ticketing: "response",
  "ticket-delivery": "response",
  processors: "handling",
  "sensitive-data-access": "handling",
  "network-context": "iris",
  identity: "people",
  api: "people",
  sessions: "people",
  access: "audit",
  audit: "audit",
  transport: "audit",
  settings: "workspace",
  licence: "workspace",
};

/** The theme for an Administration leaf; Workspace when the leaf is unknown. */
export function adminThemeFor(leafId: string | undefined): AdminTheme {
  const key = leafId ? ADMIN_LEAF_THEME[leafId] : undefined;
  return ADMIN_THEMES[key ?? "workspace"];
}

/** The CSS custom properties the `.adm-scope` wrapper carries. */
export function adminThemeVars(t: AdminTheme): Record<string, string> {
  return { "--adm-hue": t.hue, "--adm-ink": t.ink, "--adm-solid": t.solid };
}

// ---- contrast (WCAG 2.x relative luminance) — used by the tests ----------

function channel(c: number): number {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
}

function luminance(hex: string): number {
  const h = hex.replace("#", "");
  const n = parseInt(h.length === 3 ? h.split("").map((x) => x + x).join("") : h, 16);
  return 0.2126 * channel((n >> 16) & 255) + 0.7152 * channel((n >> 8) & 255) + 0.0722 * channel(n & 255);
}

/** WCAG contrast ratio between two #rrggbb colours (1–21). */
export function contrastRatio(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}
