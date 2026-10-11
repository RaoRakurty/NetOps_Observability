// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// featuresModel.ts — the pure half of the Features page: grouping and the
// plain-language status of each switch. No IO, so every state is tested.

import type { PlatformFeature } from "../../services/api";

export type FeatureGroup = { name: string; features: PlatformFeature[] };

/** Groups in first-seen order (the server's order), features in server order. */
export function groupFeatures(features: readonly PlatformFeature[]): FeatureGroup[] {
  const order: string[] = [];
  const by = new Map<string, PlatformFeature[]>();
  for (const f of features) {
    const g = f.group || "Other";
    if (!by.has(g)) {
      by.set(g, []);
      order.push(g);
    }
    by.get(g)!.push(f);
  }
  return order.map((name) => ({ name, features: by.get(name)! }));
}

/** When a change takes effect, in plain words. */
export function applyLabel(f: PlatformFeature): string {
  return f.apply === "live" ? "Applies at once" : "Applies after restart";
}

/** One line on where the value came from. */
export function sourceLine(f: PlatformFeature, fmt: (iso: string) => string): string {
  if (f.source === "console") {
    const who = f.updated_by ? ` by ${f.updated_by.replace(/^u_/, "user ")}` : "";
    const when = f.updated_at ? ` on ${fmt(f.updated_at)}` : "";
    return `Changed here${who}${when}.`;
  }
  if (f.source === "install") return `Set at install (${f.install_value ? "on" : "off"}).`;
  return "Not set at install; the built-in default applies.";
}

/**
 * The state an operator must not misread: a restart-class switch that was
 * changed shows what is RUNNING and what will run after the restart.
 */
export function pendingLine(f: PlatformFeature): string | null {
  if (!f.restart_pending) return null;
  return `Running ${f.running ? "on" : "off"} now; ${f.desired ? "on" : "off"} after restart.`;
}

/** The value the switch shows: the saved (desired) value. */
export function switchValue(f: PlatformFeature): boolean {
  return f.desired;
}
