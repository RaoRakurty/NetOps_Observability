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
  if (f.console_only) return "Set on this page only. Off until turned on here.";
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

/**
 * A switch whose licence requirement is unmet (the AI switches without the
 * Iris AI add-on): it reads off, cannot be turned on, and says why. Turning it
 * OFF stays possible, so a choice saved while licensed can be withdrawn.
 * An older server sends no `available` field: treat that as available.
 */
export function isLocked(f: PlatformFeature): boolean {
  return f.available === false;
}

/** The licence line under a locked switch, or null. */
export function lockedLine(f: PlatformFeature): string | null {
  if (!isLocked(f)) return null;
  if (f.requires === "iris_model") {
    const saved = f.desired ? " It was on and will come back on when the add-on is licensed." : "";
    return `Needs the Iris AI add-on on your license (Enterprise includes it).${saved}`;
  }
  return f.unavailable_reason ? `Not available: ${f.unavailable_reason}.` : "Not included in your license.";
}

/** Whether the switch control is usable in this direction. */
export function toggleDisabled(f: PlatformFeature): boolean {
  return isLocked(f) && !switchValue(f);
}

/** The confirmation text for a risky switch. AI switches send data out. */
export function confirmText(f: PlatformFeature): string {
  if (f.requires === "iris_model") {
    return "Questions, and the network evidence Iris gathers to answer them, will be sent to the AI provider configured in Iris settings. Turn this on only if your data policy allows that provider.";
  }
  return "This feature reaches into your network or out of Correlix. Turn it on only if your security policy allows it.";
}
