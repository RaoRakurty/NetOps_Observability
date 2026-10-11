// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// deviceHealth.ts — the ONE device status every inventory surface renders
// (list, detail popup, monitoring page), so they can never disagree.
//
// Owner report 2026-10-10: the list showed a device green while its detail
// popup showed it red. Three surfaces each derived up/down from last_seen with
// different thresholds — and last_seen only means "discovery still lists the
// device". The server now stamps `reachability` from the collectors' own poll
// results (collector_target_up); this file only adds the alert overlay.

import type { Device } from "../../services/api";

export type DeviceHealth = "up" | "degraded" | "down" | "unknown";

export const DEVICE_HEALTH_META: Record<DeviceHealth, { label: string; color: string; arrow: string }> = {
  up: { label: "Up", color: "var(--good, #16a34a)", arrow: "↑" },
  degraded: { label: "Degraded", color: "var(--warn, #d97706)", arrow: "↕" },
  down: { label: "Down", color: "var(--bad, #dc2626)", arrow: "↓" },
  unknown: { label: "Not polled recently", color: "var(--muted, #94a3b8)", arrow: "–" },
};

/**
 * deviceHealth folds the server's live reachability with active alerts:
 *   down    — no collector polling the device got an answer;
 *   degraded — some collectors answered and some did not, or it is reachable
 *              but has an active warning/critical alert;
 *   up      — every collector answered and nothing is alerting;
 *   unknown — no collector has polled it recently (not monitored, or the
 *              status store could not be read). Never shown as down.
 */
export function deviceHealth(d: Pick<Device, "reachability">, alerted: boolean): DeviceHealth {
  switch (d.reachability) {
    case "down":
      return "down";
    case "partial":
      return "degraded";
    case "up":
      return alerted ? "degraded" : "up";
    default:
      return "unknown";
  }
}
