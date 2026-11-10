// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// The full event page's route, kept out of the page's own chunk so the Logs leaf can
// read it without loading the page.

import type { LogSearchOpts } from "../../services/api";

export const EVENT_SIGNALS: Record<string, LogSearchOpts["signal"]> = {
  all: "", syslog: "syslog", snmptrap: "snmptrap", flows: "flows", applogs: "applogs", cloud: "cloud",
};

export interface EventRoute {
  signal: string;
  id: string;
  t: string;
}

/** Reads #/explore/logs/event/<signal>/<id>?t=… ; null when the hash is not an event link. */
export function eventRouteFromHash(hash: string): EventRoute | null {
  const [path, qs = ""] = hash.replace(/^#\/?/, "").split("?");
  const segs = path.split("/");
  if (segs[0] !== "explore" || segs[1] !== "logs" || segs[2] !== "event" || segs.length < 5) return null;
  let id = "";
  try {
    id = decodeURIComponent(segs.slice(4).join("/"));
  } catch {
    return null;
  }
  const t = new URLSearchParams(qs).get("t") ?? "";
  if (!id || !(segs[3] in EVENT_SIGNALS)) return null;
  return { signal: segs[3], id, t };
}

