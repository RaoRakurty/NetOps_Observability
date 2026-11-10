// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// EventDetailPage — the full event page (owner screenshot B) at
// #/explore/logs/event/<signal>/<record id>?t=<timestamp>. It fetches the one record
// through the same tenant-scoped log search the Logs page uses (an `_id` clause in a
// narrow window around `t`), so a record outside the caller's tenant is simply not
// found. Nothing about the record travels in the URL except its id and time.

import { useEffect, useMemo, useState } from "react";
import { api, LogSearchOpts } from "../../services/api";
import { luceneQuote } from "../../lib/logEvent";
import { parseIso, toEventView } from "../../lib/eventModel";
import type { OSHit } from "../../services/api";
import EventDetailView from "./EventDetailView";
import { EVENT_SIGNALS, EventRoute } from "./eventRoute";
import "./event.css";

const WINDOW_MS = 3600_000;

export default function EventDetailPage({ route }: { route: EventRoute }) {
  const [hit, setHit] = useState<OSHit | null>(null);
  const [status, setStatus] = useState<"loading" | "found" | "missing" | "error">("loading");
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    setStatus("loading");
    const at = parseIso(route.t)?.getTime();
    const opts: LogSearchOpts = {
      query: `_id:${luceneQuote(route.id)}`,
      signal: EVENT_SIGNALS[route.signal],
      size: 1,
      ...(at !== undefined
        ? { from: new Date(at - WINDOW_MS).toISOString(), to: new Date(at + WINDOW_MS).toISOString() }
        : { from: new Date(Date.now() - 24 * WINDOW_MS).toISOString(), to: new Date().toISOString() }),
    };
    api.searchLogs(opts)
      .then((r) => {
        if (!alive) return;
        const found = (r?.hits?.hits ?? []).find((h) => h._id === route.id) ?? null;
        setHit(found);
        setStatus(found ? "found" : "missing");
      })
      .catch((e: unknown) => {
        if (!alive) return;
        setError((e as Error)?.message || "The search failed.");
        setStatus("error");
      });
    return () => { alive = false; };
  }, [route.signal, route.id, route.t]);

  const view = useMemo(() => (hit ? toEventView(hit) : null), [hit]);

  if (status === "loading") return <div className="evd evd-page-msg">Loading the event…</div>;
  if (status === "error") return <div className="evd evd-page-msg" role="alert">This event could not be loaded: {error}</div>;
  if (!view) {
    return (
      <div className="evd evd-page-msg" role="alert">
        This event was not found. It may be outside the retention window, or not visible to your account.{" "}
        <a href="#/explore/logs">Back to Logs</a>
      </div>
    );
  }
  return <EventDetailView view={view} mode="page" />;
}
