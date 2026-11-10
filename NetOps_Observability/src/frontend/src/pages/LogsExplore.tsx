// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// LogsExplore — Explore → Logs (2026-08 nav redesign, owner tree). The old
// top-level Logs section's Log Search + Cloud Logs planes in ONE leaf, with the
// active plane carried in the route's third segment so both stay deep-linkable:
//
//   #/explore/logs        → Log Search (device/app syslog, default)
//   #/explore/logs/cloud  → Cloud Logs (the tagged cloud-log lanes)
//   #/explore/logs/event/<signal>/<id>?t=… → one event's full page (tracker 387)
//
// Legacy #/logs/logs and #/logs/cloud alias here with the suffix preserved
// (nav.tsx LEGACY_ROUTE_ALIAS + App's canonicalHash rewrite). Saved Searches
// stayed its own leaf (#/explore/saved), exactly as the owner tree lists it.
// Both panes lazy-load — this shell must not drag the OpenSearch table AND the
// cloud lanes into one chunk when the operator only opens one.

import { Suspense, lazy, useEffect, useState } from "react";
import { Segmented } from "../components/ui";
import { eventRouteFromHash } from "../components/event/eventRoute";

const Logs = lazy(() => import("../tabs/Logs"));
const CloudLogs = lazy(() => import("./CloudLogs"));
const EventDetailPage = lazy(() => import("../components/event/EventDetailPage"));

type Plane = "search" | "cloud" | "event";

function planeFromHash(): Plane {
  const seg = location.hash.replace(/^#\/?/, "").split("?")[0].split("/")[2];
  return seg === "cloud" ? "cloud" : seg === "event" ? "event" : "search";
}

export default function LogsExplore({ initialQuery, rangeMinutes }: {
  initialQuery: string;
  rangeMinutes: number;
}) {
  const [plane, setPlane] = useState<Plane>(planeFromHash);
  const [route, setRoute] = useState(() => eventRouteFromHash(location.hash));
  // Re-read on hashchange so the flyout's "Cloud Logs" sub-item switches the
  // plane while this leaf is already mounted (a mount-only read looks dead).
  useEffect(() => {
    const on = () => {
      setPlane(planeFromHash());
      setRoute(eventRouteFromHash(location.hash));
    };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const go = (p: Plane) => {
    const next = p === "cloud" ? "#/explore/logs/cloud" : "#/explore/logs";
    if (location.hash.split("?")[0] !== next) window.history.replaceState(null, "", next);
    setPlane(p);
  };

  if (plane === "event" && route) {
    return (
      <Suspense fallback={<div style={{ padding: 40, color: "var(--muted)" }}>Loading…</div>}>
        <EventDetailPage route={route} />
      </Suspense>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <Segmented
        value={plane}
        ariaLabel="Log plane"
        options={[
          { value: "search", label: "Log Search" },
          { value: "cloud", label: "Cloud Logs" },
        ]}
        onChange={go}
      />
      <Suspense fallback={<div style={{ padding: 40, color: "var(--muted)" }}>Loading…</div>}>
        {plane === "cloud" ? <CloudLogs /> : <Logs initialQuery={initialQuery} rangeMinutes={rangeMinutes} />}
      </Suspense>
    </div>
  );
}
