// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Sites — Infrastructure → Sites (2026-08 nav redesign, owner tree). Before
// this page, "Sites" existed only as columns, the SitesManager buried inside
// the Device Geomap, and a broken dashboard drill. The owner tree has no
// separate geomap leaf, so the WHOLE geomap surface folds in here as tabs:
//
//   #/infrastructure/sites            → Map (geomap + per-site health rollup)
//   #/infrastructure/sites/map        → same, explicit
//   #/infrastructure/sites/sites      → Manage Sites (the SitesManager CRUD)
//   #/infrastructure/sites/locations  → Set Locations (per-device placement)
//
// The active tab lives in the route's third segment so every view is
// deep-linkable (the nav flyout's sub-items point at these); DeviceGeomap is
// rendered in controlled mode (view/onViewChange) — all data comes from the
// EXISTING /api/geomap + /api/sites endpoints, nothing invented.

import { useEffect, useState } from "react";
import DeviceGeomap, { GeoView } from "./DeviceGeomap";

function viewFromHash(): GeoView {
  const seg = location.hash.replace(/^#\/?/, "").split("?")[0].split("/")[2];
  return seg === "sites" || seg === "locations" ? seg : "map";
}

export default function Sites() {
  const [view, setView] = useState<GeoView>(viewFromHash);
  // Re-read on hashchange so a flyout sub-item click while ALREADY on this page
  // switches tabs (the leaf component stays mounted — a mount-only read would
  // make the click look dead; same lesson as AppObservability's deep links).
  useEffect(() => {
    const on = () => setView(viewFromHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return (
    <DeviceGeomap
      view={view}
      onViewChange={(v) => {
        const next = `#/infrastructure/sites/${v}`;
        if (location.hash.split("?")[0] !== next) window.history.replaceState(null, "", next);
        setView(v);
      }}
    />
  );
}
