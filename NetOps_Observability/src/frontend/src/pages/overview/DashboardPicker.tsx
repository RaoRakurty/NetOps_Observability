// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DashboardPicker — the header switch between the default Overview and the
// tenant's own dashboards. Choosing one navigates to its address
// (#/overview/dashboards/<id>), so every dashboard is a bookmarkable link. A
// failed list read leaves only "Overview" and "Manage dashboards".

import { useEffect, useState } from "react";
import { api, type SavedObject } from "../../services/api";
import { dashHref } from "./dashboardModel";

const DEFAULT_VALUE = "__default";
const BUILTIN_VALUE = "__builtin";
const MANAGE_VALUE = "__manage";

/** The built-in Overview's own address, for when the tenant has a team default. */
export const BUILTIN_OVERVIEW_HREF = "#/overview/operations/builtin";

/** `teamDefault`: the tenant has a team-default dashboard, so "Overview
 *  (default)" opens it and the built-in Overview gets its own entry. */
export default function DashboardPicker({ current, teamDefault = false }: { current: "default" | "builtin" | string; teamDefault?: boolean }) {
  const [boards, setBoards] = useState<SavedObject[]>([]);
  useEffect(() => {
    let alive = true;
    // Started inside a promise so even a synchronous failure only hides the list.
    Promise.resolve().then(() => api.listSaved("dashboard"))
      .then((l) => { if (alive) setBoards(Array.isArray(l) ? l : []); })
      .catch(() => { /* the picker still offers Overview and Manage */ });
    return () => { alive = false; };
  }, []);

  const value = current === "default" ? DEFAULT_VALUE : current === "builtin" ? BUILTIN_VALUE : current;
  const go = (v: string) => {
    if (v === DEFAULT_VALUE) location.hash = "#/overview/operations";
    else if (v === BUILTIN_VALUE) location.hash = BUILTIN_OVERVIEW_HREF;
    else if (v === MANAGE_VALUE) location.hash = dashHref({ kind: "list" });
    else location.hash = dashHref({ kind: "open", id: v });
  };
  const named = current !== "default" && current !== "builtin";
  return (
    <label className="ov-picker">
      <span className="ov-picker-l">Dashboard</span>
      <select value={value} onChange={(e) => go(e.target.value)} aria-label="Dashboard" data-testid="dashboard-picker">
        <option value={DEFAULT_VALUE}>{teamDefault ? "Overview (team default)" : "Overview (default)"}</option>
        {(teamDefault || current === "builtin") && <option value={BUILTIN_VALUE}>Built-in Overview</option>}
        {boards.map((b) => <option key={b.id} value={b.id}>{b.name}</option>)}
        {named && !boards.some((b) => b.id === current) && <option value={current}>This dashboard</option>}
        <option value={MANAGE_VALUE}>Manage dashboards…</option>
      </select>
    </label>
  );
}
