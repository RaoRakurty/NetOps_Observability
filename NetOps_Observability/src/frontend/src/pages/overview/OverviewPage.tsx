// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Overview — the ONE default page under Overview (owner, 2026-11-22: "merge My
// Dashboard and Operations Overview and make one standard default look; NOC
// admins build their own custom dashboards"). It answers, top to bottom:
//
//   What needs attention   the headline problem and the one next step
//   KPI strip              health, incidents, suspected, impacted sites/devices, telemetry
//   Open problems          top issues, where the fault is, impact, RCA coverage
//   What is broken now     active alerts, health contributors, routing, hot paths
//   Health by site         devices up/down per site, worst first (/api/geomap)
//   What changed           changes in 24 h, capacity outlook
//   Is data arriving       telemetry coverage, devices reachable, platform health (admins)
//   Traffic and resources  collapsed: traffic, utilization, tunnels, CPU, memory
//
// The RCA panels share ONE read of correlations / health / stats per tick
// (useOverviewData). A collapsed group renders nothing inside it, so it polls
// nothing. Liveness is derived from real fetch outcomes (useBoardHealth), never
// a wall clock: a failing source reads "Disconnected". The header's picker
// switches to a custom dashboard (My dashboards); this page stays the default.
//
// Team default (2026-11-22): when a tenant administrator has made one of the
// tenant's dashboards the team default, #/overview/operations opens THAT
// dashboard for everyone in the tenant, and the built-in page moves to
// #/overview/operations/builtin. A team default that was deleted, or that this
// user may not read, falls back to the built-in page with a quiet note. The
// built-in page's reads start only when it is the page shown.

import { useEffect, useState } from "react";
import { api, type AuthUser, type SavedObject } from "../../services/api";
import PathHealthList from "../../components/PathHealthList";
import { useOverviewData } from "./useOverviewData";
import { customerProblems, internalObjects, topProblem } from "./overviewModel";
import { AttentionBlock, LazyGroup, Liveness, RegistryCell, SiteHealth } from "./boardParts";
import DashboardPicker from "./DashboardPicker";
import { ReadOnlyBoard } from "./MyDashboards";
import {
  CapacityOutlook, ImpactSummary, InternalMonitoringChecks, KpiStrip, PlatformHealth, RcaCoverage,
  RcaPanel, RcaPathPanel, Safe, TelemetryCoverage, TopHealthContributors, TopIssues, WhatChanged,
} from "./rcaPanels";

/** Whether the caller is the platform admin (cross-tenant): only then are the
 *  platform's own health panels shown. Read once; a failure keeps them hidden. */
function usePlatformAdmin(): boolean {
  const [admin, setAdmin] = useState(false);
  useEffect(() => {
    let alive = true;
    api.me().then((u: AuthUser) => { if (alive) setAdmin(!!u?.platform_admin); }).catch(() => { /* stays hidden */ });
    return () => { alive = false; };
  }, []);
  return admin;
}

type TeamDefault =
  | { state: "loading" }
  | { state: "none" }
  | { state: "board"; board: SavedObject }
  | { state: "unavailable" };

/** The tenant's team-default dashboard, read once. A failed read is "none":
 *  the built-in Overview is always a safe answer. */
function useTeamDefault(): TeamDefault {
  const [team, setTeam] = useState<TeamDefault>({ state: "loading" });
  useEffect(() => {
    let alive = true;
    // Started inside a promise so even a synchronous failure falls back.
    Promise.resolve().then(() => api.getOverviewDefault())
      .then((d) => {
        if (!alive) return;
        if (d?.dashboard) setTeam({ state: "board", board: d.dashboard });
        else setTeam(d?.dashboard_id ? { state: "unavailable" } : { state: "none" });
      })
      .catch(() => { if (alive) setTeam({ state: "none" }); });
    return () => { alive = false; };
  }, []);
  return team;
}

/** Whether the address asks for the built-in page (#/overview/operations/builtin). */
function isBuiltinHash(hash: string): boolean {
  return hash.replace(/^#\/?/, "").split("?")[0].split("/")[2] === "builtin";
}

function useBuiltinRoute(): boolean {
  const [builtin, setBuiltin] = useState(() => isBuiltinHash(location.hash));
  useEffect(() => {
    const on = () => setBuiltin(isBuiltinHash(location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return builtin;
}

/** The team-default dashboard shown as the Overview. */
function TeamOverview({ board }: { board: SavedObject }) {
  return (
    <div className="overview-page fp dm-board" data-testid="overview-page">
      <div className="mydash-head">
        <div>
          <h1 className="mydash-title">Overview</h1>
          <div className="ov-sub">Your team's default: {board.name}</div>
        </div>
        <div className="ov-head-right">
          <DashboardPicker current="default" teamDefault />
          <Liveness />
        </div>
      </div>
      <ReadOnlyBoard board={board} />
    </div>
  );
}

export default function OverviewPage() {
  const team = useTeamDefault();
  const builtin = useBuiltinRoute();
  if (team.state === "loading") {
    return <div className="overview-page card" aria-busy="true" data-testid="overview-loading">Loading the Overview…</div>;
  }
  if (team.state === "board" && !builtin) return <TeamOverview board={team.board} />;
  return (
    <BuiltinOverview
      teamDefault={team.state === "board"}
      note={team.state === "unavailable"
        ? "Your team's default dashboard is no longer available, so this is the built-in Overview."
        : undefined}
    />
  );
}

/** The built-in Overview. `teamDefault`: the tenant has a team default and this
 *  is the built-in page opened by its own address. */
function BuiltinOverview({ teamDefault, note }: { teamDefault: boolean; note?: string }) {
  const d = useOverviewData();
  const platformAdmin = usePlatformAdmin();
  const problems = d.corr ? customerProblems(d.corr) : undefined;
  const top = problems ? topProblem(problems) : undefined;

  return (
    <div className="overview-page fp dm-board" data-testid="overview-page">
      <div className="mydash-head">
        <div>
          <h1 className="mydash-title">Overview</h1>
          <div className="ov-sub">What is broken, where, and what to do first.</div>
        </div>
        <div className="ov-head-right">
          <DashboardPicker current={teamDefault ? "builtin" : "default"} teamDefault={teamDefault} />
          <Liveness />
        </div>
      </div>

      {note && <div className="ccw-hint ov-note" data-testid="team-default-unavailable">{note}</div>}

      <AttentionBlock d={d} />

      <Safe><KpiStrip problems={problems} health={d.health} stats={d.stats} /></Safe>

      <LazyGroup title="Open problems" hue="#ef4444" topic="page.overview">
        <div className="dm-grid">
          <Safe><TopIssues problems={problems} health={d.health} err={d.corrErr} /></Safe>
          <Safe><RcaPathPanel top={top} err={d.corrErr} /></Safe>
          <Safe><ImpactSummary problems={problems} err={d.corrErr} /></Safe>
          <Safe><RcaCoverage stats={d.stats} err={d.statsErr} /></Safe>
        </div>
      </LazyGroup>

      <LazyGroup title="What is broken now" hue="#f97316">
        <div className="ov-grid">
          <RegistryCell type="active-alerts" span={6} />
          <div className="col-6"><Safe><TopHealthContributors health={d.health} err={d.healthErr} /></Safe></div>
          <RegistryCell type="bgp-peers" span={6} />
          <RegistryCell type="ospf-nbrs" span={6} />
          <div className="col-12"><Safe><RcaPanel title="Hot paths" to="investigate/paths/wan-circuits"><PathHealthList limit={5} /></RcaPanel></Safe></div>
        </div>
      </LazyGroup>

      <LazyGroup title="Health by site" hue="#14b8a6">
        <Safe><SiteHealth /></Safe>
      </LazyGroup>

      <LazyGroup title="What changed" hue="#8b5cf6">
        <div className="dm-grid">
          <Safe><WhatChanged /></Safe>
          <Safe><CapacityOutlook /></Safe>
        </div>
      </LazyGroup>

      <LazyGroup title="Is data arriving" hue="#3b82f6">
        <div className="ov-grid">
          <div className="col-6"><Safe><TelemetryCoverage health={d.health} err={d.healthErr} /></Safe></div>
          <RegistryCell type="site-availability" span={6} title="Devices reachable" />
          {platformAdmin && <div className="col-6"><Safe><PlatformHealth /></Safe></div>}
          {platformAdmin && <div className="col-6"><Safe><InternalMonitoringChecks internal={internalObjects(d.corr)} /></Safe></div>}
        </div>
      </LazyGroup>

      <LazyGroup title="Traffic and resources" hue="#06b6d4" defaultOpen={false}>
        <div className="ov-grid">
          <RegistryCell type="traffic" span={8} />
          <RegistryCell type="tunnels-health" span={4} />
          <RegistryCell type="if-util-topn" span={6} />
          <RegistryCell type="sat-cpu" span={3} />
          <RegistryCell type="sat-mem" span={3} />
        </div>
      </LazyGroup>
    </div>
  );
}
