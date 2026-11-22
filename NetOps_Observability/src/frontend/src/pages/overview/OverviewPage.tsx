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
// a wall clock: a failing source reads "Disconnected".

import { ReactNode, useEffect, useState } from "react";
import { api, type AuthUser } from "../../services/api";
import { fmtTime } from "../../lib/time";
import { useShell } from "../../context/shell";
import Icon from "../../components/Icon";
import AskIris from "../../components/AskIris";
import PathHealthList from "../../components/PathHealthList";
import { isInternalStackAffected } from "../../components/rca/labels";
import { PANELS, useBoardHealth, usePolled } from "../panels";
import { useOverviewData } from "./useOverviewData";
import { attentionOf, customerProblems, internalObjects, siteHealthRows, topProblem, type SiteHealthRow } from "./overviewModel";
import {
  CapacityOutlook, ImpactSummary, InternalMonitoringChecks, KpiStrip, PlatformHealth, RcaCoverage,
  RcaPanel, RcaPathPanel, RecommendedAction, Safe, TelemetryCoverage, TopHealthContributors, TopIssueSpotlight,
  TopIssues, WhatChanged,
} from "./rcaPanels";

// ── page chrome ─────────────────────────────────────────────────────────────

/** Liveness from real fetches (the panel board's health signal). */
export function Liveness() {
  const { lastOk, failing, feeds } = useBoardHealth();
  const degraded = failing > 0;
  const connecting = lastOk === null && !degraded;
  return (
    <div className="mydash-head-meta" role="status" aria-live="polite">
      {degraded ? (
        <>
          <span className="mydash-live" style={{ color: "var(--bad)" }}>
            <span className="mydash-live-dot" style={{ background: "var(--bad)", animation: "none" }} /> Disconnected
          </span>
          <span className="mydash-asof">
            {failing} of {feeds} feed{feeds === 1 ? "" : "s"} failing
            {lastOk === null ? " · no data loaded" : ` · last data ${fmtTime(new Date(lastOk))}`}
          </span>
        </>
      ) : connecting ? (
        <>
          <span className="mydash-live" style={{ color: "var(--muted)" }}>
            <span className="mydash-live-dot" style={{ background: "var(--muted)", animation: "none" }} /> Connecting
          </span>
          <span className="mydash-asof">no data loaded yet</span>
        </>
      ) : (
        <>
          <span className="mydash-live"><span className="mydash-live-dot" /> Live</span>
          <span className="mydash-asof">as of {fmtTime(new Date(lastOk!))}</span>
        </>
      )}
    </div>
  );
}

/** A collapsible group whose children exist only while it is open: a closed
 *  <details> keeps its children mounted and polling, which this host pays for. */
export function LazyGroup({ title, hue, defaultOpen = true, topic, children }: {
  title: string; hue: string; defaultOpen?: boolean; topic?: string; children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <details className="dm-group" open={open} onToggle={(e) => setOpen((e.currentTarget as HTMLDetailsElement).open)}>
      <summary className="dm-group-head" style={{ ["--g" as string]: hue } as React.CSSProperties}>
        <Icon name="chevron" size={14} className="dm-group-chevron" />
        <span>{title}</span>
        {topic && <span onClick={(e) => e.stopPropagation()}><AskIris topic={topic} label={title} /></span>}
      </summary>
      {open && <div className="dm-group-body">{children}</div>}
    </details>
  );
}

/** One registry panel (pages/panels.tsx PANELS) in a grid cell, with its drill. */
export function RegistryCell({ type, span, title }: { type: string; span: number; title?: string }) {
  const { navigate } = useShell();
  const def = PANELS[type];
  if (!def) return null;
  const label = title ?? def.title;
  return (
    <div className={`panel col-${span}`}>
      <div className="panel-tools">
        <h3>
          {def.drill ? (
            <button type="button" className="panel-title-link" onClick={() => navigate(def.drill!)}
              title="Open detail view" aria-label={`${label} — open detail view`}>
              {label}
              <Icon name="arrow-up-right" size={13} className="panel-drill-icon" />
            </button>
          ) : label}
        </h3>
      </div>
      <Safe>{def.render()}</Safe>
    </div>
  );
}

// ── Health by site ──────────────────────────────────────────────────────────

const SITE_TONE: Record<SiteHealthRow["state"], string> = {
  down: "var(--crit)", partial: "var(--warn)", up: "var(--ok)", empty: "var(--fg-subtle)",
};
const SITE_WORD: Record<SiteHealthRow["state"], string> = {
  down: "All down", partial: "Partly down", up: "All up", empty: "No devices",
};

export function SiteHealth() {
  const { data, err } = usePolled(() => api.geomap(), 60_000);
  if (err && !data) return <RcaPanel title="Health by site" state="degraded" note="The site list is not answering right now." />;
  if (!data) return <RcaPanel title="Health by site" state="inactive" note="Reading…" />;
  if (!data.geo_enabled) {
    return <RcaPanel title="Health by site" state="inactive" note="Sites are not set up."
      hint={data.reason || "Declare your sites so devices can be counted per site."} />;
  }
  const { rows, total } = siteHealthRows(data.sites, 12);
  if (total === 0) {
    return (
      <RcaPanel title="Health by site" state="ok">
        <div className="fp-empty">
          <span className="fp-empty-mark" />
          <div className="fp-empty-t">No sites declared yet.</div>
          <div className="fp-empty-h"><a href="#/infrastructure/sites/sites">Add sites</a> so devices can be counted per site.</div>
        </div>
      </RcaPanel>
    );
  }
  return (
    <RcaPanel title="Health by site" to="infrastructure/sites/map"
      action={<span>{total > rows.length ? `${rows.length} of ${total}` : `${total} site${total === 1 ? "" : "s"}`}</span>}>
      <table className="ov-sites" data-testid="overview-site-health">
        <thead><tr><th>Site</th><th>State</th><th className="num">Devices</th><th className="num">Up</th><th className="num">Down</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.slug || r.name}>
              <td>{r.name}</td>
              <td><span className="fp-tag" style={{ color: SITE_TONE[r.state], border: `1px solid ${SITE_TONE[r.state]}` }}>{SITE_WORD[r.state]}</span></td>
              <td className="num">{r.devices}</td>
              <td className="num">{r.up}</td>
              <td className="num" style={r.down > 0 ? { color: "var(--crit)", fontWeight: 600 } : undefined}>{r.down}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {(data.unplaced ?? 0) > 0 && (
        <div className="fp-empty-h">{data.unplaced} device{data.unplaced === 1 ? " is" : "s are"} not placed at any site.</div>
      )}
    </RcaPanel>
  );
}

// ── the page ────────────────────────────────────────────────────────────────

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

export default function OverviewPage({ headerExtra }: { headerExtra?: ReactNode } = {}) {
  const d = useOverviewData();
  const platformAdmin = usePlatformAdmin();
  const problems = d.corr ? customerProblems(d.corr) : undefined;
  const top = problems ? topProblem(problems) : undefined;
  const attention = attentionOf(problems, d.health);

  return (
    <div className="overview-page fp dm-board" data-testid="overview-page">
      <div className="mydash-head">
        <div>
          <h1 className="mydash-title">Overview</h1>
          <div className="ov-sub">What is broken, where, and what to do first.</div>
        </div>
        <div className="ov-head-right">
          {headerExtra}
          <Liveness />
        </div>
      </div>

      {/* What needs attention: the headline and the next step, side by side. */}
      <section className="ov-attention" aria-label="What needs attention">
        <div className="ov-attention-main">
          {attention === "problem" && top
            ? <Safe><TopIssueSpotlight top={top} /></Safe>
            : <div className="fp-spot ov-quiet" data-testid="overview-attention">
                <span className="fp-spot-text">
                  {attention === "quiet" ? "Nothing needs attention right now."
                    : attention === "unhealthy" ? `Health is ${d.health?.band} but no cause is confirmed yet — start with the health contributors.`
                    : attention === "insufficient" ? "Not enough telemetry to judge health yet — connect more signal sources."
                    : d.corrErr || d.healthErr ? "Correlation or health is not answering right now."
                    : "Reading…"}
                </span>
              </div>}
        </div>
        <div className="ov-attention-side">
          <Safe><RecommendedAction objs={d.corr ? d.corr.filter((o) => !isInternalStackAffected(o.affected)) : undefined} health={d.health} err={d.corrErr} /></Safe>
        </div>
      </section>

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
          <div className="col-12"><Safe><RcaPanel title="Hot paths" to="investigate/paths/measured"><PathHealthList limit={5} /></RcaPanel></Safe></div>
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
