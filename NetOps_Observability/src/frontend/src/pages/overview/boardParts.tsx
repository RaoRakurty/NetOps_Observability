// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// boardParts.tsx — the pieces Overview and My dashboards share: the liveness
// header, the lazy group, a registry cell, Health by site, and the "What needs
// attention" block. Kept apart from OverviewPage so the dashboard builder can use
// them without importing the page.

import { ReactNode, useState } from "react";
import { api } from "../../services/api";
import { fmtTime } from "../../lib/time";
import { useShell } from "../../context/shell";
import Icon from "../../components/Icon";
import AskIris from "../../components/AskIris";
import { isInternalStackAffected } from "../../components/rca/labels";
import { PANELS, useBoardHealth, usePolled } from "../panels";
import type { OverviewData } from "./useOverviewData";
import { attentionOf, customerProblems, siteHealthRows, topProblem, type SiteHealthRow } from "./overviewModel";
import { RcaPanel, RecommendedAction, Safe, TopIssueSpotlight } from "./rcaPanels";

/** Liveness from real fetches (the panel board's health signal), never a clock. */
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
  title: string; hue?: string; defaultOpen?: boolean; topic?: string; children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  // No hue = the neutral heading (visual language: a heading is not a state).
  return (
    <details className="dm-group" open={open} onToggle={(e) => setOpen((e.currentTarget as HTMLDetailsElement).open)}>
      <summary className={hue ? "dm-group-head" : "dm-group-head dm-group-neutral"} style={hue ? ({ ["--g" as string]: hue } as React.CSSProperties) : undefined}>
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

// ── What needs attention ────────────────────────────────────────────────────

/** The headline problem (or an honest quiet/degraded line) beside the one next
 *  step. Never says "nothing needs attention" while health is degraded. */
export function AttentionBlock({ d }: { d: OverviewData }) {
  const problems = d.corr ? customerProblems(d.corr) : undefined;
  const top = problems ? topProblem(problems) : undefined;
  const attention = attentionOf(problems, d.health);
  return (
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
  );
}
