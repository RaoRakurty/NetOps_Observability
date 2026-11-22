// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// panelRegistry.tsx — what My dashboards can place: the telemetry panels of
// pages/panels.tsx PLUS the Overview's answer-first panels (verdicts, the next
// step, impact, health by site…). Before this, a custom dashboard could not show
// a single RCA panel — the main gap for this product (Overview merge plan).
//
// An RCA panel takes the shared read from the surrounding OverviewDataProvider
// (one correlations / health / stats fetch per tick for the whole dashboard);
// placed alone it brings its own provider. These panels draw their own title,
// so the builder does not add a second one ("selfTitled").

import type { ReactNode } from "react";
import PathHealthList from "../../components/PathHealthList";
import { PANELS, PANEL_CATEGORIES, type PanelDef } from "../panels";
import { OverviewDataProvider, useSharedOverviewData, type OverviewData } from "./useOverviewData";
import { customerProblems, topProblem } from "./overviewModel";
import { AttentionBlock, SiteHealth } from "./boardParts";
import {
  CapacityOutlook, ImpactSummary, KpiStrip, RcaCoverage, RcaPanel, RcaPathPanel, TelemetryCoverage,
  TopHealthContributors, TopIssues, WhatChanged,
} from "./rcaPanels";

export type BoardPanelDef = Omit<PanelDef, "category"> & { category: string; selfTitled?: boolean };

function Inner({ draw }: { draw: (d: OverviewData) => ReactNode }) {
  return <>{draw(useSharedOverviewData()!)}</>;
}

/** Renders with the shared read, bringing a provider when there is none. */
function WithData({ draw }: { draw: (d: OverviewData) => ReactNode }) {
  const shared = useSharedOverviewData();
  if (shared) return <>{draw(shared)}</>;
  return <OverviewDataProvider><Inner draw={draw} /></OverviewDataProvider>;
}

const problemsOf = (d: OverviewData) => (d.corr ? customerProblems(d.corr) : undefined);

const RCA_CATEGORY = "Problems and RCA";

const rca = (type: string, title: string, defaultSpan: number, render: () => JSX.Element, drill?: string): BoardPanelDef =>
  ({ type, title, defaultSpan, category: RCA_CATEGORY, render, drill, selfTitled: true });

export const RCA_PANELS: Record<string, BoardPanelDef> = {
  "overview-attention": rca("overview-attention", "What needs attention", 12, () => <WithData draw={(d) => <AttentionBlock d={d} />} />),
  "overview-kpis": rca("overview-kpis", "Overview KPIs", 12, () => <WithData draw={(d) => <KpiStrip problems={problemsOf(d)} health={d.health} stats={d.stats} />} />),
  "rca-top-issues": rca("rca-top-issues", "Top active issues", 6, () => <WithData draw={(d) => <TopIssues problems={problemsOf(d)} health={d.health} err={d.corrErr} />} />, "operations/queue"),
  "rca-path": rca("rca-path", "Where the fault is", 6, () => <WithData draw={(d) => { const p = problemsOf(d); return <RcaPathPanel top={p ? topProblem(p) : undefined} err={d.corrErr} />; }} />, "investigate/rca"),
  "rca-impact": rca("rca-impact", "Impact", 6, () => <WithData draw={(d) => <ImpactSummary problems={problemsOf(d)} err={d.corrErr} />} />, "investigate/topology"),
  "rca-coverage": rca("rca-coverage", "RCA coverage", 6, () => <WithData draw={(d) => <RcaCoverage stats={d.stats} err={d.statsErr} />} />, "investigate/rca"),
  "rca-contributors": rca("rca-contributors", "Top health contributors", 6, () => <WithData draw={(d) => <TopHealthContributors health={d.health} err={d.healthErr} />} />, "operations/alerts"),
  "telemetry-coverage": rca("telemetry-coverage", "Telemetry coverage", 6, () => <WithData draw={(d) => <TelemetryCoverage health={d.health} err={d.healthErr} />} />),
  "site-health": rca("site-health", "Health by site", 12, () => <SiteHealth />, "infrastructure/sites/map"),
  "what-changed": rca("what-changed", "What changed", 6, () => <WhatChanged />, "explore/logs"),
  "capacity-outlook": rca("capacity-outlook", "Capacity outlook", 6, () => <CapacityOutlook />, "analytics/interface-performance"),
  "hot-paths": rca("hot-paths", "Hot paths", 12, () => <RcaPanel title="Hot paths" to="investigate/paths/wan-circuits"><PathHealthList limit={5} /></RcaPanel>, "investigate/paths/measured"),
};

/** Everything a dashboard can place, the RCA panels first. */
export const BOARD_PANELS: Record<string, BoardPanelDef> = { ...RCA_PANELS, ...PANELS };

/** The "Add panel" picker's groups, in display order. */
export const BOARD_CATEGORIES: { category: string; types: string[] }[] = [
  { category: RCA_CATEGORY, types: Object.keys(RCA_PANELS) },
  ...PANEL_CATEGORIES.map((c) => ({ category: String(c.category), types: c.types })),
];
