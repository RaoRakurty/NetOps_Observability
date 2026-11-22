// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// useOverviewData — ONE read of each source the Overview's RCA panels share.
// Operations Overview polled /api/correlations seven times, /api/health/score
// five times and /api/correlations/stats twice per 20 s, one per panel; the
// merged page reads each once and hands the result to every panel. The reads go
// through usePolled, so they report into the board-health signal the page's
// liveness header reads (a failing source reads "Disconnected", never "Live").

import { createContext, createElement, useContext, type ReactNode } from "react";
import { api, type CorrObject, type CorrStats, type HealthScoreResp } from "../../services/api";
import { usePolled } from "../panels";

export const OVERVIEW_REFRESH_MS = 20_000;

/** The 30-day window matches the KPI strip and RCA coverage: a graded case older
 *  than a day still counts as open. */
export const OVERVIEW_CORR_WINDOW_S = 2_592_000;

export type OverviewData = {
  /** undefined until the first answer; [] is an answer. */
  corr: CorrObject[] | undefined;
  corrErr: boolean;
  health: HealthScoreResp | undefined;
  healthErr: boolean;
  stats: CorrStats | undefined;
  statsErr: boolean;
};

export function useOverviewData(): OverviewData {
  const corr = usePolled(() => api.correlations(120, OVERVIEW_CORR_WINDOW_S, "open"), OVERVIEW_REFRESH_MS);
  const health = usePolled(() => api.healthScore("global"), OVERVIEW_REFRESH_MS);
  const stats = usePolled(() => api.correlationsStats(), OVERVIEW_REFRESH_MS);
  return {
    corr: corr.data ? (corr.data.data ?? []) : undefined,
    corrErr: corr.err,
    health: health.data,
    healthErr: health.err,
    stats: stats.data,
    statsErr: stats.err,
  };
}

// A custom dashboard can hold several RCA panels; they share ONE read through
// this provider instead of each polling the same three endpoints.
const OverviewDataContext = createContext<OverviewData | null>(null);

export function OverviewDataProvider({ children }: { children?: ReactNode }) {
  const d = useOverviewData();
  return createElement(OverviewDataContext.Provider, { value: d }, children);
}

/** The shared read, or null outside an OverviewDataProvider. */
export function useSharedOverviewData(): OverviewData | null {
  return useContext(OverviewDataContext);
}
