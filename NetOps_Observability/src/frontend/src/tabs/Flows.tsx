// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Flows — Explore → Flows (P1 of the Flows page redesign, 2026-11-12).
//
// The unit of the page is a LINK (device · interface). Interface utilisation
// is the anchor and the flows explain it. Three tabs, the tab carried in the
// route's third segment so each is deep-linkable, plus a drawer:
//
//   #/explore/flows           Right now   — busiest links, one link in detail
//   #/explore/flows/talking   Who is talking — conversations, apps, ports…
//   #/explore/flows/capacity  Capacity    — per-link 95th percentile, headroom, reaches 90 %
//   "About this data"           sources, sampling, coverage, datasets
//
// Deep link (from an RCA case's traffic lane):
//   #/explore/flows?device=<exporter>&if=<ifIndex>&from=<iso>&to=<iso>
// opens Right now with that link selected, an exact window around the problem
// (P2: the link APIs take from/to), and the problem window marked.
//
// Refresh: ONE clock for the page (lib/refreshTick). Only the visible tab is
// mounted, so only it re-reads, and nothing re-reads while the browser tab is
// hidden. #/flows and #/explore/flows alias here (nav.tsx).

import { useCallback, useEffect, useMemo, useState } from "react";
import { Segmented } from "../components/ui";
import { RefreshTickContext, useRefreshTick } from "../lib/refreshTick";
import { fmtDateTime } from "../lib/time";
import RightNow from "./flows/RightNow";
import WhoIsTalking from "./flows/WhoIsTalking";
import Capacity from "./flows/Capacity";
import AboutData from "./flows/AboutData";
import {
  linkKey, parseDeepLink, tabFromHash, flowsHref, flowsWindow,
  type DeepLink, type TalkFilters, type FlowsTab,
} from "./flows/flowsModel";

export const REFRESH_MS = 30_000;

const TABS: { value: FlowsTab; label: string }[] = [
  { value: "now", label: "Right now" },
  { value: "talking", label: "Who is talking" },
  { value: "capacity", label: "Capacity" },
];

export default function Flows({ rangeMinutes = 60 }: { rangeMinutes?: number } = {}) {
  const [tab, setTab] = useState<FlowsTab>(() => tabFromHash(location.hash));
  const [link, setLink] = useState<DeepLink>(() => parseDeepLink(location.hash));
  const [filters, setFilters] = useState<TalkFilters>(() => {
    const l = parseDeepLink(location.hash);
    return l.device ? { device: l.device, if: l.ifIndex, ifDir: l.ifIndex ? "either" : undefined } : {};
  });
  const [includePlatform, setIncludePlatform] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const tick = useRefreshTick(REFRESH_MS);

  // The route is the source of truth for the tab and the deep link, so the
  // browser's back button and a pasted link behave.
  useEffect(() => {
    const on = () => {
      setTab(tabFromHash(location.hash));
      setLink(parseDeepLink(location.hash));
    };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);

  // Recomputed per render on purpose: "the last N seconds" moves with the clock.
  const win = useMemo(() => flowsWindow(rangeMinutes * 60, link), [rangeMinutes, link, tick]);
  const selected = link.device && link.ifIndex ? linkKey(link.device, link.ifIndex) : "";

  const go = useCallback((next: FlowsTab, l: DeepLink = link) => {
    const h = flowsHref(l, next);
    if (location.hash !== h) window.history.replaceState(null, "", h);
    setTab(next);
    setLink(l);
  }, [link]);

  const select = useCallback((l: { exporter: string; ifIndex: string } | null) => {
    go("now", l ? { ...link, device: l.exporter, ifIndex: l.ifIndex } : { from: link.from, to: link.to });
  }, [go, link]);

  const talkers = useCallback((l: { exporter: string; ifIndex: string }) => {
    setFilters((f) => ({ ...f, device: l.exporter, if: l.ifIndex, ifDir: "either" }));
    go("talking", { ...link, device: l.exporter, ifIndex: l.ifIndex });
  }, [go, link]);

  return (
    <RefreshTickContext.Provider value={tick}>
      <div className="flows-page" data-testid="flows-page">
        <div className="tr-head">
          <h2>Flows</h2>
          <Segmented<FlowsTab> value={tab} ariaLabel="Flows tabs" options={TABS} onChange={(t) => go(t)} />
          <button className="btn-ghost tr-about-btn" onClick={() => setAboutOpen(true)} aria-haspopup="dialog">About this data</button>
        </div>

        {win.problem && (
          <div className="tr-banner" role="status" data-testid="problem-banner">
            <span>Problem window {fmtDateTime(win.problem.from)} – {fmtDateTime(win.problem.to)}</span>
            <button className="btn-ghost" onClick={() => go(tab, { device: link.device, ifIndex: link.ifIndex })}>Show the usual window</button>
          </div>
        )}

        {tab === "now" && (
          <RightNow
            win={win}
            ftype=""
            includePlatform={includePlatform}
            selected={selected}
            onSelect={select}
            onTalkers={talkers}
          />
        )}
        {tab === "talking" && (
          <WhoIsTalking since={win.since} filters={filters} onFilters={setFilters} includePlatform={includePlatform} />
        )}
        {tab === "capacity" && <Capacity win={win} onOpenLink={select} />}

        <AboutData
          open={aboutOpen}
          onClose={() => setAboutOpen(false)}
          since={win.since}
          includePlatform={includePlatform}
          onIncludePlatform={setIncludePlatform}
        />
      </div>
    </RefreshTickContext.Provider>
  );
}
