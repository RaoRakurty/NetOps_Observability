// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// PathsPage — Investigate → Paths, ONE leaf with three tabs (Paths redesign P5):
// Measured paths, Tunnels and WAN circuits. Until P5 they were three sidebar
// leaves with three headers and no shared way to narrow them; now they share
// one header: the tab bar, a site filter, and the "Path data" drawer that says
// what is on and where to turn it on.
//
// ROUTING. `#/investigate/paths/<tab>`, read from the THIRD hash segment on
// mount and on every `hashchange` (the leaf stays mounted when a flyout sub-item
// is clicked, so a mount-only read would make the click look dead — the same
// reason as Digital Experience). Old addresses (#/investigate/flowtrace,
// /tunnels, /wan-paths and their older spellings) are rewritten by nav.tsx's
// alias table before this page reads them.
//
// SITE FILTER. Each tab reports the sites its rows name; the list is those, the
// choice is applied to the open tab's rows, and it is remembered per viewer in
// this browser (try/catch: storage can be missing or refuse). The time range is
// the console's own, passed to the tab that charts over time — one window for
// the whole page, never a second picker that could disagree with it.

import { useCallback, useEffect, useMemo, useState } from "react";
import AskIris from "../../components/AskIris";
import NetworkPath from "../NetworkPath";
import Tunnels from "../../tabs/Tunnels";
import WanCircuits from "../WanCircuits";
import PathData from "./PathData";
import {
  PATHS_TABS, browserStorage, loadSite, saveSite, siteOptions, tabFromHash, tabHash, type PathsTab,
} from "./pathsModel";

export default function PathsPage({ rangeMinutes = 60 }: { rangeMinutes?: number }) {
  const [tab, setTab] = useState<PathsTab>(() => tabFromHash(typeof window === "undefined" ? "" : window.location.hash));
  const [site, setSite] = useState<string>(() => loadSite(browserStorage()));
  const [labels, setLabels] = useState<string[]>([]);
  const [dataOpen, setDataOpen] = useState(false);

  useEffect(() => {
    const apply = () => setTab(tabFromHash(window.location.hash));
    apply();
    window.addEventListener("hashchange", apply);
    return () => window.removeEventListener("hashchange", apply);
  }, []);

  const open = (t: PathsTab) => {
    if (t === tab) return;
    setLabels([]);
    window.location.hash = tabHash(t);
    setTab(t);
  };

  const choose = (v: string) => {
    setSite(v);
    saveSite(browserStorage(), v);
  };

  const onSites = useCallback((next: string[]) => setLabels(next), []);
  const options = useMemo(() => siteOptions(labels), [labels]);
  // A remembered site this tab has no rows for stays chosen (the list says so),
  // so switching tabs never silently widens the view to every site.
  const missing = !!site && !options.some((o) => o.key === site);

  const tabProps = { site, onSites };

  return (
    <div className="paths-shell paths-page" data-testid="paths-page">
      <div className="paths-head">
        <h2>Paths</h2>
        <nav className="paths-tabs" role="tablist" aria-label="Paths">
          {PATHS_TABS.map((t) => (
            <button key={t.id} type="button" role="tab" id={`paths-tab-${t.id}`}
              aria-selected={tab === t.id} aria-controls="paths-panel" className="paths-tab"
              data-testid={`paths-tab-${t.id}`} onClick={() => open(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>
        <div className="paths-toolbar">
          <label className="paths-site">
            <span>Site</span>
            <select value={site} onChange={(e) => choose(e.target.value)} data-testid="paths-site" aria-label="Site">
              <option value="">All sites</option>
              {missing && <option value={site}>{site} (no rows here)</option>}
              {options.map((o) => <option key={o.key} value={o.key}>{o.label}</option>)}
            </select>
            <AskIris topic="paths.site-filter" label="Site filter" />
          </label>
          <button type="button" className="btn-ghost" data-testid="paths-data-open" onClick={() => setDataOpen(true)}>
            Path data
          </button>
        </div>
      </div>

      <div id="paths-panel" role="tabpanel" aria-labelledby={`paths-tab-${tab}`}>
        {tab === "measured" && <NetworkPath rangeMinutes={rangeMinutes} {...tabProps} />}
        {tab === "tunnels" && <Tunnels {...tabProps} />}
        {tab === "wan-circuits" && <WanCircuits {...tabProps} />}
      </div>

      <PathData open={dataOpen} onClose={() => setDataOpen(false)} />
    </div>
  );
}
