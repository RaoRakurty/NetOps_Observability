// state.ts — routing and loading state for the Digital Experience surface.
//
// TWO THINGS LIVE HERE.
//
// 1. THE HASH ROUTE. `#/operations/digital-experience/<tab>?<filters>`. The tab
//    is read from the THIRD segment on mount and on every `hashchange` — the
//    mechanism AppObservability uses, for the same reason: the leaf component
//    stays mounted when a rail sub-item is clicked, so a mount-only effect
//    would never see the new suffix and the click would look dead.
//
//    Unlike AppObservability, this surface also PUSHES the hash when a tab or a
//    filter changes. A tab an operator cannot link to is a tab they cannot hand
//    to the next shift, and a filtered incident list that a refresh silently
//    widens is worse than one that does not filter at all.
//
// 2. THE LOAD STATE. Explicit loading / error / ready, never a fake-empty
//    fallback: "the read failed" and "there is nothing" are opposite claims and
//    a screen that renders them identically is the failure this whole surface
//    exists to avoid.

import { useCallback, useEffect, useState } from "react";

import type { DemWindow } from "../../services/api";

export const DX_ROUTE = "#/operations/digital-experience";

export const DX_TABS = [
  "experience", "incidents", "journeys", "paths", "synthetics", "changes", "data-health",
] as const;
export type DxTab = (typeof DX_TABS)[number];

export const DX_TAB_LABEL: Record<DxTab, string> = {
  experience: "Experience",
  incidents: "Incidents",
  journeys: "Journeys",
  paths: "Service Paths",
  synthetics: "Synthetics",
  changes: "Changes",
  "data-health": "Data Health",
};

export const DX_WINDOWS: readonly DemWindow[] = ["1h", "24h"];

function isTab(v: string): v is DxTab {
  return (DX_TABS as readonly string[]).includes(v);
}

/** The current hash, split into its tab and its query. Exported for the tests,
 *  which assert the URL and the state cannot disagree. */
export function parseHash(hash: string): { tab: DxTab; params: URLSearchParams } {
  const [path, query = ""] = hash.replace(/^#\/?/, "").split("?");
  const seg = path.split("/")[2] ?? "";
  return { tab: isTab(seg) ? seg : "experience", params: new URLSearchParams(query) };
}

export function buildHash(tab: DxTab, params: URLSearchParams): string {
  const q = params.toString();
  return `${DX_ROUTE}/${tab}${q ? `?${q}` : ""}`;
}

export interface DxRoute {
  tab: DxTab;
  /** Read one filter out of the URL. "" when unset — never undefined, so a
   *  control is always a controlled input. */
  get: (key: string) => string;
  setTab: (tab: DxTab) => void;
  /** Sets (or, with "", clears) one filter and pushes the new hash. */
  setParam: (key: string, value: string) => void;
}

export function useDxRoute(): DxRoute {
  const read = () => parseHash(typeof window === "undefined" ? "" : window.location.hash);
  const [state, setState] = useState(read);

  useEffect(() => {
    const apply = () => setState(read());
    apply();
    window.addEventListener("hashchange", apply);
    return () => window.removeEventListener("hashchange", apply);
  }, []);

  const setTab = useCallback((tab: DxTab) => {
    // A tab change drops the previous tab's filters on purpose: carrying an
    // incident severity onto the Changes feed would silently narrow a list the
    // operator never filtered.
    const next = buildHash(tab, new URLSearchParams());
    window.location.hash = next;
    setState(parseHash(next));
  }, []);

  const setParam = useCallback((key: string, value: string) => {
    setState((prev) => {
      const params = new URLSearchParams(prev.params.toString());
      if (value) params.set(key, value);
      else params.delete(key);
      const next = buildHash(prev.tab, params);
      window.location.hash = next;
      return { tab: prev.tab, params };
    });
  }, []);

  return {
    tab: state.tab,
    get: (key: string) => state.params.get(key) ?? "",
    setTab,
    setParam,
  };
}

export type LoadState = "loading" | "ready" | "error";

export interface Async<T> {
  data: T | null;
  status: LoadState;
  error: string;
  reload: () => void;
}

/**
 * One read, with honest states. There is deliberately no cached-stale-data
 * behaviour: when a refetch fails the screen says so rather than continuing to
 * show the previous window's numbers under the new window's label.
 */
export function useDemRead<T>(fn: () => Promise<T>, deps: unknown[]): Async<T> {
  const [data, setData] = useState<T | null>(null);
  const [status, setStatus] = useState<LoadState>("loading");
  const [error, setError] = useState("");
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    setStatus("loading");
    setError("");
    fn().then(
      (d) => { if (live) { setData(d); setStatus("ready"); } },
      (e: unknown) => {
        if (!live) return;
        setData(null);
        setError(e instanceof Error ? e.message : String(e));
        setStatus("error");
      },
    );
    return () => { live = false; };
    // The caller owns the dependency list; `fn` is rebuilt on every render by
    // design (it closes over the window and the filters).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  return { data, status, error, reload: () => setNonce((n) => n + 1) };
}
