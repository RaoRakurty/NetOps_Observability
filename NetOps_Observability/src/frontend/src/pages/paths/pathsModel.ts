// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// pathsModel.ts — the rules behind Investigate → Paths, the one page that holds
// the measurement plane (Paths redesign P5): which tab a hash opens, the shared
// site filter, and what the "Path data" drawer says is on or off. No React, no
// IO beyond the storage handle a caller passes in — every rule is unit-tested.

/** The three tabs, in display order. The ids ARE the URL: #/investigate/paths/<id>. */
export type PathsTab = "measured" | "tunnels" | "wan-circuits";

export const PATHS_TABS: readonly { id: PathsTab; label: string }[] = [
  { id: "measured", label: "Measured paths" },
  { id: "tunnels", label: "Tunnels" },
  { id: "wan-circuits", label: "WAN circuits" },
];

/** The leaf's route; a tab is the third segment. */
export const PATHS_ROUTE = "investigate/paths";

/**
 * The tab a hash opens. Reads the THIRD segment of `#/investigate/paths/<tab>`;
 * anything else (no tab, an unknown one, a query string) opens Measured paths.
 * Legacy hashes are rewritten to this form before the page sees them
 * (nav.tsx LEGACY_ROUTE_ALIAS), so only canonical spellings arrive here.
 */
export function tabFromHash(hash: string): PathsTab {
  const path = hash.replace(/^#\/?/, "").split("?")[0];
  const seg = path.split("/")[2] ?? "";
  return PATHS_TABS.some((t) => t.id === seg) ? (seg as PathsTab) : "measured";
}

/** The hash that opens a tab. */
export function tabHash(tab: PathsTab): string {
  return `#/${PATHS_ROUTE}/${tab}`;
}

/**
 * The comparison form of a site name. It mirrors the backend's siteSlug
 * (src/backend/sites.go): lower case, letters and digits kept, a run of
 * space / - / _ / . / / becomes one dash, anything else dropped. So a site's
 * label ("DC East", what Tunnels rows carry) and its slug ("dc-east", what WAN
 * rows carry) compare equal.
 */
export function siteKey(name: string | null | undefined): string {
  const s = (name ?? "").trim().toLowerCase();
  let out = "";
  let dash = false;
  for (const ch of s) {
    if ((ch >= "a" && ch <= "z") || (ch >= "0" && ch <= "9")) {
      out += ch;
      dash = false;
    } else if (" -_./".includes(ch)) {
      if (!dash && out.length > 0) {
        out += "-";
        dash = true;
      }
    }
  }
  return out.replace(/-+$/, "");
}

export interface SiteOption {
  /** siteKey of the site — what the filter stores and compares. */
  key: string;
  /** What a person reads. */
  label: string;
}

/** A label written for people (capitals or spaces) beats its slug spelling. */
function readable(label: string): number {
  return (/[A-Z]/.test(label) ? 2 : 0) + (/\s/.test(label) ? 1 : 0);
}

/**
 * The site choices for the rows a tab has loaded: one per site, whichever
 * spelling the rows used, with the most readable spelling shown. Sorted by label.
 * Empty and unplaced ends are not a site.
 */
export function siteOptions(labels: readonly (string | null | undefined)[]): SiteOption[] {
  const byKey = new Map<string, string>();
  for (const raw of labels) {
    const label = (raw ?? "").trim();
    const key = siteKey(label);
    if (!key) continue;
    const have = byKey.get(key);
    if (have === undefined || readable(label) > readable(have)) byKey.set(key, label);
  }
  return [...byKey.entries()]
    .map(([key, label]) => ({ key, label }))
    .sort((a, b) => a.label.localeCompare(b.label) || a.key.localeCompare(b.key));
}

/**
 * Whether a row placed at `labels` (a tunnel's two ends, a circuit's router, a
 * path's target) belongs to the chosen site. "" is All sites. A row with no site
 * at all is shown only under All sites.
 */
export function matchesSite(site: string, ...labels: (string | null | undefined)[]): boolean {
  if (!site) return true;
  return labels.some((l) => siteKey(l) === site);
}

/** Where the viewer's site choice is remembered (per browser, per viewer). */
export const SITE_STORAGE_KEY = "correlix.paths.site";

/** The remembered site, or "" — storage can be missing or refuse (private mode). */
export function loadSite(storage: Pick<Storage, "getItem"> | null | undefined): string {
  try {
    return siteKey(storage?.getItem(SITE_STORAGE_KEY) ?? "");
  } catch {
    return "";
  }
}

/** Remember the site; "" forgets it. A storage that refuses is not an error. */
export function saveSite(storage: Pick<Storage, "setItem" | "removeItem"> | null | undefined, site: string): void {
  try {
    if (!storage) return;
    if (site) storage.setItem(SITE_STORAGE_KEY, site);
    else storage.removeItem(SITE_STORAGE_KEY);
  } catch {
    // A full or blocked storage only means the choice is not remembered.
  }
}

/** The browser's storage, or null where reading it throws. */
export function browserStorage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

// ── "Path data" drawer ────────────────────────────────────────────────────────

/** What the drawer could read. null = could not be read (never "off"). */
export interface PathDataFacts {
  pathDiscovery: boolean | null;
  activeProbe: boolean | null;
  /** This workspace's targets that trace their path. */
  tracing: number | null;
  /** Tunnels the controller reports for this workspace. */
  tunnels: number | null;
  /** WAN interfaces found, and how many have a measured SLA. */
  wanInterfaces: number | null;
  wanMeasured: number | null;
}

export type SourceState = "on" | "off" | "unknown";

export interface PathDataItem {
  id: "discovery" | "stamp" | "tunnels" | "wan";
  title: string;
  state: SourceState;
  /** One plain sentence: what it gives, or what is missing. */
  text: string;
  /** Where to turn it on, as a console page — never a setting name. */
  href: string;
  where: string;
}

export const FEATURES_HREF = "#/platform/features";
export const NMS_HREF = "#/infrastructure/nms";
export const TARGETS_HREF = "#/operations/digital-experience/synthetics";

function plural(n: number, one: string): string {
  return `${n} ${one}${n === 1 ? "" : "s"}`;
}

/**
 * The four sources behind the Paths tabs, each with its state and where it is
 * turned on. A source that could not be read says so; it is never shown as off.
 */
export function pathDataItems(f: PathDataFacts): PathDataItem[] {
  const discovery: PathDataItem = {
    id: "discovery", title: "Path discovery", href: FEATURES_HREF, where: "Platform › Configuration › Features",
    state: f.pathDiscovery === null ? "unknown" : f.pathDiscovery ? "on" : "off",
    text: f.pathDiscovery === null
      ? "Could not be read."
      : f.pathDiscovery
        ? (f.tracing ? `On. Tracing ${plural(f.tracing, "target")}.` : "On. No targets traced yet.")
        : "Off. Measured paths stay empty until a platform administrator turns it on.",
  };
  const stamp: PathDataItem = {
    id: "stamp", title: "Path SLA probes", href: FEATURES_HREF, where: "Platform › Configuration › Features",
    state: f.activeProbe === null ? "unknown" : f.activeProbe ? "on" : "off",
    text: f.activeProbe === null
      ? "Could not be read."
      : f.activeProbe
        ? "On. Delay, jitter and loss are measured each way."
        : "Off. Path SLA and WAN circuit SLA show a dash.",
  };
  const tunnels: PathDataItem = {
    id: "tunnels", title: "SD-WAN tunnels", href: NMS_HREF, where: "Infrastructure › NMS Integrations",
    state: f.tunnels === null ? "unknown" : f.tunnels > 0 ? "on" : "off",
    text: f.tunnels === null
      ? "Could not be read."
      : f.tunnels > 0
        ? `${plural(f.tunnels, "tunnel")} reported by your controller. Quality runs 30–60 minutes behind.`
        : "No tunnels reported. Connect your SD-WAN controller.",
  };
  const wan: PathDataItem = {
    id: "wan", title: "WAN circuits", href: FEATURES_HREF, where: "Platform › Configuration › Features",
    state: f.wanInterfaces === null ? "unknown" : f.wanMeasured ? "on" : "off",
    text: f.wanInterfaces === null
      ? "Could not be read."
      : f.wanInterfaces === 0
        ? "No WAN interfaces found yet."
        : f.wanMeasured
          ? `${f.wanMeasured} of ${plural(f.wanInterfaces, "interface")} measured.`
          : `${plural(f.wanInterfaces, "interface")} found; none measured. Turn on path SLA probes.`,
  };
  return [discovery, stamp, tunnels, wan];
}
