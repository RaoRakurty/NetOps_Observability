// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// BgpOps — the consolidated BGP operations page (product wave item 10,
// 2026-08-25), rebuilt as a SINGLE-SCREEN outage view (owner, 2026-09-03:
// "put all the data into one page so that a NOC admin gets a single view during
// an outage without clicking so much") and rewritten FOR THAT NOC ADMIN on
// 2026-09-06:
//
//   "There is too much jargon. Make it brief, NOC admin doesn't need all the
//    jargon. Each section should just show what NOC admin wants to see. Also
//    fonts are too small looks hard on eye. Readjust the panels and fit all of
//    them in harmony and make watchable font, elegant and crisp and easy on
//    eye."
//
// THREE THINGS THAT CHANGED, AND ONE THAT DID NOT.
//
//  1. PLAIN LANGUAGE. Every heading is now a question a NOC admin actually
//     asks — "Is BGP healthy?", "Sessions down or flapping", "Route changes",
//     "Prefix origin problems", "What to do next". The protocol word (RPKI,
//     ASPA, bogon, BMP, geofeed) is not gone; it moved to the section's
//     secondary line and to the chip tooltips, where an engineer still finds it
//     and a NOC admin never has to read it.
//
//  2. NOTHING WAS DELETED — IT WAS DEMOTED. Every panel, every row and every
//     caveat this page carried is still here. Provenance, protocol caveats and
//     long explanations moved behind a `Details` disclosure (pages/bgp/Section.tsx)
//     so a section shows the thing you act on first.
//
//  3. TYPE AND GRID. Body 14px, tables 14px, headings 16px, KPI numbers 30px,
//     12.5px the floor anywhere (captions only). The two ragged flex columns
//     became ONE grid whose cards span either one column (always paired, so a
//     row is never half-empty) or both — equal gutters, aligned tops,
//     equal-height cards per row, and tables that scroll inside their own card
//     so the page never scrolls sideways at 1366px or 1920px.
//
//     Layout, top to bottom (each line is one grid ROW):
//        health bar (pinned) · four KPI tiles
//        what to do next          | sessions down or flapping
//        route changes .................................. (full width)
//        how the internet reaches this prefix ........... (full width)
//        prefixes you're watching | prefix origin problems
//        alert rules              | addresses that should never be routed
//        who owns this space      | approved upstream providers
//        where this space is used ....................... (full width)
//
//     "Alert rules" stays directly beneath "Prefixes you're watching" (both in
//     the left column) because the verdicts above it are that policy's output —
//     the 2026-09-05 reason for pairing them is preserved by the grid.
//
// UI-WORDS SWEEP 5 (tracker 270, 2026-09-06). The owner asked again, wider:
// "remove the jargon and lots of words across the site … instead train the Iris
// AI to answer those questions." So the three `Details` disclosures this page
// carried (how the to-do list is built · where the RDAP record comes from ·
// what the screen deliberately does not show) are authored files under
// ai/skills/explain/, reached from the `(i)` that now sits where the paragraph
// was. Nothing lost a CLAIM — only word count moved. Small print that states a
// FACT (a timestamp, a server-returned summary, a failed read, a contact role,
// the RIPE licence line) is `.fact-line`, not `.mini-meta`: a stated fact is not
// an explanatory note, and the word-budget guard counts notes.
//
// WHAT DID NOT CHANGE: every section still renders on load (no tabs — a tab is
// a question the operator has to answer before they can see the evidence), long
// lists are still capped with an explicit "show all" (which is what keeps this
// page inside its render budget, perf/budgets.json `bgp-ops`), each panel still
// fails independently and SAYS so, and the page still names the evidence it
// deliberately does NOT have rather than showing an empty box that reads clean.

import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api, type BgpAlert, type BgpAlertStatus, type BgpIncident, type BgpIncidentClass,
  type BgpStatusResp, type BgpUpdatesResp, type BgpWatchEntry,
} from "../services/api";
import { NocHeader, Chip } from "../components/noc";
import Icon from "../components/Icon";
import AskIris from "../components/AskIris";
import { operatorError } from "../lib/errors";
import { Kpi, Kpis, Section, SubBlock } from "./bgp/Section";
import { incidentTone } from "./bgp/bgpAlerts.model";
// Each panel owns its own fetch and its own failure, so a dead geofeed or an
// unreachable validator never blanks the page. Lazy so the React Flow graph and
// the heavy tables never ride in this route's first chunk.
const RpkiPanel = lazy(() => import("./bgp/RpkiPanel"));
const AspaCard = lazy(() => import("./bgp/AspaCard"));
const GeofeedPanel = lazy(() => import("./bgp/GeofeedPanel"));
const LiveFeedPanel = lazy(() => import("./bgp/LiveFeedPanel"));
const AsPathGraphPanel = lazy(() => import("./bgp/AsPathGraphPanel"));
const PrefixesPanel = lazy(() => import("./bgp/PrefixesPanel"));
const PeersPanel = lazy(() => import("./bgp/PeersPanel"));
const BogonsPanel = lazy(() => import("./bgp/BogonsPanel"));
const AlertPolicyPanel = lazy(() => import("./bgp/AlertPolicyPanel"));

/** Watchlist + alert-history refresh cadence. Matches the near-live feed's own
 *  bounded fetch in spirit: slow enough to be free, fast enough that an operator
 *  watching the screen sees a class change without reloading. */
const WATCH_POLL_MS = 30_000;

/** A panel that has not loaded its chunk yet says so — never an empty gap. */
function PanelFallback({ label }: { label: string }) {
  return <div className="bgp-sec"><div className="empty">Loading {label}…</div></div>;
}

// ── small pure helpers (exported for tests) ──────────────────────────────────

export type RpkiTone = { label: string; tone: string; detail: string };

/**
 * Map a RIPEstat rpki-validation status onto the page's health chip.
 *
 * The LABEL is the NOC admin's sentence; "RPKI" and "ROA" live in the tooltip.
 * The wire status strings are untouched — only the wording an operator reads.
 */
export function rpkiVerdict(status: string | undefined, origin?: string): RpkiTone {
  switch ((status || "").toLowerCase()) {
    case "valid":
      return {
        label: "Origin authorised", tone: "var(--ok)",
        detail: `RPKI valid — a ROA authorises this announcement${origin ? ` by ${origin}` : ""}.`,
      };
    case "invalid":
      return {
        label: "Origin not authorised", tone: "var(--crit)",
        detail: "RPKI invalid — the announcement breaks a published ROA. Possible hijack, or a stale ROA of your own.",
      };
    case "invalid_asn":
      return {
        label: "Wrong origin AS", tone: "var(--crit)",
        detail: "RPKI invalid — a ROA exists but authorises a different origin AS.",
      };
    case "invalid_length":
      return {
        label: "Prefix too specific", tone: "var(--crit)",
        detail: "RPKI invalid — more specific than the ROA's maxLength allows.",
      };
    case "unknown":
    case "not-found":
    case "notfound":
      return {
        label: "Not protected", tone: "var(--muted)",
        detail: "No ROA covers this prefix — publishing one is what lets the internet drop a hijack of it.",
      };
    default:
      return { label: "Origin check unavailable", tone: "var(--muted)", detail: "The origin check did not answer." };
  }
}

/** Visibility fraction 0..1 across v4+v6 RIS peers, or null when unknown. */
export function visibilityFraction(s: BgpStatusResp["routing_status"]): number | null {
  const v4 = s?.visibility?.v4, v6 = s?.visibility?.v6;
  const seeing = (v4?.ris_peers_seeing ?? 0) + (v6?.ris_peers_seeing ?? 0);
  const total = (v4?.total_ris_peers ?? 0) + (v6?.total_ris_peers ?? 0);
  if (!total) return null;
  return seeing / total;
}

/** Compress an AS path string ("3333 1234 1234 64500") to unique hops. */
export function compressPath(path: string): string[] {
  const out: string[] = [];
  for (const hop of path.trim().split(/\s+/)) {
    if (hop && out[out.length - 1] !== hop) out.push(hop);
  }
  return out;
}

/** Group looking-glass peers by their (compressed) AS path; most-seen first. */
export function groupPaths(paths: BgpStatusResp["paths"]): { path: string[]; count: number }[] {
  const seen = new Map<string, number>();
  for (const rrc of paths?.rrcs ?? []) {
    for (const p of rrc.peers ?? []) {
      if (!p.as_path) continue;
      const key = compressPath(p.as_path).join(" ");
      seen.set(key, (seen.get(key) ?? 0) + 1);
    }
  }
  return [...seen.entries()]
    .map(([k, count]) => ({ path: k.split(" "), count }))
    .sort((a, b) => b.count - a.count);
}

/** Bucket updates per hour for the churn strip: [hourIso, announces, withdrawals]. */
export function bucketUpdates(u: BgpUpdatesResp["updates"] | undefined): [string, number, number][] {
  const buckets = new Map<string, [number, number]>();
  for (const ev of u?.updates ?? []) {
    if (!ev.timestamp) continue;
    const hour = ev.timestamp.slice(0, 13);
    const b = buckets.get(hour) ?? [0, 0];
    if ((ev.type || "").toUpperCase().startsWith("W")) b[1]++;
    else b[0]++;
    buckets.set(hour, b);
  }
  return [...buckets.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([h, [a, w]]) => [h, a, w]);
}

/** An AS in any of the notations RIPEstat hands back ("AS64500", "{64500}",
 *  64500) reduced to its digits, or "" when there is nothing usable. */
export function normalizeAsn(v: string | number | undefined | null): string {
  if (v == null) return "";
  const first = String(v).replace(/^AS/i, "").split(/[{},\s]/).filter(Boolean)[0] ?? "";
  return /^\d+$/.test(first) ? first : "";
}

/** The three numbers the "Route changes" section leads with. */
export type RouteChangeTotals = {
  /** Announcements in the window — the prefix being (re)learned by the internet. */
  learned: number;
  /** Withdrawals in the window. */
  withdrawn: number;
  /**
   * Announcements that arrived carrying an origin AS OTHER than the one this
   * resource is currently seen with. `null` = we cannot say, which is a
   * different fact from zero and is rendered differently: it is null when no
   * current origin is known, or when not one update carried an AS path.
   */
  suspicious: number | null;
};

/**
 * Count learned / withdrawn / suspicious route changes over the fetched window.
 *
 * "Suspicious" is deliberately a MEASURED definition, not a vibe: an
 * announcement whose path ends on a different AS than the origin currently seen
 * for this resource. That is exactly the shape of a hijack or a mis-origination,
 * and when we have no origin to compare against we say so instead of printing a
 * reassuring zero.
 */
export function updateTotals(
  u: BgpUpdatesResp["updates"] | undefined,
  currentOrigin?: string | number,
): RouteChangeTotals {
  const want = normalizeAsn(currentOrigin);
  let learned = 0, withdrawn = 0, suspicious = 0, comparable = 0;
  for (const ev of u?.updates ?? []) {
    const isWithdraw = (ev.type || "").toUpperCase().startsWith("W");
    if (isWithdraw) { withdrawn++; continue; }
    learned++;
    const path = ev.attrs?.path;
    if (!want || !path?.length) continue;
    comparable++;
    if (normalizeAsn(path[path.length - 1]) !== want) suspicious++;
  }
  return { learned, withdrawn, suspicious: comparable > 0 ? suspicious : null };
}

/** One line of the "What to do next" list: the action, and why it is on screen. */
export type NextStep = { title: string; why: string };

/**
 * The actions a NOC admin can take on what this page currently shows.
 *
 * Pure, and derived ONLY from measurements already on the screen — this list
 * never invents a finding a panel below it is not also showing. Worst first,
 * capped at five so it stays a to-do list rather than a second dashboard, and
 * it always returns at least one line: an empty action list would read as
 * "nothing is wrong" even when the truth is "nothing has been checked".
 */
export function nextSteps(input: {
  resource?: string;
  incident?: BgpIncident;
  announced?: boolean;
  visibility: number | null;
  /** The raw rpki-validation status for the selected prefix, if any. */
  rpkiStatus?: string;
  watched: boolean;
  alertingEnabled: boolean;
}): NextStep[] {
  const { resource, incident, announced, visibility, rpkiStatus, watched, alertingEnabled } = input;
  if (!resource) {
    return [{
      title: "Pick a prefix or AS above",
      why: "Every section on this page answers about the one resource you select.",
    }];
  }

  const out: NextStep[] = [];
  const classes: BgpIncidentClass[] = incident ? [incident.class, ...(incident.also ?? [])] : [];
  const has = (c: BgpIncidentClass) => classes.includes(c);

  if (has("origin_change")) {
    out.push({
      title: "Call your upstream — someone else is announcing this prefix",
      why: "Ask them to filter the announcement, and confirm nobody on your side changed which AS originates it.",
    });
  }
  if (has("rpki_invalid") || rpkiStatus?.toLowerCase().startsWith("invalid")) {
    out.push({
      title: "Check the origin authorisation you published for this prefix",
      why: "The announcement does not match it. Either the record is out of date, or the announcement is not yours.",
    });
  }
  if (has("bogon")) {
    out.push({
      title: "Filter this prefix at your edge",
      why: "It is reserved or private address space and must never be carried in the global routing table.",
    });
  }
  if (has("route_leak")) {
    out.push({
      title: "Ask the unexpected carrier to stop announcing it",
      why: "A network outside your declared upstreams is carrying this prefix — traffic is taking a path you did not buy.",
    });
  }
  if (announced === false) {
    out.push({
      title: "Confirm you are still announcing this prefix",
      why: "No public route collector currently sees it, so most of the internet cannot reach it.",
    });
  } else if (has("visibility_loss") || (visibility !== null && visibility <= 0.9)) {
    out.push({
      title: "Check the session to your upstream",
      why: "Part of the internet is not seeing this prefix. A dropped or filtered session is the usual cause.",
    });
  }
  if (out.length === 0 && !watched) {
    out.push({
      title: "Add this to the watchlist",
      why: "Watched prefixes are re-checked on their own and raise an alert; an unwatched one is only checked when you look.",
    });
  }
  if (out.length === 0 && !alertingEnabled) {
    out.push({
      title: "Turn on automatic BGP checks",
      why: "Nothing is being evaluated between visits to this page, so a quiet screen is not proof of a quiet network.",
    });
  }
  if (out.length === 0) {
    out.push({
      title: "Nothing needs doing right now",
      why: incident
        ? "This resource is announced, its origin is the expected one, and enough collectors see it."
        : "No problem was found on the checks that ran. Watch it to have that checked continuously.",
    });
  }
  return out.slice(0, 5);
}

// RDAP entities → a flat contact list (name + roles), defensively parsed.
export function rdapContacts(rdap: unknown): { name: string; roles: string[] }[] {
  const out: { name: string; roles: string[] }[] = [];
  const doc = rdap as { name?: string; entities?: unknown[] } | null;
  for (const e of (doc?.entities ?? []) as { roles?: string[]; vcardArray?: unknown }[]) {
    let name = "";
    const v = e.vcardArray as [string, [string, unknown, string, unknown][]] | undefined;
    if (Array.isArray(v) && Array.isArray(v[1])) {
      for (const item of v[1]) {
        if (Array.isArray(item) && item[0] === "fn" && typeof item[3] === "string") name = item[3];
      }
    }
    if (name || e.roles?.length) out.push({ name: name || "(unnamed)", roles: e.roles ?? [] });
  }
  return out.slice(0, 8);
}

/**
 * Worst-first ordering of the incident vocabulary. An operator opening this page
 * mid-outage should land on the prefix that is actually broken, not on whichever
 * one happens to sort first alphabetically.
 *
 * `unknown` deliberately ranks ABOVE `none`: an unmeasured prefix is an absent
 * measurement, not a clean one, and is worth looking at before a measured-quiet
 * one.
 */
const CLASS_RANK: Record<BgpIncidentClass, number> = {
  origin_change: 0, rpki_invalid: 1, bogon: 2, route_leak: 3,
  visibility_loss: 4, unknown: 5, none: 6,
};

/**
 * Which watched resource the page opens on: the worst-classified one, else the
 * first watched entry, else nothing. Pure so the choice is testable and so the
 * page never "helpfully" moves an operator off the resource they picked.
 */
export function pickInitial(
  watch: BgpWatchEntry[],
  incidents: Record<string, BgpIncident>,
): string {
  let best = "";
  let bestRank = Number.POSITIVE_INFINITY;
  for (const w of watch) {
    const cls = incidents[w.resource]?.class;
    const rank = cls ? CLASS_RANK[cls] : CLASS_RANK.unknown;
    if (rank < bestRank) { bestRank = rank; best = w.resource; }
  }
  return best || watch[0]?.resource || "";
}

// ── page ─────────────────────────────────────────────────────────────────────

export default function BgpOps() {
  const [watch, setWatch] = useState<BgpWatchEntry[]>([]);
  const [incidents, setIncidents] = useState<Record<string, BgpIncident>>({});
  const [incidentsNote, setIncidentsNote] = useState<string | undefined>();
  const [alerts, setAlerts] = useState<BgpAlert[]>([]);
  const [alertStatus, setAlertStatus] = useState<BgpAlertStatus | undefined>();
  const [watchAt, setWatchAt] = useState<number | null>(null);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState("");
  const [status, setStatus] = useState<BgpStatusResp | null>(null);
  const [statusAt, setStatusAt] = useState<number | null>(null);
  const [updates, setUpdates] = useState<BgpUpdatesResp | null>(null);
  const [updatesAt, setUpdatesAt] = useState<number | null>(null);
  const [whois, setWhois] = useState<unknown>(null);
  const [whoisAt, setWhoisAt] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const loadWatch = useCallback(() => {
    // The watchlist call carries the incident class per prefix (tracker #5), so
    // one request feeds both the chip row and the incidents section.
    api.bgpWatchlist()
      .then((r) => {
        setWatch(r.watchlist);
        setIncidents(r.incidents ?? {});
        setIncidentsNote(r.incidents_note);
        setWatchAt(Date.now());
      })
      .catch(() => { setWatch([]); setIncidents({}); });
    // The alert history is its own request and fails independently — a dead
    // evaluator must not blank the watchlist.
    api.bgpAlerts()
      .then((r) => { setAlerts(r.alerts); setAlertStatus(r.status); })
      .catch(() => { setAlerts([]); setAlertStatus(undefined); });
  }, []);
  useEffect(loadWatch, [loadWatch]);

  // Auto-refresh: a NOC screen left open during an outage must not go stale in
  // silence. Every section carries its own "upd HH:MM:SS" stamp so the operator
  // can see exactly how old each answer is.
  useEffect(() => {
    const id = window.setInterval(loadWatch, WATCH_POLL_MS);
    return () => window.clearInterval(id);
  }, [loadWatch]);

  // Latest-wins guard: each investigation bumps the sequence, and every setter
  // (including the secondary panel loads) checks it before touching state — a
  // slow response from an earlier lookup must never overwrite the one the
  // user asked for last. Same staleness discipline as the `cancelled`/`alive`
  // flags the effect-driven pages use.
  const investSeq = useRef(0);

  const investigate = useCallback((resource: string) => {
    const r = resource.trim();
    if (!r) return;
    const seq = ++investSeq.current;
    const fresh = () => seq === investSeq.current;
    setActive(r); setBusy(true); setErr(""); setStatus(null); setUpdates(null); setWhois(null);
    api.bgpStatus(r)
      .then((s) => {
        if (!fresh()) return;
        setStatus(s); setStatusAt(Date.now());
        // Secondary panels load after the verdict — independent failures stay quiet
        // in the corner of their own panel, never on the page.
        api.bgpUpdates(r, 8)
          .then((u) => { if (fresh()) { setUpdates(u); setUpdatesAt(Date.now()); } })
          .catch(() => { if (fresh()) setUpdates(null); });
        api.bgpWhois(r)
          .then((w) => { if (fresh()) { setWhois(w.rdap); setWhoisAt(Date.now()); } })
          .catch(() => { if (fresh()) setWhois(null); });
      })
      .catch((e: Error) => { if (fresh()) setErr(operatorError(e, "The lookup could not be completed.")); })
      .finally(() => { if (fresh()) setBusy(false); });
  }, []);

  // Open on the worst watched resource, ONCE. After that the selection is the
  // operator's — a later poll must never move them off what they are reading.
  const autoPicked = useRef(false);
  useEffect(() => {
    if (autoPicked.current || active || watch.length === 0) return;
    const pick = pickInitial(watch, incidents);
    if (!pick) return;
    autoPicked.current = true;
    setQuery(pick);
    investigate(pick);
  }, [watch, incidents, active, investigate]);

  const rs = status?.routing_status;
  const vis = useMemo(() => visibilityFraction(rs), [rs]);
  const rpki = useMemo(() => rpkiVerdict(status?.rpki?.status, status?.rpki_origin), [status]);
  const pathGroups = useMemo(() => groupPaths(status?.paths).slice(0, 8), [status]);
  const churn = useMemo(() => bucketUpdates(updates?.updates), [updates]);
  const churnMax = useMemo(() => Math.max(...churn.map(([, a, w]) => a + w), 1), [churn]);
  const contacts = useMemo(() => rdapContacts(whois), [whois]);
  const watched = watch.some((w) => w.resource === status?.resource);
  const incidentList = useMemo(() => Object.values(incidents), [incidents]);
  const openIncidents = useMemo(
    () => incidentList.filter((i) => i.class !== "none").length,
    [incidentList],
  );
  const activeIncident = active ? incidents[active] : undefined;
  const activeTone = activeIncident ? incidentTone(activeIncident.class) : null;
  const totals = useMemo(
    () => updateTotals(updates?.updates, rs?.last_seen?.origin),
    [updates, rs],
  );
  const todo = useMemo(() => nextSteps({
    resource: status?.resource,
    incident: activeIncident,
    announced: rs?.announced,
    visibility: vis,
    rpkiStatus: status?.rpki?.status,
    watched,
    alertingEnabled: !!alertStatus?.enabled,
  }), [status, activeIncident, rs, vis, watched, alertStatus]);
  // ASPA is a property of an AS, so for a prefix lookup we ask about the AS that
  // is ACTUALLY announcing it (from the live routing status) — never a guess.
  const aspaAsn = useMemo(() => {
    if (status?.kind === "asn") return status.resource;
    const digits = normalizeAsn(status?.rpki_origin ?? rs?.last_seen?.origin);
    return digits ? `AS${digits}` : undefined;
  }, [status, rs]);
  const prefixResource = status?.kind === "prefix" ? status.resource : undefined;

  return (
    <div className="dm-board cc-board bgp-page">
      <NocHeader
        title="BGP Operations"
        subtitle="One screen for the outage call: is BGP healthy, what changed, what is down, and what to do about it."
        chips={<>
          <Chip label={`${watch.length} watched`} />
          {openIncidents > 0 && <Chip label={`${openIncidents} needing attention`} tone="var(--warn)" />}
        </>}
      />

      {/* Selector: the watchlist as chips plus the free-form lookup. Picking a
          chip drives EVERY section below — that is the whole point of the page. */}
      <div className="bgp-selector">
        <form
          className="bgp-find"
          onSubmit={(e) => { e.preventDefault(); investigate(query); }}
        >
          <input
            className="input"
            style={{ flex: 1, fontFamily: "var(--font-mono)" }}
            placeholder="203.0.113.0/24 · 2001:db8::/32 · AS64500"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Prefix or ASN"
          />
          <button className="btn-accent" type="submit" disabled={busy}>
            <Icon name="search" size={14} /> {busy ? "Checking…" : "Check it"}
          </button>
        </form>
        <div className="bgp-chips" aria-label="Watched resources">
          {watch.length === 0 && (
            <span className="fact-line">Nothing is watched yet. Check a prefix, then Watch it.</span>
          )}
          {watch.map((w) => {
            const t = incidents[w.resource] ? incidentTone(incidents[w.resource].class) : null;
            return (
              <button key={w.resource} className={`chip-btn ${w.resource === active ? "chip-btn-on" : ""}`}
                title={w.note || w.resource} onClick={() => { setQuery(w.resource); investigate(w.resource); }}>
                <span className="mono">{w.resource}</span>
                {t && t.label !== "Healthy" && <span className="bgp-chip-dot" style={{ background: t.tone }} title={t.detail} />}
              </button>
            );
          })}
        </div>
      </div>

      {err && <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>}

      {/* ── 1. THE ANSWER — pinned. Everything below is evidence for it. ────── */}
      <div className="bgp-verdict-wrap">
        <Section
          id="verdict"
          title="Is BGP healthy?"
          sub="The one-line answer for the prefix or AS selected above"
          updatedAt={statusAt}
          actions={status && (
            <>
              {watched ? (
                <button className="btn-ghost" style={{ fontSize: 13 }}
                  onClick={() => api.bgpWatchDelete(status.resource).then(loadWatch)
                    .catch((e: Error) => setErr(`Watchlist update failed: ${e.message || "error"}`))}>
                  <Icon name="check" size={13} /> Watching — remove
                </button>
              ) : (
                <button className="btn-ghost" style={{ fontSize: 13 }}
                  onClick={() => api.bgpWatchAdd(status.resource).then(loadWatch)
                    .catch((e: Error) => setErr(`Watchlist update failed: ${e.message || "error"}`))}>
                  <Icon name="alerts" size={13} /> Watch this {status.kind === "asn" ? "ASN" : "prefix"}
                </button>
              )}
              <AskIris topic="bgp.watchlist-checks" label="Watching a prefix" />
            </>
          )}
        >
          {!status && !busy && (
            <div className="empty">
              No resource is selected. Pick a watched one above, or type a prefix or AS — every section below then
              answers about that one.
            </div>
          )}
          {!status && busy && <div className="empty">Checking how the internet sees {active}…</div>}

          {status && (
            <>
              <div className="bgp-verdict">
                <span className="device-name">{status.resource}</span>
                {activeTone && <Chip label={activeTone.label} tone={activeTone.tone} title={activeTone.detail} />}
                {activeIncident && (
                  <span className="fact-line" title="When this state started">
                    since {new Date(activeIncident.since).toLocaleString()}
                  </span>
                )}
                {rs?.announced === false && <Chip label="Not announced" tone="var(--crit)" title="No public route collector currently sees this prefix." />}
                {rs?.announced && rs.last_seen?.origin && (
                  <Chip label={`Origin AS${normalizeAsn(rs.last_seen.origin) || String(rs.last_seen.origin)}`}
                    title={`The AS announcing it. Last seen ${rs.last_seen.time ?? ""}`} />
                )}
                {vis !== null && (
                  <>
                    <Chip
                      label={`Seen by ${(vis * 100).toFixed(0)}% of collectors`}
                      tone={vis > 0.9 ? "var(--ok)" : vis > 0.5 ? "var(--warn)" : "var(--crit)"}
                      title="Share of public RIPE RIS full-feed collectors currently seeing this resource."
                    />
                    <AskIris topic="bgp.visibility" label="Seen by collectors" />
                  </>
                )}
                {status.kind === "prefix" && <Chip label={rpki.label} tone={rpki.tone} title={rpki.detail} />}
              </div>
              {activeIncident?.summary && <p className="fact-line" style={{ margin: "6px 0 0" }}>{activeIncident.summary}</p>}
              {(status.routing_status_error || status.rpki_error) && (
                <p className="fact-line fact-warn" style={{ margin: "6px 0 0" }}>
                  {status.routing_status_error && <>Routing status unavailable: {status.routing_status_error}. </>}
                  {status.rpki_error && <>Origin check unavailable: {status.rpki_error}.</>}
                </p>
              )}
            </>
          )}
        </Section>
      </div>

      {/* ── the grid. Whole rows only: a card spans one column (always paired)
             or both, so tops align, heights match and no row ends half-empty. */}
      <div className="bgp-grid">

        {/* the four numbers a NOC admin reads from across the room */}
        <div className="bgp-kpis bgp-wide" role="group" aria-label="At a glance">
          <Kpi
            n={watch.length}
            label="Prefixes watched"
            interp={alertStatus?.enabled ? "Re-checked automatically" : "Automatic checks off"}
            tone={watch.length === 0 ? "var(--muted)" : undefined}
            title="Prefixes or ASNs on this tenant's watchlist. Only these are checked between visits."
          />
          <Kpi
            n={openIncidents}
            label="Needing attention"
            interp={openIncidents === 0 ? "Nothing flagged" : "See the watchlist"}
            tone={openIncidents > 0 ? "var(--crit)" : "var(--ok)"}
            title="Watched resources whose latest check found something other than healthy."
          />
          <Kpi
            n={vis === null ? "—" : `${(vis * 100).toFixed(0)}%`}
            label="Reaching the internet"
            interp={vis === null ? "Not measured" : "Collectors seeing it"}
            tone={vis === null ? "var(--muted)" : vis > 0.9 ? "var(--ok)" : vis > 0.5 ? "var(--warn)" : "var(--crit)"}
            title="Share of public route collectors currently seeing this resource. A dash is not a zero."
          />
          <Kpi
            n={totals.learned + totals.withdrawn}
            label="Route changes (8 h)"
            interp={totals.withdrawn > 0 ? `${totals.withdrawn} of them withdrawals` : "No withdrawals"}
            tone={totals.withdrawn > 0 ? "var(--warn)" : undefined}
            title="Announcements plus withdrawals seen for the selected resource over the fetched window."
          />
        </div>

        {/* 2. what to do next — actions, never a second dashboard */}
        <Section
          id="next-steps"
          title="What to do next"
          sub="Actions for what is on screen now"
          updatedAt={statusAt}
          actions={<AskIris topic="bgp.next-steps" label="What to do next" />}
        >
          <ul className="bgp-todo">
            {todo.map((s) => (
              <li key={s.title}>
                <div>
                  <div className="bgp-todo-t">{s.title}</div>
                  <div className="bgp-todo-w">{s.why}</div>
                </div>
              </li>
            ))}
          </ul>
        </Section>

        {/* 3. sessions down or flapping (own routers) */}
        <Suspense fallback={<PanelFallback label="the sessions table" />}>
          <PeersPanel incidents={incidentList} />
        </Suspense>

        {/* 4. route changes — learned / withdrawn / suspicious, then the feed */}
        <Section
          id="updates"
          title="Route changes"
          sub="Learned, withdrawn, and unexpected origins"
          updatedAt={updatesAt}
          actions={<AskIris topic="bgp.suspicious-announcements" label="Suspicious" />}
          wide
        >
          <Kpis cols={3}>
            <Kpi n={totals.learned} label="Routes learned"
              interp="In this window"
              title="Announcements seen for this resource over the fetched window." />
            <Kpi n={totals.withdrawn} label="Routes withdrawn"
              interp={totals.withdrawn > 0 ? "In this window" : "None"}
              tone={totals.withdrawn > 0 ? "var(--crit)" : undefined}
              title="Withdrawals seen for this resource over the fetched window." />
            <Kpi
              n={totals.suspicious === null ? "—" : totals.suspicious}
              label="Suspicious"
              interp={totals.suspicious === null ? "Cannot tell" : "From another AS"}
              tone={totals.suspicious === null ? "var(--muted)" : totals.suspicious > 0 ? "var(--crit)" : "var(--ok)"}
              title="Announcements whose AS path ends on a different AS than the current origin. A dash is not a zero."
            />
          </Kpis>

          <SubBlock title="Last 8 hours">
            {!status && <div className="empty">No resource is selected.</div>}
            {status && !updates && <div className="empty">Reading route changes…</div>}
            {updates && churn.length === 0 && (
              <div className="empty">Quiet — no BGP updates for this resource in the window. That is good news.</div>
            )}
            {churn.length > 0 && (
              <div className="bgp-churn">
                {churn.map(([hour, a, w]) => (
                  <div key={hour} className="bgp-churn-col"
                    title={`${hour}:00Z — ${a} learned, ${w} withdrawn`}>
                    <div className="bgp-churn-w" style={{ height: `${(w / churnMax) * 100}%` }} />
                    <div className="bgp-churn-a" style={{ height: `${(a / churnMax) * 100}%` }} />
                    <span className="bgp-churn-l">{hour.slice(11)}h</span>
                  </div>
                ))}
              </div>
            )}
            <p className="mini-meta bgp-legend">
              <span><span style={{ color: "var(--accent)" }}>■</span> learned</span>
              <span><span style={{ color: "var(--crit)" }}>■</span> withdrawn</span>
              <span>
                A burst of withdrawals means an outage or a flap.
                <AskIris topic="bgp.withdrawal-burst" label="Routes withdrawn" />
              </span>
            </p>
          </SubBlock>

          <Suspense fallback={<div className="empty">Loading the latest changes…</div>}>
            <LiveFeedPanel bare />
          </Suspense>
        </Section>

        {/* 5. how the internet reaches this prefix */}
        <Section
          id="paths"
          title="How the internet reaches this prefix"
          sub="AS paths seen by public route collectors"
          updatedAt={statusAt}
          wide
        >
          <Suspense fallback={<div className="empty">Loading the path map…</div>}>
            <AsPathGraphPanel bare prefix={prefixResource} />
          </Suspense>

          <SubBlock title="Paths in use">
            {!status && <div className="empty">No resource is selected.</div>}
            {status && status.kind !== "prefix" && (
              <div className="empty">Collector paths are per PREFIX. Look up one of this AS&apos;s prefixes to see them.</div>
            )}
            {status?.paths_error && (
              <p className="fact-line fact-warn">Path data unavailable: {status.paths_error}</p>
            )}
            {status?.kind === "prefix" && !status.paths_error && pathGroups.length === 0 && (
              <div className="empty">No paths observed.</div>
            )}
            {pathGroups.length > 0 && (
              <div className="bgp-scroll">
                <table className="tbl bgp-tbl" style={{ width: "100%" }}>
                  <thead>
                    <tr>
                      <th className="num">Collectors</th>
                      <th>Path to you<AskIris topic="bgp.collector-paths" label="Path to you" /></th>
                    </tr>
                  </thead>
                  <tbody>
                    {pathGroups.map((g) => (
                      <tr key={g.path.join(" ")}>
                        <td className="mono num" title="Route-collector peers seeing this exact path">{g.count}</td>
                        <td>
                          <span className="bgp-path">
                            {g.path.map((asn, i) => (
                              <span key={`${asn}-${i}`} className="bgp-hop-wrap">
                                {i > 0 && <span className="bgp-arrow">→</span>}
                                <span className={`bgp-hop${i === g.path.length - 1 ? " origin" : ""}`}
                                  title={i === g.path.length - 1 ? "Origin AS — the network announcing this prefix" : undefined}>AS{asn}</span>
                              </span>
                            ))}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </SubBlock>
        </Section>

        {/* 6. the watchlist WITH its state and evidence, plus the alert history.
               ONE classifier drives this and the pager. */}
        <Suspense fallback={<PanelFallback label="the watchlist" />}>
          <PrefixesPanel
            watch={watch} incidents={incidents} incidentsNote={incidentsNote}
            status={alertStatus} alerts={alerts} active={active} updatedAt={watchAt}
            onInvestigate={(r) => { setQuery(r); investigate(r); }}
          />
        </Suspense>

        {/* 7. prefix origin problems */}
        <Suspense fallback={<PanelFallback label="the origin check" />}>
          <RpkiPanel resource={prefixResource} />
        </Suspense>

        {/* 8. the rules those verdicts came from. It sits in the same column,
               directly under the watchlist it decides, so an operator who
               disagrees with a verdict can change the rule without leaving. */}
        <Suspense fallback={<PanelFallback label="the alert rules" />}>
          <AlertPolicyPanel status={alertStatus} />
        </Suspense>

        {/* 9. addresses that should never be routed */}
        <Suspense fallback={<PanelFallback label="the reserved-address listing" />}>
          <BogonsPanel />
        </Suspense>

        {/* 10. who owns this address space (RDAP) */}
        <Section
          id="ownership"
          title="Who owns this address space"
          sub="Registry holder and contacts, from RDAP"
          updatedAt={whoisAt}
          actions={<AskIris topic="bgp.rdap-record" label="Who owns this address space" />}
        >
          {!status && <div className="empty">No resource is selected.</div>}
          {status && whois == null && <div className="empty">Asking the registry…</div>}
          {whois != null && (
            <>
              {(whois as { name?: string }).name && (
                <p style={{ marginTop: 0, fontSize: 16, fontWeight: 650 }}>{(whois as { name?: string }).name}</p>
              )}
              {contacts.length === 0 ? (
                <div className="empty">The registry returned no contacts.</div>
              ) : (
                <ul className="bgp-contacts">
                  {contacts.map((c, i) => (
                    <li key={i}>
                      {c.name} {c.roles.length > 0 && <span className="fact-line">({c.roles.join(", ")})</span>}
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </Section>

        {/* 11. approved upstream providers (ASPA) */}
        <Suspense fallback={<PanelFallback label="the approved providers" />}>
          <AspaCard asn={aspaAsn} />
        </Suspense>

        {/* 12. where this address space is used (geofeed) */}
        <Suspense fallback={<PanelFallback label="the published locations" />}>
          <GeofeedPanel resource={status?.resource} />
        </Suspense>
      </div>

      {/* What this screen deliberately does NOT show. Naming the gaps is the
          honest alternative to an empty panel that reads as a clean result — it
          is demoted behind a disclosure, not removed. */}
      <div className="bgp-footer">
        <p className="fact-line">
          Absent here, not empty: IRR route-object consistency, looking-glass verification, third-party corroboration.
          <AskIris topic="bgp.not-shown" label="What this screen does not show" />
        </p>
        {/* RIPE attribution: a LICENSE CONDITION of the RIS/RIPEstat data, not
            decoration, so it stays in plain sight and keeps every word. */}
        <p className="fact-line">
          Routing data from <a href="https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/" target="_blank" rel="noreferrer">RIPE NCC RIS / RIPEstat</a>.
        </p>
      </div>
    </div>
  );
}
