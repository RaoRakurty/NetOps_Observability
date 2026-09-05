// BgpOps — the consolidated BGP operations page (product wave item 10,
// 2026-08-25), rebuilt as a SINGLE-SCREEN outage view (owner, 2026-09-03:
// "put all the data into one page so that a NOC admin gets a single view during
// an outage without clicking so much").
//
// LAYOUT IS THE FEATURE. The design of record is
// docs/design/research/BGP_OPS_CONSOLIDATION_RESEARCH_2026-08-25.md §(b) "The
// one-page incident view (top to bottom)", and its ordering is implemented
// literally:
//
//   1 verdict bar (prefix + origin, incident class, visibility, RPKI)  — pinned
//   2 current paths from N vantage points (AS-path graph + path table)  ┐ left
//   3 updates timeline (churn + near-live feed)                        ┘ column
//   4 RPKI · 5 incidents · 6 peers · 7 bogons · 8 ownership (RDAP)     ┐ right
//   9 geofeed · 10 ASPA                                                ┘ column
//
// Three items of that list are DELIBERATELY ABSENT rather than faked: the IRR
// consistency strip (no IRR mirror is built, so there is no data to be
// consistent with), on-demand looking-glass verification (not built), and
// third-party corroboration (license-blocked / not built). The page says so in
// its footer instead of showing an empty box that reads as "clean".
//
// EVERY SECTION RENDERS ON LOAD. There is no tab switcher any more — during an
// outage a tab is a question the operator has to answer before they can see the
// evidence. Long lists are capped to their first N rows with an explicit "show
// all" (pages/bgp/Section.tsx), which is also what keeps this page's DOM inside
// its render budget (perf/budgets.json, `bgp-ops`).
//
// Honest by construction, unchanged: each panel fails independently and SAYS so
// (never blank, never fabricated).

import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api, type BgpAlert, type BgpAlertStatus, type BgpIncident, type BgpIncidentClass,
  type BgpStatusResp, type BgpUpdatesResp, type BgpWatchEntry,
} from "../services/api";
import { NocHeader, Chip } from "../components/noc";
import Icon from "../components/Icon";
import { operatorError } from "../lib/errors";
import { Section, SubBlock } from "./bgp/Section";
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
 *  bounded poll in spirit: slow enough to be free, fast enough that an operator
 *  watching the screen sees a class change without reloading. */
const WATCH_POLL_MS = 30_000;

/** A panel that has not loaded its chunk yet says so — never an empty gap. */
function PanelFallback({ label }: { label: string }) {
  return <div className="bgp-sec"><div className="empty">Loading {label}…</div></div>;
}

// ── small pure helpers (exported for tests) ──────────────────────────────────

export type RpkiTone = { label: string; tone: string; detail: string };

/** Map a RIPEstat rpki-validation status onto the page's verdict chip. */
export function rpkiVerdict(status: string | undefined, origin?: string): RpkiTone {
  switch ((status || "").toLowerCase()) {
    case "valid":
      return { label: "RPKI VALID", tone: "var(--ok)", detail: `ROA covers the announcement${origin ? ` by ${origin}` : ""}` };
    case "invalid":
      return { label: "RPKI INVALID", tone: "var(--crit)", detail: "The announcement violates a published ROA — possible hijack or stale ROA" };
    case "invalid_asn":
      return { label: "RPKI INVALID (origin)", tone: "var(--crit)", detail: "A ROA exists but names a different origin AS" };
    case "invalid_length":
      return { label: "RPKI INVALID (length)", tone: "var(--crit)", detail: "More specific than the ROA's maxLength allows" };
    case "unknown":
    case "not-found":
    case "notfound":
      return { label: "No ROA", tone: "var(--muted)", detail: "No ROA covers this prefix — publishing one protects it" };
    default:
      return { label: "RPKI —", tone: "var(--muted)", detail: "Verdict unavailable" };
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
  // ASPA is a property of an AS, so for a prefix lookup we ask about the AS that
  // is ACTUALLY announcing it (from the live routing status) — never a guess.
  const aspaAsn = useMemo(() => {
    if (status?.kind === "asn") return status.resource;
    const origin = status?.rpki_origin ?? (rs?.last_seen?.origin ? `AS${String(rs.last_seen.origin).replace(/^AS/i, "").split(/[{},]/).filter(Boolean)[0]}` : "");
    return origin || undefined;
  }, [status, rs]);
  const prefixResource = status?.kind === "prefix" ? status.resource : undefined;

  return (
    <div className="dm-board cc-board bgp-page">
      <NocHeader
        title="BGP Operations"
        subtitle="One screen for the outage call — verdict, paths, updates, RPKI, incidents, peers, bogons and registry ownership, all on load."
        chips={<>
          <Chip label={`${watch.length} watched`} />
          {openIncidents > 0 && <Chip label={`${openIncidents} with an open class`} tone="var(--warn)" />}
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
            <Icon name="search" size={14} /> {busy ? "Checking…" : "Investigate"}
          </button>
        </form>
        <div className="bgp-chips" aria-label="Watched resources">
          {watch.length === 0 && (
            <span className="mini-meta">Nothing is watched yet — investigate a resource and watch it to pin it here.</span>
          )}
          {watch.map((w) => {
            const t = incidents[w.resource] ? incidentTone(incidents[w.resource].class) : null;
            return (
              <button key={w.resource} className={`chip-btn ${w.resource === active ? "chip-btn-on" : ""}`}
                title={w.note || w.resource} onClick={() => { setQuery(w.resource); investigate(w.resource); }}>
                <span className="mono">{w.resource}</span>
                {t && t.label !== "OK" && <span className="bgp-chip-dot" style={{ background: t.tone }} title={t.detail} />}
              </button>
            );
          })}
        </div>
      </div>

      {err && <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>}

      {/* ── 1. VERDICT BAR — pinned. Everything below is evidence for it. ──── */}
      <div className="bgp-verdict-wrap">
        <Section
          id="verdict"
          title="Verdict"
          updatedAt={statusAt}
          actions={status && (
            watched ? (
              <button className="btn-ghost" style={{ fontSize: 11 }}
                onClick={() => api.bgpWatchDelete(status.resource).then(loadWatch)
                  .catch((e: Error) => setErr(`Watchlist update failed: ${e.message || "error"}`))}>
                <Icon name="check" size={12} /> Watching — remove
              </button>
            ) : (
              <button className="btn-ghost" style={{ fontSize: 11 }}
                onClick={() => api.bgpWatchAdd(status.resource).then(loadWatch)
                  .catch((e: Error) => setErr(`Watchlist update failed: ${e.message || "error"}`))}>
                <Icon name="alerts" size={12} /> Watch this {status.kind === "asn" ? "ASN" : "prefix"}
              </button>
            )
          )}
        >
          {!status && !busy && (
            <div className="empty">
              No resource is selected. Pick a watched resource above, or investigate one — every section below then
              answers about that resource.
            </div>
          )}
          {!status && busy && <div className="empty">Reading the global routing story for {active}…</div>}

          {status && (
            <>
              <div className="bgp-verdict">
                <span className="device-name">{status.resource}</span>
                {activeTone && <Chip label={activeTone.label} tone={activeTone.tone} title={activeTone.detail} />}
                {activeIncident && (
                  <span className="mini-meta" title="When this class started">
                    since {new Date(activeIncident.since).toLocaleString()}
                  </span>
                )}
                {rs?.announced === false && <Chip label="NOT ANNOUNCED" tone="var(--crit)" title="No RIS peer currently sees this prefix" />}
                {rs?.announced && rs.last_seen?.origin && (
                  <Chip label={`origin AS${String(rs.last_seen.origin).replace(/^AS/i, "")}`} title={`Last seen ${rs.last_seen.time ?? ""}`} />
                )}
                {vis !== null && (
                  <Chip
                    label={`visibility ${(vis * 100).toFixed(0)}%`}
                    tone={vis > 0.9 ? "var(--ok)" : vis > 0.5 ? "var(--warn)" : "var(--crit)"}
                    title="Share of RIPE RIS full-feed peers currently seeing this resource"
                  />
                )}
                {status.kind === "prefix" && <Chip label={rpki.label} tone={rpki.tone} title={rpki.detail} />}
              </div>
              {activeIncident?.summary && <p className="mini-meta" style={{ margin: "4px 0 0" }}>{activeIncident.summary}</p>}
              {(status.routing_status_error || status.rpki_error) && (
                <p className="mini-meta" style={{ color: "var(--warn)", margin: "4px 0 0" }}>
                  {status.routing_status_error && <>Routing status unavailable: {status.routing_status_error}. </>}
                  {status.rpki_error && <>RPKI verdict unavailable: {status.rpki_error}.</>}
                </p>
              )}
            </>
          )}
        </Section>
      </div>

      {/* ── the dense two-column grid. Left = the outage narrative in time
             order; right = the standing evidence panels. ────────────────────── */}
      <div className="bgp-grid">
        <div className="bgp-col">

          {/* 2. Current paths from N vantage points */}
          <Section id="paths" title="Current paths from route collectors" updatedAt={statusAt}>
            <Suspense fallback={<div className="empty">Loading the AS-path graph…</div>}>
              <AsPathGraphPanel bare prefix={prefixResource} />
            </Suspense>

            <SubBlock title="Paths seen by route collectors">
              {!status && <div className="empty">No resource is selected.</div>}
              {status && status.kind !== "prefix" && (
                <div className="empty">Route-collector paths are per PREFIX. Look up one of this AS's prefixes to see them.</div>
              )}
              {status?.paths_error && (
                <p className="mini-meta" style={{ color: "var(--warn)" }}>Path data unavailable: {status.paths_error}</p>
              )}
              {status?.kind === "prefix" && !status.paths_error && pathGroups.length === 0 && (
                <div className="empty">No paths observed.</div>
              )}
              {pathGroups.length > 0 && (
                <div className="bgp-scroll">
                  <table className="tbl bgp-tbl" style={{ width: "100%" }}>
                    <thead>
                      <tr><th className="num">Peers</th><th>AS path (collector → origin)</th></tr>
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
                                    title={i === g.path.length - 1 ? "Origin AS" : undefined}>AS{asn}</span>
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

          {/* 3. Updates timeline — churn over the local window, then the feed */}
          <Section id="updates" title="Updates timeline" updatedAt={updatesAt}>
            <SubBlock title="Update churn — last 8h">
              {!status && <div className="empty">No resource is selected.</div>}
              {status && !updates && <div className="empty">Reading updates…</div>}
              {updates && churn.length === 0 && (
                <div className="empty">Quiet — no BGP updates for this resource in the window. That is good news.</div>
              )}
              {churn.length > 0 && (
                <div className="bgp-churn">
                  {churn.map(([hour, a, w]) => (
                    <div key={hour} className="bgp-churn-col"
                      title={`${hour}:00Z — ${a} announce, ${w} withdraw`}>
                      <div className="bgp-churn-w" style={{ height: `${(w / churnMax) * 100}%` }} />
                      <div className="bgp-churn-a" style={{ height: `${(a / churnMax) * 100}%` }} />
                      <span className="bgp-churn-l">{hour.slice(11)}h</span>
                    </div>
                  ))}
                </div>
              )}
              <p className="mini-meta" style={{ marginBottom: 0 }}>
                <span style={{ color: "var(--accent)" }}>■</span> announcements · <span style={{ color: "var(--crit)" }}>■</span> withdrawals — bursts of withdrawals across many peers are the signature of an outage or a flap.
              </p>
            </SubBlock>

            <Suspense fallback={<div className="empty">Loading the near-live feed…</div>}>
              <LiveFeedPanel bare />
            </Suspense>
          </Section>
        </div>

        <div className="bgp-col">
          {/* 4. RPKI */}
          <Suspense fallback={<PanelFallback label="RPKI" />}>
            <RpkiPanel resource={prefixResource} />
          </Suspense>

          {/* 5. Incidents — the watchlist WITH its class and evidence, plus the
                 alert history. ONE classifier drives this and the pager. */}
          <Suspense fallback={<PanelFallback label="the incident list" />}>
            <PrefixesPanel
              watch={watch} incidents={incidents} incidentsNote={incidentsNote}
              status={alertStatus} alerts={alerts} active={active} updatedAt={watchAt}
              onInvestigate={(r) => { setQuery(r); investigate(r); }}
            />
          </Suspense>

          {/* 5b. The policy those verdicts came from. It sits directly under the
                 incidents it decides, so an operator who disagrees with a
                 verdict can change the rule without leaving the screen. */}
          <Suspense fallback={<PanelFallback label="the alert policy" />}>
            <AlertPolicyPanel status={alertStatus} />
          </Suspense>

          {/* 6. Peers */}
          <Suspense fallback={<PanelFallback label="the peers table" />}>
            <PeersPanel incidents={incidentList} />
          </Suspense>

          {/* 7. Bogons */}
          <Suspense fallback={<PanelFallback label="the bogon listing" />}>
            <BogonsPanel />
          </Suspense>

          {/* 8. Ownership & contacts (RDAP) */}
          <Section id="ownership" title="Ownership & contacts" updatedAt={whoisAt}>
            {!status && <div className="empty">No resource is selected.</div>}
            {status && whois == null && <div className="empty">Registry lookup…</div>}
            {whois != null && (
              <>
                {(whois as { name?: string }).name && (
                  <p style={{ marginTop: 0 }}><strong>{(whois as { name?: string }).name}</strong></p>
                )}
                {contacts.length === 0 ? (
                  <div className="empty">The registry returned no contact entities.</div>
                ) : (
                  <ul className="bgp-contacts">
                    {contacts.map((c, i) => (
                      <li key={i}>
                        {c.name} {c.roles.length > 0 && <span className="mini-meta">({c.roles.join(", ")})</span>}
                      </li>
                    ))}
                  </ul>
                )}
                <p className="mini-meta" style={{ marginBottom: 0 }}>Authoritative registry data via RDAP.</p>
              </>
            )}
          </Section>

          {/* 9. Geofeed */}
          <Suspense fallback={<PanelFallback label="the geofeed" />}>
            <GeofeedPanel resource={status?.resource} />
          </Suspense>

          {/* 10. ASPA */}
          <Suspense fallback={<PanelFallback label="ASPA" />}>
            <AspaCard asn={aspaAsn} />
          </Suspense>
        </div>
      </div>

      {/* What this screen deliberately does NOT show. Naming the gaps is the
          honest alternative to an empty panel that reads as a clean result. */}
      <p className="mini-meta bgp-footer">
        Not on this screen, because the data does not exist here yet: IRR route-object consistency (no IRR mirror is
        built), on-demand looking-glass verification, and third-party corroboration feeds. They are absent rather than
        empty — see the BGP capability tracker.
      </p>

      {/* RIPE attribution: a LICENSE CONDITION of the RIS/RIPEstat data, not decoration. */}
      <p className="mini-meta">
        Routing data from <a href="https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/" target="_blank" rel="noreferrer">RIPE NCC RIS / RIPEstat</a>.
      </p>
    </div>
  );
}
