// BgpOps — the consolidated BGP operations page (product wave item 10,
// 2026-08-25). One screen for the outage call: global verdict, RPKI, AS-paths
// from RIPE's route collectors, update churn, and registry ownership — the
// five browser tabs a NOC engineer used to juggle. Design authority:
// docs/design/research/BGP_OPS_CONSOLIDATION_RESEARCH_2026-08-25.md.
//
// v0.9 data spine = the api's cached RIPEstat/RDAP proxy. The RIS Live local
// buffer upgrades the timeline to realtime later WITHOUT changing this page's
// shape. Honest by construction: each panel fails independently and SAYS so
// (never blank, never fabricated).

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api, type BgpStatusResp, type BgpUpdatesResp, type BgpWatchEntry,
} from "../services/api";
import { NocHeader, Chip } from "../components/noc";
import Icon from "../components/Icon";

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

// ── page ─────────────────────────────────────────────────────────────────────

const panelCss: React.CSSProperties = { marginTop: 12 };

export default function BgpOps() {
  const [watch, setWatch] = useState<BgpWatchEntry[]>([]);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState("");
  const [status, setStatus] = useState<BgpStatusResp | null>(null);
  const [updates, setUpdates] = useState<BgpUpdatesResp | null>(null);
  const [whois, setWhois] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const loadWatch = useCallback(() => {
    api.bgpWatchlist().then((r) => setWatch(r.watchlist)).catch(() => setWatch([]));
  }, []);
  useEffect(loadWatch, [loadWatch]);

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
        setStatus(s);
        // Secondary panels load after the verdict — independent failures stay quiet
        // in the corner of their own panel, never on the page.
        api.bgpUpdates(r, 8).then((u) => { if (fresh()) setUpdates(u); }).catch(() => { if (fresh()) setUpdates(null); });
        api.bgpWhois(r).then((w) => { if (fresh()) setWhois(w.rdap); }).catch(() => { if (fresh()) setWhois(null); });
      })
      .catch((e: Error) => { if (fresh()) setErr(e.message || "lookup failed"); })
      .finally(() => { if (fresh()) setBusy(false); });
  }, []);

  const rs = status?.routing_status;
  const vis = useMemo(() => visibilityFraction(rs), [rs]);
  const rpki = useMemo(() => rpkiVerdict(status?.rpki?.status, status?.rpki_origin), [status]);
  const pathGroups = useMemo(() => groupPaths(status?.paths).slice(0, 8), [status]);
  const churn = useMemo(() => bucketUpdates(updates?.updates), [updates]);
  const contacts = useMemo(() => rdapContacts(whois), [whois]);
  const watched = watch.some((w) => w.resource === status?.resource);

  return (
    <div className="dm-board cc-board">
      <NocHeader
        title="BGP Operations"
        subtitle="Routing status, RPKI, AS-paths, update churn and registry ownership — one screen for the outage call."
        chips={<Chip label={`${watch.length} watched`} />}
      />

      {/* entry row: search + watchlist */}
      <div className="card" style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <form
          style={{ display: "flex", gap: 8, flex: "1 1 320px" }}
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
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {watch.map((w) => (
            <button key={w.resource} className={`chip-btn ${w.resource === active ? "chip-btn-on" : ""}`}
              title={w.note || w.resource} onClick={() => { setQuery(w.resource); investigate(w.resource); }}>
              <span className="mono">{w.resource}</span>
            </button>
          ))}
        </div>
      </div>

      {err && <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>}

      {status && (
        <>
          {/* verdict hero */}
          <div className="card" style={panelCss}>
            <div style={{ display: "flex", gap: 18, alignItems: "baseline", flexWrap: "wrap" }}>
              <span className="device-name" style={{ fontSize: 22 }}>{status.resource}</span>
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
            {(status.routing_status_error || status.rpki_error) && (
              <p className="mini-meta" style={{ color: "var(--warn)", marginBottom: 0 }}>
                {status.routing_status_error && <>Routing status unavailable: {status.routing_status_error}. </>}
                {status.rpki_error && <>RPKI verdict unavailable: {status.rpki_error}.</>}
              </p>
            )}
            <div style={{ marginTop: 8 }}>
              {watched ? (
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
              )}
            </div>
          </div>

          {/* AS paths */}
          {status.kind === "prefix" && (
            <div className="card" style={panelCss}>
              <h2>Paths seen by route collectors</h2>
              {status.paths_error && <p className="mini-meta" style={{ color: "var(--warn)" }}>Path data unavailable: {status.paths_error}</p>}
              {!status.paths_error && pathGroups.length === 0 && <div className="empty">No paths observed.</div>}
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {pathGroups.map((g) => (
                  <div key={g.path.join(" ")} style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                    <span className="badge" title="Route-collector peers seeing this exact path">{g.count}×</span>
                    {g.path.map((asn, i) => (
                      <span key={`${asn}-${i}`} style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                        {i > 0 && <span style={{ color: "var(--muted)" }}>→</span>}
                        <span className="mono" style={{
                          padding: "2px 8px", borderRadius: 999, border: "1px solid var(--border)",
                          background: i === g.path.length - 1 ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "var(--surface)",
                          fontSize: 12,
                        }} title={i === g.path.length - 1 ? "Origin AS" : undefined}>
                          AS{asn}
                        </span>
                      </span>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* update churn */}
          <div className="card" style={panelCss}>
            <h2>Update churn — last 8h</h2>
            {!updates && <div className="empty">Loading updates…</div>}
            {updates && churn.length === 0 && <div className="empty">Quiet — no BGP updates for this resource in the window. That is good news.</div>}
            {churn.length > 0 && (
              <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 90, overflowX: "auto", paddingTop: 6 }}>
                {churn.map(([hour, a, w]) => {
                  const max = Math.max(...churn.map(([, x, y]) => x + y), 1);
                  return (
                    <div key={hour} title={`${hour}:00Z — ${a} announce, ${w} withdraw`}
                      style={{ display: "flex", flexDirection: "column", justifyContent: "flex-end", gap: 1, minWidth: 22, height: "100%" }}>
                      <div style={{ height: `${(w / max) * 100}%`, background: "var(--crit)", borderRadius: 2, opacity: 0.85 }} />
                      <div style={{ height: `${(a / max) * 100}%`, background: "var(--accent)", borderRadius: 2, opacity: 0.85 }} />
                      <span className="mini-meta" style={{ fontSize: 9, textAlign: "center" }}>{hour.slice(11)}h</span>
                    </div>
                  );
                })}
              </div>
            )}
            <p className="mini-meta" style={{ marginBottom: 0 }}>
              <span style={{ color: "var(--accent)" }}>■</span> announcements · <span style={{ color: "var(--crit)" }}>■</span> withdrawals — bursts of withdrawals across many peers are the signature of an outage or a flap.
            </p>
          </div>

          {/* ownership */}
          <div className="card" style={panelCss}>
            <h2>Ownership & contacts</h2>
            {!whois && <div className="empty">Registry lookup…</div>}
            {whois != null && (
              <>
                {(whois as { name?: string }).name && (
                  <p style={{ marginTop: 0 }}><strong>{(whois as { name?: string }).name}</strong></p>
                )}
                {contacts.length === 0 ? (
                  <div className="empty">The registry returned no contact entities.</div>
                ) : (
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
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
          </div>
        </>
      )}

      {!status && !err && (
        <div className="empty" style={{ marginTop: 16 }}>
          Enter a prefix or ASN — or pick a watched resource — to see its global routing story.
        </div>
      )}

      {/* RIPE attribution: a LICENSE CONDITION of the RIS/RIPEstat data, not decoration. */}
      <p className="mini-meta" style={{ marginTop: 16 }}>
        Routing data from <a href="https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/" target="_blank" rel="noreferrer">RIPE NCC RIS / RIPEstat</a>.
      </p>
    </div>
  );
}
