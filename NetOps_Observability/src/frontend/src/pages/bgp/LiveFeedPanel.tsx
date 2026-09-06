// LiveFeedPanel — the near-live BGP update feed.
//
// NEAR-live, and the panel says so. RIPE's RIS Live is WebSocket-only and no
// WebSocket client is on this codebase's dependency allowlist, so the producer
// is a bounded, jittered poller over RIPEstat's bgp-updates call; the server
// keeps a constant-size per-tenant ring buffer in front of it and this panel
// mirrors that ring locally with the same discipline (fixed cap, oldest
// dropped). Calling it "live" when it is one poll interval behind would be the
// dishonest choice.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, type BgpFeedResp, type BgpFeedUpdate } from "../../services/api";
import { Chip } from "../../components/noc";
import { feedCounts, mergeFeed } from "./bgpDepth.model";
import { Section, ShowAll, SubBlock, useCap } from "./Section";
import AskIris from "../../components/AskIris";

const POLL_MS = 20_000;
const CLIENT_BUFFER = 500;
/** Rows shown before the operator asks for the rest (one-page view, 2026-09-03).
 *  The buffer holds up to CLIENT_BUFFER updates; rendering all of them on load
 *  is what would blow this page's DOM budget, so the newest N are on screen and
 *  the rest are one control away. */
const FIRST_ROWS = 25;

/**
 * `bare` drops the section shell so the page can nest the feed inside its
 * "Updates timeline" section beside the churn strip — the two halves of the
 * research doc's §(b)3 belong under one heading, not in two competing cards.
 */
export function LiveFeedPanel({ bare = false }: { bare?: boolean } = {}) {
  const [updates, setUpdates] = useState<BgpFeedUpdate[]>([]);
  const [status, setStatus] = useState<BgpFeedResp["status"] | null>(null);
  const [gap, setGap] = useState(false);
  const [err, setErr] = useState("");
  const [at, setAt] = useState<number | null>(null);
  const cursor = useRef(0);

  const poll = useCallback(async (alive: () => boolean) => {
    try {
      const page = await api.bgpFeed(cursor.current, 200);
      if (!alive()) return;
      setStatus(page.status);
      setErr("");
      setAt(Date.now());
      if (page.gap) setGap(true);
      if (typeof page.next === "number") cursor.current = page.next;
      if (page.updates?.length) setUpdates((prev) => mergeFeed(prev, page.updates, CLIENT_BUFFER));
    } catch (e) {
      if (alive()) setErr((e as Error).message || "feed unavailable");
    }
  }, []);

  useEffect(() => {
    let on = true;
    const alive = () => on;
    void poll(alive);
    const id = window.setInterval(() => { void poll(alive); }, POLL_MS);
    return () => { on = false; window.clearInterval(id); };
  }, [poll]);

  const counts = feedCounts(updates);
  // Newest first: during an outage the last thirty seconds are the story.
  const newest = useMemo(() => [...updates].reverse(), [updates]);
  const cap = useCap(newest, FIRST_ROWS);

  const body = (
    <>
      {err && <p className="fact-line fact-bad" role="alert">{err}</p>}

      {status && !status.enabled && (
        <div className="empty" style={{ textAlign: "left" }}>
          <Chip label="Feed is off" tone="var(--muted)" />
          <p style={{ margin: "8px 0 0" }}>{status.note || "The near-live BGP update feed is switched off."}</p>
        </div>
      )}

      {status?.enabled && (
        <>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8, alignItems: "center" }}>
            <Chip label={status.capped ? "Paused — at capacity" : status.polling ? "Receiving" : "Idle"}
              tone={status.capped ? "var(--warn)" : status.polling ? "var(--ok)" : "var(--muted)"}
              title={status.capped ? status.note : `Every ~${status.interval ?? "60s"}, jittered`} />
            <Chip label={`${counts.announce} learned`} tone="var(--accent)" />
            <Chip label={`${counts.withdraw} withdrawn`} tone="var(--crit)" />
            <Chip label={`${status.buffered ?? 0}/${status.ring_size} held`}
              title="Keeps the most recent updates; older ones roll off." />
            {(status.dropped ?? 0) > 0 && (
              <Chip label={`${status.dropped} overwritten`} tone="var(--warn)"
                title="Updates that rolled out of the buffer before this page read them." />
            )}
          </div>

          {status.resources?.length ? (
            <p className="fact-line">Following {status.resources.length} watched resource{status.resources.length === 1 ? "" : "s"}: <span className="mono">{status.resources.join(" · ")}</span></p>
          ) : (
            <div className="empty">{status.note || "Add prefixes or ASNs to this tenant's watchlist — the feed follows the watchlist."}</div>
          )}

          {gap && (
            <p className="fact-line fact-warn">
              Some updates rolled out of the buffer before this page read them — the list below is not continuous.
            </p>
          )}

          {updates.length === 0 && status.resources?.length ? (
            <div className="empty">Nothing held yet. The first read covers the last 30 minutes.</div>
          ) : null}

          {updates.length > 0 && (
            <div className="bgp-scroll">
              <table className="dm-table bgp-tbl" style={{ width: "100%" }}>
                <thead>
                  <tr><th>Time (UTC)</th><th>Change</th><th>Prefix</th><th>Path to the origin</th><th>Seen by</th></tr>
                </thead>
                <tbody>
                  {cap.rows.map((u) => (
                    <tr key={u.seq}>
                      <td className="mono">{u.time ? new Date(u.time).toISOString().slice(11, 19) : "—"}</td>
                      <td>
                        <span style={{ color: u.type === "W" ? "var(--crit)" : "var(--accent)", fontWeight: 600 }}>
                          {u.type === "W" ? "withdrawn" : "learned"}
                        </span>
                      </td>
                      <td className="mono">{u.prefix || "—"}</td>
                      <td className="mono" style={{ fontSize: 13 }}>{u.path?.length ? u.path.join(" → ") : "—"}</td>
                      <td className="mono" style={{ fontSize: 13 }}>{u.peer || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <ShowAll cap={cap} noun="updates" />

          <p className="mini-meta" style={{ marginBottom: 0 }}>
            <strong>Near-live, not live.</strong> Read every ~{status.interval ?? "60s"}, jittered.
            <AskIris topic="bgp.near-live-feed" label="How fresh this is" />
          </p>
        </>
      )}
    </>
  );

  return bare
    ? <SubBlock title="Latest changes" updatedAt={at}>{body}</SubBlock>
    : (
      <Section
        id="updates-feed"
        title="Latest route changes"
        sub="Near-live — one read interval behind"
        updatedAt={at}
      >
        {body}
      </Section>
    );
}

export default LiveFeedPanel;
