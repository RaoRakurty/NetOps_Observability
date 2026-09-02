// LiveFeedPanel — the near-live BGP update feed.
//
// NEAR-live, and the panel says so. RIPE's RIS Live is WebSocket-only and no
// WebSocket client is on this codebase's dependency allowlist, so the producer
// is a bounded, jittered poller over RIPEstat's bgp-updates call; the server
// keeps a constant-size per-tenant ring buffer in front of it and this panel
// mirrors that ring locally with the same discipline (fixed cap, oldest
// dropped). Calling it "live" when it is one poll interval behind would be the
// dishonest choice.

import { useCallback, useEffect, useRef, useState } from "react";
import { api, type BgpFeedResp, type BgpFeedUpdate } from "../../services/api";
import { Chip } from "../../components/noc";
import { feedCounts, mergeFeed } from "./bgpDepth.model";

const POLL_MS = 20_000;
const CLIENT_BUFFER = 500;

export function LiveFeedPanel() {
  const [updates, setUpdates] = useState<BgpFeedUpdate[]>([]);
  const [status, setStatus] = useState<BgpFeedResp["status"] | null>(null);
  const [gap, setGap] = useState(false);
  const [err, setErr] = useState("");
  const cursor = useRef(0);

  const poll = useCallback(async (alive: () => boolean) => {
    try {
      const page = await api.bgpFeed(cursor.current, 200);
      if (!alive()) return;
      setStatus(page.status);
      setErr("");
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

  return (
    <div className="card" style={{ marginTop: 12 }}>
      <h2>Near-live update feed</h2>

      {err && <p className="mini-meta" style={{ color: "var(--bad)" }} role="alert">{err}</p>}

      {status && !status.enabled && (
        <div className="empty" style={{ textAlign: "left" }}>
          <Chip label="FEED NOT ENABLED" tone="var(--muted)" />
          <p style={{ margin: "8px 0 0" }}>{status.note || "The near-live BGP update feed is switched off."}</p>
        </div>
      )}

      {status?.enabled && (
        <>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8, alignItems: "center" }}>
            <Chip label={status.capped ? "PAUSED · poller cap" : status.polling ? "POLLING" : "IDLE"}
              tone={status.capped ? "var(--warn)" : status.polling ? "var(--ok)" : "var(--muted)"}
              title={status.capped ? status.note : `Every ~${status.interval ?? "60s"}, jittered`} />
            <Chip label={`${counts.announce} announce`} tone="var(--accent)" />
            <Chip label={`${counts.withdraw} withdraw`} tone="var(--crit)" />
            <Chip label={`${status.buffered ?? 0}/${status.ring_size} buffered`}
              title="Server-side ring buffer: constant size, oldest overwritten." />
            {(status.dropped ?? 0) > 0 && (
              <Chip label={`${status.dropped} overwritten`} tone="var(--warn)"
                title="Updates that rolled out of the ring before this page read them." />
            )}
          </div>

          {status.resources?.length ? (
            <p className="mini-meta">Following {status.resources.length} watched resource{status.resources.length === 1 ? "" : "s"}: <span className="mono">{status.resources.join(" · ")}</span></p>
          ) : (
            <div className="empty">{status.note || "Add prefixes or ASNs to this tenant's watchlist — the feed follows the watchlist."}</div>
          )}

          {gap && (
            <p className="mini-meta" style={{ color: "var(--warn)" }}>
              Some updates rolled out of the buffer before this page read them — the list below is not continuous.
            </p>
          )}

          {updates.length === 0 && status.resources?.length ? (
            <div className="empty">No updates buffered yet. The first poll covers the last 30 minutes.</div>
          ) : null}

          {updates.length > 0 && (
            <div style={{ maxHeight: 300, overflowY: "auto", overflowX: "auto" }}>
              <table className="dm-table" style={{ width: "100%" }}>
                <thead>
                  <tr><th>Time (UTC)</th><th>Type</th><th>Prefix</th><th>AS path</th><th>Collector peer</th></tr>
                </thead>
                <tbody>
                  {[...updates].reverse().map((u) => (
                    <tr key={u.seq}>
                      <td className="mono">{u.time ? new Date(u.time).toISOString().slice(11, 19) : "—"}</td>
                      <td>
                        <span style={{ color: u.type === "W" ? "var(--crit)" : "var(--accent)", fontWeight: 600 }}>
                          {u.type === "W" ? "withdraw" : "announce"}
                        </span>
                      </td>
                      <td className="mono">{u.prefix || "—"}</td>
                      <td className="mono" style={{ fontSize: 11 }}>{u.path?.length ? u.path.join(" → ") : "—"}</td>
                      <td className="mono" style={{ fontSize: 11 }}>{u.peer || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <p className="mini-meta" style={{ marginBottom: 0 }}>
            <strong>Near-live, not live.</strong> RIS Live is WebSocket-only and no WebSocket client is on this
            platform's dependency allowlist, so updates arrive from a bounded poll of RIPEstat every
            ~{status.interval ?? "60s"} (jittered). A dedicated BMP receiver — the on-device, truly live path — is a
            separate item.
          </p>
        </>
      )}
    </div>
  );
}

export default LiveFeedPanel;
