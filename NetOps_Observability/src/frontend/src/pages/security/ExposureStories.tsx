import { useCallback, useEffect, useMemo, useState } from "react";
import "./Security.css";
import { api, CorrObject } from "../../services/api";
import { CorrelationDetail } from "../../tabs/Correlations";
import { Group, Panel } from "../../components/board/panels";
import { fmtDateTime } from "../../lib/time";
import { storyConfidence, storyList } from "./model";

// Exposure Stories — the flagship object: a correlation whose evidence set
// includes the security lane, grounded on the same entities and seams as the
// rest of the telemetry (HLD §3). The DETAIL view is the existing RCA
// workspace, reused verbatim (CorrelationDetail → RcaWorkspace): an exposure
// story IS an RCA object, so it must read exactly like one — same causality
// path, same broken-red rendering, same ownership panel, same export.
//
// Tenant isolation (§3a): the list is scoped server-side; a story id that does
// not belong to the caller answers 404 and is rendered as "not found", never as
// a blank workspace that could imply the story exists but is empty.

/** Reads a #/security/stories/<id> deep link. Returns "" for the list route. */
export function storyIdFromHash(hash: string): string {
  const path = hash.replace(/^#\/?/, "").split("?")[0];
  const segs = path.split("/");
  if (segs[0] !== "security" || segs[1] !== "stories" || segs.length < 3) return "";
  const raw = segs.slice(2).join("/");
  try { return decodeURIComponent(raw); } catch { return raw; }
}

function StoryCard({ story, onOpen }: { story: CorrObject; onOpen: (id: string) => void }) {
  const conf = storyConfidence(story);
  return (
    <button type="button" className="sec-row" onClick={() => onOpen(story.correlation_id)}>
      <span
        className={`sec-stripe ${story.verdict_tier === "confirmed" ? "t-bad" : story.verdict_tier === "suspected" ? "t-warn" : ""}`}
        aria-hidden="true"
      />
      <span className="main">
        <b>{story.top_hypothesis || "Correlated exposure"}</b>
        <span className="sub">
          {story.owner ? `${story.owner} · ` : ""}
          {story.verdict_tier || "undetermined"}
          {conf === null ? "" : ` · confidence ${conf}%`}
          {story.window_start ? ` · ${fmtDateTime(story.window_start)}` : ""}
        </span>
      </span>
      <span className="fix">{Number(story.signal_count) || 0} observations</span>
    </button>
  );
}

export default function ExposureStories() {
  const [stories, setStories] = useState<CorrObject[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [openId, setOpenId] = useState(() => storyIdFromHash(window.location.hash));
  const [detailErr, setDetailErr] = useState<string | null>(null);
  const [detailOk, setDetailOk] = useState(false);

  useEffect(() => {
    const onHash = () => setOpenId(storyIdFromHash(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    let alive = true;
    api.securityExposureStories(25)
      .then((r) => { if (alive) { setStories(storyList(r)); setErr(null); } })
      .catch((e: Error) => { if (alive) setErr(e.message); })
      .finally(() => { if (alive) setLoaded(true); });
    return () => { alive = false; };
  }, []);

  // Confirm the story is one of THIS tenant's before rendering the workspace.
  // A 404 (foreign or unknown id) must read as "not found", not as an empty RCA.
  useEffect(() => {
    let alive = true;
    setDetailErr(null); setDetailOk(false);
    if (!openId) return;
    api.securityExposureStory(openId)
      .then(() => { if (alive) setDetailOk(true); })
      .catch((e: Error) => { if (alive) setDetailErr(e.message); });
    return () => { alive = false; };
  }, [openId]);

  const open = useCallback((id: string) => {
    window.location.hash = `#/security/stories/${encodeURIComponent(id)}`;
    setOpenId(id);
  }, []);

  const flagship = useMemo(() => stories[0], [stories]);

  if (openId) {
    return (
      <div className="sec dm-board">
        <div className="sec-toolbar">
          <button className="btn" type="button" onClick={() => { window.location.hash = "#/security/stories"; setOpenId(""); }}>
            ← All exposure stories
          </button>
        </div>
        {detailErr ? (
          <Panel title="Exposure story">
            <div className="empty" role="alert">
              This exposure story is not available to you: {detailErr}
            </div>
          </Panel>
        ) : !detailOk ? (
          <Panel title="Exposure story"><div className="empty" role="status">Loading…</div></Panel>
        ) : (
          <CorrelationDetail id={openId} />
        )}
      </div>
    );
  }

  return (
    <div className="sec dm-board">
      <Group title="Exposure stories" hue="#0ea5e9">
        {err ? (
          <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>
        ) : !loaded ? (
          <div className="empty" role="status">Loading…</div>
        ) : stories.length === 0 ? (
          <div className="empty">
            No exposure story has been grounded yet. A story appears when security evidence lands on
            the same entity and seam as other telemetry inside one correlation window — an empty list
            means nothing correlated, not that nothing is wrong.
          </div>
        ) : (
          <>
            {flagship && (
              <p className="mini-meta" style={{ margin: "0 0 6px" }} role="status">
                {stories.length} stor{stories.length === 1 ? "y" : "ies"} · newest window opened{" "}
                {flagship.window_start ? fmtDateTime(flagship.window_start) : "—"}
              </p>
            )}
            <Panel title="Stories">
              {stories.map((s) => <StoryCard key={s.correlation_id} story={s} onOpen={open} />)}
            </Panel>
            <p className="mini-meta" style={{ margin: 0 }}>
              Each story opens in the RCA workspace — the same causality path, ownership and export the
              network incidents use. Security is a fourth evidence class, not a separate product.
            </p>
          </>
        )}
      </Group>
    </div>
  );
}
