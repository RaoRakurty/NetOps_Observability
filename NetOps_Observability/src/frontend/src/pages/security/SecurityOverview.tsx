import { useEffect, useMemo, useState } from "react";
import "./Security.css";
import {
  api, CorrObject, CorrTimeline, SecFacets, SecFinding, SecPosture, SecTrend, Seam,
} from "../../services/api";
import { buildCaseEvents, type CaseEvent } from "../../components/rca/rcaCase";
import { Group, Panel } from "../../components/board/panels";
import { fmtDateTime } from "../../lib/time";
import { operatorError } from "../../lib/errors";
import {
  CoverageCard, CtemFunnel, EvidenceLane, FindingRow, SeamStrip,
} from "./parts";
import {
  coverageOf, evidenceClassLabel, facetTotal, funnelStages, isThreatLane,
  mapFacetRows, seamCards, storyConfidence, storyList, topExposures, trendPoints,
} from "./model";

// Security Overview — the CTEM command centre (P3-T8, design of record: the
// owner-approved Security mockup). Four things, in the order an operator asks
// them: how much of the estate did we actually assess · what is the pipeline
// doing · what is the ONE story that matters right now · where does the estate
// meet untrusted networks.
//
// Honesty rules (enforced in model.ts, rendered here):
//  · Coverage leads. An unassessed asset is UNKNOWN — the page says so in words
//    and renders it in the neutral ramp, never green, never a bare 0.
//  · Every panel that has no data says WHY it has none instead of drawing a
//    reassuring empty chart.
// Tenant isolation (§3a): every call is scoped server-side by the bearer token.
// The page never asks for another tenant's data and never renders a total it
// was not given.

const LANES: { key: string; title: string; match: (c?: string) => boolean }[] = [
  { key: "posture", title: "Hardening & posture", match: (c) => (c ?? "").toLowerCase() === "posture" },
  { key: "exposure", title: "Seam exposure", match: (c) => (c ?? "").toLowerCase() === "exposure" },
  { key: "threat", title: "Threat detections", match: (c) => isThreatLane(c) },
];

/** The flagship Exposure Story hero. Renders only what the objects state. */
function StoryHero({ story, events, onOpen }: {
  story: CorrObject; events: CaseEvent[]; onOpen: (id: string) => void;
}) {
  const conf = storyConfidence(story);
  const chain = events.slice(0, 6);
  return (
    <section className="sec-hero" aria-labelledby="sec-hero-h">
      <div className="sec-eyebrow">Exposure story · flagship</div>
      <h3 id="sec-hero-h">{story.top_hypothesis || "Correlated exposure"}</h3>
      <p className="sec-sub">
        One narrative, not four alerts — the engine folded {Number(story.signal_count) || 0} observation
        {Number(story.signal_count) === 1 ? "" : "s"} across {Number(story.node_count) || 0} entit
        {Number(story.node_count) === 1 ? "y" : "ies"} into a single seam-owned story.
      </p>
      <div className="sec-hero-grid">
        <div>
          {chain.length === 0 ? (
            <p className="mini-meta" style={{ margin: 0 }}>
              The chronology for this story has not loaded — open the full story for its causality path.
            </p>
          ) : (
            <ol className="sec-chain" aria-label="Causality chain">
              {chain.map((e, i) => (
                <li className="sec-node" key={`${e.ts}-${i}`}>
                  <span className="rail" aria-hidden="true">
                    <span className={`pin ${e.tone === "red" ? "t-bad" : e.tone === "orange" ? "t-warn" : e.tone === "green" ? "t-good" : ""}`} />
                    <span className="link" />
                  </span>
                  <span className="body">
                    <b>{e.label}</b>
                    {e.detail && <p>{e.detail}</p>}
                    <span className="meta">{fmtDateTime(e.ts)}</span>
                  </span>
                </li>
              ))}
            </ol>
          )}
        </div>
        <div>
          <div className="sec-owner">
            <div className="sec-eyebrow">Ownership</div>
            <div className="seam-name">{story.owner || "unattributed"}</div>
            <div className="who">
              Verdict {story.verdict_tier || "undetermined"}
            </div>
            <div className="conf">
              Confidence: {conf === null ? <span className="sec-unassessed">not stated</span> : `${conf}%`}
              {story.grounding ? ` · grounded on ${story.grounding}` : ""}
            </div>
            <div className="sec-chips">
              {story.state && <span className="sec-chip">{story.state}</span>}
              {story.grounding && <span className="sec-chip k">{story.grounding}</span>}
              {story.plane_count !== undefined && <span className="sec-chip">{String(story.plane_count)} planes</span>}
            </div>
          </div>
          <div className="sec-hero-cta">
            <button className="btn accent" onClick={() => onOpen(story.correlation_id)}>
              Open the full story
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function SecurityOverview() {
  const [posture, setPosture] = useState<SecPosture | null>(null);
  const [facets, setFacets] = useState<SecFacets | null>(null);
  const [findings, setFindings] = useState<SecFinding[]>([]);
  const [trend, setTrend] = useState<SecTrend | null>(null);
  const [stories, setStories] = useState<CorrObject[]>([]);
  const [heroEvents, setHeroEvents] = useState<CaseEvent[]>([]);
  const [seams, setSeams] = useState<Seam[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let alive = true;
    // Everything is "current verdicts only" — the overview answers "what is
    // true now", never a history the operator did not ask for.
    const q = { current: true } as const;
    Promise.all([
      api.securityPosture().catch((e: Error) => { throw e; }),
      api.securityFindingFacets(q).catch(() => null),
      api.securityFindings({ ...q, limit: 100 }).catch(() => null),
      api.securityFindingTrend(q, "1d").catch(() => null),
      api.securityExposureStories(5).catch(() => null),
      api.seams("active").catch(() => null),
    ]).then(([p, f, list, t, st, sm]) => {
      if (!alive) return;
      setPosture(p);
      setFacets(f);
      setFindings(list?.items ?? []);
      setTrend(t);
      setStories(storyList(st));
      setSeams(sm);
      setErr(null);
    }).catch((e: Error) => {
      if (alive) setErr(operatorError(e, "The security overview could not be loaded."));
    }).finally(() => {
      if (alive) setLoaded(true);
    });
    return () => { alive = false; };
  }, []);

  // The flagship story's chronology, read from the SAME correlation timeline the
  // RCA workspace renders. Best-effort: a missing timeline degrades the hero to
  // its summary rather than blanking it.
  const flagship = stories[0];
  useEffect(() => {
    let alive = true;
    setHeroEvents([]);
    if (!flagship?.correlation_id) return;
    api.correlationTimeline(flagship.correlation_id)
      .then((tl: CorrTimeline) => { if (alive) setHeroEvents(buildCaseEvents(tl, flagship)); })
      .catch(() => { /* chronology optional — the hero still states the verdict */ });
    return () => { alive = false; };
  }, [flagship]);

  const stages = useMemo(() => funnelStages(posture), [posture]);
  const coverage = useMemo(() => coverageOf(posture), [posture]);
  const seamStrip = useMemo(() => seamCards(facets, seams), [facets, seams]);
  const points = useMemo(() => trendPoints(trend), [trend]);
  const laneFindings = useMemo(
    () => LANES.map((l) => ({ ...l, rows: topExposures(findings.filter((f) => l.match(f.evidence_class)), 4) })),
    [findings],
  );
  const frameworks = useMemo(() => mapFacetRows(facets?.framework), [facets]);

  const openStory = (id: string) => { window.location.hash = `#/security/stories/${encodeURIComponent(id)}`; };

  if (err) {
    return (
      <div className="sec">
        <Panel title="Security Overview">
          <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>
        </Panel>
      </div>
    );
  }
  if (!loaded) {
    return <div className="sec"><Panel title="Security Overview"><div className="empty" role="status">Loading…</div></Panel></div>;
  }

  return (
    <div className="sec dm-board">
      <Group title="Exposure pipeline" hue="#e11d48">
        <div className="sec-band">
          <CoverageCard coverage={coverage} />
          <CtemFunnel stages={stages} />
        </div>
        <p className="mini-meta" style={{ margin: 0 }} role="status">
          {posture?.last_scan?.time
            ? <>Last assessment {fmtDateTime(posture.last_scan.time)} · scan {posture.last_scan.scan_id || "—"}</>
            : <>No assessment has run yet — every stage below counts zero because nothing was measured, not because the estate is clear.</>}
        </p>
      </Group>

      {stories.length > 0 && flagship ? (
        <Group title="Exposure story" hue="#0ea5e9">
          <StoryHero story={flagship} events={heroEvents} onOpen={openStory} />
        </Group>
      ) : (
        <Group title="Exposure story" hue="#0ea5e9">
          <div className="empty">
            No security-lane correlation has been grounded yet. Stories appear once security evidence
            lands on the same entity and seam as other telemetry inside one window.
          </div>
        </Group>
      )}

      <Group title="Evidence, by class" hue="#8b5cf6">
        <div className="sec-lanes">
          {laneFindings.map((l) => (
            <EvidenceLane
              key={l.key}
              title={l.title}
              count={`${(facets?.evidence_class?.[l.key] ?? (l.key === "threat" ? facets?.evidence_class?.signal : undefined) ?? 0).toLocaleString()} current`}
              tone={l.rows.length > 0 ? "bad" : ""}
              empty={`No ${evidenceClassLabel(l.key).toLowerCase()} verdicts yet — this lane has no producer reporting.`}
            >
              {l.rows.length > 0
                ? l.rows.map((f) => <FindingRow key={f.id} finding={f} />)
                : undefined}
            </EvidenceLane>
          ))}
          <EvidenceLane
            title="Standards coverage"
            count={`${frameworks.length} tagged`}
            empty="No finding carries a standards tag yet — nothing can be reported against a control set."
          >
            {frameworks.length > 0 ? (
              <div>
                {frameworks.slice(0, 6).map((f) => (
                  <div key={f.key} className="sec-row" style={{ cursor: "default" }}>
                    <span className="sec-stripe" aria-hidden="true" />
                    <span className="main"><b>{f.label}</b><span className="sub">tagged hardening findings</span></span>
                    <span className="fix">{f.count.toLocaleString()}</span>
                  </div>
                ))}
                <p className="mini-meta" style={{ margin: "8px 0 0" }}>
                  Counts of hardening findings on the tagged control set — not a framework compliance verdict.
                </p>
              </div>
            ) : undefined}
          </EvidenceLane>
        </div>
      </Group>

      <Group title="Exposure by seam" hue="#f59e0b">
        <SeamStrip cards={seamStrip} />
        <p className="mini-meta" style={{ margin: 0 }}>
          Where the estate meets untrusted networks, and who owns each boundary. A seam with no
          assessment shows <span className="sec-unassessed">—</span>, never a zero.
        </p>
      </Group>

      <Group title="Verdict trend" hue="#14b8a6">
        <Panel title="Fail / warning / pass per day">
          {points.length === 0 ? (
            <div className="empty">
              No assessment history in range — a trend needs at least one completed scan.
            </div>
          ) : (
            <table className="ds-table" aria-label="Verdict trend by day">
              <thead>
                <tr><th scope="col">Day</th><th scope="col">Fail</th><th scope="col">Warning</th><th scope="col">Pass</th><th scope="col">Total</th></tr>
              </thead>
              <tbody>
                {points.map((p) => (
                  <tr key={p.t}>
                    <th scope="row" style={{ fontWeight: 500, textAlign: "left" }}>{p.t}</th>
                    <td>{p.fail.toLocaleString()}</td>
                    <td>{p.warn.toLocaleString()}</td>
                    <td>{p.pass.toLocaleString()}</td>
                    <td>{p.total.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        <p className="mini-meta" style={{ margin: 0 }}>
          {facetTotal(facets?.severity)} current findings across {facetTotal(facets?.seam) || 0} scored seams.
        </p>
      </Group>
    </div>
  );
}
