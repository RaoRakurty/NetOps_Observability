// ExperienceOverview.tsx — the Experience tab.
//
// The order is the owner's Phase E layout and it is not arbitrary: five
// headline cards, then the incidents they lead to, then the journeys those
// incidents broke, then what changed, then where it is worst, and finally how
// much of any of it we could actually see.
//
// Telemetry Confidence sits LAST on purpose and is driven entirely by the real
// `data_health` payload. It is the panel that tells an operator whether the six
// panels above it are worth reading, and a hard-coded green tick there would
// quietly authorise every other number on the screen.
//
// It reads two routes: /api/dem/overview for the whole story, and
// /api/dem/experience for the per-check scores that the site × application
// heatmap is built from. The heatmap needs the (site, app, score) triples, and
// the overview's hotspots are per-dimension roll-ups — the cross product is not
// in that payload and is not invented from it.

import { useState } from "react";

import { api } from "../../services/api";
import type {
  DemExperienceResponse, DemHotspot, DemJourneyHealth, DemOverviewResponse, DemWindow,
} from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { AiInvestigatorPanel } from "./ai";
import { ExperienceHeatmap } from "./heatmap";
import type { HeatCell } from "./heatmap";
import { IncidentTable } from "./incidentTable";
import { SeamRibbon } from "./ribbon";
import {
  BandChip, Loading, LoadError, Money, NotMeasured, Panel, ScoreBreakdown,
  aggregationText, bandFor, pct, reasonText, scoreTooltip,
} from "./honest";
import { useDemRead } from "./state";
import type { DxTab } from "./state";
import AskIris from "../../components/AskIris";

export default function ExperienceOverview({ window: win, onTab, onIncident }: {
  window: DemWindow;
  onTab: (tab: DxTab) => void;
  onIncident: (id: string) => void;
}) {
  const ov = useDemRead<DemOverviewResponse>(() => api.demOverview(win), [win]);
  const ex = useDemRead<DemExperienceResponse>(() => api.demExperience(win), [win]);
  const [showBreakdown, setShowBreakdown] = useState(false);

  if (ov.status === "loading") return <Loading what="the experience overview" />;
  if (ov.status === "error" || !ov.data) {
    return <LoadError what="The experience overview" error={ov.error} onRetry={ov.reload} />;
  }
  const d = ov.data;

  return (
    <div className="dx-section">
      {!d.enabled && (
        <p className="dx-error" role="alert">
          Experience collection is switched off for this deployment. Nothing on this screen
          was measured, and an empty table here does not mean everything is well.
        </p>
      )}
      {d.enabled && !d.measured && (
        <p className="dx-error" role="alert">
          {reasonText(d.reason)} {d.note}
        </p>
      )}

      <Cards data={d} onTab={onTab}
        onScore={() => setShowBreakdown((v) => !v)} breakdownOpen={showBreakdown} />

      {showBreakdown && (
        <Panel title="How the experience score was made"
          label="Experience score breakdown">
          <p className="dx-note">
            Policy <b>{d.score.policy_name}</b> version <b>{d.score.policy_version}</b>.
            {" "}{d.score.measured_dimensions} of {d.score.declared_dimensions} dimensions were
            measured; an unmeasured dimension contributes nothing and its weight is shared
            out among the rest, which is why the weights below may not be the policy's.
          </p>
          <p className="dx-note">Subjects were folded together by {aggregationText(d.score.aggregation)}.</p>
          <ScoreBreakdown score={d.score} />
        </Panel>
      )}

      <Panel title="Active experience incidents" label="Active experience incidents"
        actions={<span className="dx-chip">{d.incidents.length} open</span>}>
        <IncidentTable rows={d.incidents} onOpen={onIncident} />
        {d.incidents.length > 0 && (
          <SeamRibbon label="Seam ribbon for the leading incident"
            layer={d.incidents[0].likely_layer}
            seam={d.incidents[0].seam}
            owner={d.incidents[0].owner}
            cause={d.incidents[0].leading_cause} />
        )}
      </Panel>

      <Panel title="Journey health" label="Journey health"
        actions={<button type="button" className="btn" onClick={() => onTab("journeys")}>Journeys</button>}>
        <JourneyHealthList rows={d.journeys} />
      </Panel>

      <Panel title="What changed?" label="What changed"
        actions={<button type="button" className="btn" onClick={() => onTab("changes")}>Change feed</button>}>
        {d.changes.length === 0 ? (
          <p className="dx-note">
            Nothing recorded in this window.<AskIris topic="dem.unwired-producers" label="an empty change feed" />
          </p>
        ) : (
          <div className="dx-scroll">
            <table className="dx-table">
              <thead>
                <tr>
                  <th scope="col">When</th><th scope="col">Type</th><th scope="col">Object</th>
                  <th scope="col">Summary</th><th scope="col">Actor</th><th scope="col">Where</th>
                </tr>
              </thead>
              <tbody>
                {d.changes.slice(0, 12).map((c) => (
                  <tr key={c.id}>
                    <td className="dx-mono">{fmtDateTime(c.provenance?.event_at)}</td>
                    <td>{c.type.replace(/_/g, " ").toLowerCase()}</td>
                    <td className="dx-mono">{c.object}</td>
                    <td>{c.summary}</td>
                    <td>{c.actor || <span className="dx-subtle">Not recorded</span>}</td>
                    <td className="dx-cap">{[c.app, c.site, c.seam].filter(Boolean).join(" · ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Experience hotspots" label="Experience hotspots">
        <Hotspots rows={d.hotspots} />
      </Panel>

      <Panel title="Site × application" label="Site and application heatmap">
        {ex.status === "loading" && <Loading what="the per-check scores" />}
        {ex.status === "error" && (
          <LoadError what="The per-check scores" error={ex.error} onRetry={ex.reload} />
        )}
        {ex.status === "ready" && ex.data && <HeatmapFrom data={ex.data} />}
      </Panel>

      <Panel title="Telemetry confidence" label="Telemetry confidence"
        actions={<button type="button" className="btn" onClick={() => onTab("data-health")}>Data health</button>}>
        <ConfidencePanel data={d} />
      </Panel>

      <AiInvestigatorPanel availability={d.ai_investigator}
        subject={`this ${d.window} window`} />

      <p className="dx-cap">
        Assembled {fmtDateTime(d.generated_at)} · score policy version {d.policy_version}
      </p>
    </div>
  );
}

// ── the five cards ──────────────────────────────────────────────────────────

function Card({ label, tooltip, onClick, children }: {
  label: string; tooltip: string; onClick: () => void; children: React.ReactNode;
}) {
  return (
    <button type="button" className="dx-card" onClick={onClick} title={tooltip}
      aria-label={`${label}. ${tooltip.split("\n")[0]}`}>
      <span className="dx-card-label">{label}</span>
      {children}
    </button>
  );
}

function Delta({ delta, previous }: { delta?: number; previous?: number }) {
  if (delta === undefined || previous === undefined) {
    return <span className="dx-card-prev">No previous window to compare with</span>;
  }
  const dir = delta > 0.05 ? "up" : delta < -0.05 ? "down" : "flat";
  const arrow = dir === "up" ? "▲" : dir === "down" ? "▼" : "▬";
  return (
    <span className="dx-card-foot">
      <span className={`dx-delta dx-delta--${dir}`}>
        {arrow} {delta >= 0 ? "+" : ""}{delta.toFixed(1)}
      </span>
      <span className="dx-card-prev">was {previous.toFixed(1)}</span>
    </span>
  );
}

function Cards({ data, onTab, onScore, breakdownOpen }: {
  data: DemOverviewResponse;
  onTab: (t: DxTab) => void;
  onScore: () => void;
  breakdownOpen: boolean;
}) {
  const s = data.score;
  const journeySuccess = meanJourneySuccess(data.journeys);
  const rum = data.data_health?.sources?.find((x) => x.source === "rum");

  return (
    <div className="dx-cards" role="group" aria-label="Experience headline measures">
      <Card label="Experience SLO" onClick={onScore} tooltip={scoreTooltip(s)}>
        {s.measured && s.score !== undefined ? (
          <>
            <span className="dx-card-value">{s.score.toFixed(1)}</span>
            <span className="dx-card-foot">
              <BandChip band={s.band} />
              <span className="dx-card-prev">{breakdownOpen ? "Hide the breakdown" : "How this number was made"}</span>
            </span>
            <Delta delta={s.delta} previous={s.previous_score} />
          </>
        ) : (
          <NotMeasured reason={s.reason} detail={s.detail} />
        )}
      </Card>

      <Card label="Journey success" onClick={() => onTab("journeys")}
        tooltip={"The product of each journey's required measured steps, averaged over the journeys that were measured at all.\nA journey with an unmeasured required step is not counted, so this is never a coverage-inflated number."}>
        {journeySuccess === undefined ? (
          <NotMeasured
            reason={data.journeys.length === 0 ? "no_journeys" : "journey_not_measured"}
            detail={data.journeys.length === 0 ? undefined
              : "Not one declared journey had a measured required step in this window."} />
        ) : (
          <>
            <span className="dx-card-value">{journeySuccess.toFixed(1)}<span className="dx-card-unit">%</span></span>
            <span className="dx-card-foot">
              <BandChip band={bandFor(journeySuccess)} />
              <span className="dx-card-prev">
                {data.journeys.filter((j) => j.measured).length} of {data.journeys.length} journeys measured
              </span>
            </span>
          </>
        )}
      </Card>

      <Card label="Impacted users" onClick={() => onTab("data-health")}
        tooltip={"A user count needs first-party real-user telemetry.\nWithout it, 'we cannot count users' and 'no users were affected' are opposite claims and only one of them is true."}>
        <NotMeasured
          reason={rum ? rum.state : "not_configured"}
          detail={rum?.detail
            || "Real-user telemetry is the only source that can count affected people, and it is not reporting."} />
      </Card>

      <Card label="Business impact" onClick={() => onTab("journeys")}
        tooltip={"The declared value of one successful traversal multiplied by the successes the objective expected and did not get.\nShown only when an operator declared a value — an invented one is worse than none."}>
        {data.business_impact === undefined ? (
          // Two different absences, and they must not read alike. A NOTE means
          // the figures exist but cannot be added up (more than one currency);
          // no note means nobody declared a value at all.
          <NotMeasured
            reason={data.business_impact_note ? "not_totalled" : "not_declared"}
            detail={data.business_impact_note
              || "No affected journey declares a value per successful traversal, so the loss cannot be valued."} />
        ) : (
          <>
            <span className="dx-card-value">
              <Money value={data.business_impact} currency={data.business_impact_currency} />
            </span>
            <span className="dx-card-prev">value not realised over this window</span>
          </>
        )}
      </Card>

      <Card label="Active experience incidents" onClick={() => onTab("incidents")}
        tooltip={"Incidents derived from this window's evidence.\nZero is only a good result when the sources behind it are flowing — see Telemetry confidence."}>
        <span className="dx-card-value">{data.incidents.length}</span>
        <span className="dx-card-foot">
          <span className="dx-card-prev">
            {data.incidents.filter((i) => i.verdict_tier === "confirmed").length} confirmed ·
            {" "}{data.incidents.filter((i) => i.verdict_tier === "suspected").length} suspected
          </span>
        </span>
      </Card>
    </div>
  );
}

function meanJourneySuccess(rows: DemJourneyHealth[]): number | undefined {
  const measured = rows.filter((j) => j.measured && j.success_pct !== undefined);
  if (measured.length === 0) return undefined;
  return measured.reduce((a, j) => a + (j.success_pct ?? 0), 0) / measured.length;
}

// ── journey health ──────────────────────────────────────────────────────────

function JourneyHealthList({ rows }: { rows: DemJourneyHealth[] }) {
  if (rows.length === 0) {
    return (
      <p className="dx-note">
        No journey is declared.<AskIris topic="dem.no-journey-declared" label="a declared journey" />
      </p>
    );
  }
  return (
    <div className="dx-section">
      {rows.map((j) => (
        <article className="dx-journey" key={j.journey_id}>
          <div className="dx-src-head">
            <h3 className="dx-h3">{j.name}</h3>
            <span className="dx-chip">{j.business_importance || "importance not declared"}</span>
          </div>
          {j.measured && j.success_pct !== undefined ? (
            <>
              <div className="dx-card-foot">
                <span className="dx-mono">{pct(j.success_pct)}</span>
                <BandChip band={bandFor(j.success_pct)} />
                <span className={j.meets_slo ? "dx-subtle" : "dx-delta dx-delta--down"}>
                  {j.meets_slo ? "meets its objective" : `misses its objective of ${pct(j.slo.success_pct)}`}
                </span>
                <span className="dx-cap">
                  {j.steps_measured} of {j.steps_declared} steps measured
                </span>
              </div>
              <div className="dx-steps">
                {j.steps.map((st) => (
                  <span key={st.step_id}
                    className={`dx-step${st.failing ? " dx-step--failing" : ""}${st.measured ? "" : " dx-step--unmeasured"}`}
                    title={st.measured
                      ? `${pct(st.success_pct)} over ${st.samples ?? 0} observations`
                      : reasonText(st.reason) + (st.detail ? ` ${st.detail}` : "")}>
                    <span className="dx-step-label">{st.label}</span>
                    <span>{st.measured ? pct(st.success_pct) : "not measured"}</span>
                  </span>
                ))}
              </div>
            </>
          ) : (
            <NotMeasured reason={j.reason} detail={j.detail} />
          )}
          {j.business_impact !== undefined && (
            <p className="dx-cap">
              Value not realised: <Money value={j.business_impact} currency={j.business_impact_currency} />
            </p>
          )}
        </article>
      ))}
    </div>
  );
}

// ── hotspots ────────────────────────────────────────────────────────────────

const DIMENSION_TITLE: Record<string, string> = {
  site: "Geography (site)",
  app: "Application",
  isp: "Provider (ISP)",
  device: "Device",
  browser: "Browser",
  version: "Release version",
  network: "Network type",
};

function Hotspots({ rows }: { rows: DemHotspot[] }) {
  const order = ["site", "app", "isp", "device", "browser", "version", "network"];
  const byDim = new Map<string, DemHotspot[]>();
  for (const h of rows) {
    const list = byDim.get(h.dimension) ?? [];
    list.push(h);
    byDim.set(h.dimension, list);
  }
  const dims = [...new Set([...order, ...byDim.keys()])].filter((d) => byDim.has(d));

  return (
    <div className="dx-src-grid">
      {dims.map((dim) => {
        const list = byDim.get(dim) ?? [];
        const measured = list.filter((h) => h.measured);
        return (
          <section className="dx-src" key={dim} aria-label={DIMENSION_TITLE[dim] ?? dim}>
            <div className="dx-src-head">
              <h3 className="dx-h3">{DIMENSION_TITLE[dim] ?? dim}</h3>
              <span className="dx-chip">{list.length}</span>
            </div>
            {measured.length === 0 ? (
              // A dimension nothing produces is reported with its reason, never
              // omitted and never shown as a zero — the absence is the finding.
              <NotMeasured detail={list[0]?.reason} />
            ) : (
              <ul className="dx-dims">
                {measured
                  .slice()
                  .sort((a, b) => (a.score ?? 0) - (b.score ?? 0))
                  .slice(0, 8)
                  .map((h) => (
                    <li className="dx-dim" key={h.key}>
                      <span className="dx-dim-head">
                        <span className="dx-dim-name">{h.key || "unlabelled"}</span>
                        <span className="dx-dim-w">{h.score?.toFixed(1)}</span>
                      </span>
                      <span className="dx-card-foot">
                        <BandChip band={h.band} />
                        <span className="dx-cap">
                          {h.subjects} subject{h.subjects === 1 ? "" : "s"}
                          {h.failing > 0 ? ` · ${h.failing} failing` : ""}
                        </span>
                      </span>
                    </li>
                  ))}
              </ul>
            )}
            {measured.length === 0 && list.length > 0 && list.some((h) => h.key) && (
              <ul className="dx-dims">
                {list.filter((h) => h.key).slice(0, 8).map((h) => (
                  <li className="dx-dim" key={h.key}>
                    <span className="dx-dim-head">
                      <span className="dx-dim-name">{h.key}</span>
                      <span className="dx-dim-w">{h.failing} failing</span>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        );
      })}
    </div>
  );
}

// ── heatmap ─────────────────────────────────────────────────────────────────

export function buildHeatCells(data: DemExperienceResponse): {
  cells: HeatCell[]; unplaced: number;
} {
  const acc = new Map<string, {
    site: string; app: string; sum: number; scored: number; subjects: number;
    components: Set<string>; reason?: string;
  }>();
  let unplaced = 0;
  for (const t of data.targets ?? []) {
    if (!t.site || !t.app) { unplaced++; continue; }
    const key = `${t.site} ${t.app}`;
    const cur = acc.get(key) ?? {
      site: t.site, app: t.app, sum: 0, scored: 0, subjects: 0,
      components: new Set<string>(), reason: undefined as string | undefined,
    };
    cur.subjects++;
    if (t.measured && t.score !== undefined) {
      cur.sum += t.score;
      cur.scored++;
      if (t.availability?.measured && !t.availability.met) cur.components.add("availability below its budget");
      if (t.latency?.measured && !t.latency.met) cur.components.add("latency above its budget");
      if (t.path_stability?.measured && !t.path_stability.met) cur.components.add("the path changed");
    } else if (!cur.reason) {
      cur.reason = t.detail || t.reason;
    }
    acc.set(key, cur);
  }
  const cells: HeatCell[] = [...acc.values()].map((c) => {
    const measured = c.scored > 0;
    const score = measured ? c.sum / c.scored : undefined;
    return {
      site: c.site, app: c.app, subjects: c.subjects, measured, score,
      band: measured ? bandFor(score) : "not_measured",
      components: [...c.components],
      reason: measured ? undefined : c.reason,
    };
  });
  return { cells, unplaced };
}

function HeatmapFrom({ data }: { data: DemExperienceResponse }) {
  const { cells, unplaced } = buildHeatCells(data);
  return (
    <>
      <ExperienceHeatmap cells={cells} caption="Site by application" />
      {unplaced > 0 && (
        <p className="dx-cap">
          {unplaced} unplotted<AskIris topic="dem.unplaced-checks" label="unplotted checks" />
        </p>
      )}
    </>
  );
}

// ── telemetry confidence ────────────────────────────────────────────────────

function ConfidencePanel({ data }: { data: DemOverviewResponse }) {
  const dh = data.data_health;
  const sources = dh?.sources ?? [];
  const flowing = sources.filter((s) => s.state === "flowing");
  return (
    <div className="dx-section">
      <p className={dh?.can_confirm ? "dx-note" : "dx-error"} role="note">
        <b>{dh?.can_confirm ? "A cause can be confirmed." : "No cause can be confirmed."}</b>
        {" "}{dh?.explanation}
      </p>
      <p className="dx-note">
        {flowing.length} of {sources.length} sources are reporting;
        {" "}{dh?.anchor_sources_flowing ?? 0} of them can anchor a confirmed verdict.
      </p>
      <div className="dx-src-grid">
        {sources.map((s) => (
          <section className={`dx-src dx-src--${s.state}`} key={s.source} aria-label={s.label}>
            <div className="dx-src-head">
              <h3 className="dx-h3">{s.label}</h3>
              <span className="dx-chip">{s.state.replace(/_/g, " ")}</span>
            </div>
            <p className="dx-cap">{s.detail || reasonText(s.state)}</p>
            <p className="dx-cap">
              {s.anchor_capable ? "Can anchor a confirmed verdict." : "Cannot anchor a confirmed verdict on its own."}
              {s.confidence_influence > 0
                ? ` Lowering confidence by ${(s.confidence_influence * 100).toFixed(0)}%.`
                : " Not lowering confidence."}
            </p>
          </section>
        ))}
      </div>
    </div>
  );
}
