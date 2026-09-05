// ExperienceSynthetics.tsx — the Synthetics tab.
//
// Three reads, and all three are load-bearing:
//
//   /api/dem/synthetics/coverage — what PROTECTS each declared user action.
//   /api/dem/targets             — the checks that exist at all.
//   /api/dem/experience          — what those checks actually measured.
//
// Coverage alone would say "this action is protected" while the check behind it
// had not passed for a day; the catalogue alone would list checks nobody bound
// to a journey. Together they answer the question an operator actually has:
// which of the things people do is covered, by what, and is that thing working.
//
// THE ONE RULE. An action nothing measures is UNTESTED — never healthy, never
// 100%, never a blank cell. And a check nobody has graded reads as unknown
// reliability rather than as trustworthy: a check that has never been assessed
// is not a check that passed.

import { useMemo } from "react";

import { api } from "../../services/api";
import type {
  DemCoverageResponse, DemExperienceResponse, DemTargetsResponse, DemWindow,
} from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { buildHeatCells } from "./ExperienceOverview";
import { ExperienceHeatmap } from "./heatmap";
import {
  BandChip, Loading, LoadError, NotMeasured, Panel, bandFor, pct,
} from "./honest";
import { useDemRead } from "./state";

const STATE_WORDS: Record<string, string> = {
  protected: "Protected",
  thin: "Thinly protected — one check, or one vantage",
  untested: "Untested — nothing measures this",
  broken: "Broken — checks exist but none can be trusted",
  stale: "Stale — nothing has succeeded recently enough to count",
};

const GRADE_WORDS: Record<string, string> = {
  solid: "consistent across its runs",
  noisy: "occasional flips or retries",
  flaky: "the result changes between runs",
  broken: "the runner itself is failing",
  unknown: "nobody has graded this check",
};

export default function ExperienceSynthetics({ window: win }: { window: DemWindow }) {
  const cov = useDemRead<DemCoverageResponse>(() => api.demSyntheticCoverage(win), [win]);
  const cat = useDemRead<DemTargetsResponse>(() => api.demTargets(), []);
  const exp = useDemRead<DemExperienceResponse>(() => api.demExperience(win), [win]);

  const scoreByTarget = useMemo(() => {
    const m = new Map<string, DemExperienceResponse["targets"][number]>();
    for (const r of exp.data?.targets ?? []) m.set(r.target, r);
    return m;
  }, [exp.data]);

  return (
    <div className="dx-section">
      <Panel title="Coverage of what people do" label="Synthetic coverage">
        {cov.status === "loading" && <Loading what="the coverage model" />}
        {cov.status === "error" && (
          <LoadError what="The coverage model" error={cov.error} onRetry={cov.reload} />
        )}
        {cov.status === "ready" && cov.data && (
          <>
            <div className="dx-cards">
              <CoverageStat label="Critical actions" value={cov.data.coverage.critical_actions} />
              <CoverageStat label="Protected" value={cov.data.coverage.protected_actions} />
              <CoverageStat label="Thinly protected" value={cov.data.coverage.thin_actions} />
              <CoverageStat label="Untested" value={cov.data.coverage.untested_actions} />
              <CoverageStat label="Broken checks" value={cov.data.coverage.broken_tests} />
            </div>
            <p className="dx-note">{cov.data.coverage.detail}</p>
            {cov.data.coverage.coverage_pct === undefined ? (
              <NotMeasured reason="no_journeys"
                detail="There is nothing to cover yet: full coverage of zero actions is not a result worth showing as a success." />
            ) : (
              <p className="dx-card-foot">
                <span className="dx-mono">{pct(cov.data.coverage.coverage_pct)} of declared actions protected</span>
                <BandChip band={bandFor(cov.data.coverage.coverage_pct)} />
              </p>
            )}
            <p className="dx-cap">{cov.data.reliability_note}</p>

            {cov.data.coverage.actions.length > 0 && (
              <div className="dx-scroll">
                <table className="dx-table">
                  <thead>
                    <tr>
                      <th scope="col">Action</th><th scope="col">Application</th>
                      <th scope="col">Importance</th><th scope="col">Checks</th>
                      <th scope="col">Vantages</th><th scope="col">Last success</th>
                      <th scope="col">Reliability</th><th scope="col">State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cov.data.coverage.actions.map((a) => (
                      <tr key={`${a.journey_id}/${a.step_id}`}>
                        <td>
                          <b>{a.label}</b>
                          <div className="dx-cap">{a.detail}</div>
                        </td>
                        <td>{a.app || <span className="dx-subtle">not declared</span>}</td>
                        <td>{a.business_importance}</td>
                        <td className="dx-mono">{a.synthetics}</td>
                        <td className="dx-mono">{a.vantages}</td>
                        <td className="dx-mono">
                          {a.last_success
                            ? fmtDateTime(a.last_success)
                            : <span className="dx-subtle">never</span>}
                        </td>
                        <td>
                          {a.reliability_grade}
                          <div className="dx-cap">{GRADE_WORDS[a.reliability_grade] ?? ""}</div>
                        </td>
                        <td>{STATE_WORDS[a.state] ?? a.state}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </Panel>

      <Panel title="Site × application" label="Synthetic site and application heatmap">
        {exp.status === "loading" && <Loading what="the per-check scores" />}
        {exp.status === "error" && (
          <LoadError what="The per-check scores" error={exp.error} onRetry={exp.reload} />
        )}
        {exp.status === "ready" && exp.data && (
          <ExperienceHeatmap cells={buildHeatCells(exp.data).cells}
            caption="Experience band per site and application, from the checks in the catalogue." />
        )}
      </Panel>

      <Panel title="Check catalogue" label="Synthetic check catalogue">
        {cat.status === "loading" && <Loading what="the check catalogue" />}
        {cat.status === "error" && (
          <LoadError what="The check catalogue" error={cat.error} onRetry={cat.reload} />
        )}
        {cat.status === "ready" && cat.data && (
          <>
            {!cat.data.enabled && <p className="dx-error" role="alert">{cat.data.note}</p>}
            <p className="dx-cap">{cat.data.count} of at most {cat.data.limit} for this tenant.</p>
            {cat.data.targets.length === 0 ? (
              <p className="dx-note">
                No check is declared for this tenant, so nothing is being measured.
              </p>
            ) : (
              <div className="dx-scroll">
                <table className="dx-table">
                  <thead>
                    <tr>
                      <th scope="col">Check</th><th scope="col">Kind</th>
                      <th scope="col">Destination</th><th scope="col">Site</th>
                      <th scope="col">Application</th><th scope="col">Score</th>
                      <th scope="col">Availability</th><th scope="col">Response</th>
                      <th scope="col">Path stability</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cat.data.targets.map((t) => {
                      const r = scoreByTarget.get(t.id);
                      return (
                        <tr key={t.id}>
                          <td>
                            <b>{t.name}</b>
                            {t.paused && <div className="dx-cap">paused by an operator</div>}
                          </td>
                          <td>{t.kind}</td>
                          <td className="dx-mono">{t.host}</td>
                          <td>{t.site || <span className="dx-subtle">not labelled</span>}</td>
                          <td>{t.app || <span className="dx-subtle">not labelled</span>}</td>
                          <td>
                            {r?.measured && r.score !== undefined ? (
                              <span className="dx-card-foot">
                                <span className="dx-mono">{r.score.toFixed(1)}</span>
                                <BandChip band={bandFor(r.score)} />
                              </span>
                            ) : (
                              <NotMeasured compact reason={r?.reason ?? "no_samples"}
                                detail={r?.detail} />
                            )}
                          </td>
                          <td><ComponentCell c={r?.availability} unit="%" /></td>
                          <td><ComponentCell c={r?.latency} unit="ms" /></td>
                          <td><ComponentCell c={r?.path_stability} unit="" /></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </Panel>
    </div>
  );
}

function CoverageStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="dx-card" role="group" aria-label={label}>
      <span className="dx-card-label">{label}</span>
      <span className="dx-card-value">{value}</span>
    </div>
  );
}

function ComponentCell({ c, unit }: {
  c?: { measured: boolean; reason?: string; value?: number; budget?: number; budget_declared: boolean; met: boolean };
  unit: string;
}) {
  if (!c || !c.measured) {
    return <NotMeasured compact reason={c?.reason ?? "no_samples"} />;
  }
  return (
    <span className={c.met ? "dx-mono" : "dx-mono dx-delta dx-delta--down"}>
      {c.value?.toFixed(unit === "%" ? 2 : 0)}{unit}
      {c.budget
        ? <span className="dx-cap"> vs {c.budget}{unit}{c.budget_declared ? "" : " (platform default)"}</span>
        : <span className="dx-cap"> no budget declared</span>}
    </span>
  );
}
