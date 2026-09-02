import { useEffect, useMemo, useState } from "react";
import "./Security.css";
import { api, SecFacets } from "../../services/api";
import ComplianceMonitoring from "../ComplianceMonitoring";
import { Group, Panel } from "../../components/board/panels";
import { Segmented } from "../../components/ui";
import { FrameworkScore, frameworkScore, mapFacetRows } from "./model";

// Compliance — two sub-views:
//
//  · Control set — hardening findings on the TAGGED control set, per standard.
//    The number is pass ÷ (pass+warn+fail) over the findings that carry that
//    standard's tag, and the page says exactly that. It is NOT a framework
//    compliance percentage, and the copy never claims one: we do not know the
//    denominator of the standard, only of our own tagged findings, and no
//    licensed benchmark text is redistributed.
//  · Drift & baselines — the existing Compliance Monitoring board (source-of-
//    truth drift + management-plane baselines), reused as a sub-view.
//
// Tenant isolation (§3a): the facet calls are server-scoped by the token.

type SubView = "controls" | "drift";

/** Per-framework scores need one facet call per framework (the facets endpoint
 *  returns a framework HISTOGRAM, not a per-framework verdict split). Bounded
 *  by the number of tagged standards, which is small by construction. */
async function loadFrameworkScores(frameworks: string[]): Promise<FrameworkScore[]> {
  const results = await Promise.all(frameworks.map(async (fw) => {
    try {
      const facets = await api.securityFindingFacets({ current: true, framework: fw });
      return { fw, facets };
    } catch {
      return { fw, facets: null as SecFacets | null };
    }
  }));
  return results.map((r) => frameworkScore(r.fw, 0, r.facets));
}

function Ring({ score }: { score: FrameworkScore }) {
  const toneCls = score.tone === "bad" ? "t-bad" : score.tone === "warn" ? "t-warn" : score.tone === "good" ? "t-good" : "";
  return (
    <div className="sec-ring">
      <div className={`g ${toneCls}`} aria-hidden="true">
        {score.pct === null ? "—" : `${score.pct}%`}
      </div>
      <div className="cap">{score.framework}</div>
      <div className="st">
        {score.pct === null
          ? <span className="sec-unassessed">unassessed</span>
          : `${score.pass}/${score.pass + score.warn + score.fail} passing`}
      </div>
    </div>
  );
}

export default function SecurityCompliance() {
  const [tab, setTab] = useState<SubView>("controls");
  const [facets, setFacets] = useState<SecFacets | null>(null);
  const [scores, setScores] = useState<FrameworkScore[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let alive = true;
    api.securityFindingFacets({ current: true })
      .then(async (f) => {
        if (!alive) return;
        setFacets(f);
        const names = mapFacetRows(f.framework).map((r) => r.key);
        const s = await loadFrameworkScores(names);
        if (!alive) return;
        // Re-attach the tagged count from the unfiltered histogram.
        const tagged = f.framework ?? {};
        setScores(s.map((x) => ({ ...x, tagged: Number(tagged[x.framework]) || 0 })));
        setErr(null);
      })
      .catch((e: Error) => { if (alive) setErr(e.message); })
      .finally(() => { if (alive) setLoaded(true); });
    return () => { alive = false; };
  }, []);

  const taggedTotal = useMemo(
    () => scores.reduce((n, s) => n + s.tagged, 0),
    [scores],
  );

  return (
    <div className="sec dm-board">
      <div className="sec-toolbar">
        <Segmented
          value={tab}
          onChange={setTab}
          options={[
            { value: "controls" as SubView, label: "Control set" },
            { value: "drift" as SubView, label: "Drift & baselines" },
          ]}
          ariaLabel="Compliance view"
        />
      </div>

      {tab === "drift" ? (
        <ComplianceMonitoring />
      ) : (
        <Group title="Hardening findings on the tagged control set" hue="#8b5cf6">
          {err ? (
            <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>
          ) : !loaded ? (
            <div className="empty" role="status">Loading…</div>
          ) : scores.length === 0 ? (
            <div className="empty">
              No finding carries a standards tag yet, so nothing can be reported against a control set.
              This is an absence of assessment, not a passing result.
            </div>
          ) : (
            <>
              <Panel title="Per standard">
                <div className="sec-rings">
                  {scores.map((s) => <Ring key={s.framework} score={s} />)}
                </div>
              </Panel>
              <table className="ds-table" aria-label="Hardening findings by standard">
                <thead>
                  <tr>
                    <th scope="col">Standard</th>
                    <th scope="col">Tagged findings</th>
                    <th scope="col">Pass</th>
                    <th scope="col">Warning</th>
                    <th scope="col">Fail</th>
                    <th scope="col">Passing share</th>
                  </tr>
                </thead>
                <tbody>
                  {scores.map((s) => (
                    <tr key={s.framework}>
                      <th scope="row" style={{ textAlign: "left", fontWeight: 500 }}>{s.framework}</th>
                      <td>{s.tagged.toLocaleString()}</td>
                      <td>{s.pass.toLocaleString()}</td>
                      <td>{s.warn.toLocaleString()}</td>
                      <td>{s.fail.toLocaleString()}</td>
                      <td>{s.pct === null ? <span className="sec-unassessed">unassessed</span> : `${s.pct}%`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="mini-meta" style={{ margin: 0 }} role="status">
                {taggedTotal.toLocaleString()} hardening findings carry a standards tag
                {facets ? ` across ${scores.length} standard${scores.length === 1 ? "" : "s"}` : ""}.
                The share shown is passing verdicts over the tagged control set only — it is not a
                framework compliance score, and an untested control is counted nowhere.
              </p>
            </>
          )}
        </Group>
      )}
    </div>
  );
}
