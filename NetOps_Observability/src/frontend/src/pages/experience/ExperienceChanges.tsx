// ExperienceChanges.tsx — the Changes tab.
//
// One normalized feed of everything that was done to the estate: deployments,
// device and cloud configuration, feature flags, security policy, DNS and
// routing. It is the answer to "what did we change" that a chronological list
// per tool can never give, because the tools do not share a clock or a noun.
//
// THE SENTENCE THAT MATTERS MOST IS THE EMPTY ONE. An empty feed is rendered
// with the server's own note: a quiet estate reports nothing, but silence here
// is not proof that nothing changed — only the producers that are wired report
// at all. A blank table with no caption would read as the first claim while
// meaning the second.

import { api } from "../../services/api";
import type { DemChangesResponse, DemCohort, DemWindow } from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { ProvenanceChip, Loading, LoadError, Panel } from "./honest";
import { useDemRead } from "./state";
import type { DxRoute } from "./state";

const TYPES = [
  "APPLICATION_DEPLOY", "CONFIG_CHANGE", "FEATURE_FLAG_CHANGE", "CLOUD_CHANGE",
  "NETWORK_CHANGE", "SECURITY_POLICY_CHANGE", "DNS_CHANGE", "ROUTE_CHANGE",
  "INFRASTRUCTURE_CHANGE",
] as const;

function typeWords(t: string): string {
  return t.replace(/_/g, " ").toLowerCase();
}

export default function ExperienceChanges({ window: win, route }: {
  window: DemWindow; route: DxRoute;
}) {
  const type = route.get("type");
  const app = route.get("app");
  const site = route.get("site");

  const res = useDemRead<DemChangesResponse>(
    () => api.demChanges({
      window: win,
      type: type || undefined,
      app: app || undefined,
      site: site || undefined,
    }),
    [win, type, app, site],
  );

  return (
    <div className="dx-section">
      <Panel title="Change feed" label="Change feed filters">
        <div className="dx-field-row">
          <div className="dx-field">
            <label htmlFor="dx-ch-type">Kind of change</label>
            <select id="dx-ch-type" value={type}
              onChange={(e) => route.setParam("type", e.target.value)}>
              <option value="">Any kind</option>
              {TYPES.map((t) => <option key={t} value={t}>{typeWords(t)}</option>)}
            </select>
          </div>
          <div className="dx-field">
            <label htmlFor="dx-ch-app">Application</label>
            <input id="dx-ch-app" value={app} placeholder="Any application"
              onChange={(e) => route.setParam("app", e.target.value)} />
          </div>
          <div className="dx-field">
            <label htmlFor="dx-ch-site">Site</label>
            <input id="dx-ch-site" value={site} placeholder="Any site"
              onChange={(e) => route.setParam("site", e.target.value)} />
          </div>
        </div>
      </Panel>

      {res.status === "loading" && <Loading what="the change feed" />}
      {res.status === "error" && (
        <LoadError what="The change feed" error={res.error} onRetry={res.reload} />
      )}
      {res.status === "ready" && res.data && (
        <Panel title="Changes" label="Change feed results"
          actions={<span className="dx-chip">{res.data.returned} of {res.data.total}</span>}>
          {res.data.changes.length === 0 ? (
            <p className="dx-note">{res.data.note}</p>
          ) : (
            <div className="dx-scroll">
              <table className="dx-table">
                <caption className="dx-cap" style={{ captionSide: "bottom", textAlign: "left" }}>
                  {res.data.complete
                    ? "The whole window is shown."
                    : `Showing ${res.data.returned} of ${res.data.total} — the feed is paged at ${res.data.limit}.`}
                </caption>
                <thead>
                  <tr>
                    <th scope="col">When</th><th scope="col">Kind</th>
                    <th scope="col">Object</th><th scope="col">Summary</th>
                    <th scope="col">Before → after</th><th scope="col">Actor</th>
                    <th scope="col">Where</th><th scope="col">How we know</th>
                  </tr>
                </thead>
                <tbody>
                  {res.data.changes.map((c) => (
                    <tr key={c.id}>
                      <td className="dx-mono">{fmtDateTime(c.provenance?.event_at)}</td>
                      <td>{typeWords(c.type)}</td>
                      <td className="dx-mono">
                        {c.object}
                        {c.object_kind && <div className="dx-cap">{c.object_kind}</div>}
                      </td>
                      <td>
                        {c.summary}
                        {c.release_id && <div className="dx-cap">release {c.release_id}</div>}
                        {c.rollback_ref && <div className="dx-cap">rollback {c.rollback_ref}</div>}
                      </td>
                      <td className="dx-cap">
                        {c.before || c.after
                          ? `${c.before || "—"} → ${c.after || "—"}`
                          : <span className="dx-subtle">not recorded</span>}
                      </td>
                      <td>{c.actor || <span className="dx-subtle">not recorded</span>}</td>
                      <td className="dx-cap">
                        {[c.app, c.site, c.seam].filter(Boolean).join(" · ") || "—"}
                        {cohortWords(c.cohort) && <div>{cohortWords(c.cohort)}</div>}
                      </td>
                      <td>
                        <ProvenanceChip observation={c.provenance?.observation} />
                        <div className="dx-cap">{c.provenance?.source}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}

function cohortWords(c?: DemCohort): string {
  if (!c) return "";
  const parts = Object.entries(c as Record<string, string | undefined>)
    .filter(([, v]) => v).map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`);
  return parts.length ? `reached ${parts.join(", ")}` : "";
}
