// ExperiencePaths.tsx — the Service Paths tab.
//
// WHAT THIS TAB DELIBERATELY DOES NOT DO: draw a path.
//
// The ordered spine of hops belongs to the service path graph, which owns the
// frozen path contract and is the single source of hop order. An experience
// incident carries a REFERENCE to the immutable path observation it rode, and
// nothing else. Assembling a path here out of the evidence that happened to be
// collected would produce a picture that looks measured and is not — the exact
// class of drawing an operator would then escalate on.
//
// So this tab renders the reference, and when the server says `measured:false`
// it renders the server's sentence VERBATIM. "No forward path was observed" and
// "the path was clean" are opposite findings, and only the first one is true
// here.

import { api } from "../../services/api";
import type { DemIncidentsResponse, DemWindow } from "../../services/api";
import { SeamRibbon } from "./ribbon";
import { Loading, LoadError, Panel, SeverityChip, reasonText } from "./honest";
import { useDemRead } from "./state";
import type { DxRoute } from "./state";

export default function ExperiencePaths({ window: win, route }: {
  window: DemWindow;
  route: DxRoute;
}) {
  const list = useDemRead<DemIncidentsResponse>(() => api.demIncidents({ window: win }), [win]);
  const selected = route.get("incident");

  if (list.status === "loading") return <Loading what="the experience incidents" />;
  if (list.status === "error" || !list.data) {
    return <LoadError what="The experience incidents" error={list.error} onRetry={list.reload} />;
  }

  const rows = list.data.incidents;
  const current = rows.find((r) => r.id === selected) ?? rows[0];

  return (
    <div className="dx-section">
      <Panel title="Service paths" label="Service paths">
        <p className="dx-note">
          A path is shown only where one was observed. The ordered hops belong to the service
          path graph and are fetched from it by the observation reference below; they are never
          reconstructed here from whatever evidence happened to be collected.
        </p>
        {!list.data.measured && (
          <p className="dx-error" role="alert">{reasonText(list.data.reason)} {list.data.note}</p>
        )}
        {rows.length === 0 ? (
          <p className="dx-note">
            No experience incident is open in this window, so there is no path to look at.
          </p>
        ) : (
          <div className="dx-field">
            <label htmlFor="dx-path-incident">Incident</label>
            <select id="dx-path-incident" value={current?.id ?? ""}
              onChange={(e) => route.setParam("incident", e.target.value)}>
              {rows.map((r) => (
                <option key={r.id} value={r.id}>{r.severity} · {r.title}</option>
              ))}
            </select>
          </div>
        )}
      </Panel>

      {current && <PathForIncident id={current.id} win={win} title={current.title}
        severity={current.severity} layer={current.likely_layer} seam={current.seam}
        owner={current.owner} cause={current.leading_cause} />}
    </div>
  );
}

function PathForIncident({ id, win, title, severity, layer, seam, owner, cause }: {
  id: string; win: DemWindow; title: string; severity: string;
  layer?: string; seam?: string; owner?: string; cause?: string;
}) {
  const path = useDemRead(() => api.demIncidentPath(id, win), [id, win]);

  return (
    <Panel title={title} label={`Path for ${title}`}
      actions={<SeverityChip severity={severity} />}>
      <SeamRibbon layer={layer} seam={seam} owner={owner} cause={cause}
        label={`Seam ribbon for ${title}`} />

      {path.status === "loading" && <Loading what="the path reference" />}
      {path.status === "error" && (
        <LoadError what="The path reference" error={path.error} onRetry={path.reload} />
      )}
      {path.status === "ready" && path.data && (
        path.data.measured === false || !path.data.path_observation_id ? (
          <p className="dx-note" role="note">{path.data.reason}</p>
        ) : (
          <>
            <p className="dx-note">
              Path observation <span className="dx-mono">{path.data.path_observation_id}</span>.
            </p>
            <p className="dx-cap">{path.data.note}</p>
          </>
        )
      )}
    </Panel>
  );
}
