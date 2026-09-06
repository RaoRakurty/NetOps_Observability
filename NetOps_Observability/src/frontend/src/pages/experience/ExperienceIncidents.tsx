// ExperienceIncidents.tsx — the Incidents tab.
//
// The same table the overview shows, with the server's own filters in front of
// it. Every filter is mirrored into the URL, so a narrowed list can be handed
// to the next shift and a refresh reproduces exactly what was on screen — a
// filter that survives in component state but not in the link is how two people
// end up looking at different incidents while saying the same words.
//
// An unset filter is DROPPED from the request rather than sent blank: a blank
// `app` would narrow the answer to incidents with no application at all, which
// looks identical to "there is nothing" and is not the same claim.

import { api } from "../../services/api";
import type { DemIncidentsResponse, DemSeverity, DemWindow } from "../../services/api";
import { IncidentTable } from "./incidentTable";
import { Loading, LoadError, Panel, reasonText } from "./honest";
import { useDemRead } from "./state";
import type { DxRoute } from "./state";
import AskIris from "../../components/AskIris";

const SEVERITIES: readonly DemSeverity[] = ["critical", "high", "medium", "low", "info"];

export default function ExperienceIncidents({ window: win, route, onIncident }: {
  window: DemWindow;
  route: DxRoute;
  onIncident: (id: string) => void;
}) {
  const severity = route.get("severity");
  const app = route.get("app");
  const journey = route.get("journey");

  const res = useDemRead<DemIncidentsResponse>(
    () => api.demIncidents({
      window: win,
      severity: (severity || undefined) as DemSeverity | undefined,
      app: app || undefined,
      journey: journey || undefined,
    }),
    [win, severity, app, journey],
  );

  return (
    <div className="dx-section">
      <Panel title="Experience incidents" label="Experience incident filters">
        <div className="dx-field-row">
          <div className="dx-field">
            <label htmlFor="dx-inc-sev">Severity</label>
            <select id="dx-inc-sev" value={severity}
              onChange={(e) => route.setParam("severity", e.target.value)}>
              <option value="">Any severity</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="dx-field">
            <label htmlFor="dx-inc-app">Application</label>
            <input id="dx-inc-app" value={app} placeholder="Any application"
              onChange={(e) => route.setParam("app", e.target.value)} />
          </div>
          <div className="dx-field">
            <label htmlFor="dx-inc-journey">Journey</label>
            <input id="dx-inc-journey" value={journey} placeholder="Any journey"
              onChange={(e) => route.setParam("journey", e.target.value)} />
          </div>
        </div>
        {(severity || app || journey) && (
          <div className="dx-actions">
            <button type="button" className="btn" onClick={() => {
              route.setParam("severity", "");
              route.setParam("app", "");
              route.setParam("journey", "");
            }}>Clear filters</button>
            <span className="dx-cap">
              Filtered<AskIris topic="dem.filtered-not-absent" label="a filtered list" />
            </span>
          </div>
        )}
      </Panel>

      {res.status === "loading" && <Loading what="the experience incidents" />}
      {res.status === "error" && (
        <LoadError what="The experience incidents" error={res.error} onRetry={res.reload} />
      )}
      {res.status === "ready" && res.data && (
        <Panel title="Results" label="Experience incident results"
          actions={<span className="dx-chip">{res.data.returned} of {res.data.total}</span>}>
          {!res.data.measured && (
            <p className="dx-error" role="alert">
              {reasonText(res.data.reason)} {res.data.note}
            </p>
          )}
          <IncidentTable rows={res.data.incidents} onOpen={onIncident}
            caption={res.data.complete
              ? undefined
              : `Showing ${res.data.returned} of ${res.data.total} — the list is paged at ${res.data.limit}.`} />
        </Panel>
      )}
    </div>
  );
}
