// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ExperiencePage.tsx — the Digital Experience surface's container.
//
// Seven tabs, in the order an operator works: Experience (what is the state) →
// Incidents (what is broken) → Journeys (what people were trying to do) →
// Service Paths (where it broke) → Synthetics (what we measure it with) →
// Changes (what we did to ourselves) → Data Health (how much of the above we
// could actually see).
//
// ROUTING. `#/operations/digital-experience/<tab>`, read from the THIRD hash
// segment on mount and on every `hashchange` — the same mechanism
// AppObservability uses, and for the same reason: this leaf stays mounted when
// a rail sub-item is clicked, so a mount-only effect would never see the new
// suffix and the click would look dead.
//
// One INTENTIONAL improvement over AppObservability: this page also PUSHES the
// hash when a tab or a filter changes, so every sub-view and every narrowed
// list is linkable. A view you cannot hand to the next shift is a view that
// gets described in words instead, and descriptions drift.
//
// The measurement window (1h | 24h) is owned here and passed down, so the seven
// tabs can never quietly describe different windows.

import { useState } from "react";

import { NocHeader } from "../../components/noc";
import type { DemWindow } from "../../services/api";
import ExperienceChanges from "./ExperienceChanges";
import ExperienceDataHealth from "./ExperienceDataHealth";
import ExperienceIncidentView from "./ExperienceIncidentView";
import ExperienceIncidents from "./ExperienceIncidents";
import ExperienceJourneys from "./ExperienceJourneys";
import ExperienceOverview from "./ExperienceOverview";
import ExperiencePaths from "./ExperiencePaths";
import ExperienceSynthetics from "./ExperienceSynthetics";
import "./experience.css";
import { DX_TABS, DX_TAB_LABEL, DX_WINDOWS, useDxRoute } from "./state";
import type { DxTab } from "./state";
import AskIris from "../../components/AskIris";

export default function ExperiencePage() {
  const route = useDxRoute();
  const [win, setWin] = useState<DemWindow>("1h");

  const openIncident = (id: string) => {
    route.setTab("incidents");
    // setTab clears the previous tab's filters, so the incident is set after it.
    route.setParam("incident", id);
  };

  const incidentId = route.tab === "incidents" ? route.get("incident") : "";

  return (
    <div className="dm-board cc-board dx">
      <NocHeader
        title="Digital Experience"
        subtitle="What people actually experienced, what broke it, and how much of that we could see"
      />

      <nav className="dx-tabs" role="tablist" aria-label="Digital Experience">
        {DX_TABS.map((t) => (
          <button key={t} type="button" role="tab" id={`dx-tab-${t}`}
            aria-selected={route.tab === t} aria-controls="dx-panel"
            className="dx-tab" onClick={() => route.setTab(t)}>
            {DX_TAB_LABEL[t]}
          </button>
        ))}
      </nav>

      <div className="dx-toolbar">
        <div className="dx-toolbar-group">
          <span className="dx-card-label" id="dx-window-label">Window</span>
          <div className="dx-window" role="group" aria-labelledby="dx-window-label">
            {DX_WINDOWS.map((w) => (
              <button key={w} type="button" aria-pressed={win === w}
                aria-label={`Measure over the last ${w}`}
                onClick={() => setWin(w)}>{w}</button>
            ))}
          </div>
        </div>
        <p className="dx-cap">
          Absent is not healthy.<AskIris topic="dem.absence-not-health" label="an absent measurement" />
        </p>
      </div>

      <div id="dx-panel" role="tabpanel" aria-labelledby={`dx-tab-${route.tab}`}>
        {route.tab === "experience" && (
          <ExperienceOverview window={win} onTab={(t: DxTab) => route.setTab(t)}
            onIncident={openIncident} />
        )}
        {route.tab === "incidents" && (
          incidentId
            ? <ExperienceIncidentView id={incidentId} window={win}
                onBack={() => route.setParam("incident", "")} />
            : <ExperienceIncidents window={win} route={route} onIncident={(id) => route.setParam("incident", id)} />
        )}
        {route.tab === "journeys" && <ExperienceJourneys window={win} />}
        {route.tab === "paths" && <ExperiencePaths window={win} route={route} />}
        {route.tab === "synthetics" && <ExperienceSynthetics window={win} />}
        {route.tab === "changes" && <ExperienceChanges window={win} route={route} />}
        {route.tab === "data-health" && <ExperienceDataHealth window={win} />}
      </div>
    </div>
  );
}
