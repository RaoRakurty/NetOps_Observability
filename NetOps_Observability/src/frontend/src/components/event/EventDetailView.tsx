// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// EventDetailView — the Event Intelligence view of one record, in two layouts that
// share every section:
//
//   • "panel" (owner screenshot A): header, tabs under it, and the Overview tab holds the
//     primary visual, a 3-up row of Device | Timing | Classification, a 3-up row of
//     Impact | Next checks | Identity, then the decoded details.
//   • "page" (owner screenshot B): breadcrumb and header; a wide left column with the
//     primary visual, the tabs under it and the Overview (What happened + Timing,
//     Timeline, details); a right column with Device, Classification and Identity.
//
// Actions appear only where a real endpoint stands behind them: Create incident
// (POST /api/incidents, tenant stamped from the token), Share (copies this page's deep
// link), Open full page (the deep link). There is no acknowledge, star or "more" here
// because nothing on the server backs them for a log record.

import { ReactNode, useEffect, useId, useState } from "react";
import { api } from "../../services/api";
import { EventView } from "../../lib/eventModel";
import EvIcon from "./EvIcon";
import {
  ClassificationCard, DetailsCard, DeviceCard, EVENT_TABS, EventHeader, EventTab, EventTabs, IdentityCard, ImpactCard,
  MetricsTab, NextChecksCard, PrimaryVisualCard, RawTab, TechnicalTab, TimelineCard, TimingCard, WhatHappenedCard, toneClass,
} from "./EventSections";
import { copyText, useMetricTrend, useRelatedRecords } from "./useEventData";
import "./event.css";

/** The deep link to the full event page. The id and time are encoded; nothing else rides along. */
export function eventHref(view: EventView): string | null {
  const l = view.link;
  if (!l) return null;
  return `#/explore/logs/event/${l.signal || "all"}/${encodeURIComponent(l.id)}?t=${encodeURIComponent(l.t)}`;
}

function CreateIncident({ view }: { view: EventView }) {
  const [step, setStep] = useState<"idle" | "confirm" | "busy" | "done" | "error">("idle");
  const [msg, setMsg] = useState("");
  const create = async () => {
    setStep("busy");
    try {
      const r = await api.createIncident(view.incidentDraft);
      setStep("done");
      setMsg(r?.created === false ? "Added to the open incident with the same title." : "Incident created. Find it under Operations → Incidents.");
    } catch (e) {
      setStep("error");
      setMsg((e as Error)?.message || "The incident could not be created.");
    }
  };
  if (step === "confirm" || step === "busy") {
    return (
      <span className="evd-confirm" role="group" aria-label="Create incident">
        <span className="evd-confirm-q">Open an incident titled “{view.incidentDraft.title}”?</span>
        <button type="button" className="evd-btn evd-btn-primary" onClick={create} disabled={step === "busy"}>
          {step === "busy" ? "Creating…" : "Create"}
        </button>
        <button type="button" className="evd-btn" onClick={() => setStep("idle")} disabled={step === "busy"}>Cancel</button>
      </span>
    );
  }
  return (
    <>
      <button type="button" className="evd-btn" onClick={() => { setStep("confirm"); setMsg(""); }}>
        <EvIcon name="plus-doc" size={16} /> Create Incident
      </button>
      {msg && <span className={`evd-action-msg${step === "error" ? " evd-action-err" : ""}`} role="status">{msg}</span>}
    </>
  );
}

function ShareButton({ view }: { view: EventView }) {
  const [state, setState] = useState("");
  const href = eventHref(view);
  if (!href) return null;
  const url = `${location.origin}${location.pathname}${href}`;
  return (
    <>
      <button type="button" className="evd-btn" onClick={async () => setState(await copyText(url))} title="Copy a link to this event">
        <EvIcon name="share" size={16} /> Share
      </button>
      {state && <span className="evd-action-msg" role="status">{state === "Copied" ? "Link copied" : state}</span>}
    </>
  );
}

export interface EventDetailViewProps {
  view: EventView;
  mode: "panel" | "page";
  /** Panel only: the close control. */
  onClose?: () => void;
  /** Panel only: where the title's id goes, for the dialog's aria-labelledby. */
  titleId?: string;
}

export default function EventDetailView({ view, mode, onClose, titleId }: EventDetailViewProps) {
  const [tab, setTab] = useState<EventTab>("Overview");
  const uid = useId();
  const tid = titleId ?? `${uid}-title`;
  const related = useRelatedRecords(view);
  const trend = useMetricTrend(view, tab === "Metrics");
  useEffect(() => setTab("Overview"), [view.id]);
  const href = eventHref(view);

  const actions = (
    <>
      <CreateIncident view={view} />
      <ShareButton view={view} />
      {mode === "panel" && href && (
        <a className="evd-btn" href={href} title="Open this event as a full page">
          <EvIcon name="external" size={16} /> Full page
        </a>
      )}
    </>
  );
  const close = mode === "panel" && onClose ? (
    <button type="button" className="evd-icon-btn evd-close" onClick={onClose} aria-label="Close event details" title="Close (Esc)" data-testid="event-close">
      <EvIcon name="close" size={20} />
    </button>
  ) : undefined;

  const tabPanel = (content: ReactNode) => (
    <div className="evd-tabpanel" role="tabpanel" id={`${uid}-panel`} aria-labelledby={`${uid}-tab-${tab.replace(/\s/g, "")}`} tabIndex={0}>
      {content}
    </div>
  );

  const identityTitle = mode === "panel" ? "Event Identity & Lifecycle" : "Event Identity & Correlation";
  const otherTab = (): ReactNode => {
    switch (tab) {
      case "Metrics": return <MetricsTab view={view} trend={trend} />;
      case "Timeline": return <div className="evd-stack"><TimelineCard view={view} related={related} /></div>;
      case "Technical Details": return <TechnicalTab view={view} />;
      case "Raw Event": return <RawTab view={view} />;
      default: return null;
    }
  };

  if (mode === "panel") {
    return (
      <div className={`evd evd-mode-panel ${toneClass(view.severity.tone)}`} data-testid="event-detail" data-lane={view.lane}>
        <EventHeader view={view} actions={actions} close={close} titleId={tid} />
        <EventTabs tab={tab} onTab={setTab} uid={uid} />
        {tabPanel(tab === "Overview" ? (
          <div className="evd-stack">
            <PrimaryVisualCard view={view} />
            <div className="evd-grid3">
              <DeviceCard view={view} variant="rows" />
              <TimingCard view={view} />
              <ClassificationCard view={view} />
            </div>
            <div className="evd-grid3">
              <ImpactCard view={view} />
              <NextChecksCard view={view} />
              <IdentityCard view={view} related={related} title={identityTitle} />
            </div>
            {view.overview.what && view.overview.impact.length === 0 && (
              <section className="evd-card evd-what" aria-label="What happened">
                <header className="evd-card-head"><EvIcon name="doc" size={18} className="evd-card-ico" /><h3 className="evd-card-title">What Happened</h3></header>
                <p className="evd-what-text">{view.overview.what}</p>
              </section>
            )}
            <DetailsCard view={view} />
          </div>
        ) : otherTab())}
      </div>
    );
  }

  return (
    <div className={`evd evd-mode-page ${toneClass(view.severity.tone)}`} data-testid="event-detail" data-lane={view.lane}>
      <nav className="evd-crumbs" aria-label="Breadcrumb">
        <a href="#/explore/logs">Logs</a>
        <EvIcon name="chevron" size={14} />
        <span aria-current="page">Event Detail</span>
      </nav>
      <EventHeader view={view} actions={actions} titleId={tid} />
      <div className="evd-page-grid">
        <div className="evd-page-main">
          <PrimaryVisualCard view={view} />
          <EventTabs tab={tab} onTab={setTab} uid={uid} />
          {tabPanel(tab === "Overview" ? (
            <div className="evd-stack">
              <div className="evd-grid-what">
                <WhatHappenedCard view={view} />
                <TimingCard view={view} />
              </div>
              <TimelineCard view={view} related={related} />
              <DetailsCard view={view} />
            </div>
          ) : otherTab())}
        </div>
        <aside className="evd-page-side" aria-label="Event context">
          <DeviceCard view={view} variant="header" />
          <ClassificationCard view={view} />
          <IdentityCard view={view} related={related} title={identityTitle} />
        </aside>
      </div>
    </div>
  );
}

export { EVENT_TABS };
