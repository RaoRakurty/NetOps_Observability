// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// EventDetailPanel — the Event Intelligence panel sliding over the Logs list from the
// right (owner screenshot A). The modal behaviour (focus in and back, Tab trapped,
// Esc closes, full screen under 900px) lives in SidePanel, which Active Alerts and
// Incidents share.

import { useId, useMemo } from "react";
import { LogHit } from "../../lib/logEvent";
import { toEventView } from "../../lib/eventModel";
import EventDetailView from "./EventDetailView";
import SidePanel from "./SidePanel";

export default function EventDetailPanel({ hit, onClose }: { hit: LogHit; onClose: () => void }) {
  const view = useMemo(() => toEventView(hit), [hit]);
  const titleId = useId();
  return (
    <SidePanel onClose={onClose} labelledBy={titleId} testId="event-panel" overlayTestId="event-panel-overlay">
      <EventDetailView view={view} mode="panel" onClose={onClose} titleId={titleId} />
    </SidePanel>
  );
}
