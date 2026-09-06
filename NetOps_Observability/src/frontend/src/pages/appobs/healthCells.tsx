// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// healthCells.tsx — how ONE health row renders, wherever it is shown.
//
// Owner review: a CRITICAL Azure cloud_resource_health "down" row rendered empty
// metric / baseline / current cells. Those three columns describe a METRIC
// ANOMALY ("CPU is 94% vs a 31% baseline"). A provider health STATE event ("the
// provider declares this resource Unavailable, reasonType: Customer Initiated")
// carries none of them — by design, not by omission: it declares a state, it does
// not measure one. Routing it through the metric columns produced "— — —" on the
// most severe row on the page.
//
// These cells answer for BOTH kinds and never with a bare blank. They live here
// rather than in a page so the Investigations Alerts table and the App Detail
// Health table render a state event identically — one rule, one place.

import { ReactNode } from "react";
import type { HealthSignal } from "./types";
import { isStateEvent, stateLabel, stateReason } from "./timeline";

const STATE_EVENT_HINT =
  "A provider health-state declaration: it reports a state, not a measurement, so it carries no metric.";

// Metric — the measurement's name, or an explicit "this row has no measurement".
export function healthMetricCell(r: HealthSignal): ReactNode {
  if (!isStateEvent(r)) return <span className="ao-mono">{r.metric}</span>;
  return <span className="ao-muted" title={STATE_EVENT_HINT}>state change</span>;
}

// Current — the observed value, or (for a state event) the declared STATE, which
// is the row's actual reading.
export function healthCurrentCell(r: HealthSignal): ReactNode {
  if (!isStateEvent(r)) return <strong>{r.current}</strong>;
  return <strong title="The state the provider declared for this resource.">{stateLabel(r.state)}</strong>;
}

// Baseline — a declared state has nothing to compare against, and says so.
export function healthBaselineCell(r: HealthSignal): ReactNode {
  if (!isStateEvent(r)) return <span className="ao-muted">{r.baseline}</span>;
  return <span className="ao-muted" title="A declared state has no baseline to compare against.">—</span>;
}

// Reason — the provider's own reasonType. This is a state event's substance, and
// the field the empty triplet was hiding.
export function healthReasonCell(r: HealthSignal): ReactNode {
  const reason = stateReason(r);
  if (reason) return <span title={`The provider declared this state as "${reason}".`}>{reason}</span>;
  if (isStateEvent(r)) {
    return <span className="ao-muted" title="The provider declared this state without a reason.">no reason stated</span>;
  }
  return <span className="ao-muted">—</span>;
}
