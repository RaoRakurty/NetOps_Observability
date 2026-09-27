// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisProgress — the operational trace of one question (tracker 337 N-E2/N-E3,
// design §4.1 decision 8). The steps are the server's CLOSED event names
// (resolved, querying, found, rca_loaded, rendering) mapped to plain words —
// never model reasoning text. An unknown event name is shown as a generic
// "Working" step, not echoed, so a newer or hostile stream cannot put words on
// screen through the event name. A step's `detail` is server data (a count, an
// entity) rendered as escaped text and clipped.
//
// The latest step is announced through a polite live region (WCAG 4.1.3).

import { clip, lookup } from "./presentation";

export type ProgressState = "done" | "active" | "failed";

export interface ProgressStep {
  event: string;
  detail?: string;
  state?: ProgressState;
}

const EVENT_LABEL: Record<string, string> = {
  resolved: "Understood the question",
  querying: "Reading the data",
  found: "Found results",
  rca_loaded: "Loaded the root-cause analysis",
  rendering: "Preparing the answer",
};

export function stepLabel(event: string): string {
  return lookup(EVENT_LABEL, event) ?? "Working";
}

const STATE_WORD: Record<ProgressState, string> = {
  done: "done",
  active: "in progress",
  failed: "failed",
};

const MAX_STEPS = 20;

export default function IrisProgress({ steps }: { steps: ProgressStep[] }) {
  const list = (Array.isArray(steps) ? steps : []).filter((s) => s && typeof s.event === "string").slice(-MAX_STEPS);
  const last = list[list.length - 1];
  const announce = last ? `${stepLabel(last.event)} — ${lookup(STATE_WORD, last.state ?? "active") ?? "in progress"}` : "";
  return (
    <div className="iris-progress">
      <ol className="iris-progress-list" aria-label="What Iris is doing">
        {list.map((s, i) => {
          const state: ProgressState = s.state === "done" || s.state === "failed" ? s.state : "active";
          return (
            <li key={i} className={`iris-progress-step state-${state}`}>
              <span className="iris-progress-mark" aria-hidden="true">
                {state === "done" ? "✓" : state === "failed" ? "!" : "…"}
              </span>
              <span>
                {stepLabel(s.event)}
                {typeof s.detail === "string" && s.detail.trim() !== "" && (
                  <span className="iris-muted"> · {clip(s.detail, 120)}</span>
                )}
                <span className="sr-only"> ({STATE_WORD[state]})</span>
              </span>
            </li>
          );
        })}
      </ol>
      <div className="sr-only" role="status" aria-live="polite">
        {announce}
      </div>
    </div>
  );
}
