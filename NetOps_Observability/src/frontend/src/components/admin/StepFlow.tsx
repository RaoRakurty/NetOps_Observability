// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import type { ReactNode } from "react";

// StepFlow — a numbered, prerequisite-gated setup flow (NOC-admin standard:
// numbered-step workflow pages).
//
// GATING RULE. Step N's body shows when step N−1 is done, OR when step N
// already holds data. The second half matters: a failing delivery outbox must
// never be hidden behind "finish step 2 first" just because someone later
// disabled the policy that filled it. A locked step shows its number, title
// and "Finish step N first."; an optional step never blocks the next one.

export type FlowStep = {
  id: string;
  title: string; // ≤ 3 words (card-heading word budget)
  done: boolean;
  /** The step already has data of its own — show it even if locked. */
  hasData?: boolean;
  optional?: boolean;
  /** One short fact shown beside the title (a state, a count). */
  status?: string;
  render: () => ReactNode;
};

/** Per step: is its body shown, and does it count as done. A step counts as
 *  done only when it is also OPEN — a locked step's own "done" (e.g. "no rules
 *  needed, ticketing runs") must not unlock the steps after it or wear a ✓
 *  while its prerequisite is unmet. Pure — the tests drive it. */
export function stepStates(steps: readonly FlowStep[]): { open: boolean; done: boolean }[] {
  const out: { open: boolean; done: boolean }[] = [];
  for (let i = 0; i < steps.length; i++) {
    let open = i === 0 || !!steps[i].hasData;
    if (!open) {
      // The nearest earlier step that is not optional decides.
      let decided = false;
      for (let j = i - 1; j >= 0; j--) {
        if (!steps[j].optional) { open = out[j].done; decided = true; break; }
      }
      if (!decided) open = true;
    }
    out.push({ open, done: open && steps[i].done });
  }
  return out;
}

/** For each step, whether its body is shown. */
export function unlockedSteps(steps: readonly FlowStep[]): boolean[] {
  return stepStates(steps).map((s) => s.open);
}

/** The number a locked step names: the nearest earlier required step. */
function blockingStep(steps: readonly FlowStep[], i: number): number {
  for (let j = i - 1; j >= 0; j--) if (!steps[j].optional) return j + 1;
  return 1;
}

export default function StepFlow({ steps, label }: { steps: FlowStep[]; label: string }) {
  const st = stepStates(steps);
  return (
    <ol className="step-flow" aria-label={label}>
      {steps.map((s, i) => (
        <li key={s.id} className={`step-flow-step${st[i].done ? " done" : ""}${st[i].open ? "" : " locked"}`} data-step={s.id}>
          <div className="step-flow-head">
            <span className="step-flow-num" aria-hidden>{st[i].done ? "✓" : i + 1}</span>
            <h3 className="step-flow-title">
              <span className="sr-only">Step {i + 1}: </span>
              {s.title}
              {s.optional && <span className="step-flow-opt"> (optional)</span>}
            </h3>
            {s.status && <span className="step-flow-status">{s.status}</span>}
          </div>
          {st[i].open ? (
            <div className="step-flow-body">{s.render()}</div>
          ) : (
            <p className="step-flow-locked">Finish step {blockingStep(steps, i)} first.</p>
          )}
        </li>
      ))}
    </ol>
  );
}
