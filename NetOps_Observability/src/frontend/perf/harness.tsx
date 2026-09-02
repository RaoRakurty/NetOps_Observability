// perf/harness.tsx — the measurement rig behind `npm run perf:budget`.
//
// WHAT IT MEASURES. Each scenario renders one real page/component with a
// synthetic high-EPS payload and records three numbers:
//
//   mountMs  — median wall time to mount AND settle the page with that payload
//              (React render + effects + the awaited data commit). This is the
//              "operator clicked the tab during a storm" number.
//   updateMs — median wall time for a RE-RENDER of the settled page. This is
//              the poll-tick cost: every 15-30s these pages swap in a refreshed
//              array and re-render, and anything the render body recomputes
//              without a memo is paid again, on top of whatever the operator
//              was doing. Optional per scenario.
//   nodes    — DOM element count after settling. DETERMINISTIC: it does not
//              vary with the machine, so it is the budget that actually guards
//              "this list renders every row" in CI. A windowed list keeps this
//              flat as the payload grows; an unwindowed one grows with it.
//
// METHOD. WARMUP untimed runs prime the JIT and module graph, then RUNS timed
// runs are taken and the MEDIAN reported (median, not mean: one GC pause must
// not fail a build). Payloads are built once, outside the timed region, from a
// deterministic generator, so consecutive runs measure render, not data setup.
//
// HONESTY. This is happy-dom, not Chrome — the absolute milliseconds are NOT a
// browser frame budget and must never be quoted as one. They are a repeatable
// RELATIVE measure on one machine: they catch an O(rows) render blow-up, which
// is the class of regression these budgets exist to stop. `nodes` is exact and
// machine-independent; treat it as the primary gate.

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import type { ReactElement } from "react";

const WARMUP = Number(process.env.PERF_WARMUP ?? 2);
const RUNS = Number(process.env.PERF_RUNS ?? 5);

export type Budget = {
  /** Median mount+settle budget in ms (machine-relative — see the header). */
  mountMs: number;
  /** Median poll-tick re-render budget in ms. Omit when not measured. */
  updateMs?: number;
  /** Hard DOM element ceiling after settling. Deterministic. */
  nodes: number;
};

export type Result = {
  scenario: string;
  payload: string;
  mountMs: number;
  updateMs: number | null;
  nodes: number;
  budget: Budget;
  ok: boolean;
  breaches: string[];
};

const results: Result[] = [];
export function allResults(): Result[] {
  return results;
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

function mountHost(): { host: HTMLDivElement; root: Root } {
  const host = document.createElement("div");
  document.body.appendChild(host);
  return { host, root: createRoot(host) };
}

async function settle(root: Root, el: ReactElement): Promise<void> {
  // A single act() covers the render, the effects it schedules, and the state
  // commit from any promise those effects await (our api mocks resolve
  // immediately), so the timed region is the whole "page appears with data".
  await act(async () => {
    root.render(el);
  });
}

export type Scenario = {
  name: string;
  /** Human description of the payload, e.g. "5,000 events". */
  payload: string;
  /** Builds a fresh element to render. Called once per run. */
  element: () => ReactElement;
  /** Optional: builds the element a poll tick would produce (new identity). */
  update?: () => ReactElement;
  /**
   * SANITY GUARD. Returns an error string when the settled DOM does not show
   * the payload actually arrived. Without this a broken api stub would render
   * an empty page and the surface would "pass" its budget on nothing at all —
   * the one way a perf gate can lie.
   */
  verify?: (host: HTMLElement) => string | null;
  budget: Budget;
};

/**
 * Runs one scenario and records its result. Returns the result so the caller
 * can assert on it (the spec fails the run; this function never throws on a
 * budget breach, so every scenario is measured even when an earlier one fails).
 */
export async function measure(s: Scenario): Promise<Result> {
  const mounts: number[] = [];
  const updates: number[] = [];
  let nodes = 0;
  let notRendered: string | null = null;

  for (let i = 0; i < WARMUP + RUNS; i++) {
    const { host, root } = mountHost();
    const el = s.element();
    const t0 = performance.now();
    await settle(root, el);
    const t1 = performance.now();

    let u = -1;
    if (s.update) {
      const upd = s.update();
      const t2 = performance.now();
      await settle(root, upd);
      u = performance.now() - t2;
    }

    if (i >= WARMUP) {
      mounts.push(t1 - t0);
      if (u >= 0) updates.push(u);
      nodes = host.querySelectorAll("*").length;
      notRendered = s.verify ? s.verify(host) : null;
    }
    await act(async () => {
      root.unmount();
    });
    host.remove();
  }

  const mountMs = median(mounts);
  const updateMs = updates.length ? median(updates) : null;
  const breaches: string[] = [];
  if (notRendered) breaches.push(`payload did not render: ${notRendered}`);
  if (mountMs > s.budget.mountMs) breaches.push(`mount ${mountMs.toFixed(1)}ms > ${s.budget.mountMs}ms`);
  if (s.budget.updateMs != null && updateMs != null && updateMs > s.budget.updateMs)
    breaches.push(`update ${updateMs.toFixed(1)}ms > ${s.budget.updateMs}ms`);
  if (nodes > s.budget.nodes) breaches.push(`DOM ${nodes} nodes > ${s.budget.nodes}`);

  const r: Result = {
    scenario: s.name,
    payload: s.payload,
    mountMs,
    updateMs,
    nodes,
    budget: s.budget,
    ok: breaches.length === 0,
    breaches,
  };
  results.push(r);
  return r;
}

/** Prints the budget table. Called once from the spec's afterAll. */
export function printTable(): void {
  const head = ["Surface", "Payload", "mount ms", "budget", "poll ms", "budget", "DOM nodes", "budget", ""];
  const rows = results.map((r) => [
    r.scenario,
    r.payload,
    r.mountMs.toFixed(1),
    String(r.budget.mountMs),
    r.updateMs == null ? "—" : r.updateMs.toFixed(1),
    r.budget.updateMs == null ? "—" : String(r.budget.updateMs),
    String(r.nodes),
    String(r.budget.nodes),
    r.ok ? "PASS" : "FAIL",
  ]);
  const w = head.map((h, i) => Math.max(h.length, ...rows.map((row) => row[i].length)));
  const line = (cells: string[]) => cells.map((c, i) => (i <= 1 ? c.padEnd(w[i]) : c.padStart(w[i]))).join("  ");
  const sep = w.map((n) => "-".repeat(n)).join("  ");
  const failed = results.filter((r) => !r.ok);
  const out = [
    "",
    "FRONTEND RENDER BUDGETS — happy-dom, median of " + RUNS + " runs after " + WARMUP + " warmups",
    "(ms are machine-relative; DOM node counts are exact and are the real gate)",
    "",
    line(head),
    sep,
    ...rows.map(line),
    "",
    failed.length === 0
      ? `All ${results.length} surfaces within budget.`
      : `${failed.length} of ${results.length} surfaces OVER BUDGET:\n` +
        failed.map((r) => `  ✗ ${r.scenario}: ${r.breaches.join("; ")}`).join("\n"),
    "",
  ].join("\n");
  // eslint-disable-next-line no-console
  console.log(out);
}
