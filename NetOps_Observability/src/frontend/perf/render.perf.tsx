// perf/render.perf.tsx — the render-budget suite (`npm run perf:budget`).
//
// One scenario per heavy operator surface, each fed the volume a busy network
// produces during a storm. A scenario FAILS the run when it exceeds the budget
// recorded in perf/budgets.json. See perf/harness.tsx for the method and its
// honest limits, and docs/design/FRONTEND_PERF_BUDGETS_2026-09-02.md for the
// before/after numbers and why each budget sits where it does.

import { describe, it, expect, beforeEach, afterEach, afterAll, vi } from "vitest";
import { measure, printTable, type Budget } from "./harness";
import * as synth from "./synth";
import budgetsJson from "./budgets.json";

import { api } from "../src/services/api";

const budgets = budgetsJson as unknown as Record<string, Budget>;

// Pages under test.
import Events from "../src/pages/Events";
import Correlations from "../src/tabs/Correlations";
import Logs from "../src/tabs/Logs";
import Devices from "../src/pages/Devices";
import { TopologyInventoryPanel } from "../src/features/topology/components/TopologyInventoryPanel";

// ── payloads, built ONCE (outside every timed region) ────────────────────────
synth.resetRand();
const EVENT_SYSLOG = synth.syslogHits(2400);
const EVENT_TRAPS = synth.trapHits(2400);
const EVENT_ALERTS = synth.alerts(200);  // 2400 + 2400 + 200 = 5,000 events
const CORR_ROWS = synth.correlations(2000);
const LOG_HITS = synth.syslogHits(20000);
const DEVICE_ROWS = synth.devices(2000);
const TOPO_VIEW = synth.topologyView(1000);
// A second identity of the SAME data — what a poll tick hands the component.
const TOPO_VIEW_TICK = { ...TOPO_VIEW, nodes: [...TOPO_VIEW.nodes], edges: [...TOPO_VIEW.edges] };

const NO_SELECTION = {};
const noop = () => {};

beforeEach(() => {
  // Stub only what these pages fetch on mount; everything else stays real, so
  // an api rename breaks this suite instead of silently measuring a stub.
  vi.spyOn(api, "alerts").mockResolvedValue(EVENT_ALERTS as never);
  vi.spyOn(api, "features").mockResolvedValue({} as never);
  vi.spyOn(api, "devices").mockResolvedValue(DEVICE_ROWS as never);
  vi.spyOn(api, "deviceLocations").mockResolvedValue({ devices: [] } as never);
  vi.spyOn(api, "sites").mockResolvedValue({ sites: [], active: "internal" } as never);
  vi.spyOn(api, "logsRetention").mockResolvedValue(null as never);
  vi.spyOn(api, "rcaLibrary").mockResolvedValue({ reports: [] } as never);
  vi.spyOn(api, "ticketLinks").mockResolvedValue({ links: [] } as never);
  vi.spyOn(api, "correlationsSummary").mockResolvedValue({
    total: CORR_ROWS.length, confirmed: 700, suspected: 800, undetermined: 500,
  } as never);
  // `data` is the ClickHouse envelope key the list reads. The server pages at
  // 200; handing the whole 2,000 here is the "operator pressed Load more ten
  // times during a storm" case the budget is meant to hold.
  vi.spyOn(api, "correlations").mockResolvedValue({
    data: CORR_ROWS, rows: CORR_ROWS.length, next_cursor: "",
  } as never);
  // Both the Events feed and the Log search call searchLogs; they are told
  // apart by the bounded window the Log search always sends (`to`). Each is
  // handed its FULL scenario payload rather than one server page — the budget
  // is for the loaded-through state ("Load more" pressed to the end), which is
  // what an operator working a storm actually ends up looking at.
  vi.spyOn(api, "searchLogs").mockImplementation(((opts: { signal?: string; to?: string }) => {
    if (opts?.to) return Promise.resolve(synth.osEnvelope(LOG_HITS));      // Log search
    if (opts?.signal === "snmptrap") return Promise.resolve(synth.osEnvelope(EVENT_TRAPS));
    return Promise.resolve(synth.osEnvelope(EVENT_SYSLOG));                 // Events feed
  }) as never);
});

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(() => {
  printTable();
});

/**
 * Asserts the table really holds `n` rows. DataTable publishes the full view
 * size as aria-rowcount (NOT the windowed slice), so this proves the payload
 * arrived even though only a screenful is in the DOM — which is exactly the
 * property a windowed list must have.
 */
function hasRows(n: number) {
  return (host: HTMLElement): string | null => {
    const grid = host.querySelector('[role="grid"]');
    if (!grid) return "no table rendered";
    const got = Number(grid.getAttribute("aria-rowcount"));
    return got === n ? null : `table holds ${got} rows, expected ${n}`;
  };
}

/** Asserts a phrase carrying the payload size is on screen. */
function showsAll(...needles: string[]) {
  return (host: HTMLElement): string | null => {
    const text = host.textContent ?? "";
    const missing = needles.filter((n) => !text.includes(n));
    return missing.length ? `missing ${missing.map((m) => JSON.stringify(m)).join(", ")}` : null;
  };
}

function scenario(
  key: string,
  payload: string,
  element: () => React.ReactElement,
  opts: { update?: () => React.ReactElement; verify?: (host: HTMLElement) => string | null } = {},
) {
  return async () => {
    const r = await measure({ name: key, payload, element, budget: budgets[key], ...opts });
    expect(r.breaches, `${key} over budget`).toEqual([]);
  };
}

describe("frontend render budgets (high-EPS payloads)", () => {
  it(
    "events feed — 5,000 events on one timeline",
    scenario("events-feed", "5,000 events", () => <Events sinceSeconds={3600} />, {
      update: () => <Events sinceSeconds={3600} />,
      verify: hasRows(5000),
    }),
    120_000,
  );

  it(
    "RCA list — 2,000 correlation objects",
    scenario("rca-list", "2,000 correlations", () => <Correlations />, {
      update: () => <Correlations />,
      verify: hasRows(2000),
    }),
    120_000,
  );

  it(
    "log search — 20,000 hits",
    scenario("log-search", "20,000 log hits", () => <Logs initialQuery="*" />, {
      update: () => <Logs initialQuery="*" />,
      verify: hasRows(20000),
    }),
    180_000,
  );

  it(
    "device inventory — 2,000 devices",
    scenario("device-inventory", "2,000 devices", () => <Devices />, {
      update: () => <Devices />,
      verify: hasRows(2000),
    }),
    120_000,
  );

  it(
    "topology device list — 1,000-node view",
    scenario(
      "topology-device-list",
      "1,000 topology nodes",
      () => <TopologyInventoryPanel view={TOPO_VIEW} selection={NO_SELECTION} onPick={noop} />,
      {
        update: () => <TopologyInventoryPanel view={TOPO_VIEW_TICK} selection={NO_SELECTION} onPick={noop} />,
        verify: showsAll("1000"),
      },
    ),
    120_000,
  );
});
