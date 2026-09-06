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

import { api, setToken } from "../src/services/api";

const budgets = budgetsJson as unknown as Record<string, Budget>;

// Pages under test.
import Events from "../src/pages/Events";
import Correlations from "../src/tabs/Correlations";
import Logs from "../src/tabs/Logs";
import Devices from "../src/pages/Devices";
import BgpOps from "../src/pages/BgpOps";
import DataProtection from "../src/pages/DataProtection";
import Licence from "../src/pages/Licence";
import { TopologyInventoryPanel } from "../src/features/topology/components/TopologyInventoryPanel";

// ── the Licence page's payload (its contract is a closed vocabulary) ─────────

/** The GET /api/system/licence body, at the size the server always sends. */
function licenceView() {
  const ceiling = (
    name: string, label: string, limit: number, current: number | null,
    enforced: boolean, reason?: string, over = false,
  ) => ({ name, label, limit, current, enforced, over, current_reason: reason, lifted_by: "enterprise" });
  const feature = (name: string, label: string, entitled: boolean, tier: string) =>
    ({ name, label, entitled, included_in: tier });
  return {
    state: {
      source: "file", tier: "team", licensed_tier: "team",
      customer: "Acme Networks", licence_id: "lic-2026-0007",
      issued_at: "2026-01-01T00:00:00Z", expires_at: "2027-01-01T00:00:00Z",
      grace_days: 30, in_grace: false, degraded: false, key_id: "k-lab-1",
      features: ["security_findings"],
      support: { level: "business hours", contact: "support@correlix.example" },
      ceilings: {
        devices: 250, tenants: 5, orgs: 1, retention_days: 30,
        watched_prefixes: 100, skills: 10, provider_tokens_per_day: 0,
      },
    },
    ceilings: [
      ceiling("devices", "devices", 250, 262, true, undefined, true),
      ceiling("watched_prefixes", "watched prefixes", 100, 40, true),
      ceiling("tenants", "tenants", 5, 3, false),
      ceiling("orgs", "organisations", 1, null, false, "the platform does not count organisations"),
      ceiling("retention_days", "retention days", 30, null, false, "retention is not counted as a usage"),
      ceiling("skills", "Iris skills", 10, null, false, "skills are not counted yet"),
      ceiling("provider_tokens_per_day", "provider tokens per day", 0, null, false, "provider spend is not counted here"),
    ],
    features: [
      feature("security_findings", "security findings", true, "team"),
      feature("security_dialects", "security dialects", false, "enterprise"),
      feature("siem_export", "findings export to SIEM", false, "enterprise"),
      feature("msp_management", "multi-tenant fleet management", false, "enterprise"),
      feature("saml", "SAML single sign-on", false, "enterprise"),
      feature("scim", "SCIM provisioning", false, "enterprise"),
      feature("ldap", "LDAP authentication", false, "enterprise"),
    ],
    overages: [{
      ceiling: "devices", label: "devices", current: 262, limit: 250, over: 12, lifted_by: "enterprise",
      message: "12 of 262 devices are over the Team ceiling of 250 — they are still here and nothing has been deleted",
    }],
    keys: [
      { id: "k-prod-1", role: "current", note: "production signing key", base64: "Q+PMj3/TNIjbRvopQwXLM5tJfgjzPTsoHIWwiM0apR8=" },
      { id: "k-lab-1", role: "previous", note: "retired lab key", base64: "AAAAC3NzaC1lZDI1NTE5AAAAIF9Qb2tlbW9uSXNOb3RBS2V5AAAA" },
    ],
    path: "/data/licence/licence.json",
    verify_hint: "Verify a licence offline with: correlix-licence verify <file>",
    expiry_semantics: "Expiry semantics are an owner decision that is still open. Nothing is ever deleted, and no licence state can affect tenant isolation, data separation, permissions or sign-in.",
    days_to_expiry: 119,
  };
}

// ── payloads, built ONCE (outside every timed region) ────────────────────────
synth.resetRand();
const EVENT_SYSLOG = synth.syslogHits(2400);
const EVENT_TRAPS = synth.trapHits(2400);
const EVENT_ALERTS = synth.alerts(200);  // 2400 + 2400 + 200 = 5,000 events
const CORR_ROWS = synth.correlations(2000);
const LOG_HITS = synth.syslogHits(20000);
const DEVICE_ROWS = synth.devices(2000);
const TOPO_VIEW = synth.topologyView(1000);
// BGP single-screen outage view: 50 watched prefixes, a full 500-update
// near-live buffer, 30 BGP peers and 20 bogon sightings, all on ONE page.
const BGP_PREFIXES = synth.bgpPrefixes(50);
const BGP_WATCHLIST = synth.bgpWatchlist(BGP_PREFIXES);
const BGP_ALERTS = synth.bgpAlerts(BGP_PREFIXES);
const BGP_SELECTED = BGP_PREFIXES[0];
const BGP_STATUS = synth.bgpStatus(BGP_SELECTED);
const BGP_UPDATES = synth.bgpUpdates(BGP_SELECTED, 480);
const BGP_FEED = synth.bgpFeed(BGP_PREFIXES, 500);
const BGP_BMP = synth.bgpBmpSessions(30);
const BGP_PEER_METRICS = synth.bgpPeerMetrics(30);
const BGP_BOGONS = synth.bgpBogons(20);
// Data Protection: a repository holding 500 recovery points, the full coverage
// matrix and a long audit trail — the "daily policy with a long retention"
// case, which is where an unwindowed table would blow up.
const DP_COVERAGE = synth.backupCoverage();
const DP_POINTS = synth.snapshotList(500);
const DP_OPS = synth.backupOperations(200);
// Licence: the whole page at its real, bounded size — the seven-ceiling closed
// vocabulary, the seven-capability closed vocabulary, both trusted signing keys
// and an over-ceiling list. Unlike the other surfaces this one has NO unbounded
// list, so the budget's job is different: it pins that a fixed-size admin page
// stays a fixed-size admin page, and catches a per-ceiling panel or a
// per-capability card being added without anyone noticing the cost.
const LICENCE_VIEW = licenceView();
const BGP_RPKI = synth.bgpRpki(BGP_PREFIXES);
const BGP_GRAPH = synth.bgpAsPathGraph(BGP_SELECTED);
const BGP_GEOFEED = synth.bgpGeofeed(BGP_SELECTED);
const BGP_WHOIS = synth.bgpWhois(BGP_SELECTED);
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

  // BGP operations — a dozen independent panels on one screen, each stubbed at
  // its own volume. The page auto-selects the worst-classified watched prefix
  // on load, so the per-resource panels are fed as if that lookup resolved.
  vi.spyOn(api, "bgpWatchlist").mockResolvedValue(BGP_WATCHLIST as never);
  vi.spyOn(api, "bgpAlerts").mockResolvedValue(BGP_ALERTS as never);
  vi.spyOn(api, "bgpStatus").mockResolvedValue(BGP_STATUS as never);
  vi.spyOn(api, "bgpUpdates").mockResolvedValue(BGP_UPDATES as never);
  vi.spyOn(api, "bgpWhois").mockResolvedValue(BGP_WHOIS as never);
  vi.spyOn(api, "bgpRpki").mockResolvedValue(BGP_RPKI as never);
  vi.spyOn(api, "bgpAspa").mockResolvedValue({
    resource: "AS64500",
    status: { configured: false, reason: "No ASPA data source is configured." },
  } as never);
  vi.spyOn(api, "bgpGeofeed").mockResolvedValue(BGP_GEOFEED as never);
  vi.spyOn(api, "bgpAsPathGraph").mockResolvedValue(BGP_GRAPH as never);
  vi.spyOn(api, "bgpFeed").mockResolvedValue(BGP_FEED as never);
  vi.spyOn(api, "bgpBogons").mockResolvedValue(BGP_BOGONS as never);
  vi.spyOn(api, "bgpBmpSessions").mockResolvedValue(BGP_BMP as never);
  vi.spyOn(api, "metricsQuery").mockResolvedValue(BGP_PEER_METRICS as never);

  // Licence page — one read, five sections.
  vi.spyOn(api, "getLicence").mockResolvedValue(LICENCE_VIEW as never);

  // Data Protection console. Its five panels read independently, so all five
  // are stubbed; the volume that matters is the 500-row recovery-point table.
  vi.spyOn(api, "backupCoverage").mockResolvedValue(DP_COVERAGE as never);
  vi.spyOn(api, "snapshotList").mockResolvedValue(DP_POINTS as never);
  vi.spyOn(api, "backupOperations").mockResolvedValue(DP_OPS as never);
  vi.spyOn(api, "snapshotPolicy").mockResolvedValue({
    enabled: true, schedule_cron: "30 1 * * *", retention_max_count: 14,
    retention_max_age_days: 30, next_run: "2026-09-05T01:30:00Z",
    last_run: { status: "SUCCESS", time: "2026-09-04T01:33:00Z", duration_seconds: 180 },
  } as never);
  vi.spyOn(api, "backupConfig").mockResolvedValue({
    config: { remote_url: "rsync://nas/correlix/", schedule_enabled: true, schedule_cron: "30 2 * * *" },
    status: {},
  } as never);
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

  it(
    "BGP operations — 50 watched prefixes, 500 updates, 30 peers, 20 sightings on ONE screen",
    scenario(
      "bgp-ops",
      "50 prefixes · 500 updates · 30 peers · 20 sightings",
      () => <BgpOps />,
      {
        update: () => <BgpOps />,
        // Proves the page really assembled the whole screen: the pinned verdict
        // for the auto-selected prefix, a section that only exists once the
        // watchlist arrived, and the near-live feed's own counters. Without this
        // a broken stub would render ten honest empty states and "pass".
        // Plain-language headings (owner, 2026-09-06). These markers are the
        // renamed sub-blocks, one per lazy panel, plus the feed's row wording —
        // they prove every panel actually rendered, not just the page shell.
        verify: showsAll(BGP_SELECTED, "Recent alerts", "Neighbour sessions", "Seen on your network", "learned"),
      },
    ),
    180_000,
  );

  it(
    "data protection — 500 restore points, the coverage matrix and a 200-line operations trail",
    async () => {
      // The console is platform-admin gated, so the measured page must be the
      // ADMIN one: the read-only variant renders none of the per-row action
      // buttons and would understate the DOM by three buttons per visible row.
      setToken("perf-session");
      vi.spyOn(api, "me").mockResolvedValue({
        username: "root", role: "admin", platform_admin: true,
      } as never);
      try {
        await scenario(
          "data-protection",
          "500 restore points · 7 engines · 200 operations",
          () => <DataProtection />,
          {
            update: () => <DataProtection />,
            // Proves the whole console assembled: the coverage matrix under the
            // operator's vocabulary, the honest "not measured" cell for the
            // engine with no successful run, and the full 500-row table behind a
            // windowed viewport.
            verify: (host: HTMLElement) =>
              hasRows(500)(host) ??
              showsAll("Metrics history", "Recovery point per engine", "not measured —")(host),
          },
        )();
      } finally {
        setToken(null);
      }
    },
    180_000,
  );

  it(
    "licence — the whole closed vocabulary on one page, as a platform admin",
    async () => {
      // Platform-admin gated like the Data Protection console: the read-only
      // variant renders no install panel at all and would understate the DOM.
      setToken("perf-session");
      vi.spyOn(api, "me").mockResolvedValue({
        username: "root", role: "admin", platform_admin: true,
      } as never);
      try {
        await scenario(
          "licence",
          "7 ceilings · 7 capabilities · 2 keys · 1 overage",
          () => <Licence />,
          {
            update: () => <Licence />,
            // Proves the whole page assembled rather than five honest empty
            // states: the licensed headline, a counted ceiling, the honest
            // uncounted one, and the install panel only an admin sees.
            verify: showsAll("Team licence", "262 of 250", "not measured —", "Install licence"),
          },
        )();
      } finally {
        setToken(null);
      }
    },
    120_000,
  );
});
