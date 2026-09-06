// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// BgpOps helper tests (item 10, 2026-08-25): the verdict/visibility/path/churn
// logic is pure and carries the page's correctness — the panels only render
// what these produce.
import { describe, expect, it } from "vitest";
import {
  rpkiVerdict, visibilityFraction, compressPath, groupPaths, bucketUpdates, rdapContacts,
  pickInitial, normalizeAsn, updateTotals, nextSteps,
} from "./BgpOps";

describe("rpkiVerdict", () => {
  // Plain-language labels (owner, 2026-09-06: "too much jargon"). The chip says
  // what happened; "RPKI" and "ROA" moved into the tooltip, which is asserted
  // here so the protocol word cannot quietly vanish along with the jargon.
  it("maps the RIPEstat statuses onto plain-language chips", () => {
    expect(rpkiVerdict("valid").label).toBe("Origin authorised");
    expect(rpkiVerdict("valid").detail).toMatch(/RPKI valid/);
    expect(rpkiVerdict("invalid").tone).toBe("var(--crit)");
    expect(rpkiVerdict("invalid").label).toBe("Origin not authorised");
    expect(rpkiVerdict("invalid_asn").label).toBe("Wrong origin AS");
    expect(rpkiVerdict("invalid_length").label).toBe("Prefix too specific");
    expect(rpkiVerdict("unknown").label).toBe("Not protected");
    expect(rpkiVerdict("unknown").detail).toMatch(/ROA/);
  });
  it("no chip label shouts a protocol acronym at the operator", () => {
    for (const s of ["valid", "invalid", "invalid_asn", "invalid_length", "unknown", undefined]) {
      expect(rpkiVerdict(s).label).not.toMatch(/RPKI|ROA/);
    }
  });
  it("an absent status renders as unavailable, never as authorised", () => {
    const v = rpkiVerdict(undefined);
    expect(v.label).not.toMatch(/authorised/i);
    expect(v.tone).toBe("var(--muted)");
  });
});

describe("normalizeAsn", () => {
  it("accepts every notation RIPEstat hands back", () => {
    expect(normalizeAsn("AS64500")).toBe("64500");
    expect(normalizeAsn("as64500")).toBe("64500");
    expect(normalizeAsn(64500)).toBe("64500");
    expect(normalizeAsn("{64500,64501}")).toBe("64500");
  });
  it("returns nothing usable rather than a guess", () => {
    expect(normalizeAsn(undefined)).toBe("");
    expect(normalizeAsn("")).toBe("");
    expect(normalizeAsn("not-an-as")).toBe("");
  });
});

describe("updateTotals", () => {
  const ev = (type: string, path?: number[]) =>
    ({ type, timestamp: "2026-09-06T10:00:00", attrs: path ? { path } : undefined });

  it("counts routes learned and routes withdrawn in the operator's words", () => {
    const t = updateTotals({ updates: [ev("A"), ev("A"), ev("W")] });
    expect(t.learned).toBe(2);
    expect(t.withdrawn).toBe(1);
  });

  it("calls an announcement from another AS suspicious", () => {
    const t = updateTotals(
      { updates: [ev("A", [3356, 64500]), ev("A", [174, 64511]), ev("W")] },
      "AS64500",
    );
    expect(t.suspicious).toBe(1);
  });

  it("reports NULL, never a reassuring zero, when there is nothing to compare against", () => {
    // No current origin…
    expect(updateTotals({ updates: [ev("A", [3356, 64500])] }).suspicious).toBeNull();
    // …and an origin, but not one update carried a path.
    expect(updateTotals({ updates: [ev("A"), ev("W")] }, "AS64500").suspicious).toBeNull();
  });

  it("tolerates absent data", () => {
    expect(updateTotals(undefined)).toEqual({ learned: 0, withdrawn: 0, suspicious: null });
  });
});

describe("nextSteps", () => {
  const base = { visibility: null as number | null, watched: true, alertingEnabled: true };
  const inc = (cls: string) => ({
    prefix: "p", class: cls, severity: "critical", summary: "", evidence: { detail: "" },
    first_seen: "", last_seen: "", since: "",
  } as never);

  it("asks for a resource before it asks for anything else", () => {
    const steps = nextSteps({ ...base, resource: undefined });
    expect(steps).toHaveLength(1);
    expect(steps[0].title).toMatch(/Pick a prefix/);
  });

  it("leads with the hijack-shaped action when the origin changed", () => {
    const steps = nextSteps({ ...base, resource: "p", incident: inc("origin_change") });
    expect(steps[0].title).toMatch(/Call your upstream/);
  });

  it("acts on an unauthorised origin even when the classifier has not run", () => {
    const steps = nextSteps({ ...base, resource: "p", rpkiStatus: "invalid_asn" });
    expect(steps.some((s) => /origin authorisation/i.test(s.title))).toBe(true);
  });

  it("treats a prefix nobody sees as the outage it is", () => {
    const steps = nextSteps({ ...base, resource: "p", announced: false });
    expect(steps[0].title).toMatch(/still announcing/);
  });

  it("is never empty, and never says 'all clear' when nothing was checked", () => {
    const unwatched = nextSteps({ ...base, resource: "p", watched: false });
    expect(unwatched[0].title).toMatch(/Add this to the watchlist/);
    const off = nextSteps({ ...base, resource: "p", alertingEnabled: false });
    expect(off[0].title).toMatch(/Turn on automatic BGP checks/);
  });

  it("says nothing needs doing only when the checks actually ran clean", () => {
    const steps = nextSteps({
      ...base, resource: "p", incident: inc("none"), announced: true, visibility: 0.99,
    });
    expect(steps).toHaveLength(1);
    expect(steps[0].title).toMatch(/Nothing needs doing/);
  });

  it("caps the list so it stays a to-do list, not a second dashboard", () => {
    const many = nextSteps({
      resource: "p", visibility: 0.1, watched: false, alertingEnabled: false, announced: false,
      rpkiStatus: "invalid",
      incident: { ...(inc("origin_change") as object), also: ["bogon", "route_leak"] } as never,
    });
    expect(many.length).toBeLessThanOrEqual(5);
  });
});

describe("visibilityFraction", () => {
  it("combines v4+v6 peers", () => {
    expect(
      visibilityFraction({
        visibility: {
          v4: { total_ris_peers: 300, ris_peers_seeing: 270 },
          v6: { total_ris_peers: 100, ris_peers_seeing: 90 },
        },
      }),
    ).toBeCloseTo(0.9);
  });
  it("returns null (never 0%) when totals are unknown — absence of data is not an outage", () => {
    expect(visibilityFraction({})).toBeNull();
    expect(visibilityFraction(undefined)).toBeNull();
  });
});

describe("compressPath / groupPaths", () => {
  it("collapses AS-path prepending", () => {
    expect(compressPath("3333 1234 1234 1234 64500")).toEqual(["3333", "1234", "64500"]);
  });
  it("groups identical compressed paths and sorts by prevalence", () => {
    const g = groupPaths({
      rrcs: [
        { rrc: "RRC00", peers: [{ as_path: "1 2 3" }, { as_path: "1 2 2 3" }] },
        { rrc: "RRC01", peers: [{ as_path: "9 8 3" }] },
      ],
    });
    expect(g[0]).toEqual({ path: ["1", "2", "3"], count: 2 });
    expect(g[1].count).toBe(1);
  });
});

describe("bucketUpdates", () => {
  it("buckets announces and withdrawals per hour, sorted", () => {
    const b = bucketUpdates({
      updates: [
        { type: "A", timestamp: "2026-08-25T10:01:00" },
        { type: "W", timestamp: "2026-08-25T10:31:00" },
        { type: "W", timestamp: "2026-08-25T09:59:00" },
      ],
    });
    expect(b).toEqual([
      ["2026-08-25T09", 0, 1],
      ["2026-08-25T10", 1, 1],
    ]);
  });
  it("tolerates absent data", () => {
    expect(bucketUpdates(undefined)).toEqual([]);
  });
});

describe("rdapContacts", () => {
  it("pulls fn + roles from vcards and never throws on junk", () => {
    const c = rdapContacts({
      entities: [
        { roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "Example NOC"]]] },
        { roles: ["abuse"] },
        { vcardArray: "garbage" },
      ],
    });
    expect(c[0]).toEqual({ name: "Example NOC", roles: ["registrant"] });
    expect(c[1].roles).toEqual(["abuse"]);
    expect(rdapContacts(null)).toEqual([]);
    expect(rdapContacts("nonsense")).toEqual([]);
  });
});


describe("pickInitial", () => {
  const w = (resource: string) => ({ resource, kind: "prefix" as const, note: "", added_by: "t", created_at: "2026-09-01T00:00:00Z" });
  const inc = (prefix: string, cls: string) => ({
    prefix, class: cls, severity: "warning", summary: "", evidence: { detail: "" },
    first_seen: "", last_seen: "", since: "2026-09-01T00:00:00Z",
  } as never);

  it("opens on the WORST-classified watched resource, not the first one", () => {
    expect(pickInitial(
      [w("10.0.0.0/24"), w("10.0.1.0/24"), w("10.0.2.0/24")],
      { "10.0.1.0/24": inc("10.0.1.0/24", "origin_change"), "10.0.2.0/24": inc("10.0.2.0/24", "visibility_loss") },
    )).toBe("10.0.1.0/24");
  });

  it("ranks an UNMEASURED prefix above a measured-clean one — absence is not health", () => {
    expect(pickInitial(
      [w("10.0.0.0/24"), w("10.0.1.0/24")],
      { "10.0.0.0/24": inc("10.0.0.0/24", "none") },
    )).toBe("10.0.1.0/24");
  });

  it("falls back to the first watched entry, and to nothing at all when nothing is watched", () => {
    expect(pickInitial([w("10.0.0.0/24")], {})).toBe("10.0.0.0/24");
    expect(pickInitial([], {})).toBe("");
  });
});

// ── the SINGLE-SCREEN layout (owner, 2026-09-03) ────────────────────────────
//
// The page is now one screen with no tab switcher, and its section ORDER is the
// design of record (research §(b)). These tests hold that contract, plus the
// two behaviours an earlier ultra review found:
//   #32: investigate() latest-wins guard — a slow earlier response must never
//        overwrite the investigation the user asked for last.
//   #33: watchlist add/delete failures surface through the page's error alert.

import { afterEach, beforeEach, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import BgpOps from "./BgpOps";

const bgpWatchlist = vi.fn();
const bgpStatus = vi.fn();
const bgpUpdates = vi.fn();
const bgpWhois = vi.fn();
const bgpWatchAdd = vi.fn();
const bgpWatchDelete = vi.fn();
// Tracker #10: the page also loads the alert history, independently of the
// watchlist. It is stubbed here so this file keeps testing the PAGE; the
// alerting contracts live in src/pages/bgp/alertPanels.test.tsx.
const bgpAlerts = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    bgpWatchlist: (...a: unknown[]) => bgpWatchlist(...a),
    bgpStatus: (...a: unknown[]) => bgpStatus(...a),
    bgpUpdates: (...a: unknown[]) => bgpUpdates(...a),
    bgpWhois: (...a: unknown[]) => bgpWhois(...a),
    bgpWatchAdd: (...a: unknown[]) => bgpWatchAdd(...a),
    bgpWatchDelete: (...a: unknown[]) => bgpWatchDelete(...a),
    bgpAlerts: (...a: unknown[]) => bgpAlerts(...a),
  },
}));

// The seven lazy panels are children that fetch on their own; their contracts
// live in src/pages/bgp/panels.test.tsx and alertPanels.test.tsx. Here they are
// stubbed — but each stub emits the SAME `data-section` id the real panel does
// (asserted against the real components in those two files), so the ordering
// test below is a genuine check on this page's layout rather than on a mock.
const panelProps: Record<string, Record<string, unknown>> = {};
function stubPanel(section: string) {
  return (props: Record<string, unknown>) => {
    panelProps[section] = props;
    return <section data-section={section} data-testid={`${section}-panel`} />;
  };
}
vi.mock("./bgp/RpkiPanel", () => ({ default: stubPanel("rpki") }));
vi.mock("./bgp/AspaCard", () => ({ default: stubPanel("aspa") }));
vi.mock("./bgp/GeofeedPanel", () => ({ default: stubPanel("geofeed") }));
vi.mock("./bgp/PrefixesPanel", () => ({ default: stubPanel("incidents") }));
vi.mock("./bgp/AlertPolicyPanel", () => ({ default: stubPanel("alert-policy") }));
vi.mock("./bgp/PeersPanel", () => ({ default: stubPanel("peers") }));
vi.mock("./bgp/BogonsPanel", () => ({ default: stubPanel("bogons") }));
// These two render INSIDE a page-owned section (`bare`), so they emit no
// section of their own — the stub records that it was asked for bare mode.
vi.mock("./bgp/LiveFeedPanel", () => ({
  default: (p: Record<string, unknown>) => { panelProps.feed = p; return <div data-testid="live-feed-panel" />; },
}));
vi.mock("./bgp/AsPathGraphPanel", () => ({
  default: (p: Record<string, unknown>) => { panelProps.graph = p; return <div data-testid="aspath-panel" />; },
}));

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const statusFor = (resource: string) => ({ resource, kind: "asn" as const });
const watchEntry = (resource: string) => ({ resource, kind: "asn" as const, note: "", added_by: "t", created_at: "2026-09-01T00:00:00Z" });

/**
 * The layout contract, as WHOLE GRID ROWS (owner, 2026-09-06: "readjust the
 * panels and fit all of them in harmony"). Each card spans one column — always
 * paired, so a row is never half-empty — or both. Reading the list two at a
 * time gives the rows:
 *
 *   verdict (pinned, above the grid)
 *   next-steps          | peers
 *   updates ......................... (full width)
 *   paths ........................... (full width)
 *   incidents           | rpki
 *   alert-policy        | bogons          ← policy sits under the results it
 *   ownership           | aspa              decides, same column, next row
 *   geofeed ......................... (full width)
 */
const SECTION_ORDER = [
  "verdict",
  "next-steps", "peers",
  "updates",
  "paths",
  "incidents", "rpki",
  "alert-policy", "bogons",
  "ownership", "aspa",
  "geofeed",
];

function sectionsInDom(container: HTMLElement): string[] {
  return [...container.querySelectorAll("[data-section]")].map((el) => (el as HTMLElement).dataset.section!);
}

function submitQuery(value: string) {
  const input = screen.getByLabelText("Prefix or ASN");
  fireEvent.change(input, { target: { value } });
  fireEvent.submit(input.closest("form")!);
}

beforeEach(() => {
  for (const k of Object.keys(panelProps)) delete panelProps[k];
  for (const m of [bgpWatchlist, bgpStatus, bgpUpdates, bgpWhois, bgpWatchAdd, bgpWatchDelete, bgpAlerts]) m.mockReset();
  bgpWatchlist.mockResolvedValue({ watchlist: [] });
  bgpAlerts.mockResolvedValue({ alerts: [], incidents: [], classes: [], status: { enabled: false } });
  bgpUpdates.mockResolvedValue({ resource: "x", kind: "asn", updates: { updates: [] } });
  bgpWhois.mockResolvedValue({ rdap: null });
});
afterEach(cleanup);

describe("one-page layout", () => {
  it("renders EVERY section on load, in the order of the design of record", async () => {
    const { container } = render(<BgpOps />);
    await waitFor(() => expect(sectionsInDom(container).length).toBe(SECTION_ORDER.length));
    expect(sectionsInDom(container)).toEqual(SECTION_ORDER);
  });

  it("has no tab switcher — a tab is a question an operator should not answer mid-outage", async () => {
    render(<BgpOps />);
    await screen.findByLabelText("Prefix or ASN");
    expect(screen.queryAllByRole("tab")).toHaveLength(0);
    expect(screen.queryByRole("tablist")).toBeNull();
  });

  it("names what is deliberately absent instead of showing an empty box", async () => {
    render(<BgpOps />);
    // Sweep 5 (tracker 270): the paragraph that explained WHY each gap exists is
    // ai/skills/explain/bgp.not-shown.md now, reached from the `(i)`. The CLAIM
    // did not soften — the three absent evidence sources are still named on the
    // screen, and "absent, not empty" is still said out loud, because an empty
    // panel that reads clean is the failure this line exists to prevent.
    const footer = await screen.findByText(/IRR route-object consistency/);
    expect(footer.textContent).toContain("Absent here, not empty");
    expect(footer.textContent).toContain("looking-glass");
    expect(footer.textContent).toContain("third-party corroboration");
    expect(
      screen.getByRole("button", { name: "Ask Iris about What this screen does not show" }),
    ).toBeTruthy();
    // The RIPE attribution is a LICENCE CONDITION, so it keeps every word and
    // stays in plain sight rather than behind a disclosure.
    expect(screen.getByText(/RIPE NCC RIS \/ RIPEstat/).closest("details")).toBeNull();
  });

  it("nests the graph and the feed inside their page-owned sections rather than as cards", async () => {
    render(<BgpOps />);
    await screen.findByTestId("live-feed-panel");
    expect(panelProps.feed.bare).toBe(true);
    expect(panelProps.graph.bare).toBe(true);
  });
});

// ── PLAIN LANGUAGE (owner, 2026-09-06) ──────────────────────────────────────
//
// "There is too much jargon. Make it brief, NOC admin doesn't need all the
//  jargon. Each section should just show what NOC admin wants to see."
//
// Every heading below WAS on this page and is now gone from the heading level.
// The protocol word itself is not banned — it lives in the section's secondary
// line and in the chip tooltips, which is why this guard is aimed at `h2` and
// not at the page text.

/** old heading → the plain-language question that replaced it. */
const RENAMED_HEADINGS: [old: string, plain: string][] = [
  ["Verdict", "Is BGP healthy?"],
  ["Updates timeline", "Route changes"],
  ["Current paths from route collectors", "How the internet reaches this prefix"],
  ["Ownership & contacts", "Who owns this address space"],
  // These five belong to the lazy panels (stubbed here); their own tests pin the
  // new heading on the real component. Listed so ONE place records the rename.
  ["RPKI origin validation", "Prefix origin problems"],
  ["Incidents — watched prefixes", "Prefixes you’re watching"],
  ["Peers — sessions and transit", "Sessions down or flapping"],
  ["Bogons — set in force and sightings", "Addresses that should never be routed"],
  ["ASPA — AS provider authorization", "Approved upstream providers"],
];

describe("plain language for a NOC admin", () => {
  it("renders no jargon-only heading — every old one was replaced, not reworded", async () => {
    const { container } = render(<BgpOps />);
    await waitFor(() => expect(sectionsInDom(container).length).toBe(SECTION_ORDER.length));
    const headings = [...container.querySelectorAll("h2")].map((h) => h.textContent?.trim() ?? "");
    for (const [old] of RENAMED_HEADINGS) expect(headings).not.toContain(old);
    // …and the page's OWN sections carry the replacement, so this is not a test
    // that would pass on an empty page.
    expect(headings).toContain("Is BGP healthy?");
    expect(headings).toContain("Route changes");
    expect(headings).toContain("How the internet reaches this prefix");
    expect(headings).toContain("Who owns this address space");
    expect(headings).toContain("What to do next");
  });

  it("keeps the protocol word available under the heading rather than deleting it", async () => {
    const { container } = render(<BgpOps />);
    const paths = await waitFor(() => container.querySelector('[data-section="paths"]') as HTMLElement);
    expect(paths.querySelector(".bgp-sec-sub")?.textContent).toMatch(/AS paths/);
    const own = container.querySelector('[data-section="ownership"]') as HTMLElement;
    expect(own.querySelector(".bgp-sec-sub")?.textContent).toMatch(/RDAP/);
  });
});

describe("what to do next", () => {
  it("asks for a resource before anything is selected, instead of an empty card", async () => {
    const { container } = render(<BgpOps />);
    const todo = await waitFor(() => container.querySelector('[data-section="next-steps"]') as HTMLElement);
    expect(within(todo).getByText(/Pick a prefix or AS above/)).toBeTruthy();
  });

  it("turns the health verdict into an action a NOC admin can take", async () => {
    bgpStatus.mockResolvedValue({
      resource: "203.0.113.0/24", kind: "prefix",
      routing_status: { announced: true, last_seen: { origin: "AS64500" } },
    });
    bgpWatchlist.mockResolvedValue({
      watchlist: [watchEntry("203.0.113.0/24")],
      incidents: {
        "203.0.113.0/24": {
          prefix: "203.0.113.0/24", class: "origin_change", severity: "critical",
          summary: "AS64511 is announcing this prefix.", evidence: { detail: "" },
          first_seen: "", last_seen: "", since: "2026-09-03T00:00:00Z",
        },
      },
    });
    const { container } = render(<BgpOps />);
    const todo = await waitFor(() => {
      const el = container.querySelector('[data-section="next-steps"]') as HTMLElement;
      expect(within(el).getByText(/Call your upstream/)).toBeTruthy();
      return el;
    });
    expect(within(todo).getByText(/Ask them to filter the announcement/)).toBeTruthy();
  });
});

describe("the numbers a NOC admin reads first", () => {
  it("shows the at-a-glance tiles, and a dash rather than a reassuring zero", async () => {
    render(<BgpOps />);
    const strip = await screen.findByLabelText("At a glance");
    const tiles = [...strip.querySelectorAll(".bgp-kpi-l")].map((n) => n.textContent);
    expect(tiles).toEqual([
      "Prefixes watched", "Needing attention", "Reaching the internet", "Route changes (8 h)",
    ]);
    // Visibility is unmeasured with nothing selected: a dash, never "0%".
    const reach = strip.querySelectorAll(".bgp-kpi")[2] as HTMLElement;
    expect(reach.querySelector(".bgp-kpi-n")?.textContent).toBe("—");
    expect(within(reach).getByText(/Not measured/)).toBeTruthy();
  });

  it("counts learned, withdrawn and suspicious route changes for the selected resource", async () => {
    bgpStatus.mockResolvedValue({
      resource: "203.0.113.0/24", kind: "prefix",
      routing_status: { announced: true, last_seen: { origin: "AS64500" } },
    });
    bgpUpdates.mockResolvedValue({
      resource: "203.0.113.0/24", kind: "prefix",
      updates: {
        updates: [
          { type: "A", timestamp: "2026-09-06T10:00:00", attrs: { path: [3356, 64500] } },
          { type: "A", timestamp: "2026-09-06T10:05:00", attrs: { path: [174, 64511] } },
          { type: "W", timestamp: "2026-09-06T10:10:00" },
        ],
      },
    });
    const { container } = render(<BgpOps />);
    submitQuery("203.0.113.0/24");
    const upd = await waitFor(() => {
      const el = container.querySelector('[data-section="updates"]') as HTMLElement;
      expect(within(el).getByText("Routes learned")).toBeTruthy();
      return el;
    });
    const tiles = [...upd.querySelectorAll(".bgp-kpi")] as HTMLElement[];
    expect(tiles.map((t) => t.querySelector(".bgp-kpi-n")?.textContent)).toEqual(["2", "1", "1"]);
    expect(within(upd).getByText("Suspicious")).toBeTruthy();
  });
});

describe("verdict bar", () => {
  it("says no resource is selected rather than rendering a blank verdict", async () => {
    const { container } = render(<BgpOps />);
    const verdict = await waitFor(() => container.querySelector('[data-section="verdict"]') as HTMLElement);
    expect(within(verdict).getByText(/No resource is selected/)).toBeTruthy();
  });

  it("carries the resource, its incident class, the visibility gauge and the RPKI verdict", async () => {
    bgpStatus.mockResolvedValue({
      resource: "203.0.113.0/24", kind: "prefix",
      routing_status: {
        announced: true,
        last_seen: { origin: "AS64500" },
        visibility: { v4: { total_ris_peers: 300, ris_peers_seeing: 120 } },
      },
      rpki: { status: "invalid_asn" },
    });
    bgpWatchlist.mockResolvedValue({
      watchlist: [watchEntry("203.0.113.0/24")],
      incidents: {
        "203.0.113.0/24": {
          prefix: "203.0.113.0/24", class: "origin_change", severity: "critical",
          summary: "AS64511 is announcing this prefix.", evidence: { detail: "" },
          first_seen: "2026-09-03T00:00:00Z", last_seen: "2026-09-03T01:00:00Z",
          since: "2026-09-03T00:00:00Z",
        },
      },
    });
    const { container } = render(<BgpOps />);
    const verdict = await waitFor(() => {
      const el = container.querySelector('[data-section="verdict"]') as HTMLElement;
      expect(within(el).getByText("203.0.113.0/24", { selector: "span.device-name" })).toBeTruthy();
      return el;
    });
    expect(within(verdict).getByText("Origin changed")).toBeTruthy();
    expect(within(verdict).getByText("Origin AS64500")).toBeTruthy();
    expect(within(verdict).getByText("Seen by 40% of collectors")).toBeTruthy();
    expect(within(verdict).getByText("Wrong origin AS")).toBeTruthy();
    expect(within(verdict).getByText(/AS64511 is announcing this prefix/)).toBeTruthy();
  });

  it("reports an unavailable routing lookup instead of implying a clean verdict", async () => {
    bgpStatus.mockResolvedValue({
      resource: "AS64500", kind: "asn", routing_status_error: "RIPEstat timed out",
    });
    const { container } = render(<BgpOps />);
    submitQuery("AS64500");
    const verdict = await waitFor(() => {
      const el = container.querySelector('[data-section="verdict"]') as HTMLElement;
      expect(within(el).getByText(/RIPEstat timed out/)).toBeTruthy();
      return el;
    });
    expect(within(verdict).queryByText(/Origin authorised/)).toBeNull();
  });
});

describe("the selector drives every section", () => {
  it("opens on the WORST-classified watched resource without the operator picking one", async () => {
    bgpWatchlist.mockResolvedValue({
      watchlist: [watchEntry("AS111"), watchEntry("AS222")],
      incidents: {
        AS111: { prefix: "AS111", class: "none", severity: "info", summary: "", evidence: { detail: "" }, first_seen: "", last_seen: "", since: "2026-09-03T00:00:00Z" },
        AS222: { prefix: "AS222", class: "rpki_invalid", severity: "critical", summary: "", evidence: { detail: "" }, first_seen: "", last_seen: "", since: "2026-09-03T00:00:00Z" },
      },
    });
    bgpStatus.mockImplementation((r: string) => Promise.resolve(statusFor(r)));
    render(<BgpOps />);
    await screen.findByText("AS222", { selector: "span.device-name" });
    expect(bgpStatus).toHaveBeenCalledWith("AS222");
  });

  it("picking a watched chip re-points the verdict AND the per-resource sections", async () => {
    bgpWatchlist.mockResolvedValue({ watchlist: [watchEntry("AS111"), watchEntry("AS222")] });
    bgpStatus.mockImplementation((r: string) =>
      Promise.resolve({ resource: r, kind: "prefix" as const }));
    render(<BgpOps />);
    await screen.findByText("AS111", { selector: "span.device-name" });
    expect(panelProps.rpki.resource).toBe("AS111");

    fireEvent.click(screen.getByTitle("AS222"));
    await screen.findByText("AS222", { selector: "span.device-name" });
    await waitFor(() => {
      expect(panelProps.rpki.resource).toBe("AS222");
      expect(panelProps.geofeed.resource).toBe("AS222");
      expect(panelProps.graph.prefix).toBe("AS222");
    });
    expect(bgpUpdates).toHaveBeenCalledWith("AS222", 8);
    expect(bgpWhois).toHaveBeenCalledWith("AS222");
  });

  it("hands the incidents section the same watchlist the chips are built from", async () => {
    bgpWatchlist.mockResolvedValue({ watchlist: [watchEntry("AS111")], incidents_note: "requires the relational store" });
    bgpStatus.mockResolvedValue(statusFor("AS111"));
    render(<BgpOps />);
    await waitFor(() => expect(panelProps.incidents).toBeTruthy());
    expect((panelProps.incidents.watch as unknown[]).length).toBe(1);
    expect(panelProps.incidents.incidentsNote).toBe("requires the relational store");
  });
});

describe("honest states", () => {
  it("says nothing is watched instead of showing an empty chip row", async () => {
    render(<BgpOps />);
    expect(await screen.findByText(/Nothing is watched yet/)).toBeTruthy();
  });

  it("the paths section says collector paths are per-prefix for an ASN lookup", async () => {
    bgpStatus.mockResolvedValue(statusFor("AS64500"));
    const { container } = render(<BgpOps />);
    submitQuery("AS64500");
    const paths = await waitFor(() => {
      const el = container.querySelector('[data-section="paths"]') as HTMLElement;
      expect(within(el).getByText(/per PREFIX/)).toBeTruthy();
      return el;
    });
    expect(within(paths).queryByRole("table")).toBeNull();
  });

  it("calls an empty update window a measured quiet, not an absent one", async () => {
    bgpStatus.mockResolvedValue({ resource: "203.0.113.0/24", kind: "prefix" as const });
    const { container } = render(<BgpOps />);
    submitQuery("203.0.113.0/24");
    await waitFor(() => {
      const el = container.querySelector('[data-section="updates"]') as HTMLElement;
      expect(within(el).getByText(/Quiet — no BGP updates/)).toBeTruthy();
    });
  });

  it("the ownership section waits for a resource rather than showing empty contacts", async () => {
    const { container } = render(<BgpOps />);
    const own = await waitFor(() => container.querySelector('[data-section="ownership"]') as HTMLElement);
    expect(within(own).getByText(/No resource is selected/)).toBeTruthy();
  });

  it("renders RDAP contacts with their roles once the registry answers", async () => {
    bgpStatus.mockResolvedValue({ resource: "203.0.113.0/24", kind: "prefix" as const });
    bgpWhois.mockResolvedValue({
      rdap: { name: "EXAMPLE-NET", entities: [{ roles: ["abuse"], vcardArray: ["vcard", [["fn", {}, "text", "Example NOC"]]] }] },
    });
    const { container } = render(<BgpOps />);
    submitQuery("203.0.113.0/24");
    await waitFor(() => {
      const own = container.querySelector('[data-section="ownership"]') as HTMLElement;
      expect(within(own).getByText("EXAMPLE-NET")).toBeTruthy();
      expect(within(own).getByText(/Example NOC/)).toBeTruthy();
      expect(within(own).getByText(/\(abuse\)/)).toBeTruthy();
    });
  });
});

describe("investigate stale-response guard (#32)", () => {
  it("a slow earlier response never overwrites the newer investigation", async () => {
    const slow = deferred<ReturnType<typeof statusFor>>();
    const fast = deferred<ReturnType<typeof statusFor>>();
    bgpStatus.mockImplementation((r: string) => (r === "AS111" ? slow.promise : fast.promise));
    render(<BgpOps />);

    submitQuery("AS111"); // first lookup — will resolve late
    submitQuery("AS222"); // user moves on

    fast.resolve(statusFor("AS222"));
    await screen.findByText("AS222", { selector: "span.device-name" });

    slow.resolve(statusFor("AS111")); // stale response lands last
    await waitFor(() => {
      expect(screen.getByText("AS222", { selector: "span.device-name" })).toBeTruthy();
      expect(screen.queryByText("AS111", { selector: "span.device-name" })).toBeNull();
    });
  });

  it("a stale failure neither raises the page error nor clears the fresh verdict", async () => {
    const slow = deferred<ReturnType<typeof statusFor>>();
    bgpStatus.mockImplementation((r: string) =>
      r === "AS111" ? slow.promise : Promise.resolve(statusFor("AS222")));
    render(<BgpOps />);

    submitQuery("AS111");
    submitQuery("AS222");
    await screen.findByText("AS222", { selector: "span.device-name" });

    slow.reject(new Error("timeout"));
    await waitFor(() => {
      expect(screen.queryByRole("alert")).toBeNull();
      expect(screen.getByText("AS222", { selector: "span.device-name" })).toBeTruthy();
    });
  });
});

describe("watchlist mutation errors (#33)", () => {
  it("a failed watch-add surfaces in the page alert", async () => {
    bgpStatus.mockResolvedValue(statusFor("AS111"));
    bgpWatchAdd.mockRejectedValue(new Error("watch refused"));
    render(<BgpOps />);

    submitQuery("AS111");
    fireEvent.click(await screen.findByRole("button", { name: /Watch this ASN/ }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Watchlist update failed: watch refused");
  });

  it("a failed watch-delete (e.g. tightened 404 semantics) surfaces in the page alert", async () => {
    bgpWatchlist.mockResolvedValue({ watchlist: [watchEntry("AS111")] });
    bgpStatus.mockResolvedValue(statusFor("AS111"));
    bgpWatchDelete.mockRejectedValue(new Error("not found"));
    render(<BgpOps />);

    submitQuery("AS111");
    fireEvent.click(await screen.findByRole("button", { name: /Watching — remove/ }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Watchlist update failed: not found");
  });
});
