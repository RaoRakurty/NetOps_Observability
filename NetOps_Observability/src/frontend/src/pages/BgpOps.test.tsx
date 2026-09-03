// BgpOps helper tests (item 10, 2026-08-25): the verdict/visibility/path/churn
// logic is pure and carries the page's correctness — the panels only render
// what these produce.
import { describe, expect, it } from "vitest";
import {
  rpkiVerdict, visibilityFraction, compressPath, groupPaths, bucketUpdates, rdapContacts,
  pickInitial,
} from "./BgpOps";

describe("rpkiVerdict", () => {
  it("maps the RIPEstat statuses onto honest chips", () => {
    expect(rpkiVerdict("valid").label).toBe("RPKI VALID");
    expect(rpkiVerdict("invalid").tone).toBe("var(--crit)");
    expect(rpkiVerdict("invalid_asn").label).toContain("origin");
    expect(rpkiVerdict("unknown").label).toBe("No ROA");
  });
  it("an absent status renders as unavailable, never as valid", () => {
    const v = rpkiVerdict(undefined);
    expect(v.label).not.toContain("VALID");
    expect(v.tone).toBe("var(--muted)");
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

/** The order of docs/design/research/BGP_OPS_CONSOLIDATION_RESEARCH §(b), with
 *  the panels that landed on 2026-09-02 slotted into the right-hand column. */
const SECTION_ORDER = [
  "verdict", "paths", "updates",
  "rpki", "incidents", "peers", "bogons", "ownership", "geofeed", "aspa",
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
    const footer = await screen.findByText(/IRR route-object consistency/);
    expect(footer.textContent).toContain("no IRR mirror is");
    expect(footer.textContent).toContain("looking-glass");
    expect(footer.textContent).toContain("third-party corroboration");
  });

  it("nests the graph and the feed inside their page-owned sections rather than as cards", async () => {
    render(<BgpOps />);
    await screen.findByTestId("live-feed-panel");
    expect(panelProps.feed.bare).toBe(true);
    expect(panelProps.graph.bare).toBe(true);
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
    expect(within(verdict).getByText("ORIGIN CHANGE")).toBeTruthy();
    expect(within(verdict).getByText("origin AS64500")).toBeTruthy();
    expect(within(verdict).getByText("visibility 40%")).toBeTruthy();
    expect(within(verdict).getByText("RPKI INVALID (origin)")).toBeTruthy();
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
    expect(within(verdict).queryByText(/RPKI VALID/)).toBeNull();
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
