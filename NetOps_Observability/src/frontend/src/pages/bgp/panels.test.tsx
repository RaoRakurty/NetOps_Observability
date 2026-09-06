// panels.test.tsx — the RENDER STATES of the BGP depth panels.
//
// Each of these locks in an honesty contract, not a layout:
//   * ASPA with no data source configured must SAY there is none and must not
//     show a verdict of any kind.
//   * a geofeed that does not exist is a calm fact, not an error, and not a
//     blank.
//   * the feed with FEATURE_BGP_LIVE_FEED off must say "not enabled" rather
//     than showing an empty table that reads as "nothing is happening".
//   * an RPKI lookup that could not run must not be counted as valid.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";

const bgpRpki = vi.fn();
const bgpAspa = vi.fn();
const bgpGeofeed = vi.fn();
const bgpAsPathGraph = vi.fn();
const bgpFeed = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    bgpRpki: (...a: unknown[]) => bgpRpki(...a),
    bgpAspa: (...a: unknown[]) => bgpAspa(...a),
    bgpGeofeed: (...a: unknown[]) => bgpGeofeed(...a),
    bgpAsPathGraph: (...a: unknown[]) => bgpAsPathGraph(...a),
    bgpFeed: (...a: unknown[]) => bgpFeed(...a),
  },
}));
// React Flow needs a real layout box; the graph's correctness lives in the pure
// model (bgpDepth.model.test.ts), so the canvas itself is stubbed here.
vi.mock("@xyflow/react", () => ({
  ReactFlow: ({ nodes }: { nodes: unknown[] }) => <div data-testid="rf" data-nodes={nodes.length} />,
  Background: () => null,
  Controls: () => null,
  Handle: () => null,
  BackgroundVariant: { Dots: "dots" },
  Position: { Left: "left", Right: "right" },
}));

import RpkiPanel from "./RpkiPanel";
import AspaCard from "./AspaCard";
import GeofeedPanel from "./GeofeedPanel";
import LiveFeedPanel from "./LiveFeedPanel";
import AsPathGraphPanel from "./AsPathGraphPanel";

beforeEach(() => vi.clearAllMocks());
afterEach(cleanup);

// ── RPKI ────────────────────────────────────────────────────────────────────

describe("RpkiPanel", () => {
  it("shows an invalid prefix first and names WHY it is invalid", async () => {
    bgpRpki.mockResolvedValue({
      from_watchlist: true, truncated: false, max_prefixes: 50,
      results: [
        { prefix: "203.0.113.0/24", origin: "AS64500", state: "invalid", reason: "origin_as", fetched_at: "2026-09-02T12:00:00Z" },
        { prefix: "193.0.0.0/21", origin: "AS3333", state: "valid", validator: "routinator", fetched_at: "2026-09-02T12:00:00Z" },
      ],
    });
    render(<RpkiPanel />);
    await waitFor(() => expect(screen.getByText("203.0.113.0/24")).toBeInTheDocument());
    expect(screen.getByText("Wrong origin AS")).toBeInTheDocument();
    expect(screen.getByText("from your watchlist")).toBeInTheDocument();
  });

  it("an unavailable lookup is shown as unavailable — never folded into valid", async () => {
    bgpRpki.mockResolvedValue({
      from_watchlist: true, truncated: false, max_prefixes: 50,
      results: [{ prefix: "203.0.113.0/24", state: "unavailable", error: "validator 503", fetched_at: "" }],
    });
    render(<RpkiPanel />);
    await waitFor(() => expect(screen.getByText("Could not check")).toBeInTheDocument());
    expect(screen.getByText(/validator 503/)).toBeInTheDocument();
    expect(screen.queryByText(/Authorised/)).toBeNull();
  });

  it("says the sweep was truncated when the watchlist is past the cap", async () => {
    bgpRpki.mockResolvedValue({ from_watchlist: true, truncated: true, max_prefixes: 50, results: [] });
    render(<RpkiPanel />);
    await waitFor(() => expect(screen.getByText(/Only the first 50/)).toBeInTheDocument());
  });

  it("surfaces a failed request instead of an empty 'all valid' panel", async () => {
    bgpRpki.mockImplementation(() => Promise.reject(new Error("network down")));
    render(<RpkiPanel />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("network down"));
  });
});

// ── ASPA ────────────────────────────────────────────────────────────────────

describe("AspaCard", () => {
  it("states that no ASPA data source is configured and never shows a verdict", async () => {
    bgpAspa.mockResolvedValue({
      resource: "AS3333",
      status: {
        configured: false,
        reason: "No ASPA data source is configured.",
        how_to: "Point BGP_ASPA_PROVIDER_URL at an ASPA endpoint from your own RPKI validator",
      },
    });
    render(<AspaCard asn="AS3333" />);
    await waitFor(() => expect(screen.getByText("No source configured")).toBeInTheDocument());
    expect(screen.getByText(/BGP_ASPA_PROVIDER_URL/)).toBeInTheDocument();
    expect(screen.queryByText(/approved provider/)).toBeNull();
  });

  it("renders real providers when a source IS configured", async () => {
    bgpAspa.mockResolvedValue({
      resource: "AS64500",
      status: { configured: true, host: "validator.example", reason: "ok" },
      aspa: { customer_asn: 64500, providers: [{ asn: 3333, afi: "ipv4" }], found: true, source: "routinator", fetched_at: "" },
    });
    render(<AspaCard asn="AS64500" />);
    await waitFor(() => expect(screen.getByText("1 approved provider")).toBeInTheDocument());
    expect(screen.getByText("AS3333 · ipv4")).toBeInTheDocument();
    expect(screen.getByText("validator.example")).toBeInTheDocument();
  });

  it("does not call the API with no ASN", () => {
    render(<AspaCard />);
    expect(bgpAspa).not.toHaveBeenCalled();
  });
});

// ── geofeed ─────────────────────────────────────────────────────────────────

describe("GeofeedPanel", () => {
  it("treats 'no geofeed published' as a calm fact, not an error", async () => {
    bgpGeofeed.mockResolvedValue({
      resource: "203.0.113.0/24", published: false, entries: [],
      rows_scanned: 0, rows_kept: 0, rows_dropped: 0, truncated: false, fetched_at: "",
    });
    render(<GeofeedPanel resource="203.0.113.0/24" />);
    await waitFor(() => expect(screen.getByText(/publishes no locations for it/)).toBeInTheDocument());
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("renders published rows and DECLARES the malformed ones it dropped", async () => {
    bgpGeofeed.mockResolvedValue({
      resource: "104.28.0.0/16", published: true,
      source_url: "https://api.cloudflare.com/local-ip-ranges.csv",
      entries: [{ prefix: "104.28.1.0/24", country: "IN", city: "Chandigarh" }],
      rows_scanned: 120, rows_kept: 1, rows_dropped: 3, truncated: false, fetched_at: "",
    });
    render(<GeofeedPanel resource="104.28.0.0/16" />);
    await waitFor(() => expect(screen.getByText("104.28.1.0/24")).toBeInTheDocument());
    expect(screen.getByText("3 malformed")).toBeInTheDocument();
    expect(screen.getByText("120 scanned")).toBeInTheDocument();
    expect(screen.getByText("Chandigarh")).toBeInTheDocument();
  });
});

// ── near-live feed ──────────────────────────────────────────────────────────

describe("LiveFeedPanel", () => {
  it("says the feed is NOT ENABLED with the flag off, instead of an empty table", async () => {
    bgpFeed.mockResolvedValue({
      updates: [],
      status: { enabled: false, ring_size: 2000, producer: "ripestat-poll", note: "Set FEATURE_BGP_LIVE_FEED=true to enable it." },
    });
    render(<LiveFeedPanel />);
    await waitFor(() => expect(screen.getByText("Feed is off")).toBeInTheDocument());
    expect(screen.getByText(/FEATURE_BGP_LIVE_FEED/)).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("renders buffered updates and separates withdrawals from announcements", async () => {
    bgpFeed.mockResolvedValue({
      updates: [
        { seq: 0, time: "2026-09-02T12:00:01Z", type: "A", resource: "193.0.0.0/21", prefix: "193.0.0.0/21", peer: "rrc00", path: [7018, 3333], origin: 3333 },
        { seq: 1, time: "2026-09-02T12:00:02Z", type: "W", resource: "193.0.0.0/21", prefix: "193.0.0.0/21", peer: "rrc01" },
      ],
      next: 2, gap: false,
      status: { enabled: true, polling: true, resources: ["193.0.0.0/21"], buffered: 2, ring_size: 2000, producer: "ripestat-poll", interval: "1m0s" },
      metrics: { polls_total: 3 },
    });
    render(<LiveFeedPanel />);
    await waitFor(() => expect(screen.getByText("1 learned")).toBeInTheDocument());
    expect(screen.getByText("1 withdrawn")).toBeInTheDocument();
    expect(screen.getByText("2/2000 held")).toBeInTheDocument();
    expect(screen.getByText("7018 → 3333")).toBeInTheDocument();
    // The panel must not call itself "live".
    expect(screen.getByText(/Near-live, not live/)).toBeInTheDocument();
    expect(screen.getByText(/BMP receiver.*separate item|separate item/)).toBeInTheDocument();
  });

  it("warns when the ring overwrote entries this page never read", async () => {
    bgpFeed.mockResolvedValue({
      updates: [], next: 5000, gap: true,
      status: { enabled: true, polling: true, resources: ["AS3333"], buffered: 2000, dropped: 12, ring_size: 2000, producer: "ripestat-poll" },
    });
    render(<LiveFeedPanel />);
    await waitFor(() => expect(screen.getByText(/not continuous/)).toBeInTheDocument());
    expect(screen.getByText("12 overwritten")).toBeInTheDocument();
  });

  it("tells the operator the feed is paused because the platform is at capacity", async () => {
    bgpFeed.mockResolvedValue({
      updates: [], status: { enabled: true, polling: false, capped: true, resources: ["AS1"], ring_size: 2000, producer: "ripestat-poll", note: "The global poller cap is reached; this tenant's feed is not being polled right now." },
    });
    render(<LiveFeedPanel />);
    await waitFor(() => expect(screen.getByText("Paused — at capacity")).toBeInTheDocument());
  });
});

// ── AS-path graph ───────────────────────────────────────────────────────────

describe("AsPathGraphPanel", () => {
  it("renders the canvas and declares which RIPE data call it came from", async () => {
    bgpAsPathGraph.mockResolvedValue({
      prefix: "193.0.0.0/21",
      nodes: [
        { asn: 7018, depth: 0, paths: 1, vantage: true },
        { asn: 3333, depth: 1, paths: 1, origin: true, name: "RIPE-NCC" },
      ],
      edges: [{ from: 7018, to: 3333, peers: 1 }],
      origins: [3333], paths: 1, paths_seen: 1, max_edges: 500,
      edges_capped: false, nodes_capped: false, source: "bgp-state", fetched_at: "",
    });
    render(<AsPathGraphPanel prefix="193.0.0.0/21" />);
    await waitFor(() => expect(screen.getByTestId("rf")).toBeInTheDocument());
    expect(screen.getByTestId("rf").getAttribute("data-nodes")).toBe("2");
    expect(screen.getByText("2 networks")).toBeInTheDocument();
    expect(screen.getByText("origin AS3333")).toBeInTheDocument();
    expect(screen.getByText("RIS bgp-state")).toBeInTheDocument();
  });

  it("DECLARES a capped graph — a silent cut would misstate the topology", async () => {
    bgpAsPathGraph.mockResolvedValue({
      prefix: "193.0.0.0/21",
      nodes: [{ asn: 7018, depth: 0, paths: 1 }, { asn: 3333, depth: 1, paths: 1, origin: true }],
      edges: [{ from: 7018, to: 3333, peers: 9 }],
      origins: [3333], paths: 900, paths_seen: 900, max_edges: 500,
      edges_capped: true, nodes_capped: false, source: "looking-glass", fetched_at: "",
    });
    render(<AsPathGraphPanel prefix="193.0.0.0/21" />);
    await waitFor(() => expect(screen.getByText(/capped at 500 adjacencies/)).toBeInTheDocument());
    expect(screen.getByText("looking-glass (fallback)")).toBeInTheDocument();
  });

  it("says a collector outage is a collector outage, not an unreachable prefix", async () => {
    bgpAsPathGraph.mockResolvedValue({
      prefix: "193.0.0.0/21", nodes: [], edges: [], origins: [],
      paths: 0, paths_seen: 0, max_edges: 500, edges_capped: false, nodes_capped: false,
      source: "bgp-state", fetched_at: "", error: "upstream 502",
    });
    render(<AsPathGraphPanel prefix="193.0.0.0/21" />);
    await waitFor(() => expect(screen.getByText(/not evidence that the prefix is/)).toBeInTheDocument());
  });

  it("does not fetch without a prefix", () => {
    render(<AsPathGraphPanel />);
    expect(bgpAsPathGraph).not.toHaveBeenCalled();
  });
});

// ── section identity (one-page outage view, 2026-09-03) ─────────────────────
//
// BgpOps.test.tsx asserts the ORDER of the page's sections against stubs. That
// test is only worth anything if the stubs carry the same `data-section` id the
// real panel emits, so this case pins the ids on the REAL components. Change an
// id here and the page's ordering test is telling the truth about a mock, not
// about the product — which is the failure mode this guards.

describe("section identity", () => {
  it("each depth panel is a section with the id the page lays out by", async () => {
    bgpRpki.mockResolvedValue({ results: [], from_watchlist: true, truncated: false, max_prefixes: 50 });
    bgpAspa.mockResolvedValue({ resource: "AS3333", status: { configured: false, reason: "none configured" } });
    bgpGeofeed.mockResolvedValue({ resource: "193.0.0.0/21", published: false, entries: [], rows_scanned: 0, rows_kept: 0, rows_dropped: 0, truncated: false, fetched_at: "" });
    bgpFeed.mockResolvedValue({ updates: [], status: { enabled: false, ring_size: 2000, producer: "ripestat" } });

    const cases: [string, React.ReactElement][] = [
      ["rpki", <RpkiPanel key="r" />],
      ["aspa", <AspaCard key="a" asn="AS3333" />],
      ["geofeed", <GeofeedPanel key="g" resource="193.0.0.0/21" />],
      ["updates-feed", <LiveFeedPanel key="f" />],
      ["aspath-graph", <AsPathGraphPanel key="p" />],
    ];
    for (const [id, el] of cases) {
      const { container, unmount } = render(el);
      await waitFor(() => expect(container.querySelector(`[data-section="${id}"]`)).toBeTruthy());
      unmount();
    }
  });

  // ── PLAIN LANGUAGE (owner, 2026-09-06) ────────────────────────────────────
  // Each of these headings WAS the protocol's name. It is now the NOC admin's
  // question, and the protocol word survives one line down — asserted here so a
  // future "tidy-up" cannot delete the engineer's half of the answer either.
  it.each([
    ["RPKI origin validation", "Prefix origin problems", /RPKI/, <RpkiPanel key="r" />],
    ["ASPA — AS provider authorization", "Approved upstream providers", /ASPA/, <AspaCard key="a" asn="AS3333" />],
    ["Geofeed (RFC 8805)", "Where this address space is used", /Geofeed/, <GeofeedPanel key="g" resource="193.0.0.0/21" />],
    ["Near-live update feed", "Latest route changes", /Near-live/, <LiveFeedPanel key="f" />],
    ["AS-path graph", "Path map", /AS paths/, <AsPathGraphPanel key="p" />],
  ])("replaces the jargon heading %s with %s", async (old, plain, protocolWord, el) => {
    bgpRpki.mockResolvedValue({ results: [], from_watchlist: true, truncated: false, max_prefixes: 50 });
    bgpAspa.mockResolvedValue({ resource: "AS3333", status: { configured: false, reason: "none configured" } });
    bgpGeofeed.mockResolvedValue({ resource: "193.0.0.0/21", published: false, entries: [], rows_scanned: 0, rows_kept: 0, rows_dropped: 0, truncated: false, fetched_at: "" });
    bgpFeed.mockResolvedValue({ updates: [], status: { enabled: false, ring_size: 2000, producer: "ripestat" } });
    const { container } = render(el);
    const h2 = await waitFor(() => {
      const found = container.querySelector("h2");
      expect(found).toBeTruthy();
      return found as HTMLElement;
    });
    expect(h2.textContent).toBe(plain);
    expect(h2.textContent).not.toBe(old);
    expect(container.querySelector(".bgp-sec-sub")?.textContent ?? "").toMatch(protocolWord);
  });

  it("the graph and the feed drop their own shell in `bare` mode — the page owns that heading", async () => {
    bgpFeed.mockResolvedValue({ updates: [], status: { enabled: false, ring_size: 2000, producer: "ripestat" } });
    const feed = render(<LiveFeedPanel bare />);
    await waitFor(() => expect(feed.container.querySelector("[data-section]")).toBeNull());
    expect(feed.container.querySelector(".bgp-sub")).toBeTruthy();
    feed.unmount();

    const graph = render(<AsPathGraphPanel bare />);
    expect(graph.container.querySelector("[data-section]")).toBeNull();
    expect(graph.container.querySelector(".bgp-sub")).toBeTruthy();
  });
});
