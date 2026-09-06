// alertPanels.test.tsx — the RENDER STATES of the Prefixes, Peers and Bogons
// views. Each case locks in an honesty contract, not a layout:
//   * with the evaluator off, the Prefixes view SAYS so — an empty alert list
//     must never read as "all clear".
//   * an unmeasured prefix renders as NOT MEASURED, never as OK.
//   * a corroboration shortfall (a class that almost fired) is SHOWN.
//   * the Peers tab distinguishes "the receiver is off" from "nothing is
//     exporting" from "every peer is up".
//   * the Bogons tab states the embedded set's source and date, and says when
//     the optional feed is off.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";

const bgpBmpSessions = vi.fn();
const metricsQuery = vi.fn();
const bgpBogons = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    bgpBmpSessions: (...a: unknown[]) => bgpBmpSessions(...a),
    metricsQuery: (...a: unknown[]) => metricsQuery(...a),
    bgpBogons: (...a: unknown[]) => bgpBogons(...a),
  },
}));

import PrefixesPanel from "./PrefixesPanel";
import PeersPanel from "./PeersPanel";
import BogonsPanel from "./BogonsPanel";
import type { BgpIncident, BgpWatchEntry } from "../../services/api";

beforeEach(() => vi.clearAllMocks());
afterEach(cleanup);

const entry = (resource: string): BgpWatchEntry => ({
  resource, kind: "prefix", note: "", added_by: "u", created_at: "2026-09-02T12:00:00Z",
});
const incident = (over: Partial<BgpIncident>): BgpIncident => ({
  prefix: "193.0.0.0/21", class: "none", severity: "info",
  summary: "Announced as expected.", evidence: { detail: "" },
  first_seen: "2026-09-02T12:00:00Z", last_seen: "2026-09-02T12:00:00Z",
  since: "2026-09-02T12:00:00Z", ...over,
});

// ── Prefixes ────────────────────────────────────────────────────────────────

describe("PrefixesPanel", () => {
  it("says the evaluator is off instead of showing an empty 'all clear'", () => {
    render(
      <PrefixesPanel
        watch={[entry("193.0.0.0/21")]} incidents={{}}
        incidentsNote="Incident classification is off. Set FEATURE_BGP_ALERTS=true to run the watchlist evaluator."
        status={{ enabled: false, note: "BGP alerting is off. Set FEATURE_BGP_ALERTS=true." }}
        alerts={[]} active="" onInvestigate={() => {}}
      />,
    );
    expect(screen.getAllByText(/FEATURE_BGP_ALERTS/i).length).toBeGreaterThan(0);
    expect(screen.getByText("Not checked yet")).toBeTruthy();
    expect(screen.queryByText(/^Healthy$/)).toBeNull();
  });

  it("renders an unmeasured prefix as NOT MEASURED, never as OK", () => {
    render(
      <PrefixesPanel
        watch={[entry("193.0.0.0/21")]}
        incidents={{ "193.0.0.0/21": incident({ class: "unknown", summary: "Not measured — the routing lookup did not answer.", error: "upstream 502" }) }}
        status={{ enabled: true, runs: 1 }} alerts={[]} active="" onInvestigate={() => {}}
      />,
    );
    expect(screen.getByText("Not checked")).toBeTruthy();
    expect(screen.getByText(/upstream 502/)).toBeTruthy();
    expect(screen.queryByText("Healthy")).toBeNull();
  });

  it("shows the evidence and the supporting vantage points for an origin change", () => {
    render(
      <PrefixesPanel
        watch={[entry("193.0.0.0/21")]}
        incidents={{
          "193.0.0.0/21": incident({
            class: "origin_change", severity: "critical",
            summary: "193.0.0.0/21 is being originated by AS65001 — possible hijack.",
            evidence: {
              detail: "2 vantage point(s) agree on the unexpected origin.",
              vantages: ["rrc00-1", "rrc03-4"], paths: [[174, 65001]],
              peers_seeing: 40, peers_total: 320,
            },
          }),
        }}
        status={{ enabled: true, runs: 1 }} alerts={[]} active="" onInvestigate={() => {}}
      />,
    );
    expect(screen.getByText("Origin changed")).toBeTruthy();
    expect(screen.getByText(/rrc00-1, rrc03-4/)).toBeTruthy();
    expect(screen.getByText("AS174 → AS65001")).toBeTruthy();
    expect(screen.getByText(/Seen by 40 of 320/)).toBeTruthy();
  });

  it("shows a corroboration shortfall rather than hiding the near-miss", () => {
    render(
      <PrefixesPanel
        watch={[entry("193.0.0.0/21")]}
        incidents={{
          "193.0.0.0/21": incident({
            corroboration_shortfall: "AS65001 was seen originating 193.0.0.0/21 by 1 vantage point(s); 2 are required",
          }),
        }}
        status={{ enabled: true, runs: 1 }} alerts={[]} active="" onInvestigate={() => {}}
      />,
    );
    expect(screen.getByText(/Seen but not asserted/)).toBeTruthy();
    expect(screen.getByText(/2 are required/)).toBeTruthy();
  });

  it("labels a learned origin baseline as learned", () => {
    render(
      <PrefixesPanel
        watch={[entry("193.0.0.0/21")]}
        incidents={{ "193.0.0.0/21": incident({ learned_origin: true }) }}
        status={{ enabled: true, runs: 1 }} alerts={[]} active="" onInvestigate={() => {}}
      />,
    );
    expect(screen.getByText("guessed baseline")).toBeTruthy();
  });

  it("distinguishes a measured quiet from an unwatched one in the alert history", () => {
    const { rerender } = render(
      <PrefixesPanel watch={[]} incidents={{}} status={{ enabled: true, runs: 4 }}
        alerts={[]} active="" onInvestigate={() => {}} />,
    );
    expect(screen.getByText(/measured quiet/i)).toBeTruthy();
    rerender(
      <PrefixesPanel watch={[]} incidents={{}}
        status={{ enabled: false, note: "BGP alerting is off, so nothing has been evaluated." }}
        alerts={[]} active="" onInvestigate={() => {}} />,
    );
    expect(screen.getAllByText(/nothing has been evaluated/i).length).toBeGreaterThan(0);
  });
});

// ── Peers ───────────────────────────────────────────────────────────────────

describe("PeersPanel", () => {
  it("says the receiver is not running when BMP 404s and no metric arrives", async () => {
    bgpBmpSessions.mockRejectedValue(new Error("404"));
    metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [] } });
    render(<PeersPanel />);
    await waitFor(() => expect(screen.getByText(/FEATURE_BMP/)).toBeTruthy());
    expect(screen.getByText(/absent feed, not a healthy fleet/i)).toBeTruthy();
  });

  it("says nothing is exporting when the receiver is up with no sessions", async () => {
    bgpBmpSessions.mockResolvedValue({ sessions: [], count: 0, coverage: { receiver_enabled: true, sessions_up: 0, complete: false, notes: [] } });
    metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [] } });
    render(<PeersPanel />);
    await waitFor(() => expect(screen.getByText(/No router is sending neighbour state/i)).toBeTruthy());
  });

  it("renders both sources in one table and names which witness is talking", async () => {
    bgpBmpSessions.mockResolvedValue({
      sessions: [{
        id: "s1", device_id: "edge-r1", remote_addr: "10.0.0.1", state: "up",
        opened_at: "2026-09-02T11:00:00Z", peers_partial: false, messages: {},
        updates_held: 0, updates_dropped: 0, parse_errors: 0, unsupported_elements: 0,
        peers: [{ address: "10.0.0.5", as: 64500, rib: "adj-rib-in", state: "down", down_reason: "hold timer", announced_prefixes: 0, withdrawn_prefixes: 12 }],
      }],
      count: 1, coverage: { receiver_enabled: true, sessions_up: 1, complete: true, notes: ["bounded monitoring feed"] },
    });
    metricsQuery.mockResolvedValue({
      status: "success",
      data: { resultType: "vector", result: [{ metric: { device: "edge-r2", peer: "10.1.0.1" }, value: [0, "6"] }] },
    });
    render(<PeersPanel />);
    await waitFor(() => expect(screen.getByText("10.0.0.5")).toBeTruthy());
    expect(screen.getByText("Down")).toBeTruthy();
    expect(screen.getByText("Up")).toBeTruthy();
    expect(screen.getByText("BMP")).toBeTruthy();
    expect(screen.getByText("device metric")).toBeTruthy();
    expect(screen.getByText(/bounded monitoring feed/)).toBeTruthy();
  });

  it("says the transit set is unmeasured rather than showing an empty box", async () => {
    bgpBmpSessions.mockRejectedValue(new Error("404"));
    metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [] } });
    render(<PeersPanel incidents={[]} />);
    await waitFor(() => expect(screen.getByText(/nothing is assumed/i)).toBeTruthy());
  });

  it("chips a transit change on a route-leak incident", async () => {
    bgpBmpSessions.mockRejectedValue(new Error("404"));
    metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [] } });
    render(<PeersPanel incidents={[incident({
      class: "route_leak", summary: "Possible route leak via AS65010.",
      evidence: { detail: "", paths: [[3356, 65010, 64496]] },
    })]} />);
    await waitFor(() => expect(screen.getByText("Carrier changed")).toBeTruthy());
    expect(screen.getByText("AS65010")).toBeTruthy();
  });
});

// ── Bogons ──────────────────────────────────────────────────────────────────

describe("BogonsPanel", () => {
  const base = {
    sightings: [],
    set: { source: "IANA IPv4/IPv6 Special-Purpose Address Registries (RFC 6890)", date: "2026-09-02", blocks: 31, note: "IPv4 has had no unallocated unicast /8 since 2011-02-03." },
    feed: { enabled: false, entries: 0, note: "Only the embedded RFC/IANA special-purpose set is in force. Set FEATURE_BGP_BOGON_FEED=true" },
  };

  it("states the embedded set's source and transcription date", async () => {
    bgpBogons.mockResolvedValue(base);
    render(<BogonsPanel />);
    await waitFor(() => expect(screen.getByText("31 embedded blocks")).toBeTruthy());
    expect(screen.getByText("as of 2026-09-02")).toBeTruthy();
    expect(screen.getByText(/no unallocated unicast \/8/)).toBeTruthy();
  });

  it("says the optional feed is off rather than implying nothing is bogus", async () => {
    bgpBogons.mockResolvedValue(base);
    render(<BogonsPanel />);
    await waitFor(() => expect(screen.getByText("full-bogons: off")).toBeTruthy());
    expect(screen.getAllByText(/FEATURE_BGP_BOGON_FEED/).length).toBeGreaterThan(0);
  });

  it("keeps the embedded set in force when the feed fetch failed, and says so", async () => {
    bgpBogons.mockResolvedValue({ ...base, feed: { enabled: true, entries: 4200, error: "upstream down", url: "https://example.net/x.txt" } });
    render(<BogonsPanel />);
    await waitFor(() => expect(screen.getByText(/nothing has been un-flagged/i)).toBeTruthy());
  });

  it("groups sightings by the reserved block that matched", async () => {
    bgpBogons.mockResolvedValue({
      ...base,
      sightings: [
        { prefix: "10.1.0.0/24", entry: { block: "10.0.0.0/8", reason: "special_purpose", rfc: "RFC 1918", why: "Private-use address space" }, source: "bmp", peer: "10.0.0.5", first_seen: "2026-09-02T12:00:00Z", last_seen: "2026-09-02T12:05:00Z", count: 3 },
      ],
    });
    render(<BogonsPanel />);
    await waitFor(() => expect(screen.getByText("10.0.0.0/8")).toBeTruthy());
    expect(screen.getByText("10.1.0.0/24")).toBeTruthy();
    expect(screen.getByText(/Private-use address space/)).toBeTruthy();
  });

  it("calls an empty sighting register a MEASURED healthy answer", async () => {
    bgpBogons.mockResolvedValue(base);
    render(<BogonsPanel />);
    await waitFor(() => expect(screen.getByText(/it is a measured one/i)).toBeTruthy());
  });

  it("says nothing was screened when the evaluator is off", async () => {
    bgpBogons.mockResolvedValue({ ...base, note: "The sighting register is fed by the watchlist evaluator, which is off." });
    render(<BogonsPanel />);
    await waitFor(() => expect(screen.getByText(/Nothing is watching for these addresses/i)).toBeTruthy());
  });
});

// ── section identity (one-page outage view, 2026-09-03) ─────────────────────
//
// The page's ordering test (BgpOps.test.tsx) runs against stubs; these three
// cases pin the same ids on the REAL components so the stubs cannot drift away
// from the product.

// ── PLAIN LANGUAGE (owner, 2026-09-06) ──────────────────────────────────────
// The three headings below were the protocol's vocabulary ("Incidents",
// "Peers", "Bogons"). They are now the NOC admin's question; the technical word
// moved one line down, and both halves are asserted so neither can be lost.

describe("plain language for a NOC admin", () => {
  it("replaces the jargon headings and keeps the technical word one line down", async () => {
    bgpBmpSessions.mockRejectedValue(new Error("off"));
    metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [] } });
    bgpBogons.mockResolvedValue({
      sightings: [], set: { source: "IANA", date: "2026-09-02", blocks: 1, note: "" },
      feed: { enabled: false, entries: 0, note: "off" },
    });

    const prefixes = render(
      <PrefixesPanel watch={[]} incidents={{}} alerts={[]} active="" onInvestigate={() => {}} />,
    );
    expect(prefixes.container.querySelector("h2")?.textContent).toBe("Prefixes you’re watching");
    expect(prefixes.container.querySelector("h2")?.textContent).not.toBe("Incidents — watched prefixes");
    prefixes.unmount();

    const peers = render(<PeersPanel />);
    await waitFor(() => expect(peers.container.querySelector("h2")).toBeTruthy());
    expect(peers.container.querySelector("h2")?.textContent).toBe("Sessions down or flapping");
    expect(peers.container.querySelector(".bgp-sec-sub")?.textContent).toMatch(/BGP neighbours/);
    peers.unmount();

    const bogons = render(<BogonsPanel />);
    await waitFor(() => expect(bogons.container.querySelector("h2")).toBeTruthy());
    expect(bogons.container.querySelector("h2")?.textContent).toBe("Addresses that should never be routed");
    expect(bogons.container.querySelector(".bgp-sec-sub")?.textContent).toMatch(/Bogons/);
  });
});

describe("section identity", () => {
  it("the incidents, peers and bogons panels carry the ids the page lays out by", async () => {
    bgpBmpSessions.mockRejectedValue(new Error("off"));
    metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [] } });
    bgpBogons.mockResolvedValue({
      sightings: [], set: { source: "IANA", date: "2026-09-02", blocks: 1, note: "" },
      feed: { enabled: false, entries: 0, note: "off" },
    });

    const prefixes = render(
      <PrefixesPanel watch={[]} incidents={{}} alerts={[]} active="" onInvestigate={() => {}} />,
    );
    expect(prefixes.container.querySelector('[data-section="incidents"]')).toBeTruthy();
    prefixes.unmount();

    const peers = render(<PeersPanel />);
    await waitFor(() => expect(peers.container.querySelector('[data-section="peers"]')).toBeTruthy());
    peers.unmount();

    const bogons = render(<BogonsPanel />);
    await waitFor(() => expect(bogons.container.querySelector('[data-section="bogons"]')).toBeTruthy());
  });
});
