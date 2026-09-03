// BgpOps helper tests (item 10, 2026-08-25): the verdict/visibility/path/churn
// logic is pure and carries the page's correctness — the panels only render
// what these produce.
import { describe, expect, it } from "vitest";
import {
  rpkiVerdict, visibilityFraction, compressPath, groupPaths, bucketUpdates, rdapContacts,
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

// ── component behavior (ultra findings #32/#33, 2026-09-01) ─────────────────
// #32: investigate() latest-wins guard — a slow earlier response must never
//      overwrite the investigation the user asked for last.
// #33: watchlist add/delete failures surface through the page's error alert
//      (backend delete semantics were tightened; errors are now expected).

import { afterEach, beforeEach, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

// The depth panels (item 10 completion) are lazy children that fetch on their
// own. Their contracts are covered by src/pages/bgp/panels.test.tsx; here they
// are stubbed so this file keeps testing the PAGE — otherwise every assertion
// about the page would also be waiting on five unrelated Suspense boundaries.
vi.mock("./bgp/RpkiPanel", () => ({ default: () => <div data-testid="rpki-panel" /> }));
vi.mock("./bgp/AspaCard", () => ({ default: () => <div data-testid="aspa-card" /> }));
vi.mock("./bgp/GeofeedPanel", () => ({ default: () => <div data-testid="geofeed-panel" /> }));
vi.mock("./bgp/LiveFeedPanel", () => ({ default: () => <div data-testid="live-feed-panel" /> }));
vi.mock("./bgp/AsPathGraphPanel", () => ({ default: () => <div data-testid="aspath-panel" /> }));
vi.mock("./bgp/PrefixesPanel", () => ({ default: () => <div data-testid="prefixes-panel" /> }));
vi.mock("./bgp/PeersPanel", () => ({ default: () => <div data-testid="peers-panel" /> }));
vi.mock("./bgp/BogonsPanel", () => ({ default: () => <div data-testid="bogons-panel" /> }));

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const statusFor = (resource: string) => ({ resource, kind: "asn" as const });
const watchEntry = (resource: string) => ({ resource, kind: "asn" as const, note: "", added_by: "t", created_at: "2026-09-01T00:00:00Z" });

function submitQuery(value: string) {
  const input = screen.getByLabelText("Prefix or ASN");
  fireEvent.change(input, { target: { value } });
  fireEvent.submit(input.closest("form")!);
}

beforeEach(() => {
  for (const m of [bgpWatchlist, bgpStatus, bgpUpdates, bgpWhois, bgpWatchAdd, bgpWatchDelete, bgpAlerts]) m.mockReset();
  bgpWatchlist.mockResolvedValue({ watchlist: [] });
  bgpAlerts.mockResolvedValue({ alerts: [], incidents: [], classes: [], status: { enabled: false } });
  bgpUpdates.mockResolvedValue({ resource: "x", kind: "asn", updates: { updates: [] } });
  bgpWhois.mockResolvedValue({ rdap: null });
});
afterEach(cleanup);

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
