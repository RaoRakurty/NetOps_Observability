// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// WanCircuits.test.tsx — the three derived WAN surfaces and the one thing that
// is actually stored.
//
// WHAT THESE TESTS ARE FOR. Endpoints and paths are DERIVED on read, so there is
// no row to go and look at when they come back empty. Three failure modes matter:
//
//   1. AN EMPTY DERIVATION MUST EXPLAIN ITSELF. "Nothing derived" is the normal
//      state of a fresh install, and a blank table would read as a broken page.
//      Each section's empty state has to say what has to be true for a row to
//      appear at all.
//   2. THE PUT BODY MUST CARRY INTENT ONLY. The server stamps tenant, author and
//      time from the token. If `tenant_id` ever appears in the body we are
//      asserting ownership we do not have, so the exact body is asserted.
//   3. (The policy editor moved to Administration on 2026-11-22; its guards are
//      in WanSettings.test.tsx.)
//
// Plus the two ordinary guards: one section's dead read must not blank another,
// and a rejected save must leave the operator's text where they left it.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import type { ProbePath, WanCircuit, WanEndpoint, WanInterfaceRow, WanMeasurementPolicy } from "../services/api";
import { buildMeasuredIndex } from "./paths/measuredFold";
import type { MeasuredState } from "./paths/useMeasuredPaths";

const mockApi = vi.hoisted(() => ({
  wanInterfaces: vi.fn(),
  wanEndpoints: vi.fn(),
  wanCircuits: vi.fn(),
  wanPolicy: vi.fn(),
  setWanPolicy: vi.fn(),
  setWanMark: vi.fn(),
  permissions: vi.fn(),
}));

vi.mock("../services/api", () => ({ api: mockApi }));

import WanCircuits from "./WanCircuits";

// ── fixtures (the wire shapes from wan/wan.go) ──────────────────────────────

function ep(over: Partial<WanEndpoint> = {}): WanEndpoint {
  return {
    device: "wan-edge-1",
    interface: "Ethernet1",
    address: "10.1.1.1",
    measurable_addr: "10.1.1.1",
    ...over,
  };
}

const PEER_EP = ep({
  target: "10.1.1.2", target_kind: "direct_peer", target_label: "Directly-connected peer spine-1 Ethernet9",
  wan_confidence: "confirmed", wan_basis: "sdwan_tunnel_source",
  wan_reason: "SD-WAN transport interface — tunnel Tunnel1 runs over it.",
  wan_evidence: [{ source: "controller", detail: "VPN 0, and tunnel Tunnel1 uses the same address" }],
});
/** A possible interface: the port facing a WAN router (2026-11-22: not measured). */
const LINKED_CANDIDATE = ep({
  device_id: "core-sw-2-9f1", device: "core-sw-2", interface: "Ethernet4", address: "10.2.2.4", measurable_addr: "10.2.2.4",
  connected_to_wan: true, wan_confidence: "possible", wan_basis: "linked",
  wan_reason: "Directly connected to wan-edge-1, which looks like a WAN router — this is usually the LAN side.",
});
const ISP_EP = ep({ interface: "Ethernet2", address: "203.0.113.2", measurable_addr: "203.0.113.2", target: "203.0.113.1", target_kind: "next_hop", target_label: "ISP next-hop 203.0.113.1" });
const ANCHOR_EP = ep({ interface: "Ethernet3", address: "198.51.100.2", measurable_addr: "198.51.100.2", target: "1.1.1.1", target_kind: "anchor", target_label: "Reachability anchor 1.1.1.1" });
const BARE_EP = ep({ device: "spine-1", interface: "Ethernet9", address: "10.1.1.2", measurable_addr: "10.1.1.2", connected_to_wan: true, site: "London" });

const CIRCUITS: WanCircuit[] = [
  {
    id: "wan-edge-1|Ethernet1|10.1.1.2",
    local: PEER_EP,
    remote: ep({ device: "spine-1", interface: "Ethernet9", address: "10.1.1.2", measurable_addr: "10.1.1.2" }),
    kind: "direct_peer", source: "registry", enabled: true,
  },
  {
    id: "wan-edge-1|Ethernet2|203.0.113.1",
    local: ISP_EP,
    remote: ep({ device: "", interface: "", address: "203.0.113.1", measurable_addr: "203.0.113.1" }),
    kind: "next_hop", source: "registry", enabled: true,
  },
  {
    id: "wan-edge-1|Ethernet3|1.1.1.1",
    local: ANCHOR_EP,
    remote: ep({ device: "", interface: "", address: "1.1.1.1", measurable_addr: "1.1.1.1" }),
    kind: "anchor", source: "registry", enabled: false,
  },
];

const POLICY: WanMeasurementPolicy = {
  tenant_id: "acme",
  wan_pattern: "wan|edge|gw|dmz",
  anchors: ["1.1.1.1", "8.8.8.8"],
  next_hops: { "wan-edge-1/Ethernet2": "203.0.113.1" },
  include_connected: true,
  updated_by: "rao",
  updated_at: "2026-09-04T10:00:00Z",
};

/** The section shell renders `data-section` — the handle each test grabs. */
function section(id: string): HTMLElement {
  const el = document.querySelector(`[data-section="${id}"]`);
  if (!el) throw new Error(`section ${id} is not on the page`);
  return el as HTMLElement;
}

beforeEach(() => {
  vi.clearAllMocks();
  mockApi.wanInterfaces.mockResolvedValue({ interfaces: [] });
  mockApi.wanEndpoints.mockResolvedValue({ endpoints: [PEER_EP, ISP_EP, ANCHOR_EP, BARE_EP] });
  mockApi.wanCircuits.mockResolvedValue({ circuits: CIRCUITS });
  mockApi.wanPolicy.mockResolvedValue(POLICY);
  mockApi.setWanPolicy.mockResolvedValue(POLICY);
  mockApi.permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: 2 } });
});

afterEach(() => { cleanup(); vi.useRealTimers(); });

// ── each section reads its own route ────────────────────────────────────────

describe("routes", () => {
  it("reads interfaces, endpoints and paths — one route per section — and links to WAN settings", async () => {
    render(<WanCircuits />);
    await waitFor(() => expect(mockApi.wanCircuits).toHaveBeenCalled());
    expect(mockApi.wanInterfaces).toHaveBeenCalled();
    expect(mockApi.wanEndpoints).toHaveBeenCalledTimes(1);
    expect(mockApi.wanCircuits).toHaveBeenCalledTimes(1);
    // The policy editor lives under Administration now (2026-11-22): this page
    // neither reads nor edits it, and says where it is.
    expect(mockApi.wanPolicy).not.toHaveBeenCalled();
    expect(screen.queryByLabelText("WAN device name pattern")).toBeNull();
    const link = within(screen.getByTestId("wan-settings-link")).getByRole("link", { name: "WAN settings" });
    expect(link.getAttribute("href")).toBe("#/admin/discovery/wan");
  });

  it("keeps the existing interface metrics table and its live read", async () => {
    render(<WanCircuits />);
    await waitFor(() => expect(mockApi.wanCircuits).toHaveBeenCalled());
    expect(screen.getByRole("heading", { name: "WAN circuits" })).toBeTruthy();
    // The call is made before its result renders: await the text, not the call
    // (failed #323's vitest job under CI load, 2026-11-22).
    expect(await screen.findByText(/No confirmed WAN interfaces yet\./)).toBeTruthy();
  });
});

// ── the measured paths, on their rows (2026-11-22) ──────────────────────────
//
// The "Measured paths" section only said whether a link was measured, and the
// Measured paths tab showed the prober's traces apart from the circuit. Both
// now live in the rows: "held" in the Measured-to cell, the trace in a Path
// column that opens hop by hop.

function wanRow(over: Partial<WanInterfaceRow> = {}): WanInterfaceRow {
  return {
    device: "wan-edge-1", interface: "Gi0/0/2", address: "203.0.113.2", site: "London",
    in_bps: 1000, out_bps: 2000, util_pct: 12, has_util: true, oper_up: true, has_oper: true,
    target: "203.0.113.1", target_kind: "next_hop", has_target: true,
    latency_ms: 12, jitter_ms: 1, loss_pct: 0, qoe: 9, availability_pct: 100,
    has_latency: true, has_jitter: true, has_loss: true, has_qoe: true, has_availability: true,
    source: "traceroute", source_label: "Traceroute", tier: 2, tier_label: "Active path probe",
    ...over,
  } as WanInterfaceRow;
}

const TRACE: ProbePath = {
  dst: "203.0.113.1", method: "icmp", vantage_id: "v1", site: "London", reached: true, changed: false,
  ts: new Date().toISOString(),
  hops: [{ ttl: 1, ip: "10.0.0.1", rtt_ms: 1, loss_pct: 0 }, { ttl: 2, ip: "203.0.113.1", rtt_ms: 9, loss_pct: 0 }],
};
const ELSEWHERE: ProbePath = { ...TRACE, dst: "8.8.8.8", site: "", reached: false, hops: [{ ttl: 1, ip: "10.0.0.1", rtt_ms: 1, loss_pct: 0 }] };

const probed = (paths: ProbePath[], error: string | null = null): MeasuredState =>
  ({ index: buildMeasuredIndex(paths, [], []), error, loaded: true });

describe("measured paths on the rows", () => {
  it("has no Measured paths section any more", async () => {
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [wanRow()] });
    render(<WanCircuits measured={probed([TRACE])} />);
    await screen.findByText("Gi0/0/2");
    expect(document.querySelector('[data-section="wan-measured-paths"]')).toBeNull();
    expect(screen.queryByText("Measured paths")).toBeNull();
  });

  it("marks a link the registry holds but does not measure as held, in its own row", async () => {
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [wanRow({ interface: "Ethernet3", target: "1.1.1.1", target_kind: "anchor" }), wanRow()] });
    render(<WanCircuits />);
    const held = await screen.findByTestId("wan-held");
    expect(held.getAttribute("title")).toBe("In the registry, not being measured");
    expect(screen.getAllByTestId("wan-held")).toHaveLength(1);
  });

  it("puts the prober's path to the row's target in a Path column", async () => {
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [wanRow()] });
    render(<WanCircuits measured={probed([TRACE])} />);
    const cell = await screen.findByTestId("path-cell");
    expect(within(cell).getByTestId("path-verdict").textContent).toBe("Reached");
    expect(cell.textContent).toContain("2 hops");
    expect(screen.getByText("Path")).toBeTruthy();
  });

  it("opens the row's path hop by hop, with where it goes and when it was traced", async () => {
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [wanRow()] });
    render(<WanCircuits measured={probed([TRACE])} />);
    fireEvent.click(await screen.findByText("Gi0/0/2"));
    const panel = screen.getByTestId("path-panel");
    expect(panel.className).toContain("open");
    const detail = within(panel).getByTestId("path-detail");
    expect(within(detail).getByRole("heading", { name: "To the measurement target" })).toBeTruthy();
    expect(detail.textContent).toContain("From prober v1 to 203.0.113.1");
    expect(detail.textContent).toMatch(/traced as of \d\d:\d\d/);
    expect(within(detail).getByTestId("paths-ribbon")).toBeTruthy();
    expect(within(detail).getByLabelText("Path hops")).toBeTruthy();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.getByTestId("path-panel").className).not.toContain(" open");
  });

  it("lists a path no row claims apart, collapsed, and opens it too", async () => {
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [wanRow()] });
    render(<WanCircuits measured={probed([TRACE, ELSEWHERE])} />);
    const box = await screen.findByTestId("paths-other");
    expect(box.tagName).toBe("DETAILS");
    expect((box as HTMLDetailsElement).open).toBe(false);
    expect(within(box).getByText("Measured paths to other targets (1)")).toBeTruthy();
    expect(within(box).getByTestId("path-verdict").textContent).toBe("Not reached");
    fireEvent.click(within(box).getByTestId("paths-other-open"));
    expect(within(screen.getByTestId("path-panel")).getByRole("heading", { name: "To 8.8.8.8" })).toBeTruthy();
  });

  it("shows a dash for a row with no measured path, and opens nothing", async () => {
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [wanRow({ target: "198.51.100.9" })] });
    render(<WanCircuits measured={probed([TRACE])} />);
    const cell = await screen.findByTestId("path-cell");
    expect(cell.textContent).toBe("—");
    fireEvent.click(screen.getByText("Gi0/0/2"));
    expect(screen.getByTestId("path-panel").className).not.toContain(" open");
  });

  it("says in one line when the paths could not be read, and keeps the rows", async () => {
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [wanRow()] });
    render(<WanCircuits measured={{ index: null, error: "Measured paths could not be read.", loaded: true }} />);
    expect((await screen.findByTestId("paths-read-error")).textContent).toContain("Measured paths could not be read.");
    expect(screen.getByText("Gi0/0/2")).toBeTruthy();
  });

  it("has no Path column outside the Paths page", async () => {
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [wanRow()] });
    render(<WanCircuits />);
    await screen.findByText("Gi0/0/2");
    expect(screen.queryByTestId("path-cell")).toBeNull();
    expect(screen.queryByTestId("path-panel")).toBeNull();
  });
});

// ── the derived endpoint registry ───────────────────────────────────────────

describe("endpoint registry", () => {
  it("renders each derived interface with its address, site and why it is WAN", async () => {
    render(<WanCircuits />);
    const sec = await waitFor(() => {
      const s = section("wan-endpoints");
      if (!within(s).queryByText("London")) throw new Error("not read yet");
      return s;
    });
    expect(within(sec).getAllByText("spine-1").length).toBeGreaterThan(0);
    expect(within(sec).getAllByText("198.51.100.2").length).toBeGreaterThan(0);
    const why = within(sec).getByText("Tunnel runs over it");
    expect(why.getAttribute("title")).toContain("tunnel Tunnel1 runs over it");
    expect(why.getAttribute("title")).toContain("VPN 0");
    // An interface with no stated reason shows a dash, never a guess.
    expect(within(sec).getAllByTestId("wan-why").some((c) => c.textContent === "—")).toBe(true);
  });

  it("lists possible interfaces apart, collapsed, and never as WAN circuits", async () => {
    mockApi.wanEndpoints.mockResolvedValue({ endpoints: [PEER_EP], candidates: [LINKED_CANDIDATE] });
    render(<WanCircuits />);
    const box = await screen.findByTestId("wan-possible");
    expect(box.tagName).toBe("DETAILS");
    expect((box as HTMLDetailsElement).open).toBe(false);
    expect(within(box).getByText(/Possible WAN — not confirmed \(1\)/)).toBeTruthy();
    expect(within(box).getByText("core-sw-2")).toBeTruthy();
    expect(within(box).getByText("Faces a WAN router").getAttribute("title")).toContain("usually the LAN side");
    expect(within(section("wan-endpoints")).queryByText("core-sw-2")).toBeNull();
  });

  it("marks a possible interface as WAN, then re-reads what is WAN", async () => {
    mockApi.wanEndpoints.mockResolvedValue({ endpoints: [PEER_EP], candidates: [LINKED_CANDIDATE] });
    mockApi.setWanMark.mockResolvedValue({ device_id: "core-sw-2-9f1", interface: "Ethernet4", mark: "wan" });
    render(<WanCircuits />);
    const box = await screen.findByTestId("wan-possible");
    fireEvent.click(await within(box).findByRole("button", { name: "Mark as WAN" }));
    await waitFor(() => expect(mockApi.setWanMark).toHaveBeenCalledWith("core-sw-2-9f1", "Ethernet4", "wan"));
    await waitFor(() => expect(mockApi.wanEndpoints).toHaveBeenCalledTimes(2));
    expect(mockApi.wanCircuits).toHaveBeenCalledTimes(2);
  });

  it("says why a mark was refused, and offers no buttons without write access", async () => {
    mockApi.wanEndpoints.mockResolvedValue({ endpoints: [PEER_EP], candidates: [LINKED_CANDIDATE] });
    mockApi.setWanMark.mockRejectedValue(new Error("not found"));
    render(<WanCircuits />);
    const box = await screen.findByTestId("wan-possible");
    fireEvent.click(await within(box).findByRole("button", { name: "Not WAN" }));
    expect(await within(box).findByRole("alert")).toBeTruthy();
    cleanup();

    mockApi.permissions.mockResolvedValue({ role: "viewer", permissions: { infrastructure: 1 } });
    render(<WanCircuits />);
    const ro = await screen.findByTestId("wan-possible");
    await waitFor(() => expect(mockApi.permissions).toHaveBeenCalled());
    expect(within(ro).queryByRole("button", { name: "Mark as WAN" })).toBeNull();
    expect(within(ro).queryByRole("button", { name: "Not WAN" })).toBeNull();
  });

  it("shows no possible section when there is nothing possible", async () => {
    render(<WanCircuits />);
    await waitFor(() => expect(mockApi.wanEndpoints).toHaveBeenCalled());
    await screen.findByText("London");
    expect(screen.queryByTestId("wan-possible")).toBeNull();
  });

  it("counts how many interfaces measure to a peer, an ISP next-hop, an anchor and nothing", async () => {
    render(<WanCircuits />);
    const sec = await waitFor(() => {
      const s = section("wan-endpoints");
      if (!within(s).queryByText("Directly-connected peer: 1")) throw new Error("not read yet");
      return s;
    });
    expect(within(sec).getByText("ISP next-hop: 1")).toBeTruthy();
    expect(within(sec).getByText("Reachability anchor: 1")).toBeTruthy();
    expect(within(sec).getByText("No target derived: 1")).toBeTruthy();
    expect(within(sec).getByText(/1 interface has no target yet\./)).toBeTruthy();
  });

  it("says what fills the registry, when the derivation is empty", async () => {
    mockApi.wanEndpoints.mockResolvedValue({ endpoints: [] });
    render(<WanCircuits />);
    await waitFor(() => {
      expect(within(section("wan-endpoints")).getByText(/The registry is empty\./)).toBeTruthy();
    });
    // What fills the registry is ai/skills/explain/wan.registry.md, behind the `(i)`.
    expect(within(section("wan-endpoints"))
      .getAllByRole("button", { name: /Ask Iris about (Empty registry|Endpoint registry)/ }).length)
      .toBeGreaterThan(0);
  });
});

// ── section independence ────────────────────────────────────────────────────

describe("each section owns its own failure", () => {
  it("a dead registry read leaves the interface table on screen, in an operator sentence", async () => {
    mockApi.wanEndpoints.mockRejectedValue(new Error(
      '500 Internal Server Error: {"error":"dial tcp 10.0.0.9:2379: connect: connection refused"}',
    ));
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [wanRow()] });
    render(<WanCircuits />);
    await waitFor(() => expect(within(section("wan-endpoints")).getByRole("alert")).toBeTruthy());
    const said = within(section("wan-endpoints")).getByRole("alert").textContent ?? "";
    expect(said).toContain("The service did not answer.");
    expect(said).not.toContain("10.0.0.9");
    expect(screen.getByText("Gi0/0/2")).toBeTruthy();
  });

  it("a dead held read says so in one line and leaves the registry on screen", async () => {
    mockApi.wanCircuits.mockRejectedValue(new Error("503 Service Unavailable: {}"));
    render(<WanCircuits />);
    const note = await screen.findByTestId("wan-held-error");
    expect(note.getAttribute("role")).toBe("alert");
    expect(note.textContent).not.toContain("503");
    expect(await within(section("wan-endpoints")).findByText("London")).toBeTruthy();
  });
});

// ── the adjacency evidence the SERVER could not read (tracker 290) ──────────
//
// The neighbour index is the second rung of the target-derivation ranking, so
// with no index every interface falls through to the reachability anchor. That
// fallback used to be invisible: the row said "Reachability anchor 1.1.1.1" and
// nothing said the peer across the link had never been looked for. The failure
// is SAFE — it fails closed and discloses nothing — and that is exactly what let
// it survive. The backend now says so on the payload; this is the half that puts
// it in front of the reader.

describe("a WAN projection whose adjacency evidence never arrived", () => {
  const NOTE =
    "Adjacency evidence could not be read, so directly-connected peers were not resolved — interfaces shown against a reachability anchor may in fact have a peer, and are not confirmed to be internet-facing.";

  it("says so beside the table, and still shows the table", async () => {
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [], degraded: [NOTE] });
    render(<WanCircuits />);

    const alert = await waitFor(() => screen.getByTestId("wan-degraded"));
    expect(alert).toHaveAttribute("role", "alert");
    expect(alert.textContent).toMatch(/reachability anchor/i);
    expect(screen.getByRole("heading", { name: "WAN circuits" })).toBeTruthy();
  });

  it("says nothing on a healthy read", async () => {
    render(<WanCircuits />);
    await waitFor(() => expect(mockApi.wanInterfaces).toHaveBeenCalled());
    expect(screen.queryByTestId("wan-degraded")).toBeNull();
  });
});
