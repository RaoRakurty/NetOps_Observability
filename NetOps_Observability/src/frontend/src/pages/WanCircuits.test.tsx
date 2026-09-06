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
//   3. A SAVE CHANGES THE PROJECTION. The policy is the input to the derivation,
//      so a successful save has to re-read the other two sections — otherwise the
//      operator sees a stale registry and believes their change did nothing.
//
// Plus the two ordinary guards: one section's dead read must not blank another,
// and a rejected save must leave the operator's text where they left it.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import type { WanCircuit, WanEndpoint, WanMeasurementPolicy } from "../services/api";

const mockApi = vi.hoisted(() => ({
  wanInterfaces: vi.fn(),
  wanEndpoints: vi.fn(),
  wanCircuits: vi.fn(),
  wanPolicy: vi.fn(),
  setWanPolicy: vi.fn(),
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

const PEER_EP = ep({ target: "10.1.1.2", target_kind: "direct_peer", target_label: "Directly-connected peer spine-1 Ethernet9" });
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
  it("reads interfaces, endpoints, paths and the policy — one route per section", async () => {
    render(<WanCircuits />);
    await waitFor(() => expect(mockApi.wanPolicy).toHaveBeenCalled());
    expect(mockApi.wanInterfaces).toHaveBeenCalled();
    expect(mockApi.wanEndpoints).toHaveBeenCalledTimes(1);
    expect(mockApi.wanCircuits).toHaveBeenCalledTimes(1);
    expect(mockApi.wanPolicy).toHaveBeenCalledTimes(1);
  });

  it("keeps the existing interface metrics table and its live read", async () => {
    render(<WanCircuits />);
    await waitFor(() => expect(mockApi.wanCircuits).toHaveBeenCalled());
    expect(screen.getByRole("heading", { name: "WAN interfaces" })).toBeTruthy();
    expect(screen.getByText(/No WAN interfaces yet\./)).toBeTruthy();
  });
});

// ── the derived paths ───────────────────────────────────────────────────────

describe("measured paths", () => {
  it("renders one row per interface→target link with both ends", async () => {
    render(<WanCircuits />);
    const sec = await waitFor(() => {
      const s = section("wan-measured-paths");
      if (!within(s).queryByText("10.1.1.2")) throw new Error("not read yet");
      return s;
    });
    expect(within(sec).getAllByText("wan-edge-1").length).toBeGreaterThan(0);
    expect(within(sec).getByText("spine-1")).toBeTruthy();
    expect(within(sec).getByText("Ethernet9")).toBeTruthy();
    expect(within(sec).getByText("203.0.113.1")).toBeTruthy();
  });

  it("chips each path with the provenance vocabulary — peer, ISP next-hop, anchor", async () => {
    render(<WanCircuits />);
    const sec = await waitFor(() => {
      const s = section("wan-measured-paths");
      if (!within(s).queryByText("Peer")) throw new Error("not read yet");
      return s;
    });
    expect(within(sec).getAllByText("ISP next-hop").length).toBeGreaterThan(0);
    expect(within(sec).getByText("Anchor")).toBeTruthy();
    // The house vocabulary: a next-hop is an ownership handoff to the ISP, and
    // the word "boundary" is reserved for spine zones.
    const chip = within(sec).getAllByText("ISP next-hop")[0];
    // UI-words sweep 4: the row states the target; the ownership handoff moved
    // into ai/skills/explain/wan.next-hop.md behind the section's `(i)`.
    expect(chip.getAttribute("title")).toContain("The ISP next-hop you declared");
    expect(within(sec).getByRole("button", { name: "Ask Iris about Derived target" })).toBeTruthy();
    expect(sec.textContent ?? "").not.toMatch(/boundary/i);
    expect(sec.textContent ?? "").not.toMatch(/\bhub\b|\bspoke\b/i);
  });

  it("explains what has to be true before anything is derived, when nothing is", async () => {
    mockApi.wanCircuits.mockResolvedValue({ circuits: [] });
    render(<WanCircuits />);
    await waitFor(() => {
      expect(within(section("wan-measured-paths")).getByText(/Nothing has been derived yet\./)).toBeTruthy();
    });
    // The CLAIM stays on screen; what must be true before a path is derived is
    // ai/skills/explain/wan.nothing-derived.md, reachable from the `(i)` beside it.
    expect(within(section("wan-measured-paths"))
      .getByRole("button", { name: "Ask Iris about Nothing derived yet" })).toBeTruthy();
  });
});

// ── the derived endpoint registry ───────────────────────────────────────────

describe("endpoint registry", () => {
  it("renders each derived interface with its address, site and linked flag", async () => {
    render(<WanCircuits />);
    const sec = await waitFor(() => {
      const s = section("wan-endpoints");
      if (!within(s).queryByText("London")) throw new Error("not read yet");
      return s;
    });
    expect(within(sec).getAllByText("spine-1").length).toBeGreaterThan(0);
    expect(within(sec).getByText("linked")).toBeTruthy();
    expect(within(sec).getAllByText("198.51.100.2").length).toBeGreaterThan(0);
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
  it("a dead policy read leaves the paths and the registry on screen", async () => {
    mockApi.wanPolicy.mockRejectedValue(new Error(
      '500 Internal Server Error: {"error":"dial tcp 10.0.0.9:2379: connect: connection refused"}',
    ));
    render(<WanCircuits />);
    await waitFor(() => {
      expect(within(section("wan-policy")).getByRole("alert")).toBeTruthy();
    });
    // An operator sentence, not the server's wrap chain and not its addresses.
    const said = within(section("wan-policy")).getByRole("alert").textContent ?? "";
    expect(said).toContain("The service did not answer.");
    expect(said).not.toContain("10.0.0.9");
    expect(within(section("wan-measured-paths")).getAllByText("wan-edge-1").length).toBeGreaterThan(0);
    expect(within(section("wan-endpoints")).getByText("London")).toBeTruthy();
  });

  it("a dead paths read leaves the policy editor usable", async () => {
    mockApi.wanCircuits.mockRejectedValue(new Error("503 Service Unavailable: {}"));
    render(<WanCircuits />);
    await waitFor(() => expect(within(section("wan-measured-paths")).getByRole("alert")).toBeTruthy());
    await waitFor(() => expect(screen.getByLabelText("WAN device name pattern")).toBeTruthy());
    expect(within(section("wan-endpoints")).getByText("London")).toBeTruthy();
  });
});

// ── the measurement policy editor ───────────────────────────────────────────

describe("measurement policy", () => {
  async function openEditor() {
    render(<WanCircuits />);
    return waitFor(() => screen.getByLabelText("WAN device name pattern") as HTMLInputElement);
  }

  it("seeds the form from the stored policy and names who changed it", async () => {
    const pattern = await openEditor();
    expect(pattern.value).toBe("wan|edge|gw|dmz");
    expect((screen.getByLabelText("Reachability anchors") as HTMLInputElement).value).toBe("1.1.1.1, 8.8.8.8");
    expect((screen.getByLabelText("Device or device and interface, override 1") as HTMLInputElement).value)
      .toBe("wan-edge-1/Ethernet2");
    expect(screen.getByText(/Last changed by rao/)).toBeTruthy();
  });

  it("keeps the save inert until the form differs from what is stored", async () => {
    const pattern = await openEditor();
    const save = screen.getByRole("button", { name: "Save policy" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.change(pattern, { target: { value: "wan|edge|dia" } });
    expect((screen.getByRole("button", { name: "Save policy" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("PUTs exactly the four intent fields, and never a tenant", async () => {
    const pattern = await openEditor();
    fireEvent.change(pattern, { target: { value: "wan|edge|dia" } });
    fireEvent.change(screen.getByLabelText("Reachability anchors"), { target: { value: "9.9.9.9, 1.1.1.1" } });
    fireEvent.click(screen.getByLabelText("Also measure interfaces directly connected to a WAN device"));
    fireEvent.change(screen.getByLabelText("ISP next-hop address, override 1"), { target: { value: "203.0.113.9" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));

    await waitFor(() => expect(mockApi.setWanPolicy).toHaveBeenCalledTimes(1));
    const body = mockApi.setWanPolicy.mock.calls[0][0] as WanMeasurementPolicy;
    expect(body).toEqual({
      wan_pattern: "wan|edge|dia",
      anchors: ["9.9.9.9", "1.1.1.1"],
      next_hops: { "wan-edge-1/Ethernet2": "203.0.113.9" },
      include_connected: false,
    });
    expect(Object.keys(body)).not.toContain("tenant_id");
    expect(Object.keys(body)).not.toContain("updated_by");
    expect(Object.keys(body)).not.toContain("updated_at");
  });

  it("adds and removes ISP next-hop overrides, and clearing the last one PUTs an empty map", async () => {
    await openEditor();
    fireEvent.click(screen.getByRole("button", { name: "Remove override 1" }));
    expect(screen.getByText(/No ISP next-hop has been declared/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(mockApi.setWanPolicy).toHaveBeenCalled());
    expect((mockApi.setWanPolicy.mock.calls[0][0] as WanMeasurementPolicy).next_hops).toEqual({});
  });

  it("blocks a save while an override is half-filled, and says which half is missing", async () => {
    await openEditor();
    fireEvent.click(screen.getByRole("button", { name: "Add an override" }));
    fireEvent.change(screen.getByLabelText("Device or device and interface, override 2"), { target: { value: "wan-edge-2" } });
    expect(screen.getByText(/no ISP next-hop address to measure to/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Save policy" }) as HTMLButtonElement).disabled).toBe(true);
    expect(mockApi.setWanPolicy).not.toHaveBeenCalled();
  });

  it("re-reads the endpoints and the paths after a successful save — the projection changed", async () => {
    const pattern = await openEditor();
    expect(mockApi.wanEndpoints).toHaveBeenCalledTimes(1);
    expect(mockApi.wanCircuits).toHaveBeenCalledTimes(1);

    fireEvent.change(pattern, { target: { value: "wan|edge|dia" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));

    await waitFor(() => expect(mockApi.wanEndpoints).toHaveBeenCalledTimes(2));
    expect(mockApi.wanCircuits).toHaveBeenCalledTimes(2);
    expect(mockApi.wanPolicy).toHaveBeenCalledTimes(2);
    expect(screen.getByText(/Measurement policy saved\./)).toBeTruthy();
  });

  it("catches an unreadable pattern before it is ever sent", async () => {
    const pattern = await openEditor();
    fireEvent.change(pattern, { target: { value: "wan(edge" } });
    expect(screen.getByText(/That device name pattern could not be read\./)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Save policy" }) as HTMLButtonElement).disabled).toBe(true);
    expect(mockApi.setWanPolicy).not.toHaveBeenCalled();
  });

  it("renders an operator sentence on a refused save and keeps the edit in the form", async () => {
    // A named capture group the browser accepts and the server's own matcher
    // does not — the case the local pre-flight cannot catch, so the server's
    // sentence is the one the operator has to read.
    mockApi.setWanPolicy.mockRejectedValue(new Error(
      '400 Bad Request: {"error":"wan_pattern is not a valid expression"}',
    ));
    const pattern = await openEditor();
    fireEvent.change(pattern, { target: { value: "(?<edge>wan)" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));

    await waitFor(() => expect(screen.getByRole("status")).toBeTruthy());
    // The server's own wording survives — only its shape is normalized.
    expect(screen.getByRole("status").textContent).toBe("Wan_pattern is not a valid expression.");
    // The operator's text survives the refusal, and nothing was re-derived.
    expect((screen.getByLabelText("WAN device name pattern") as HTMLInputElement).value).toBe("(?<edge>wan)");
    expect(mockApi.wanEndpoints).toHaveBeenCalledTimes(1);
  });

  it("falls back to our own sentence when the server's failure is developer text", async () => {
    mockApi.setWanPolicy.mockRejectedValue(new Error(
      '500 Internal Server Error: {"error":"kv: write /data/wan_policy.json: no space left on device"}',
    ));
    const pattern = await openEditor();
    fireEvent.change(pattern, { target: { value: "wan|edge|dia" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(screen.getByRole("status")).toBeTruthy());
    expect(screen.getByRole("status").textContent).toBe("The service did not answer.");
  });

  it("without write access explains the read-only state instead of offering a dead button", async () => {
    mockApi.permissions.mockResolvedValue({ role: "viewer", permissions: { infrastructure: 1 } });
    render(<WanCircuits />);
    await waitFor(() => expect(screen.getByText(/Changing the policy needs write access\./)).toBeTruthy());
    expect(screen.queryByRole("button", { name: "Save policy" })).toBeNull();
    expect((screen.getByLabelText("WAN device name pattern") as HTMLInputElement).disabled).toBe(true);
    // Who can grant it is ai/skills/explain/wan.policy-readonly.md, behind the `(i)`.
    expect(screen.getByRole("button", { name: "Ask Iris about Read-only policy" })).toBeTruthy();
  });

  it("treats an unreadable permission check as read-only", async () => {
    mockApi.permissions.mockRejectedValue(new Error("401 Unauthorized: {}"));
    render(<WanCircuits />);
    await waitFor(() => expect(screen.getByText(/Changing the policy needs write access\./)).toBeTruthy());
  });
});
