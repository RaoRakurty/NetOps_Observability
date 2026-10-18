// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DeviceNeighbors.unread.test.tsx — tracker 290, the device page.
//
// This tab caught a failed /api/topology/links into an empty list and rendered
// "No neighbour protocol reported one here." — a statement about the network,
// made from no evidence at all. The endpoint now REFUSES (502) rather than
// answering count:0, and the refusal has to reach the reader.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import DeviceNeighbors from "./DeviceNeighbors";
import { api, type Device } from "../services/api";

vi.mock("../services/api", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("../services/api");
  return {
    ...actual,
    api: {
      topologyLinks: vi.fn(),
      metricsQuery: vi.fn().mockResolvedValue({ data: { result: [] } }),
    },
  };
});

const device = { id: "spine-1", name: "spine-1", vendor: "arista" } as unknown as Device;

describe("the Neighbors tab when the adjacency evidence could not be read", () => {
  beforeEach(() => vi.clearAllMocks());

  it("says the neighbors are UNKNOWN, not that there are none", async () => {
    vi.mocked(api.topologyLinks).mockRejectedValue(new Error("502 Bad Gateway"));
    render(<DeviceNeighbors device={device} />);

    const alert = await waitFor(() => screen.getByTestId("device-neighbours-unread"));
    expect(alert).toHaveAttribute("role", "alert");
    expect(alert.textContent).toMatch(/UNKNOWN here — not absent/);
    // The old sentence, which asserted a fact about the network, must be gone.
    expect(screen.queryByText(/No neighbor protocol reported one here/)).toBeNull();
  });

  it("still reports an honestly empty adjacency set as empty", async () => {
    vi.mocked(api.topologyLinks).mockResolvedValue({ links: [], count: 0, source: "none" } as never);
    render(<DeviceNeighbors device={device} />);

    await waitFor(() => expect(screen.getByText(/No neighbor protocol reported one here/)).toBeInTheDocument());
    expect(screen.queryByTestId("device-neighbours-unread")).toBeNull();
  });
});

// Owner report 2026-10-10: BGP and OSPF did not show in the device popup.
describe("the BGP and OSPF sections", () => {
  beforeEach(() => vi.clearAllMocks());

  const byQuery = (map: Record<string, unknown>) => (q: string) => {
    for (const [k, v] of Object.entries(map)) if (q.startsWith(k)) return v instanceof Error ? Promise.reject(v) : Promise.resolve(v);
    return Promise.resolve({ data: { result: [] } });
  };

  it("shows OSPF neighbors by their address label and BGP peers with their remote AS", async () => {
    vi.mocked(api.topologyLinks).mockResolvedValue({ links: [], count: 0, source: "none" } as never);
    vi.mocked(api.metricsQuery).mockImplementation(byQuery({
      device_bgp_peer_state: { data: { result: [{ metric: { peer: "192.0.2.1" }, value: [0, "6"] }] } },
      device_bgp_peer_remote_as: { data: { result: [{ metric: { peer: "192.0.2.1" }, value: [0, "65010"] }] } },
      device_ospf_nbr_state: { data: { result: [{ metric: { neighbor: "172.16.40.41" }, value: [0, "8"] }] } },
    }) as never);
    render(<DeviceNeighbors device={device} />);
    expect(await screen.findByText("172.16.40.41")).toBeInTheDocument();
    expect(await screen.findByText("65010")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.1")).toBeInTheDocument();
  });

  it("says BGP and OSPF are UNKNOWN when their state could not be read", async () => {
    vi.mocked(api.topologyLinks).mockResolvedValue({ links: [], count: 0, source: "none" } as never);
    vi.mocked(api.metricsQuery).mockImplementation(byQuery({
      device_bgp_peer_state: new Error("502 Bad Gateway"),
      device_ospf_nbr_state: new Error("502 Bad Gateway"),
    }) as never);
    render(<DeviceNeighbors device={device} />);
    expect((await screen.findByTestId("device-bgp-unread")).textContent).toMatch(/UNKNOWN here — not absent/);
    expect((await screen.findByTestId("device-ospf-unread")).textContent).toMatch(/UNKNOWN here — not absent/);
    expect(screen.queryByText(/No BGP peer seen on this device/)).toBeNull();
  });
});

// SD-WAN control plane (OMP): shown on edges with their sessions, hidden on
// devices that run no OMP, counts-only on controllers, UNKNOWN when unread.
describe("the OMP section", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.topologyLinks).mockResolvedValue({ links: [], count: 0, source: "none" } as never);
  });
  const route = (map: Record<string, unknown>) => (q: string) => {
    for (const [k, v] of Object.entries(map)) if (q.startsWith(k + "{")) return v instanceof Error ? Promise.reject(v) : Promise.resolve(v);
    return Promise.resolve({ data: { result: [] } });
  };
  const series = (metric: Record<string, string>, v: string) => ({ metric, value: [0, v] });

  it("lists an edge's controller sessions with their state", async () => {
    vi.mocked(api.metricsQuery).mockImplementation(route({
      device_omp_peer_state: { data: { result: [series({ peer: "10.255.255.1", type: "vsmart", site_id: "1000" }, "3"), series({ peer: "10.255.255.2", type: "vsmart" }, "8")] } },
      device_omp_peers: { data: { result: [series({ state: "up" }, "2"), series({ state: "not_up" }, "0")] } },
    }) as never);
    render(<DeviceNeighbors device={device} />);
    expect(await screen.findByText("SD-WAN control sessions (OMP)")).toBeInTheDocument();
    expect(screen.getByText("10.255.255.1")).toBeInTheDocument();
    expect(screen.getByText("up (graceful restart)")).toBeInTheDocument();
    expect(screen.getByText("2 up · 0 not up")).toBeInTheDocument();
  });

  it("stays hidden on a device that runs no OMP", async () => {
    vi.mocked(api.metricsQuery).mockImplementation(route({}) as never);
    render(<DeviceNeighbors device={device} />);
    await screen.findByText(/No neighbor protocol reported one here/);
    expect(screen.queryByText("SD-WAN control sessions (OMP)")).toBeNull();
  });

  it("says a controller shows counts only", async () => {
    vi.mocked(api.metricsQuery).mockImplementation(route({
      device_omp_peers: { data: { result: [series({ state: "up" }, "120"), series({ state: "not_up" }, "3")] } },
    }) as never);
    render(<DeviceNeighbors device={device} />);
    expect(await screen.findByText(/Controller — session counts only/)).toBeInTheDocument();
  });

  it("says UNKNOWN when the read fails", async () => {
    vi.mocked(api.metricsQuery).mockImplementation(route({ device_omp_peer_state: new Error("502 Bad Gateway") }) as never);
    render(<DeviceNeighbors device={device} />);
    expect((await screen.findByTestId("device-omp-unread")).textContent).toMatch(/UNKNOWN here — not absent/);
  });
});

describe("peerKey — remote AS joins per instance", () => {
  it("treats the global table's spellings as one and keeps VRFs apart", async () => {
    const { peerKey } = await import("./DeviceNeighbors");
    expect(peerKey(undefined, "10.0.0.1")).toBe(peerKey("default", "10.0.0.1"));
    expect(peerKey("CUST-A", "10.0.0.1")).not.toBe(peerKey(undefined, "10.0.0.1"));
  });
});
