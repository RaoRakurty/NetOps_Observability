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

describe("the Neighbours tab when the adjacency evidence could not be read", () => {
  beforeEach(() => vi.clearAllMocks());

  it("says the neighbours are UNKNOWN, not that there are none", async () => {
    vi.mocked(api.topologyLinks).mockRejectedValue(new Error("502 Bad Gateway"));
    render(<DeviceNeighbors device={device} />);

    const alert = await waitFor(() => screen.getByTestId("device-neighbours-unread"));
    expect(alert).toHaveAttribute("role", "alert");
    expect(alert.textContent).toMatch(/UNKNOWN here — not absent/);
    // The old sentence, which asserted a fact about the network, must be gone.
    expect(screen.queryByText(/No neighbour protocol reported one here/)).toBeNull();
  });

  it("still reports an honestly empty adjacency set as empty", async () => {
    vi.mocked(api.topologyLinks).mockResolvedValue({ links: [], count: 0, source: "none" } as never);
    render(<DeviceNeighbors device={device} />);

    await waitFor(() => expect(screen.getByText(/No neighbour protocol reported one here/)).toBeInTheDocument());
    expect(screen.queryByTestId("device-neighbours-unread")).toBeNull();
  });
});
