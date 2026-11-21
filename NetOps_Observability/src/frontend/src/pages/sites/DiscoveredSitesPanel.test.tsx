// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Adopt discovered sites: a preview first (nothing written), already-placed
// devices listed as left alone, only the ticked sites adopted, and the result
// said in plain words.
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import type { AdoptPlan } from "../../services/api";

const { discoveredSites, adoptDiscoveredSites } = vi.hoisted(() => ({
  discoveredSites: vi.fn(),
  adoptDiscoveredSites: vi.fn(),
}));
vi.mock("../../services/api", () => ({ api: { discoveredSites, adoptDiscoveredSites } }));
vi.mock("../../components/AskIris", () => ({ default: () => null }));

import DiscoveredSitesPanel, { planSentence, originName } from "./DiscoveredSitesPanel";

const plan: AdoptPlan = {
  sites: [
    { key: "discovered:t1:sdwan:250", site_id: "250", origin: "vmanage", label: "Site 250 · from vManage", slug: "site-250", name: "Site 250", action: "create",
      devices: [{ device_id: "vs", name: "vSmart", action: "bind" }, { device_id: "vb", name: "vBond", action: "bind" }] },
    { key: "discovered:t1:sdwan:50", site_id: "50", origin: "vmanage", label: "Site 50 · from vManage", slug: "site-50", name: "Site 50", action: "create",
      devices: [
        { device_id: "ve51", name: "vEdge-51", action: "bind" },
        { device_id: "ve53", name: "vEdge-53", action: "skip", detail: "already placed at Boston by an operator" },
      ] },
  ],
  summary: { create: 2, reuse: 0, bind: 3, skip: 1, refused: 0, error: 0 },
};

afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("DiscoveredSitesPanel", () => {
  it("helpers read in plain words", () => {
    expect(originName("vmanage")).toBe("vManage");
    expect(originName("sdwan_peers")).toBe("SD-WAN peers");
    expect(planSentence(plan, false)).toBe("Creates 2 sites, places 3 devices, leaves 1 already placed alone.");
    expect(planSentence({ sites: [], summary: { create: 1, bind: 1, error: 1 } }, true)).toBe("Created 1 site, placed 1 device, 1 could not be done.");
  });

  it("previews, then adopts only the ticked sites", async () => {
    discoveredSites.mockResolvedValue({ adoptable: true, plan });
    adoptDiscoveredSites.mockResolvedValue({ dry_run: false, plan: { sites: [plan.sites[1]], summary: { create: 1, reuse: 0, bind: 1, skip: 1, refused: 0, error: 0 } } });
    const onDone = vi.fn();
    render(<DiscoveredSitesPanel onDone={onDone} />);

    expect(await screen.findByText("Site 50 · from vManage")).toBeTruthy();
    expect(screen.getByText(/already placed at Boston by an operator/)).toBeTruthy();
    expect(adoptDiscoveredSites).not.toHaveBeenCalled(); // the preview writes nothing

    fireEvent.click(screen.getByLabelText("Adopt Site 250 · from vManage")); // untick 250
    expect(screen.getByText("Creates 1 site, places 1 device, leaves 1 already placed alone.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Adopt 1 site" }));

    await waitFor(() => expect(adoptDiscoveredSites).toHaveBeenCalledWith({ dry_run: false, keys: ["discovered:t1:sdwan:50"] }));
    expect(await screen.findByText(/Created 1 site, placed 1 device/)).toBeTruthy();
    expect(onDone).toHaveBeenCalled();
  });

  it("the cross-tenant view says to choose a tenant and offers no adopt", async () => {
    discoveredSites.mockResolvedValue({ adoptable: false, reason: "choose a tenant before adopting discovered sites", plan: { sites: [], summary: {} } });
    render(<DiscoveredSitesPanel onDone={() => {}} />);
    expect(await screen.findByText(/choose a tenant/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Adopt/ })).toBeNull();
  });

  it("says so when nothing is waiting", async () => {
    discoveredSites.mockResolvedValue({ adoptable: true, plan: { sites: [], summary: {} } });
    render(<DiscoveredSitesPanel onDone={() => {}} />);
    expect(await screen.findByText(/No discovered sites are waiting/)).toBeTruthy();
  });
});
