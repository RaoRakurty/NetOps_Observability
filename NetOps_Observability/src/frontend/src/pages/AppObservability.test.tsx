// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// AppObservability.test.tsx — the two shells the old "Services" leaf became
// (owner IA, 2026-09-07), pinned at the level an operator sees them: which tabs
// each one carries, and which hash suffix opens which tab.
//
// WHAT THIS EXISTS TO CATCH. The split is by WHAT FEEDS THE VIEW — Operations →
// Cloud holds what the cloud connectors feed, Infrastructure → Applications
// holds the provider-neutral application layer. A tab body quietly re-parented
// back into the wrong shell would still render, still pass its own unit test,
// and still be wrong; and the "Services → Services" repetition the split existed
// to kill would come back as soon as someone re-added the tab.
//
// The API is a rejecting stand-in on purpose: this is a test about the SHELL, so
// every tab body renders its honest failure state and the tab bar is what is
// left to assert. That also means it never depends on fixture data.

import { render, screen, cleanup, fireEvent, act } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

/** Every api.* call answers the honest "not wired" refusal, so no tab fabricates. */
const mockApi = vi.hoisted(() => new Proxy({} as Record<string, unknown>, {
  get: () => vi.fn().mockRejectedValue(new Error("503 Service Unavailable: not wired")),
}));
vi.mock("../services/api", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("../services/api");
  return { ...actual, api: mockApi };
});

import CloudShell from "./CloudObservability";
import ApplicationsShell from "./ApplicationsObservability";

const CLOUD_TABS = ["Overview", "Resources", "Data sources", "Security", "Investigations", "Settings"];
const APP_TABS = ["Catalog", "Application map", "Registries", "Business services"];

beforeEach(() => { window.location.hash = ""; });
afterEach(cleanup);

describe("Operations → Cloud", () => {
  it("carries the tabs the cloud connectors feed, in the owner's order", async () => {
    render(<CloudShell />);
    const list = await screen.findByRole("tablist", { name: "Cloud" });
    expect([...list.querySelectorAll('[role="tab"]')].map((t) => t.textContent)).toEqual(CLOUD_TABS);
  });

  it("is titled in plain language, and never 'Service View' again", async () => {
    const { container } = render(<CloudShell />);
    expect(await screen.findByRole("heading", { level: 1, name: "Cloud" })).toBeTruthy();
    expect(container.textContent).not.toContain("Service View");
  });

  it("no longer carries the application layer — that leaf owns it now", async () => {
    render(<CloudShell />);
    const list = await screen.findByRole("tablist", { name: "Cloud" });
    for (const gone of ["Services", "Catalog", "Registries", "Service map"]) {
      expect(list.textContent).not.toContain(gone);
    }
  });

  it("opens the tab the hash names (#/operations/cloud/<tab>)", async () => {
    window.location.hash = "#/operations/cloud/settings";
    render(<CloudShell />);
    const tab = await screen.findByRole("tab", { name: "Settings" });
    expect(tab.getAttribute("aria-selected")).toBe("true");
  });

  it("honours the pre-split deep-link aliases (an old bookmark still lands)", async () => {
    window.location.hash = "#/operations/cloud/unknowns";
    render(<CloudShell />);
    expect((await screen.findByRole("tab", { name: "Resources" })).getAttribute("aria-selected")).toBe("true");
  });
});

describe("Infrastructure → Applications", () => {
  it("carries the four application views, Catalog first", async () => {
    render(<ApplicationsShell />);
    const list = await screen.findByRole("tablist", { name: "Applications" });
    expect([...list.querySelectorAll('[role="tab"]')].map((t) => t.textContent)).toEqual(APP_TABS);
  });

  it("no tab repeats the page name (the 'Services → Services' bug)", async () => {
    render(<ApplicationsShell />);
    const list = await screen.findByRole("tablist", { name: "Applications" });
    expect([...list.querySelectorAll('[role="tab"]')].map((t) => t.textContent))
      .not.toContain("Applications");
  });

  it("draws NO cloud scope bar — this layer is provider-neutral", async () => {
    const { container } = render(<ApplicationsShell />);
    await screen.findByRole("tablist", { name: "Applications" });
    expect(container.querySelector(".ao-scopebar")).toBeNull();
    expect(container.textContent).not.toContain("Service View");
  });

  it("opens the tab the hash names (#/infrastructure/applications/<tab>)", async () => {
    window.location.hash = "#/infrastructure/applications/registries";
    render(<ApplicationsShell />);
    expect((await screen.findByRole("tab", { name: "Registries" })).getAttribute("aria-selected")).toBe("true");
  });

  it("switches tabs on click", async () => {
    render(<ApplicationsShell />);
    fireEvent.click(await screen.findByRole("tab", { name: "Business services" }));
    expect(screen.getByRole("tab", { name: "Business services" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("tab", { name: "Catalog" }).getAttribute("aria-selected")).toBe("false");
    // Let the newly-mounted tab's refused load settle inside the test.
    await act(async () => { await Promise.resolve(); });
  });
});
