// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// NavFlyout.test.tsx — collapsible leaves (owner, 2026-11-23): under
// Operations, Digital Experience and Cloud hide their sub-items until clicked;
// every other leaf keeps its sub-items in view and navigates on click.

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent, within } from "@testing-library/react";
import NavFlyout from "./NavFlyout";
import { NAV, NavSection } from "../nav";

afterEach(() => {
  cleanup();
  location.hash = "";
});

const operations = NAV.find((s) => s.id === "operations") as NavSection;

function renderFlyout(section: NavSection, onNavigate = vi.fn()) {
  render(
    <NavFlyout
      section={section}
      top={0}
      hue="#000"
      activeSection=""
      onEnter={() => {}}
      onLeave={() => {}}
      onNavigate={onNavigate}
      onClose={() => {}}
    />,
  );
  return { onNavigate, menu: screen.getByRole("menu", { name: section.label }) };
}

describe("NavFlyout collapsible leaves", () => {
  it("marks exactly Digital Experience and Cloud collapsible in Operations", () => {
    const ids = (operations.children ?? []).filter((l) => l.collapsible).map((l) => l.id);
    expect(ids).toEqual(["digital-experience", "cloud"]);
  });

  it("hides Digital Experience and Cloud sub-items until the leaf is clicked", () => {
    const { menu, onNavigate } = renderFlyout(operations);
    const dem = within(menu).getByRole("menuitem", { name: /Digital Experience/ });
    const cloud = within(menu).getByRole("menuitem", { name: /^Cloud[▸▾]?$/ });
    expect(dem).toHaveAttribute("aria-expanded", "false");
    expect(cloud).toHaveAttribute("aria-expanded", "false");
    expect(within(menu).queryByRole("menuitem", { name: "Synthetics" })).toBeNull();
    expect(within(menu).queryByRole("menuitem", { name: "Data Sources" })).toBeNull();

    fireEvent.click(dem);
    expect(onNavigate).not.toHaveBeenCalled();
    expect(dem).toHaveAttribute("aria-expanded", "true");
    expect(within(menu).getByRole("menuitem", { name: "Synthetics" })).toBeInTheDocument();
    // Cloud is independent: still closed.
    expect(within(menu).queryByRole("menuitem", { name: "Data Sources" })).toBeNull();

    fireEvent.click(within(menu).getByRole("menuitem", { name: "Synthetics" }));
    expect(onNavigate).toHaveBeenCalledWith("operations/digital-experience/synthetics");

    fireEvent.click(dem);
    expect(dem).toHaveAttribute("aria-expanded", "false");
    expect(within(menu).queryByRole("menuitem", { name: "Synthetics" })).toBeNull();
  });

  it("opens a collapsible leaf the current route is inside", () => {
    location.hash = "#/operations/cloud/resources";
    const { menu } = renderFlyout(operations);
    expect(within(menu).getByRole("menuitem", { name: /^Cloud[▸▾]?$/ })).toHaveAttribute("aria-expanded", "true");
    expect(within(menu).getByRole("menuitem", { name: "Resources" })).toBeInTheDocument();
    expect(within(menu).queryByRole("menuitem", { name: "Synthetics" })).toBeNull();
  });

  it("opens Cloud when the route is its Cloud Logs sub-item on another page", () => {
    location.hash = "#/explore/logs/cloud";
    const { menu } = renderFlyout(operations);
    expect(within(menu).getByRole("menuitem", { name: /^Cloud[▸▾]?$/ })).toHaveAttribute("aria-expanded", "true");
  });

  it("leaves non-collapsible leaves as before: sub-items shown, click navigates", () => {
    const investigate = NAV.find((s) => s.id === "investigate") as NavSection;
    const { menu, onNavigate } = renderFlyout(investigate);
    const paths = within(menu).getByRole("menuitem", { name: "Paths" });
    expect(paths).not.toHaveAttribute("aria-expanded");
    expect(within(menu).getByRole("menuitem", { name: "Tunnels" })).toBeInTheDocument();
    fireEvent.click(paths);
    expect(onNavigate).toHaveBeenCalledWith("investigate/paths");
  });
});
