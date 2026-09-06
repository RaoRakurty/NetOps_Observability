// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// NewMonitor navigation-pointer contract. This page ENDS in an instruction —
// "your monitor is live, now go and look at it over there" — and an instruction
// that names a screen which no longer exists is worse than no instruction: the
// operator concludes the monitor did not work. The 2026-08 nav redesign
// dissolved the "Monitoring" and "Incident Response" rail sections and this
// page went on pointing at "Monitoring → Triggered" and
// "Incident Response → Notifications" for months.
//
// So the pointers are DECLARED (NAV_POINTERS) and pinned here against nav.tsx
// itself — the same table the sidebar and the ⌘K palette render from. A rename
// in nav.tsx now fails this test instead of stranding an operator.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor } from "@testing-library/react";

const h = vi.hoisted(() => ({
  navigate: vi.fn(),
  api: {
    metricNames: vi.fn(async () => ({ data: ["collector_target_up"] })),
    metricsQuery: vi.fn(async () => ({ status: "success", data: { result: [] } })),
    addRule: vi.fn(async () => ({})),
  },
}));
vi.mock("../services/api", () => ({ api: h.api }));
vi.mock("../context/shell", () => ({ useShell: () => ({ navigate: h.navigate }) }));

import NewMonitor, { NAV_POINTERS, navPath, type NavPointer } from "./NewMonitor";
import { NAV, navDestinations } from "../nav";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const POINTERS: NavPointer[] = Object.values(NAV_POINTERS);

describe("NewMonitor navigation pointers resolve in the real nav table", () => {
  // The source of truth: the flattened nav the sidebar and ⌘K both render.
  const dests = navDestinations(NAV);

  it.each(POINTERS)("route $route is a real leaf in nav.tsx", (p) => {
    const hit = dests.find((d) => d.route === p.route);
    expect(
      hit,
      `NewMonitor points at "${p.route}" (${navPath(p)}), which is NOT a route in nav.tsx. ` +
        `A renamed or removed leaf must be followed here — never leave an operator with a dead instruction.`,
    ).toBeTruthy();
  });

  it.each(POINTERS)("label for $route matches the nav tree's own wording", (p) => {
    const hit = dests.find((d) => d.route === p.route);
    // navDestinations labels a leaf "Section · Leaf"; NAV_POINTERS carries the
    // two halves separately so the copy can render them with an arrow.
    expect(hit?.label).toBe(`${p.section} · ${p.leaf}`);
  });

  it("names Active Alerts and Notifications — the screens Triggered and Incident Response became", () => {
    expect(NAV_POINTERS.alerts.route).toBe("operations/alerts");
    expect(NAV_POINTERS.notifications.route).toBe("admin/notifications");
    // The dead pre-redesign wording must never come back.
    for (const p of POINTERS) {
      expect(navPath(p)).not.toMatch(/Monitoring → Triggered|Incident Response → Notifications/);
    }
  });
});

describe("NewMonitor renders those pointers and navigates to them", () => {
  // Walk the wizard to the Review step, where the routing copy lives.
  async function openReviewStep() {
    render(<NewMonitor />);
    fireEvent.click(screen.getByText("Device unreachable"));
    fireEvent.click(screen.getByRole("button", { name: "Next" })); // Signal → Condition
    fireEvent.click(screen.getByRole("button", { name: "Next" })); // Condition → Review
    await screen.findByLabelText(/Monitor name/);
  }

  it("displays only nav paths that exist", async () => {
    await openReviewStep();
    const copy = screen.getByText(/Firing alerts appear under/).textContent ?? "";
    expect(copy).toContain(navPath(NAV_POINTERS.alerts));
    expect(copy).toContain(navPath(NAV_POINTERS.notifications));

    // Every "A → B" pair the page prints must be one of the declared pointers,
    // so new copy cannot smuggle in an unpinned (and unverified) path.
    const declared = new Set(POINTERS.map(navPath));
    // Up to three capitalised words either side of an arrow — the shape of a
    // nav path, and narrow enough that surrounding lower-case prose ends it.
    const NAV_PATH_RE = /(?:[A-Z][A-Za-z]*\s){0,2}[A-Z][A-Za-z]*\s→\s[A-Z][A-Za-z]*(?:\s[A-Z][A-Za-z]*){0,2}/g;
    const printed = copy.match(NAV_PATH_RE) ?? [];
    expect(printed.length).toBeGreaterThan(0);
    for (const path of printed) {
      expect(declared, `unpinned nav path in the copy: "${path}"`).toContain(path);
    }
  });

  it("sends 'View monitors' to the declared monitors route", async () => {
    await openReviewStep();
    fireEvent.change(screen.getByLabelText(/Monitor name/), { target: { value: "DeviceUnreachable" } });
    fireEvent.click(screen.getByRole("button", { name: "Create monitor" }));
    const view = await screen.findByRole("button", { name: /View monitors/ });
    fireEvent.click(view);
    await waitFor(() => expect(h.navigate).toHaveBeenCalledWith(NAV_POINTERS.monitors.route));
  });
});
