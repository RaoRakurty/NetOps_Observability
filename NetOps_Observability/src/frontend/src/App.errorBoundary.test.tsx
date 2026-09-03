// App.errorBoundary.test.tsx — the shell never white-screens.
//
// The regression this pins actually happened: a contract slip in
// Security → Detection Rules threw during render, nothing caught it, React
// unmounted the tree and the operator got a blank page — no route, no wording,
// nothing to report. The shell now wraps the route render in a boundary, so a
// throwing route degrades to a named panel WITH the rest of the console (rail,
// top bar, drawers, the main landmark) still on screen.
//
// The shell's own chrome is mocked away: this test is about one thing — what
// the operator sees when the ROUTE throws.

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";

// A one-leaf nav whose only route throws. Built INSIDE the factory: vi.mock is
// hoisted above every top-level binding in this file.
vi.mock("./nav", async () => {
  const { createElement } = await import("react");
  // The real shape of the failure: the PAGE throws while rendering.
  const BrokenPage = () => {
    throw new Error("rules.map is not a function");
  };
  const leaf = { id: "rules", label: "Detection Rules", render: () => createElement(BrokenPage) };
  // And the rarer one: the leaf's own render thunk throws while building the
  // element — above the page, inside App's render. Both must be caught.
  const thunkLeaf = {
    id: "thunk",
    label: "Saved Views",
    render: () => {
      throw new Error("views.filter is not a function");
    },
  };
  const section = { id: "security", label: "Security", icon: "shield", children: [leaf, thunkLeaf] };
  return {
    NAV: [section],
    ROUTE_CHUNKS: {},
    filteredNav: () => [section],
    resolveRoute: (hash: string) => ({ section, leaf: hash.includes("thunk") ? thunkLeaf : leaf }),
    resolveResourceRoute: () => null,
    landingResolves: () => false,
    routeFor: () => "security/rules",
    canonicalHash: () => null,
  };
});

// No network from a unit test: the shell polls health and the display setting
// on mount, and an unmocked fetch turns the run into a wall of ECONNREFUSED.
vi.mock("./services/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./services/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      health: async () => ({ status: "ok" }),
      getDisplaySettings: async () => ({ time_display: "local" }),
    },
  };
});

vi.mock("./hooks/useAuth", () => ({
  useAuth: () => ({
    user: { username: "operator", platform_admin: false, auth_source: "local" },
    loading: false,
    refresh: () => {},
    logout: () => {},
  }),
}));

// Shell chrome — not under test, and each piece would otherwise reach for the API.
vi.mock("./components/TopBar", () => ({ default: () => <div>top bar</div> }));
vi.mock("./components/Sidebar", () => ({ default: () => null }));
vi.mock("./components/IconRail", () => ({ default: () => <div>icon rail</div> }));
vi.mock("./components/SubNav", () => ({ default: () => null }));
vi.mock("./components/ScopeBadge", () => ({ default: () => null }));
vi.mock("./components/OpsisDrawer", () => ({ default: () => null }));
vi.mock("./components/HelpDrawer", () => ({ default: () => null }));
vi.mock("./components/CommandPalette", () => ({ default: () => null }));
vi.mock("./components/Inspector", () => ({ default: () => null }));
vi.mock("./components/BottomDrawer", () => ({ default: () => null }));
vi.mock("./components/ChangePasswordCard", () => ({ default: () => null }));
vi.mock("./pages/Login", () => ({ default: () => <div>sign in</div> }));
vi.mock("./components/TenantGate", () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

import App from "./App";

let consoleSpy: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  consoleSpy.mockRestore();
  cleanup();
});

describe("shell — a route that throws degrades instead of blanking", () => {
  it("renders the boundary panel, named for the route, and keeps the shell", () => {
    render(<App />);

    // What the operator sees INSTEAD of a white page.
    expect(screen.getByRole("alert")).toBeTruthy();
    expect(screen.getByText("Detection Rules could not be displayed")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reload this page" })).toBeTruthy();

    // …and the console is still a console: chrome and the main landmark stand.
    expect(screen.getByText("icon rail")).toBeTruthy();
    expect(screen.getByText("top bar")).toBeTruthy();
    expect(document.getElementById("main-content")).toBeTruthy();
  });

  it("shows the route's own crumb, so the failure is locatable", () => {
    render(<App />);
    expect(screen.getAllByText("Security").length).toBeGreaterThan(0);
  });

  it("puts no stack on the screen", () => {
    render(<App />);
    const shown = screen.getByRole("alert").textContent ?? "";
    expect(shown).not.toMatch(/\bat \w+ \(/);
    expect(shown).not.toContain("componentStack");
  });

  it("catches a leaf whose render thunk throws while building the element", () => {
    location.hash = "#/security/thunk";
    render(<App />);
    expect(screen.getByText("Saved Views could not be displayed")).toBeTruthy();
    expect(document.getElementById("main-content")).toBeTruthy();
    location.hash = "";
  });
});
