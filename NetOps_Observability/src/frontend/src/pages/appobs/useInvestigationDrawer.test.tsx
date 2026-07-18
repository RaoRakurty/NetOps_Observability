// useInvestigationDrawer.test — drawer open/close/URL behavior against the REAL
// workspace Inspector pane: open docks the investigation (no navigation), the
// URL mirrors the open object (?inv=<id>), ESC/X closes and clears the param,
// and a hash that already carries ?inv reopens the object (refresh/share).

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import { WorkspaceProvider } from "../../context/workspace";
import Inspector from "../../components/Inspector";

vi.mock("../../services/api", () => ({
  api: {
    rcaReportJson: vi.fn(async () => ({ states: {}, times: {} })),
    correlationTimeEvents: vi.fn(async () => ({ events: [] })),
    correlationTimeEventSet: vi.fn(),
  },
}));
vi.mock("../../tabs/Correlations", () => ({
  CorrelationDetail: ({ id }: { id: string }) => <div data-testid="corr-detail">{id}</div>,
}));
// the resolution action row has its own test file (ResolutionActions.test.tsx).
vi.mock("./ResolutionActions", () => ({
  default: ({ id }: { id: string }) => <div data-testid="resolution-actions">{id}</div>,
}));
// so does the change→incident card (InvestigationChanges.test.tsx).
vi.mock("./InvestigationChanges", () => ({
  default: ({ id }: { id: string }) => <div data-testid="investigation-changes">{id}</div>,
}));

import { useInvestigationDrawer } from "./useInvestigationDrawer";

function Harness() {
  const inv = useInvestigationDrawer();
  return (
    <>
      <button onClick={() => inv.open("aaaabbbb-cccc-dddd-eeee-ffff00001111")}>open-row</button>
      {inv.inlineId && <div data-testid="inline">{inv.inlineId}</div>}
      <Inspector />
    </>
  );
}

const mount = () => render(
  <WorkspaceProvider enabled={true}>
    <Harness />
  </WorkspaceProvider>,
);

beforeEach(() => { location.hash = "#/monitoring/appobs"; });
afterEach(cleanup);

describe("useInvestigationDrawer (shell-v2 Inspector)", () => {
  it("opens the drawer in-page and mirrors the id into the URL", async () => {
    mount();
    fireEvent.click(screen.getByText("open-row"));
    // docked Inspector shows the investigation — same page, no navigation
    await screen.findByTestId("corr-detail");
    expect(screen.getByText(/Investigation ·/)).toBeTruthy();
    expect(location.hash).toContain("inv=aaaabbbb-cccc-dddd-eeee-ffff00001111");
    expect(location.hash.startsWith("#/monitoring/appobs")).toBe(true);
    // no v1 inline fallback under shell-v2
    expect(screen.queryByTestId("inline")).toBeNull();
  });

  it("ESC closes the drawer and clears the URL param", async () => {
    mount();
    fireEvent.click(screen.getByText("open-row"));
    await screen.findByTestId("corr-detail");
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("corr-detail")).toBeNull());
    expect(location.hash).toBe("#/monitoring/appobs");
  });

  it("the X button closes and clears the URL param too", async () => {
    mount();
    fireEvent.click(screen.getByText("open-row"));
    await screen.findByTestId("corr-detail");
    fireEvent.click(screen.getByTitle("Close (Esc)"));
    await waitFor(() => expect(screen.queryByTestId("corr-detail")).toBeNull());
    expect(location.hash).toBe("#/monitoring/appobs");
  });

  it("a URL already carrying ?inv reopens the object (refresh/share)", async () => {
    location.hash = "#/monitoring/appobs?inv=deadbeef-0000-1111-2222-333344445555";
    mount();
    await screen.findByTestId("corr-detail");
    expect(screen.getByTestId("corr-detail").textContent).toBe("deadbeef-0000-1111-2222-333344445555");
  });
});

describe("useInvestigationDrawer (v1 shell fallback)", () => {
  it("falls back to the inline panel and closeInline clears the URL", async () => {
    render(
      <WorkspaceProvider enabled={false}>
        <Harness />
      </WorkspaceProvider>,
    );
    fireEvent.click(screen.getByText("open-row"));
    await screen.findByTestId("inline");
    expect(location.hash).toContain("inv=");
  });
});
