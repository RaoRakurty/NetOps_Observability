// Exposures.test.tsx — the findings workbench: facet counts, the explicit
// current/history choice, full-text search, cursor pagination, and the Finding
// detail (observed vs intended, evidence ref, remediation, standards chips).

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";

const securityFindings = vi.fn();
const securityFindingFacets = vi.fn();
const securityViews = vi.fn();
const openInspector = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    securityFindings: (...a: unknown[]) => securityFindings(...a),
    securityFindingFacets: (...a: unknown[]) => securityFindingFacets(...a),
    securityViews: (...a: unknown[]) => securityViews(...a),
  },
}));
vi.mock("../../context/workspace", () => ({
  useWorkspace: () => ({ enabled: true, openInspector }),
}));

import Exposures, { buildQuery } from "./Exposures";
import { FACETS, FINDINGS, PAGE_1, PAGE_2, VIEWS } from "./fixtures";

afterEach(cleanup);

beforeEach(() => {
  securityFindings.mockReset(); securityFindingFacets.mockReset();
  securityViews.mockReset(); openInspector.mockReset();
  securityFindings.mockResolvedValue({ items: FINDINGS, next_cursor: null, total: FINDINGS.length });
  securityFindingFacets.mockResolvedValue(FACETS);
  securityViews.mockResolvedValue(VIEWS);
});

const lastQuery = () => securityFindings.mock.calls[securityFindings.mock.calls.length - 1][0];

describe("buildQuery", () => {
  it("carries every set filter and the explicit current flag", () => {
    expect(buildQuery({ severity: "high", seam: "ISP", q: "telnet" }, "current"))
      .toEqual({ limit: 100, severity: "high", seam: "ISP", q: "telnet", current: true });
  });

  it("history mode sends current=false, not an omitted flag", () => {
    expect(buildQuery({}, "history")).toEqual({ limit: 100, current: false });
  });

  it("threads a cursor without disturbing the filters", () => {
    expect(buildQuery({ severity: "low" }, "current", "cur-2"))
      .toEqual({ limit: 100, severity: "low", cursor: "cur-2", current: true });
  });
});

describe("Exposures — facets", () => {
  it("renders every facet group with the server's counts", async () => {
    render(<Exposures />);
    await screen.findByRole("button", { name: /^Critical 2$/ });
    expect(screen.getByRole("button", { name: /^Fail 4$/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^ISP 2$/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^CIS 3$/ })).toBeTruthy();
    // The evidence lane is a READ-ONLY breakdown (the read API has no lane
    // filter), so it must not be exposed as a clickable toggle.
    const lanes = screen.getByRole("heading", { name: "Evidence lane" }).parentElement!;
    expect(within(lanes).getByText("Hardening & posture")).toBeTruthy();
    expect(within(lanes).getByText("3")).toBeTruthy();
    expect(within(lanes).queryByRole("button")).toBeNull();
  });

  it("a facet click re-queries with that filter and marks the toggle pressed", async () => {
    render(<Exposures />);
    fireEvent.click(await screen.findByRole("button", { name: /^Critical 2$/ }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ severity: "critical", current: true }));
    expect(screen.getByRole("button", { name: /^Critical 2$/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("clicking the selected facet again clears it", async () => {
    render(<Exposures />);
    const crit = await screen.findByRole("button", { name: /^Critical 2$/ });
    fireEvent.click(crit);
    await waitFor(() => expect(lastQuery().severity).toBe("critical"));
    fireEvent.click(screen.getByRole("button", { name: /^Critical 2$/ }));
    await waitFor(() => expect(lastQuery().severity).toBeUndefined());
  });

  it("a zero-count facet is disabled rather than offering an empty search", async () => {
    render(<Exposures />);
    expect((await screen.findByRole("button", { name: /^Low 0$/ })).hasAttribute("disabled")).toBe(true);
  });
});

describe("Exposures — current vs history", () => {
  it("opens on current verdicts and says so", async () => {
    render(<Exposures />);
    await waitFor(() => expect(lastQuery().current).toBe(true));
    expect(screen.getByText(/latest verdict per check/i)).toBeTruthy();
  });

  it("switching to history re-queries with current=false and labels superseded rows", async () => {
    render(<Exposures />);
    await waitFor(() => expect(securityFindings).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "Full history" }));
    await waitFor(() => expect(lastQuery().current).toBe(false));
    expect(screen.getByText(/including superseded ones/i)).toBeTruthy();
  });
});

describe("Exposures — search + pagination", () => {
  it("submits the full-text query to the server", async () => {
    render(<Exposures />);
    await waitFor(() => expect(securityFindings).toHaveBeenCalled());
    fireEvent.change(screen.getByLabelText("Search findings"), { target: { value: "  telnet  " } });
    fireEvent.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(lastQuery().q).toBe("telnet"));
  });

  it("follows the cursor and appends the next page without re-fetching facets", async () => {
    securityFindings.mockResolvedValueOnce(PAGE_1).mockResolvedValueOnce(PAGE_2);
    render(<Exposures />);
    expect(await screen.findByText(/3 of 6 shown/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await waitFor(() => expect(screen.getByText(/6 of 6 shown/)).toBeTruthy());
    expect(securityFindings.mock.calls[1][0].cursor).toBe("cur-2");
    expect(securityFindingFacets).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "All rows loaded" })).toBeTruthy();
  });

  it("an empty result names the filters that emptied it", async () => {
    securityFindings.mockResolvedValue({ items: [], next_cursor: null, total: 0 });
    render(<Exposures />);
    fireEvent.click(await screen.findByRole("button", { name: /^Critical 2$/ }));
    expect(await screen.findByText(/No finding matches severity critical/i)).toBeTruthy();
  });

  it("an unfiltered empty result says nothing was assessed, not that the estate is clear", async () => {
    securityFindings.mockResolvedValue({ items: [], next_cursor: null, total: 0 });
    render(<Exposures />);
    expect(await screen.findByText(/nothing was assessed — not that the estate is clear/i)).toBeTruthy();
  });
});

describe("Exposures — Inspector detail", () => {
  it("opens the Finding detail with observed vs intended, evidence and standards", async () => {
    render(<Exposures />);
    fireEvent.click((await screen.findAllByText("Telnet on VTY — ISP seam"))[0]);
    await waitFor(() => expect(openInspector).toHaveBeenCalled());
    const [node, meta] = openInspector.mock.calls[0];
    expect(meta.title).toBe("Telnet on VTY — ISP seam");
    cleanup();
    render(node as JSX.Element);
    expect(screen.getByRole("heading", { name: "Observed", level: 4 })).toBeTruthy();
    expect(screen.getByText(/no access-class on vty/)).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Intended", level: 4 })).toBeTruthy();
    expect(screen.getByText("transport input ssh")).toBeTruthy();
    expect(screen.getByText("netops-secfindings-acme-2026.09.01/doc-1")).toBeTruthy();
    expect(screen.getByText("netrule-v3")).toBeTruthy();
    const chips = screen.getByRole("heading", { name: "Standards", level: 4 }).parentElement!;
    expect(within(chips).getByText("CIS")).toBeTruthy();
    expect(within(chips).getByText("NIST-CSF")).toBeTruthy();
  });

  it("a NotApplicable verdict reads Unassessed and states what is missing", async () => {
    securityFindings.mockResolvedValue({ items: [FINDINGS[3]], next_cursor: null, total: 1 });
    render(<Exposures />);
    fireEvent.click(await screen.findByText("AAA / TACACS+ posture"));
    await waitFor(() => expect(openInspector).toHaveBeenCalled());
    cleanup();
    render(openInspector.mock.calls[0][0] as JSX.Element);
    expect(screen.getAllByText("Unassessed").length).toBeGreaterThan(0);
    expect(screen.getByText(/cannot be replayed against the raw artifact/i)).toBeTruthy();
    expect(screen.getByText("untagged")).toBeTruthy();
    expect(screen.getAllByText("not recorded").length).toBe(2);
  });
});

describe("Exposures — saved views", () => {
  it("applies a saved view's filters and its current/history choice", async () => {
    render(<Exposures />);
    const select = await screen.findByLabelText("Saved view");
    fireEvent.change(select, { target: { value: "v2" } });
    await waitFor(() => expect(lastQuery().current).toBe(false));
  });
});
