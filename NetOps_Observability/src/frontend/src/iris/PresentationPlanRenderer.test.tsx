// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// PresentationPlanRenderer.test.tsx — the plan renderer end to end: every view
// of the closed enum renders, malformed plans fall back safely, hostile input is
// inert, empty/truncated/adjusted answers are stated, drill-down has no dead end.

import { describe, it, expect, afterEach, vi, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, within, act } from "@testing-library/react";
import type { EChartEvents } from "../components/EChart";

const captured: { option: Record<string, unknown>; onEvents?: EChartEvents }[] = [];
vi.mock("../components/EChart", () => ({
  default: (props: { option: Record<string, unknown>; onEvents?: EChartEvents }) => {
    captured.push(props);
    return <div data-testid="chart" />;
  },
}));

import PresentationPlanRenderer from "./PresentationPlanRenderer";
import { VIEW_TYPES } from "./presentation";
import { HOSTILE, HOSTILE_IMG, baseResult, changeRow, compareResult, incidentResult, seriesResult } from "../test/irisFixtures";

beforeEach(() => {
  captured.length = 0;
});
afterEach(cleanup);

const changes = () => baseResult({ rows: [changeRow(), changeRow({ change_id: "chg-2", time: "2026-09-20T11:00:00Z", actor: "bob" })] });

describe("PresentationPlanRenderer — contract", () => {
  it("renders every view in the closed enum without throwing", () => {
    for (const v of VIEW_TYPES) {
      const { unmount } = render(<PresentationPlanRenderer result={changes()} plan={{ primary_view: v, title: `view ${v}` }} />);
      expect(screen.getByRole("region", { name: `view ${v}` })).toBeInTheDocument();
      unmount();
    }
  });

  it("a malformed plan falls back to SUMMARY as escaped text", () => {
    const { container } = render(<PresentationPlanRenderer result={changes()} plan={{ primary_view: "<iframe>", title: HOSTILE }} />);
    expect(screen.getByText(/shown as a plain summary because its layout was not recognised/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: HOSTILE })).toBeInTheDocument();
    expect(container.querySelector("script, iframe")).toBeNull();
    expect(screen.getByText("2 rows found")).toBeInTheDocument();
  });

  it("a non-object plan falls back to SUMMARY", () => {
    render(<PresentationPlanRenderer result={changes()} plan={"TABLE"} />);
    expect(screen.getByRole("heading", { name: "Answer" })).toBeInTheDocument();
    expect(screen.getByText("2 rows found")).toBeInTheDocument();
  });

  it("an unreadable result is an honest alert, not a blank", () => {
    render(<PresentationPlanRenderer result={"<b>boom</b>"} />);
    expect(screen.getByRole("alert")).toHaveTextContent("The answer could not be read.");
  });

  it("without a plan, chooses the view from the question shape", () => {
    render(<PresentationPlanRenderer result={changes()} />);
    expect(screen.getByRole("heading", { name: "Changes in this window" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Changes in this window" })).toBeInTheDocument(); // timeline
    expect(screen.getByRole("grid", { name: "Changes" })).toBeInTheDocument(); // table
  });

  it("never uses an HTML sink for hostile row values or hrefs", () => {
    const { container } = render(
      <PresentationPlanRenderer
        result={baseResult({
          rows: [changeRow({ actor: HOSTILE, object: HOSTILE_IMG, site: "javascript:alert(1)", summary: HOSTILE })],
          notes: [HOSTILE],
        })}
        plan={{ primary_view: "TABLE", secondary_view: "TIMELINE", title: "t" }}
      />,
    );
    expect(container.querySelector("script, img, iframe")).toBeNull();
    for (const a of Array.from(container.querySelectorAll("a"))) {
      const href = a.getAttribute("href") ?? "";
      expect(href.startsWith("/")).toBe(true);
      expect(href.startsWith("//")).toBe(false);
      expect(href.toLowerCase()).not.toContain("javascript:");
    }
    expect(container.textContent).toContain(HOSTILE);
  });
});

describe("PresentationPlanRenderer — honest states", () => {
  it("an empty result says 'Nothing found in this window' — never a blank chart", () => {
    render(<PresentationPlanRenderer result={seriesResult({ series: [] })} plan={{ primary_view: "TIME_SERIES", secondary_view: "TABLE", title: "t" }} />);
    expect(screen.getByRole("status")).toHaveTextContent(/^Nothing found in this window \(.+\)\.$/);
    expect(screen.queryByTestId("chart")).toBeNull();
    expect(screen.queryByRole("grid")).toBeNull();
  });

  it("a truncated answer shows a visible notice", () => {
    render(<PresentationPlanRenderer result={baseResult({ rows: [changeRow()], truncated: true })} />);
    expect(screen.getByText(/Partial answer — more matched than could be shown/)).toBeInTheDocument();
  });

  it("states every bound the validator tightened, and the server's notes", () => {
    render(
      <PresentationPlanRenderer
        result={baseResult({
          rows: [changeRow()],
          constraints_applied: [{ path: "limit", from: "10000", to: "500", reason: "row limit" }],
          notes: ["correlated in time, not established as causes"],
        })}
      />,
    );
    expect(screen.getByRole("list", { name: "Adjustments" })).toHaveTextContent("Adjusted Limit from 10000 to 500 — row limit");
    expect(screen.getByRole("list", { name: "Notes" })).toHaveTextContent("correlated in time, not established as causes");
  });

  it("an unmeasured value in a table is 'Not measured', not 0", () => {
    render(<PresentationPlanRenderer result={compareResult()} plan={{ primary_view: "TABLE", title: "t" }} />);
    const grid = screen.getByRole("grid");
    const nyc = within(grid).getAllByRole("row").find((r) => r.textContent?.includes("NYC")) as HTMLElement;
    expect(nyc).toHaveTextContent("Not measured");
    expect(within(nyc).queryByText("0")).toBeNull();
  });

  it("an explained incident renders its card and the engine's evidence", () => {
    render(<PresentationPlanRenderer result={incidentResult()} />);
    expect(screen.getByRole("article", { name: "Incident" })).toBeInTheDocument();
    expect(screen.getByText("Evidence found")).toBeInTheDocument();
    expect(screen.getByText("Interface ge-0/0/1 went down at 10:31")).toBeInTheDocument();
  });

  it("a recommendation always says no action was executed", () => {
    render(<PresentationPlanRenderer result={baseResult({ query_type: null, detail: { title: "Next", steps: ["a"] } })} plan={{ primary_view: "RECOMMENDATION_CARD", title: "r" }} />);
    expect(screen.getByText("No action has been executed.")).toBeInTheDocument();
  });

  it("TOPOLOGY/PATH say plainly that no map is available and list the entities as links", () => {
    render(
      <PresentationPlanRenderer
        result={baseResult({ rows: [changeRow()], provenance: { source: "x", executed_at: "", entities: [{ type: "device", id: "r1" }] } })}
        plan={{ primary_view: "PATH", title: "p" }}
      />,
    );
    expect(screen.getByText(/A path view is not available for this answer/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "r1" })).toHaveAttribute("href", "/#/infrastructure/devices?q=r1");
  });

  it("DIFF uses the recorded before/after, and says so when there is none", () => {
    const { unmount } = render(<PresentationPlanRenderer result={baseResult({ rows: [changeRow({ before: '{"mtu":1500}', after: '{"mtu":9000}' })] })} />);
    expect(screen.getByRole("table", { name: /side by side/ })).toBeInTheDocument();
    unmount();
    render(<PresentationPlanRenderer result={baseResult({ rows: [changeRow()] })} plan={{ primary_view: "DIFF", title: "d" }} />);
    expect(screen.getByText("No before/after was recorded for this change.")).toBeInTheDocument();
  });

  it("DIFF prefers a server unified diff through the shared view", () => {
    const { container } = render(
      <PresentationPlanRenderer result={baseResult({ rows: [changeRow({ unified: "-a\n+b", added: 1, removed: 1 })] })} plan={{ primary_view: "DIFF", title: "d" }} />,
    );
    expect(container.querySelectorAll(".cfg-diff-line")).toHaveLength(2);
  });
});

describe("PresentationPlanRenderer — no dead ends", () => {
  it("a bar click opens the rows behind it, and Back returns to the chart", () => {
    const onDrill = vi.fn();
    render(<PresentationPlanRenderer result={changes()} hint={{ group_by: ["actor"] }} onDrill={onDrill} />);
    expect(screen.getByRole("heading", { name: "Changes by Actor" })).toBeInTheDocument();
    const bar = captured.find((c) => (c.option.series as { type: string }[])[0]?.type === "bar")!;
    act(() => bar.onEvents!.click({ dataIndex: 0 }));
    expect(onDrill).toHaveBeenCalled();
    expect(screen.getByText(/1 row for/)).toBeInTheDocument();
    expect(screen.getByRole("grid", { name: /Rows for/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Back to the chart" }));
    expect(screen.queryByRole("grid", { name: /Rows for/ })).toBeNull();
  });

  it("a timeline change opens the change drawer", () => {
    render(<PresentationPlanRenderer result={changes()} plan={{ primary_view: "TIMELINE", title: "t" }} />);
    fireEvent.click(screen.getAllByRole("button", { name: /Config change · core-sw-1/ })[0]);
    expect(screen.getByRole("dialog", { name: "Config change · core-sw-1" })).toBeInTheDocument();
  });

  it("every answer has 'Why am I seeing this?'", () => {
    render(<PresentationPlanRenderer result={changes()} />);
    const whys = screen.getAllByRole("button", { name: "Why am I seeing this?" });
    fireEvent.click(whys[whys.length - 1]);
    expect(screen.getByRole("dialog", { name: "Why am I seeing this?" })).toHaveTextContent("Change record");
  });

  it("a generic table row opens its provenance", () => {
    render(<PresentationPlanRenderer result={compareResult()} plan={{ primary_view: "TABLE", title: "t" }} />);
    fireEvent.click(screen.getAllByRole("row")[1]);
    expect(screen.getByRole("dialog", { name: "Why am I seeing this?" })).toHaveTextContent("Metrics store");
  });

  it("highlights only what the plan names, in words", () => {
    render(
      <PresentationPlanRenderer
        result={changes()}
        plan={{ primary_view: "TIMELINE", title: "t", highlight: [{ kind: "critical_change", ids: ["chg-2"] }] }}
      />,
    );
    const tags = screen.getAllByText("Critical change");
    expect(tags).toHaveLength(1);
    expect(tags[0].closest("li")).toHaveTextContent("bob");
  });
});
