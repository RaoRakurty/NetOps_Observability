// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ResultTable.test.tsx — the generic TABLE view: plan columns, bounded
// fallback columns, unmeasured vs unrecorded, safe id links, row → callback.

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import ResultTable, { columnsFor } from "./ResultTable";
import { HOSTILE } from "../test/irisFixtures";

afterEach(cleanup);

describe("columnsFor", () => {
  it("uses the plan's columns that exist, in its order", () => {
    expect(columnsFor([{ a: 1, b: 2, c: 3 }], ["c", "zz", "a"])).toEqual(["c", "a"]);
  });

  it("falls back to the row keys, bounded", () => {
    const row = Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`k${i}`, i]));
    expect(columnsFor([row])).toHaveLength(12);
    expect(columnsFor([{ a: 1 }], ["nope"])).toEqual(["a"]);
  });
});

describe("ResultTable", () => {
  it("says 'Not measured' for a missing measure and 'Not recorded' otherwise", () => {
    render(<ResultTable rows={[{ site: "DFW", value: 1 }, { value: null, site: "" }]} columns={["site", "value"]} />);
    expect(screen.getByText("Not measured")).toBeInTheDocument();
    expect(screen.getByText("Not recorded")).toBeInTheDocument();
    expect(screen.queryByText("0")).toBeNull();
  });

  it("links id fields through the safe map and treats prototype-named fields as plain", () => {
    render(<ResultTable rows={[{ incident_id: "i1", constructor: "x" }]} />);
    expect(screen.getByRole("link", { name: "i1" })).toHaveAttribute("href", "/#/investigate/rca?id=i1");
    expect(screen.getByText("x").tagName).not.toBe("A");
  });

  it("formats a measure with the unit", () => {
    render(<ResultTable rows={[{ device: "r1", value: 12.5 }]} unit="ms" />);
    expect(screen.getByText("12.5 ms")).toBeInTheDocument();
  });

  it("reports row clicks", () => {
    const onRowClick = vi.fn();
    render(<ResultTable rows={[{ device: "r1", value: 1 }]} onRowClick={onRowClick} />);
    fireEvent.click(screen.getAllByRole("row")[1]);
    expect(onRowClick).toHaveBeenCalledWith({ device: "r1", value: 1 });
  });

  it("states an empty table", () => {
    render(<ResultTable rows={[]} />);
    expect(screen.getByRole("status")).toHaveTextContent("Nothing found in this window.");
  });

  it("renders hostile cells as text", () => {
    const { container } = render(<ResultTable rows={[{ device: HOSTILE, note: { html: HOSTILE } }]} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain(HOSTILE);
  });
});
