// DataTable.test.tsx — the shared table primitive powers the Cloud Service View
// UX fixes (2026-07): every data column is click-to-sort with a visible arrow
// (defect #2), the column-resize handle now renders a VISIBLE, focusable grip
// (defect #3), and a row with an onRowClick is a keyboard-operable button
// (defect #4).

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent, within } from "@testing-library/react";
import DataTable from "./DataTable";

afterEach(cleanup);

interface Row { name: string; n: number }
const rows: Row[] = [
  { name: "bravo", n: 2 },
  { name: "alpha", n: 3 },
  { name: "charlie", n: 1 },
];

function renderTable(onRowClick?: (r: Row) => void) {
  return render(
    <DataTable<Row>
      rows={rows}
      rowKey={(r) => r.name}
      ariaLabel="test table"
      onRowClick={onRowClick}
      columns={[
        { key: "name", header: "Name", sortValue: (r) => r.name, render: (r) => r.name },
        { key: "n", header: "Count", sortValue: (r) => r.n, render: (r) => r.n },
      ]}
    />,
  );
}

describe("DataTable sorting (defect #2)", () => {
  it("marks data columns sortable and toggles asc/desc with an aria-sort indicator", () => {
    renderTable();
    const nameHeader = screen.getByRole("columnheader", { name: /Name/ });
    // Column carries the sortable affordance + the neutral arrow glyph.
    expect(nameHeader.className).toContain("sortable");
    expect(nameHeader.textContent).toContain("↕");

    fireEvent.click(nameHeader);
    expect(nameHeader.getAttribute("aria-sort")).toBe("ascending");
    let firstCell = within(screen.getAllByRole("row")[1]).getAllByRole("gridcell")[0];
    expect(firstCell.textContent).toBe("alpha");

    fireEvent.click(nameHeader);
    expect(nameHeader.getAttribute("aria-sort")).toBe("descending");
    firstCell = within(screen.getAllByRole("row")[1]).getAllByRole("gridcell")[0];
    expect(firstCell.textContent).toBe("charlie");
  });
});

describe("DataTable resize handle (defect #3)", () => {
  it("renders a focusable, labeled resize separator with a visible grip", () => {
    const { container } = renderTable();
    const sep = screen.getAllByRole("separator")[0];
    expect(sep.getAttribute("aria-label")).toMatch(/Resize .* column/);
    expect(sep.getAttribute("tabindex")).toBe("0");           // keyboard-focusable
    expect(container.querySelector(".dtv-resize-grip")).toBeTruthy(); // visible mark
  });
  it("keyboard ←/→ on the handle resizes without throwing", () => {
    renderTable();
    const sep = screen.getAllByRole("separator")[0];
    expect(() => {
      fireEvent.keyDown(sep, { key: "ArrowRight" });
      fireEvent.keyDown(sep, { key: "ArrowLeft" });
    }).not.toThrow();
  });
});

describe("DataTable row drill-in (defect #4)", () => {
  it("fires onRowClick and exposes rows as clickable", () => {
    const onRowClick = vi.fn();
    renderTable(onRowClick);
    const firstRow = screen.getAllByRole("row")[1];
    expect(firstRow.className).toContain("clickable");
    fireEvent.click(firstRow);
    expect(onRowClick).toHaveBeenCalledTimes(1);
  });
});

// ── Opt-in row expansion (master-detail) ────────────────────────────────────────
// Added for the Command Center Action Queue migration (owner review 2026-07): the
// queue's expandable detail row had kept it on a hand-rolled <table>, so it never
// inherited the resize grip or sortable headers. Expansion is now a capability of
// the SHARED primitive instead of a fork. It is strictly opt-in — a table that
// passes neither prop must behave exactly as before.
describe("DataTable row expansion", () => {
  const renderExpandable = (expandedKey: string | null) =>
    render(
      <DataTable<Row>
        rows={rows}
        rowKey={(r) => r.name}
        ariaLabel="expandable table"
        expandedKey={expandedKey}
        renderExpanded={(r) => <div>detail for {r.name}</div>}
        columns={[{ key: "name", header: "Name", sortValue: (r) => r.name, render: (r) => r.name }]}
      />,
    );

  it("renders no detail panel when nothing is expanded", () => {
    renderExpandable(null);
    expect(screen.queryByText(/^detail for/)).toBeNull();
  });

  it("renders the detail panel for the expanded row only", () => {
    renderExpandable("bravo");
    expect(screen.getByText("detail for bravo")).toBeTruthy();
    expect(screen.queryByText("detail for alpha")).toBeNull();
  });

  it("marks the expanded row with aria-expanded", () => {
    const { container } = renderExpandable("bravo");
    const rowsEls = [...container.querySelectorAll(".dtv-row")];
    const expanded = rowsEls.filter((r) => r.getAttribute("aria-expanded") === "true");
    expect(expanded).toHaveLength(1);
    expect(expanded[0].textContent).toContain("bravo");
    expect(expanded[0].className).toContain("dtv-expanded");
  });

  it("stays inert (no aria-expanded) when the consumer opts out", () => {
    const { container } = renderTable();
    expect(container.querySelector(".dtv-row[aria-expanded]")).toBeNull();
    expect(container.querySelector(".dtv-expand-row")).toBeNull();
  });

  it("follows the row through a sort — expansion tracks the KEY, not the index", () => {
    const { container } = renderExpandable("alpha");
    fireEvent.click(screen.getByRole("columnheader", { name: /Name/i })); // sort A→Z
    const expanded = [...container.querySelectorAll(".dtv-row")]
      .filter((r) => r.getAttribute("aria-expanded") === "true");
    expect(expanded).toHaveLength(1);
    expect(expanded[0].textContent).toContain("alpha");
    expect(screen.getByText("detail for alpha")).toBeTruthy();
  });
});
