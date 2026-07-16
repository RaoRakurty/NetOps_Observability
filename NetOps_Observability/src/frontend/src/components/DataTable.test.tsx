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
