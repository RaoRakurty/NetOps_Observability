// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// a11y.test.tsx — Wave 6 #19 keyboard + WCAG 2.2 AA pass: pins the accessible
// semantics of the shared primitives so regressions surface in CI.
//  · Modal        — dialog role, Escape close, Tab focus containment
//  · Segmented    — toggle-button group (aria-pressed), not a bare tablist
//  · DataTable    — keyboard-sortable headers, aria-activedescendant,
//                   aria-selected on the selected row

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { Modal, Segmented } from "./ui";
import DataTable from "./DataTable";

afterEach(cleanup);

describe("Modal a11y contract", () => {
  it("renders role=dialog aria-modal with the title as accessible name", () => {
    render(<Modal title="Export limits" onClose={() => {}}><button>One</button></Modal>);
    const dlg = screen.getByRole("dialog", { name: "Export limits" });
    expect(dlg.getAttribute("aria-modal")).toBe("true");
  });

  it("closes on Escape", () => {
    const onClose = vi.fn();
    render(<Modal title="T" onClose={onClose}><button>One</button></Modal>);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("contains Tab focus: wraps from the last focusable back to the first", () => {
    render(
      <Modal title="T" onClose={() => {}}>
        <button>First</button>
        <button>Last</button>
      </Modal>,
    );
    const last = screen.getByRole("button", { name: "Last" });
    last.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    // The close button (header) is the first focusable inside the dialog.
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Close" }));
  });
});

describe("Segmented a11y contract", () => {
  it("is a labelled toggle group with aria-pressed on the active option", () => {
    render(
      <Segmented
        value="b"
        ariaLabel="View"
        options={[{ value: "a", label: "Alpha" }, { value: "b", label: "Beta" }]}
        onChange={() => {}}
      />,
    );
    expect(screen.getByRole("group", { name: "View" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Alpha" }).getAttribute("aria-pressed")).toBe("false");
    expect(screen.getByRole("button", { name: "Beta" }).getAttribute("aria-pressed")).toBe("true");
    // Deliberately NOT an ARIA tablist: no tabpanel/roving-focus wiring exists.
    expect(screen.queryByRole("tablist")).toBeNull();
  });
});

interface Row { name: string; n: number }
const rows: Row[] = [
  { name: "bravo", n: 2 },
  { name: "alpha", n: 3 },
];

describe("DataTable a11y contract", () => {
  it("exposes the active row via aria-activedescendant and sorts from the keyboard", () => {
    render(
      <DataTable<Row>
        rows={rows}
        rowKey={(r) => r.name}
        ariaLabel="t"
        rowSelected={(r) => r.name === "alpha"}
        columns={[{ key: "name", header: "Name", sortValue: (r) => r.name, render: (r) => r.name }]}
      />,
    );
    const grid = screen.getByRole("grid", { name: "t" });
    const activeId = grid.getAttribute("aria-activedescendant");
    expect(activeId).toBeTruthy();
    expect(document.getElementById(activeId!)?.getAttribute("role")).toBe("row");

    // Selection is exposed to AT, not only via the highlight class (1.4.1).
    const selected = screen.getAllByRole("row").filter((r) => r.getAttribute("aria-selected") === "true");
    expect(selected).toHaveLength(1);
    expect(selected[0].textContent).toContain("alpha");

    // Sortable header is focusable and toggles with Enter (2.1.1).
    const header = screen.getByRole("columnheader", { name: /Name/ });
    expect(header.getAttribute("tabindex")).toBe("0");
    fireEvent.keyDown(header, { key: "Enter" });
    expect(header.getAttribute("aria-sort")).toBe("ascending");
    fireEvent.keyDown(header, { key: "Enter" });
    expect(header.getAttribute("aria-sort")).toBe("descending");
  });
});
