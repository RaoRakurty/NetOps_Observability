// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// FilterChipBar.test.tsx — editable/removable chips that emit a TYPED change
// event, with no free-text path: only a value the server offered can be sent.

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import FilterChipBar, { sanitizeChips, type FilterChip } from "./FilterChipBar";
import { HOSTILE } from "../test/irisFixtures";

afterEach(cleanup);

const site: FilterChip = {
  id: "f1",
  field: "site",
  label: "Site",
  value: "DFW",
  options: [
    { value: "DFW", label: "Dallas (DFW)" },
    { value: "NYC", label: "New York (NYC)" },
  ],
};

describe("FilterChipBar", () => {
  it("renders chips with their labels and no text input anywhere", () => {
    const { container } = render(<FilterChipBar chips={[site]} onChange={() => {}} />);
    expect(screen.getByRole("list", { name: "Filters on this answer" })).toBeInTheDocument();
    expect(screen.getByText("Site:")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Site: Dallas \(DFW\)\. Change/ })).toBeInTheDocument();
    expect(container.querySelector("input, textarea")).toBeNull();
  });

  it("emits a typed remove event", () => {
    const onChange = vi.fn();
    render(<FilterChipBar chips={[site]} onChange={onChange} />);
    fireEvent.click(screen.getByRole("button", { name: "Remove Site filter" }));
    expect(onChange).toHaveBeenCalledWith({ kind: "remove", id: "f1", field: "site" });
  });

  it("emits a typed set event for an offered value", () => {
    const onChange = vi.fn();
    render(<FilterChipBar chips={[site]} onChange={onChange} />);
    fireEvent.click(screen.getByRole("button", { name: /Change/ }));
    fireEvent.change(screen.getByLabelText("Change Site"), { target: { value: "NYC" } });
    expect(onChange).toHaveBeenCalledWith({ kind: "set", id: "f1", field: "site", value: "NYC" });
  });

  it("never emits a value outside the offered list", () => {
    const onChange = vi.fn();
    render(<FilterChipBar chips={[site]} onChange={onChange} />);
    fireEvent.click(screen.getByRole("button", { name: /Change/ }));
    const select = screen.getByLabelText("Change Site") as HTMLSelectElement;
    // Forge an option (e.g. via devtools) — the bar must still refuse it.
    const forged = document.createElement("option");
    forged.value = "EVIL";
    select.appendChild(forged);
    fireEvent.change(select, { target: { value: "EVIL" } });
    expect(onChange).not.toHaveBeenCalled();
  });

  it("does not emit when the same value is re-selected", () => {
    const onChange = vi.fn();
    render(<FilterChipBar chips={[site]} onChange={onChange} />);
    fireEvent.click(screen.getByRole("button", { name: /Change/ }));
    fireEvent.change(screen.getByLabelText("Change Site"), { target: { value: "DFW" } });
    expect(onChange).not.toHaveBeenCalled();
  });

  it("a required chip cannot be removed; a chip without options is read-only", () => {
    render(<FilterChipBar chips={[{ id: "w", field: "window", label: "Time", value: "1h", removable: false }]} onChange={() => {}} />);
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.getByText("1h")).toBeInTheDocument();
  });

  it("renders nothing for no / malformed chips", () => {
    const { container } = render(<FilterChipBar chips={"nope"} onChange={() => {}} />);
    expect(container.innerHTML).toBe("");
  });

  it("sanitizeChips drops malformed chips, bad field names and duplicate ids; bounds counts", () => {
    const many = Array.from({ length: 30 }, (_, i) => ({ id: `c${i}`, field: "site", label: "S", value: "v" }));
    const chips = sanitizeChips([
      { id: "a", field: "Site Name", value: "x" },
      { id: "b", field: "site", value: 3 },
      { field: "site", value: "x" },
      { id: "ok", field: "site", value: "x", options: [{ value: "y" }, { value: "z", label: "Z" }, "junk"] },
      { id: "ok", field: "site", value: "dup" },
      ...many,
    ]);
    expect(chips[0]).toMatchObject({ id: "ok", options: [{ value: "z", label: "Z" }] });
    expect(chips.length).toBeLessThanOrEqual(12);
    expect(chips.filter((c) => c.id === "ok")).toHaveLength(1);
  });

  it("renders hostile chip text as text", () => {
    const { container } = render(<FilterChipBar chips={[{ id: "h", field: "site", label: HOSTILE, value: HOSTILE }]} onChange={() => {}} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain(HOSTILE);
  });
});
