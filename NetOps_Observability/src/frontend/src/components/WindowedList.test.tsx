import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import WindowedList from "./WindowedList";

// WindowedList's whole reason to exist is that the DOM stays FLAT as the list
// grows. happy-dom does no layout, so every element reports clientHeight 0 and
// the component would window down to its overscan — which would make these
// tests pass on a broken implementation. Report a real viewport instead, the
// same way perf/setup.ts does for the render budgets.
const VIEWPORT = 320;
let restore: PropertyDescriptor | undefined;

beforeAll(() => {
  restore = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientHeight");
  Object.defineProperty(HTMLElement.prototype, "clientHeight", {
    configurable: true,
    get: () => VIEWPORT,
  });
});
afterAll(() => {
  if (restore) Object.defineProperty(HTMLElement.prototype, "clientHeight", restore);
});
afterEach(cleanup);

const ROW_H = 32;
const rows = (n: number) => Array.from({ length: n }, (_, i) => ({ id: `r${i}`, name: `device-${i}` }));

function List({ n, overscan = 8 }: { n: number; overscan?: number }) {
  return (
    <WindowedList
      items={rows(n)}
      rowHeight={ROW_H}
      itemKey={(r) => r.id}
      renderItem={(r) => <button type="button">{r.name}</button>}
      className="wl"
      overscan={overscan}
      role="listbox"
      ariaLabel="Devices"
      empty={<div>No devices.</div>}
    />
  );
}

describe("WindowedList — only the rows in view are in the DOM", () => {
  it("renders the viewport slice plus overscan, not the whole list", () => {
    render(<List n={1000} />);
    // 320px / 32px = 10 visible, + 8 overscan each side (top is clamped at 0).
    const buttons = screen.getAllByRole("button");
    expect(buttons.length).toBeLessThanOrEqual(10 + 8 * 2);
    expect(buttons.length).toBeGreaterThan(0);
    expect(screen.getByText("device-0")).toBeInTheDocument();
    expect(screen.queryByText("device-999")).not.toBeInTheDocument();
  });

  it("keeps the DOM FLAT as the list grows — the property the budget guards", () => {
    const { container, unmount } = render(<List n={50} />);
    const small = container.querySelectorAll("*").length;
    unmount();
    const { container: c2 } = render(<List n={5000} />);
    const large = c2.querySelectorAll("*").length;
    // 100x the data must not mean more DOM. Equal, not merely "similar".
    expect(large).toBe(small);
  });

  it("gives the scroller the FULL list height so the scrollbar is honest", () => {
    const { container } = render(<List n={1000} />);
    const spacer = container.querySelector(".wl > div") as HTMLElement;
    expect(spacer.style.height).toBe(`${1000 * ROW_H}px`);
  });

  it("positions each rendered row at its true index", () => {
    const { container } = render(<List n={1000} />);
    const first = container.querySelectorAll<HTMLElement>(".wl > div > div")[0];
    expect(first.style.transform).toBe("translateY(0px)");
    expect(first.style.height).toBe(`${ROW_H}px`);
  });
});

describe("WindowedList — scrolling moves the window", () => {
  it("renders the rows around the scroll offset, and drops the ones left behind", () => {
    const { container } = render(<List n={1000} />);
    const scroller = container.querySelector(".wl") as HTMLElement;
    fireEvent.scroll(scroller, { target: { scrollTop: 500 * ROW_H } });
    expect(screen.getByText("device-500")).toBeInTheDocument();
    expect(screen.queryByText("device-0")).not.toBeInTheDocument();
  });

  it("resets a scroller parked past the end when the list shrinks", () => {
    const { container, rerender } = render(<List n={1000} />);
    const scroller = container.querySelector(".wl") as HTMLElement;
    fireEvent.scroll(scroller, { target: { scrollTop: 900 * ROW_H } });
    expect(screen.getByText("device-900")).toBeInTheDocument();
    // A filter narrows the list to 5 — without the reset the window would sit
    // past the end and the panel would render blank.
    rerender(<List n={5} />);
    expect(scroller.scrollTop).toBe(0);
    expect(screen.getByText("device-0")).toBeInTheDocument();
  });
});

describe("WindowedList — edges", () => {
  it("renders the empty node inside the still-labelled region, with no rows", () => {
    render(<List n={0} />);
    expect(screen.getByText("No devices.")).toBeInTheDocument();
    // The region KEEPS its role and name so assistive tech can still find and
    // announce it — an empty list is a state, not a missing landmark. What must
    // be gone is the scroller and every row.
    const box = screen.getByRole("listbox", { name: "Devices" });
    expect(box).toBeInTheDocument();
    expect(screen.queryAllByRole("button")).toHaveLength(0);
    expect(box.style.overflowY).toBe("");
  });

  it("renders a short list in full", () => {
    render(<List n={3} />);
    expect(screen.getAllByRole("button")).toHaveLength(3);
  });

  it("exposes the list role and accessible name for assistive tech", () => {
    render(<List n={10} />);
    expect(screen.getByRole("listbox", { name: "Devices" })).toBeInTheDocument();
  });
});
