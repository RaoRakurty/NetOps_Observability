// TopologyDomainTabs.test.tsx — the network-domain tab bar renders all four
// domains + the carrier toggle, and drives its callbacks.

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import TopologyDomainTabs from "./TopologyDomainTabs";

afterEach(cleanup);

describe("TopologyDomainTabs", () => {
  it("renders LAN · SD-WAN · DC · Cloud with the active one selected", () => {
    render(<TopologyDomainTabs value="lan" onChange={() => {}} carrier={false} onToggleCarrier={() => {}} />);
    for (const label of ["LAN", "SD-WAN", "DC", "Cloud"]) {
      expect(screen.getByRole("tab", { name: label })).toBeTruthy();
    }
    expect(screen.getByRole("tab", { name: "LAN" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("tab", { name: "Cloud" }).getAttribute("aria-selected")).toBe("false");
  });

  it("fires onChange when another domain is clicked", () => {
    const onChange = vi.fn();
    render(<TopologyDomainTabs value="lan" onChange={onChange} carrier={false} onToggleCarrier={() => {}} />);
    fireEvent.click(screen.getByRole("tab", { name: "Cloud" }));
    expect(onChange).toHaveBeenCalledWith("cloud");
  });

  it("toggles the carrier overlay", () => {
    const onToggle = vi.fn();
    render(<TopologyDomainTabs value="cloud" onChange={() => {}} carrier={false} onToggleCarrier={onToggle} />);
    const carrier = screen.getByRole("switch", { name: /carrier/i });
    expect(carrier.getAttribute("aria-checked")).toBe("false");
    fireEvent.click(carrier);
    expect(onToggle).toHaveBeenCalledWith(true);
  });
});
