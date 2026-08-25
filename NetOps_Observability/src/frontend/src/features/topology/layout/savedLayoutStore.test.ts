// savedLayoutStore tests — born with the Reset-button fix (2026-08-25).
import { beforeEach, describe, expect, it } from "vitest";
import { clearSavedLayout, clearSavedLayoutsMatching } from "./savedLayoutStore";

beforeEach(() => localStorage.clear());

describe("clearSavedLayoutsMatching (Reset-button fix 2026-08-25)", () => {
  it("sweeps every content-keyed pin-set for the view, leaves other views", () => {
    localStorage.setItem("correlix.topology.layout:v1:elk:sig-a", JSON.stringify({ n1: { x: 1, y: 2 } }));
    localStorage.setItem("correlix.topology.layout:v1:elk:sig-b", JSON.stringify({ n1: { x: 3, y: 4 } }));
    localStorage.setItem("correlix.topology.layout:v2:elk:sig-a", JSON.stringify({ n9: { x: 9, y: 9 } }));
    const removed = clearSavedLayoutsMatching("v1:");
    expect(removed).toBe(2);
    expect(localStorage.getItem("correlix.topology.layout:v1:elk:sig-a")).toBeNull();
    expect(localStorage.getItem("correlix.topology.layout:v1:elk:sig-b")).toBeNull();
    expect(localStorage.getItem("correlix.topology.layout:v2:elk:sig-a")).not.toBeNull();
  });

  it("mutation guard: the old single-key clear leaves stale-signature pins behind", () => {
    localStorage.setItem("correlix.topology.layout:v1:elk:sig-old", JSON.stringify({ n1: { x: 1, y: 2 } }));
    clearSavedLayout("v1:elk:sig-new"); // what Reset used to do after a re-key
    expect(localStorage.getItem("correlix.topology.layout:v1:elk:sig-old")).not.toBeNull();
  });
});
