// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisTimeline.test.tsx — ordering, restrained accents (with words), honest
// handling of undated events, drill-down, safe links and hostile text.

import { describe, it, expect, afterEach, vi } from "vitest";
import { render, screen, cleanup, fireEvent, within } from "@testing-library/react";
import IrisTimeline, { accentForHighlight, type TimelineEvent } from "./IrisTimeline";
import { HOSTILE } from "../test/irisFixtures";

afterEach(cleanup);

const ev = (over: Partial<TimelineEvent>): TimelineEvent => ({ id: "e", ts: "2026-09-20T10:00:00Z", label: "event", ...over });

describe("IrisTimeline", () => {
  it("orders events oldest first with a machine-readable time", () => {
    render(
      <IrisTimeline
        events={[ev({ id: "b", ts: "2026-09-20T11:00:00Z", label: "second" }), ev({ id: "a", ts: "2026-09-20T10:00:00Z", label: "first" })]}
      />,
    );
    const items = within(screen.getByRole("list", { name: "Timeline" })).getAllByRole("listitem");
    expect(items.map((i) => i.querySelector(".iris-tl-label")?.textContent)).toEqual(["first", "second"]);
    expect(items[0].querySelector("time")?.getAttribute("datetime")).toBe("2026-09-20T10:00:00.000Z");
    expect(screen.getByText("2 events · oldest first")).toBeInTheDocument();
  });

  it("accents only the allowed moments, each with a word, and leaves others neutral", () => {
    render(
      <IrisTimeline
        events={[
          ev({ id: "1", label: "cause", accent: "cause" }),
          ev({ id: "2", label: "start", accent: "start", ts: "2026-09-20T10:01:00Z" }),
          ev({ id: "3", label: "back", accent: "recovery", ts: "2026-09-20T10:02:00Z" }),
          ev({ id: "4", label: "plain", ts: "2026-09-20T10:03:00Z" }),
        ]}
      />,
    );
    expect(screen.getByText("Root cause")).toBeInTheDocument();
    expect(screen.getByText("Incident start")).toBeInTheDocument();
    expect(screen.getByText("Recovery")).toBeInTheDocument();
    const plain = screen.getByText("plain").closest("li") as HTMLElement;
    expect(plain.className).toBe("iris-tl-item");
    expect(plain.querySelector(".iris-tl-tag")).toBeNull();
  });

  it("maps plan highlights to accents", () => {
    expect(accentForHighlight("root_cause")).toBe("cause");
    expect(accentForHighlight("critical_change")).toBe("critical");
    expect(accentForHighlight("incident_start")).toBe("start");
    expect(accentForHighlight("recovery")).toBe("recovery");
    expect(accentForHighlight("high_confidence")).toBe("evidence");
    expect(accentForHighlight(undefined)).toBeUndefined();
  });

  it("does not invent a time: undated events are left off and counted", () => {
    render(<IrisTimeline events={[ev({ id: "a" }), ev({ id: "b", ts: "not a time" }), ev({ id: "c", ts: "" })]} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(1);
    expect(screen.getByText(/2 events have no recorded time/)).toBeInTheDocument();
  });

  it("empty and all-undated states are stated, not blank", () => {
    const { rerender } = render(<IrisTimeline events={[]} />);
    expect(screen.getByRole("status")).toHaveTextContent("No events in this window.");
    rerender(<IrisTimeline events={[ev({ ts: "bogus" })]} />);
    expect(screen.getByRole("status")).toHaveTextContent(/No event in this answer has a recorded time/);
  });

  it("an event opens its detail when selectable", () => {
    const onSelect = vi.fn();
    render(<IrisTimeline events={[ev({ id: "x", label: "open me" })]} onSelect={onSelect} />);
    fireEvent.click(screen.getByRole("button", { name: /open me/ }));
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ id: "x" }));
  });

  it("links an entity through the safe map, and never links an unknown kind", () => {
    render(
      <IrisTimeline
        events={[
          ev({ id: "1", label: "inc", link: { kind: "incident", id: "abc" } }),
          ev({ id: "2", label: "weird", link: { kind: "javascript", id: "alert(1)" }, ts: "2026-09-20T10:01:00Z" }),
        ]}
      />,
    );
    expect(screen.getByRole("link", { name: /inc/ })).toHaveAttribute("href", "/#/investigate/rca?id=abc");
    expect(screen.queryByRole("link", { name: /weird/ })).toBeNull();
  });

  it("renders hostile labels as text", () => {
    const { container } = render(<IrisTimeline events={[ev({ label: HOSTILE, detail: HOSTILE })]} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain(HOSTILE);
  });
});
