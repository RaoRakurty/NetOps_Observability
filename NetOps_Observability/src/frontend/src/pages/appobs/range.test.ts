// range.test.ts — the time window the cloud views show, and the honesty of what
// they say about it (2026-07 owner review #2).
//
// Acceptance: narrowing filters by real time; "showing N of M" is stated only
// when rows are actually hidden; the presets never exceed the window the backend
// ingests (no 7d button that would silently return 24h); an unreadable stamp is
// never silently dropped.

import { describe, it, expect } from "vitest";
import {
  CLOUD_RANGES, CLOUD_WINDOW_MINUTES, CLOUD_WINDOW_MAX_MINUTES, DEFAULT_CLOUD_RANGE,
  withinRange, filterByRange, newestIso, feedCount, rangeWords, freshnessText, rangeFor,
  windowHoursFor,
} from "./range";

const NOW = Date.UTC(2026, 6, 15, 12, 0, 0);
const agoMin = (m: number) => new Date(NOW - m * 60_000).toISOString();
const row = (m: number) => ({ time: agoMin(m) });

describe("the offered presets", () => {
  it("never exceeds the window the server will honor", () => {
    // /api/cloud/health|changes|evidence take ?window_hours= clamped to 168h
    // (Wave 2 #5): every preset must sit inside that clamp so a selected range
    // is always the range the read actually covered — no label can outrun it.
    for (const r of CLOUD_RANGES) expect(r.minutes).toBeLessThanOrEqual(CLOUD_WINDOW_MAX_MINUTES);
  });
  it("offers 7d now that the server honors it", () => {
    expect(CLOUD_RANGES.some((r) => r.label === "7d" && r.minutes === CLOUD_WINDOW_MAX_MINUTES)).toBe(true);
  });
  it("STILL defaults to the 24h standing window (never the 7d maximum)", () => {
    // first paint pays the standing read, not the widest scan.
    expect(DEFAULT_CLOUD_RANGE.minutes).toBe(CLOUD_WINDOW_MINUTES);
  });
  it("resolves an unknown minute count back to the default", () => {
    expect(rangeFor(99999).minutes).toBe(CLOUD_WINDOW_MINUTES);
    expect(rangeFor(60).label).toBe("1h");
  });
});

describe("windowHoursFor — the server read window a UI range requests", () => {
  it("sub-24h ranges reuse the default 24h fetch (client narrows inside it)", () => {
    expect(windowHoursFor(15)).toBe(24);
    expect(windowHoursFor(60)).toBe(24);
    expect(windowHoursFor(360)).toBe(24);
    expect(windowHoursFor(1440)).toBe(24);
  });
  it("above 24h the window is the real, server-honored range", () => {
    expect(windowHoursFor(CLOUD_WINDOW_MAX_MINUTES)).toBe(168);
  });
  it("never requests past the server clamp", () => {
    expect(windowHoursFor(99 * 24 * 60)).toBe(168);
  });
});

describe("withinRange / filterByRange", () => {
  it("keeps events inside the window and drops those outside it", () => {
    expect(withinRange(agoMin(30), 60, NOW)).toBe(true);
    expect(withinRange(agoMin(90), 60, NOW)).toBe(false);
  });
  it("narrows a 24h feed to the last hour", () => {
    const rows = [row(5), row(30), row(120), row(1000)];
    expect(filterByRange(rows, 60, NOW)).toHaveLength(2);
    expect(filterByRange(rows, 1440, NOW)).toHaveLength(4);
  });
  it("does NOT hide an event whose stamp cannot be read", () => {
    // it cannot be placed in time, so it must stay visible rather than be
    // silently filtered out by a window it was never tested against.
    expect(withinRange("not-a-date", 60, NOW)).toBe(true);
  });
});

describe("newestIso", () => {
  it("finds the most recent stamp — the freshness anchor", () => {
    expect(newestIso([row(120), row(5), row(90)])).toBe(agoMin(5));
  });
  it("is empty for an empty or unreadable feed", () => {
    expect(newestIso([])).toBe("");
    expect(newestIso([{ time: "junk" }])).toBe("");
  });
});

describe("feedCount", () => {
  it("states 'showing N of M' when the range hides rows", () => {
    const c = feedCount(12, 48, 60);
    expect(c.narrowed).toBe(true);
    expect(c.text).toBe("showing 12 of 48 · last 1 hour");
  });
  it("does not add noise when the feed is complete", () => {
    expect(feedCount(48, 48, 1440).text).toBe("48 events · last 24 hours");
    expect(feedCount(48, 48, 1440).narrowed).toBe(false);
  });
  it("keeps the event noun singular for one row", () => {
    expect(feedCount(1, 1, 60).text).toBe("1 event · last 1 hour");
  });
});

describe("rangeWords", () => {
  it("speaks each preset the way an operator would", () => {
    expect(rangeWords(15)).toBe("last 15 min");
    expect(rangeWords(60)).toBe("last 1 hour");
    expect(rangeWords(360)).toBe("last 6 hours");
    expect(rangeWords(1440)).toBe("last 24 hours");
  });
});

describe("freshnessText", () => {
  it("has seconds resolution — the whole point of a liveness cue", () => {
    // ago() in ./badges is minute-resolution and would say "now" for all of these
    expect(freshnessText(NOW - 8_000, NOW)).toBe("updated 8s ago");
    expect(freshnessText(NOW - 45_000, NOW)).toBe("updated 45s ago");
  });
  it("rolls up to minutes and hours", () => {
    expect(freshnessText(NOW - 5 * 60_000, NOW)).toBe("updated 5m ago");
    expect(freshnessText(NOW - 3 * 3600_000, NOW)).toBe("updated 3h ago");
  });
  it("never reports a negative age from clock skew", () => {
    expect(freshnessText(NOW + 5_000, NOW)).toBe("updated 0s ago");
  });
});
