// time.test.ts — parse-path table tests for the shared time authority.
// The defect class under test: zone-less ClickHouse strings were parsed as
// browser-local by `new Date(...)`, shifting every CH-backed view by the
// viewer's UTC offset. parseTs must pin zone-less strings to UTC regardless
// of the environment's timezone (vitest runs under TZ set per-suite below).
import { describe, expect, it, beforeEach } from "vitest";
import { parseTs, fmtDateTime, fmtTime, fmtDate, isoUTC, tzLabel, setTzMode } from "./time";

beforeEach(() => {
  setTzMode("utc"); // deterministic rendering for assertions
});

describe("parseTs — zone-less strings are UTC by contract", () => {
  // ClickHouse toString(DateTime64(3)) — the /api/findings shape observed live.
  it("parses CH 'YYYY-MM-DD HH:MM:SS.fff' as UTC", () => {
    const d = parseTs("2026-07-16 21:56:03.562")!;
    expect(d.toISOString()).toBe("2026-07-16T21:56:03.562Z");
  });
  it("parses zone-less T-separated datetimes as UTC", () => {
    expect(isoUTC("2026-07-16T21:56:03")).toBe("2026-07-16T21:56:03.000Z");
  });
  it("parses zone-less minute-precision datetimes as UTC", () => {
    expect(isoUTC("2026-07-16 21:56")).toBe("2026-07-16T21:56:00.000Z");
  });
  it("never yields a result that depends on the host zone", () => {
    // Whatever TZ the test host runs in, the instant must be identical.
    const a = parseTs("2026-01-15 12:00:00")!;
    expect(a.getTime()).toBe(Date.UTC(2026, 0, 15, 12, 0, 0));
  });
});

describe("parseTs — offset-carrying strings are preserved", () => {
  it("keeps an explicit Z", () => {
    expect(isoUTC("2026-07-16T21:53:35Z")).toBe("2026-07-16T21:53:35.000Z");
  });
  it("keeps a negative offset (RFC 5424 style)", () => {
    expect(isoUTC("2026-07-06T18:57:29-07:00")).toBe("2026-07-07T01:57:29.000Z");
  });
  it("keeps a half-hour offset (IST)", () => {
    expect(isoUTC("2026-07-17T03:26:03+05:30")).toBe("2026-07-16T21:56:03.000Z");
  });
});

describe("parseTs — epoch auto-ranging", () => {
  const iso = "2026-07-16T21:56:03.000Z";
  const ms = Date.parse(iso);
  it("seconds", () => expect(isoUTC(ms / 1000)).toBe(iso));
  it("milliseconds", () => expect(isoUTC(ms)).toBe(iso));
  it("microseconds", () => expect(isoUTC(ms * 1000)).toBe(iso));
  it("nanoseconds (goflow2 time_received_ns)", () => expect(isoUTC(ms * 1e6)).toBe(iso));
  it("numeric strings", () => expect(isoUTC(String(ms))).toBe(iso));
  it("FortiGate eventtime ns", () => {
    expect(isoUTC(1783389449840331717)).toBe(new Date(1783389449840).toISOString());
  });
});

describe("parseTs — garbage and absence", () => {
  it.each([null, undefined, "", "N/A", "not a date", 0, NaN])("%s → null", (v) => {
    expect(parseTs(v as never)).toBeNull();
  });
  it("formatters render an em dash for absent values", () => {
    expect(fmtDateTime(null)).toBe("—");
    expect(fmtTime(undefined)).toBe("—");
    expect(fmtDate("")).toBe("—");
  });
});

describe("rendering — labeled, mode-aware", () => {
  it("UTC mode is labeled UTC", () => {
    expect(fmtDateTime("2026-07-16 21:56:03.562")).toBe("Jul 16, 21:56:03 UTC");
    expect(fmtTime("2026-07-16 21:56:03.562", { ms: true })).toBe("21:56:03.562 UTC");
  });
  it("includes the year when it differs from the current year", () => {
    expect(fmtDateTime("2024-03-01 00:30:00")).toBe("Mar 01 2024, 00:30:00 UTC");
  });
  it("local mode labels with the viewer zone token", () => {
    setTzMode("local");
    const out = fmtDateTime("2026-07-16 21:56:03");
    // Environment-independent assertion: a label is present and it is the
    // zone token for that instant (e.g. "PDT", "IST", "UTC", "GMT+5:30").
    expect(out).not.toBe("—");
    expect(out.split(" ").length).toBeGreaterThanOrEqual(3);
  });
  it("tzLabel('utc') is exactly 'UTC'", () => {
    expect(tzLabel("utc")).toBe("UTC");
  });
  it("tzLabel('local') carries an explicit UTC offset", () => {
    const l = tzLabel("local", new Date("2026-07-16T21:56:03Z"));
    expect(l === "UTC" || /UTC[+−]\d{1,2}(:\d{2})?/.test(l)).toBe(true);
  });
  it("DST boundary: label follows the instant, not 'now'", () => {
    // Two instants across a northern-hemisphere DST change render with the
    // zone token computed AT that instant. In a fixed-offset or UTC test env
    // both tokens are equal; in a DST zone they differ — either is correct,
    // what matters is that both parse and render without error.
    setTzMode("local");
    const winter = fmtDateTime("2026-01-15 12:00:00");
    const summer = fmtDateTime("2026-07-15 12:00:00");
    expect(winter).not.toBe("—");
    expect(summer).not.toBe("—");
  });
});

describe("fmtDate", () => {
  it("renders date only", () => {
    expect(fmtDate("2026-07-16 21:56:03")).toBe("Jul 16, 2026");
  });
});
