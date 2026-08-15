// Flows.xss.test.tsx — stored-XSS regression for the TopNView BAR tooltip
// (H15a, wave-3 second pass). The first XSS sweep tested escapeHtml in
// isolation (panels.xss.test.ts) and missed this sink entirely — the TopNView
// bar formatter interpolated `label(key)` AND the resolved app name
// (FortiGate syslog `app=`, attacker-controlled) into the string ECharts
// inserts via innerHTML. These tests therefore exercise the REAL formatter:
// render the section, capture the option handed to ECharts, and call
// `tooltip.formatter` with hostile values.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, waitFor } from "@testing-library/react";

// Capture every option the section hands to ECharts so the test can invoke
// the exact formatter closure that ships (not a re-implementation of it).
const captured: any[] = [];
vi.mock("../components/EChart", () => ({
  default: (props: { option: unknown }) => {
    captured.push(props.option);
    return <div data-testid="chart" />;
  },
}));

const topTalkers = vi.fn();
const flowsTopN = vi.fn();
const appIdResolveBatch = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    topTalkers: (...a: unknown[]) => topTalkers(...a),
    flowsTopN: (...a: unknown[]) => flowsTopN(...a),
    appIdResolveBatch: (...a: unknown[]) => appIdResolveBatch(...a),
  },
}));

import { ConversationsSection } from "./Flows";
import { _resetAppNamesForTest } from "../services/appNames";

const q = { since: 3600, ftype: "", filters: {}, fkey: "", direction: "" } as never;

// A key that is NOT IP-shaped (so it skips the app resolver) but IS a script
// vector if it ever reaches innerHTML unescaped.
const HOSTILE_KEY = `<img src=x onerror=alert(1)>`;
// A hostile app name behind a legitimate IP key — this is the FortiGate
// syslog `app=` field, which the device (or whoever spoofs its syslog) writes.
const HOSTILE_APP = `<svg/onload=alert(2)>`;

afterEach(cleanup);
beforeEach(() => {
  captured.length = 0;
  topTalkers.mockReset();
  flowsTopN.mockReset();
  appIdResolveBatch.mockReset();
  _resetAppNamesForTest();
  topTalkers.mockResolvedValue({ data: [] });
  flowsTopN.mockResolvedValue({
    data: [
      { k: HOSTILE_KEY, bytes_total: 4096, packets_total: 4, flows: 2 },
      { k: "10.0.1.10", bytes_total: 2048, packets_total: 2, flows: 1 },
    ],
  });
  appIdResolveBatch.mockResolvedValue({
    "10.0.1.10": { app: HOSTILE_APP, source: "device_log", confidence: 0.9 },
  });
});

describe("H15a — TopNView bar tooltip escapes every dynamic interpolation", () => {
  it("neutralizes a hostile row key (label) in the real formatter", async () => {
    render(<ConversationsSection q={q} />);
    await waitFor(() => expect(captured.length).toBeGreaterThan(0));
    const fmt = captured[captured.length - 1].tooltip.formatter as (p: unknown) => string;
    // ECharts passes the axis params array; the formatter takes ps[0].name.
    const out = fmt([{ name: HOSTILE_KEY, value: 4096 }]);
    expect(out).not.toContain("<img");
    expect(out).toContain("&lt;img");
    // The trusted markup we emit ourselves stays intact.
    expect(out).toContain("<br/>");
  });

  it("neutralizes a hostile resolved app name in the real formatter", async () => {
    render(<ConversationsSection q={q} />);
    // Wait for the app-name batch to land AND the panels to re-render with the
    // populated apps map — the formatter closes over it.
    await waitFor(() => expect(appIdResolveBatch).toHaveBeenCalled());
    await waitFor(() => {
      const fmt = captured[captured.length - 1].tooltip.formatter as (p: unknown) => string;
      const out = fmt([{ name: "10.0.1.10", value: 2048 }]);
      expect(out).toContain("&lt;svg"); // app name is present, escaped
    });
    const fmt = captured[captured.length - 1].tooltip.formatter as (p: unknown) => string;
    const out = fmt([{ name: "10.0.1.10", value: 2048 }]);
    expect(out).not.toContain("<svg");
    // No double-escaping: the ampersand appears once per escaped char.
    expect(out).not.toContain("&amp;lt;");
  });
});
