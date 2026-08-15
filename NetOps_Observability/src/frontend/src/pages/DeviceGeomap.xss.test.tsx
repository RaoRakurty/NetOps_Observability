// DeviceGeomap.xss.test.tsx — stored-XSS regression for the geomap site
// tooltip (H15b, wave-3 second pass). The MapPanel tooltip formatter
// interpolated `s.name` (a Source-of-Truth site name — editor- or
// sync-controlled) into the string ECharts inserts via innerHTML. Like the
// Flows test, this exercises the REAL formatter by capturing the option
// handed to ECharts and calling `tooltip.formatter` with a hostile site.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, waitFor } from "@testing-library/react";

const captured: any[] = [];
vi.mock("../components/EChart", () => ({
  default: (props: { option: unknown }) => {
    captured.push(props.option);
    return <div data-testid="chart" />;
  },
}));
// The world basemap is lazy-loaded and registered on mount; neither matters
// for the tooltip, so stub both to keep the test off the 700 KB GeoJSON.
vi.mock("echarts/core", () => ({ registerMap: () => {} }));
vi.mock("../assets/world-110m.geo.json", () => ({
  default: { type: "FeatureCollection", features: [] },
}));

const geomap = vi.fn();
vi.mock("../services/api", () => ({
  api: { geomap: (...a: unknown[]) => geomap(...a) },
}));

import { GeomapSection } from "./DeviceGeomap";

const HOSTILE_SITE = {
  name: `<img src=x onerror=alert(1)>`,
  devices: 2,
  up: 1,
  down: 1,
  has_coords: true,
  lat: 52.52,
  lng: 13.4,
};

afterEach(cleanup);
beforeEach(() => {
  captured.length = 0;
  geomap.mockReset();
  geomap.mockResolvedValue({ geo_enabled: true, sites: [HOSTILE_SITE] });
});

describe("H15b — geomap site tooltip escapes the site name", () => {
  it("neutralizes a hostile SoT site name in the real formatter", async () => {
    render(<GeomapSection />);
    await waitFor(() => expect(captured.length).toBeGreaterThan(0));
    const fmt = captured[captured.length - 1].tooltip.formatter as (p: unknown) => string;
    const out = fmt({ data: { site: HOSTILE_SITE } });
    expect(out).not.toContain("<img");
    expect(out).toContain("&lt;img");
    // Our own trusted markup and the counts survive.
    expect(out).toContain("<b>");
    expect(out).toContain("2 devices");
    // No double-escaping of the payload.
    expect(out).not.toContain("&amp;lt;");
    // Missing site stays the empty string (no "undefined" leakage).
    expect(fmt({ data: {} })).toBe("");
  });
});
