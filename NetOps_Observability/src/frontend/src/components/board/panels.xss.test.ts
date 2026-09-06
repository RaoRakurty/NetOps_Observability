// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { escapeHtml, sanitizeLabel, seriesLabel } from "./panels";

// panels.xss.test.ts — stored-XSS regression (wave-3 review, 2026-08-15).
//
// ECharts renders a STRING returned from a tooltip `formatter` as HTML. The
// bar-panel formatters interpolated `p.name` straight into that string, and
// `p.name` is a device label produced by seriesLabel() from raw VictoriaMetrics
// label values (device / instance / ifName) that originate in SNMP-discovered
// sysName. Anyone controlling a monitored device could therefore store markup
// that executed in the browser of every operator who opened the panel.
//
// seriesLabel deliberately does NOT sanitize — it is also used for non-HTML
// sinks (ECharts `series.name`, which is text) where mangling the name would be
// wrong. The control belongs at the HTML sink, which is what escapeHtml is for.

describe("escapeHtml", () => {
  it("neutralizes the script-execution payloads that reach a tooltip", () => {
    for (const payload of [
      `<img src=x onerror=alert(1)>`,
      `<script>alert(document.cookie)</script>`,
      `" onmouseover="alert(1)`,
      `'><svg/onload=alert(1)>`,
    ]) {
      const out = escapeHtml(payload);
      expect(out).not.toContain("<");
      expect(out).not.toContain(">");
      // Quotes must go too: the tooltip string is spliced next to attributes.
      expect(out).not.toContain('"');
      expect(out).not.toContain("'");
    }
  });

  it("escapes the ampersand first so escaping is not itself reversible", () => {
    // &lt; must not be produced by escaping an already-escaped string in a way
    // that a second pass could unescape (&amp;lt; is correct, &lt; is not).
    expect(escapeHtml("&lt;img&gt;")).toBe("&amp;lt;img&amp;gt;");
  });

  it("preserves legitimate device-name characters that stripping would eat", () => {
    // The reason this is escapeHtml and not sanitizeLabel: real interface and
    // device names carry these, and the operator must see the true name.
    const name = "core-sw1 (rack 3) Gi0/0/1 [uplink] +spare";
    expect(escapeHtml(name)).toBe(name);
    // sanitizeLabel — correct for PromQL selectors — would mangle it.
    expect(sanitizeLabel(name)).not.toBe(name);
  });

  it("handles null/undefined without emitting 'undefined'", () => {
    expect(escapeHtml(undefined)).toBe("");
    expect(escapeHtml(null)).toBe("");
  });
});

describe("seriesLabel feeds the tooltip unsanitized (so the sink must escape)", () => {
  it("returns raw metric label values verbatim", () => {
    const hostile = `<img src=x onerror=alert(1)>`;
    const label = seriesLabel({ metric: { device: hostile }, values: [] } as never);
    // This is the documented contract: the label is NOT cleaned here. If this
    // ever starts sanitizing, the escaping at the sink is still correct — but a
    // reviewer should know which layer owns the control.
    expect(label).toBe(hostile);
    // …and the sink neutralizes it.
    expect(escapeHtml(label)).not.toContain("<");
  });
});
