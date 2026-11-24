// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// The visual-language kit (docs/design/visual-language.md › Components).

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  StatusChip, STATUS_TONE, TONE_ICON, PageHeader, OutlinedButton,
  PillSelect, FieldSelect, SortLabel, FilterSection, type StatusKind,
} from "./index";
import { hasIcon } from "../Icon";

afterEach(cleanup);

const KIT_CSS = readFileSync(join(__dirname, "kit.css"), "utf8");
const STYLES = readFileSync(join(__dirname, "..", "..", "styles.css"), "utf8");

describe("StatusChip — a state is an icon, a word and a semantic colour", () => {
  it("maps every kind to one of the five tones", () => {
    for (const [kind, tone] of Object.entries(STATUS_TONE)) {
      expect(["ok", "warn", "bad", "info", "neutral"], kind).toContain(tone);
    }
    expect(STATUS_TONE.up).toBe("ok");
    expect(STATUS_TONE.allow).toBe("ok");
    expect(STATUS_TONE.degraded).toBe("warn");
    expect(STATUS_TONE.suspected).toBe("warn");
    expect(STATUS_TONE.down).toBe("bad");
    expect(STATUS_TONE.deny).toBe("bad");
    expect(STATUS_TONE.critical).toBe("bad");
    expect(STATUS_TONE["not-polled"]).toBe("neutral");
  });

  it("gives every tone a glyph that exists in Icon.tsx", () => {
    for (const [tone, glyph] of Object.entries(TONE_ICON)) expect(hasIcon(glyph), `${tone} → ${glyph}`).toBe(true);
  });

  it("always shows the word, with the icon hidden from assistive tech", () => {
    const { container } = render(<StatusChip kind="down" label="Down" />);
    expect(screen.getByText("Down")).toBeTruthy();
    const chip = container.querySelector(".kit-status") as HTMLElement;
    expect(chip.dataset.tone).toBe("bad");
    expect(chip.querySelector("svg")?.getAttribute("aria-hidden")).toBe("true");
    // Not a live region: a table of chips must not chatter at a screen reader.
    expect(chip.getAttribute("role")).toBeNull();
  });

  it.each([
    ["up", "ok"], ["degraded", "warn"], ["down", "bad"], ["info", "info"], ["unknown", "neutral"],
  ] as [StatusKind, string][])("%s renders tone %s", (kind, tone) => {
    const { container } = render(<StatusChip kind={kind} label={kind} />);
    expect((container.querySelector(".kit-status") as HTMLElement).dataset.tone).toBe(tone);
  });
});

describe("kit colours come only from theme tokens", () => {
  it("kit.css holds no literal colour", () => {
    const body = KIT_CSS.replace(/\/\*[\s\S]*?\*\//g, "");
    expect(body).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(body).not.toMatch(/\b(rgb|rgba|hsl|hsla)\(/);
  });

  it("each status tone reads its own semantic token, and only that", () => {
    const want: Record<string, RegExp> = {
      ok: /--kit-tone:\s*var\(--ok\b/,
      warn: /--kit-tone:\s*var\(--warn\b/,
      bad: /--kit-tone:\s*var\(--crit\b/,
      info: /--kit-tone:\s*var\(--info\b/,
    };
    for (const [tone, re] of Object.entries(want)) {
      const rule = KIT_CSS.match(new RegExp(`\\.kit-status\\[data-tone="${tone}"\\]\\s*\\{[^}]*\\}`))?.[0] ?? "";
      expect(rule, tone).toMatch(re);
      expect(rule, tone).not.toMatch(/--accent/);
    }
  });

  it("the semantic tokens and the accent exist in the base theme", () => {
    for (const t of ["--ok", "--warn", "--crit", "--info", "--accent", "--fg-muted"]) {
      expect(STYLES, t).toMatch(new RegExp(`${t}\\s*:`));
    }
  });
});

describe("PageHeader", () => {
  it("is an icon tile, a level-1 title, a count and the actions", () => {
    const { container } = render(
      <PageHeader icon="server" title="Devices" count={8} actions={<OutlinedButton icon="plus">Add device</OutlinedButton>} />,
    );
    expect(screen.getByRole("heading", { level: 1, name: "Devices" })).toBeTruthy();
    expect(screen.getByLabelText("8 items").textContent).toBe("8");
    expect(screen.getByRole("button", { name: "Add device" })).toBeTruthy();
    expect(container.querySelector(".kit-ph-tile")?.getAttribute("aria-hidden")).toBe("true");
  });

  it("omits the count when there is none", () => {
    render(<PageHeader icon="server" title="Settings" />);
    expect(screen.queryByLabelText(/items$/)).toBeNull();
  });
});

describe("OutlinedButton", () => {
  it("names an icon-only button by its label", () => {
    render(<OutlinedButton icon="bookmark" label="Save view" />);
    expect(screen.getByRole("button", { name: "Save view" })).toBeTruthy();
  });

  it("fires onClick and adds the chevron for a row action", () => {
    const onClick = vi.fn();
    const { container } = render(<OutlinedButton chevron onClick={onClick}>Open</OutlinedButton>);
    fireEvent.click(screen.getByRole("button", { name: "Open" }));
    expect(onClick).toHaveBeenCalledTimes(1);
    expect(container.querySelectorAll("svg").length).toBe(1);
  });
});

describe("dropdowns are native selects — keyboard and screen reader for free", () => {
  const options = [{ value: "", label: "All sites" }, { value: "s40", label: "Site 40" }];

  it("PillSelect is named, shows its lead word and reports the change", () => {
    const onChange = vi.fn();
    render(<PillSelect label="Filter by site" lead="Site" icon="map-pin" value="" options={options} onChange={onChange} />);
    const sel = screen.getByRole("combobox", { name: "Filter by site" });
    expect(screen.getByText("Site")).toBeTruthy();
    fireEvent.change(sel, { target: { value: "s40" } });
    expect(onChange).toHaveBeenCalledWith("s40");
  });

  it("FieldSelect is a full-width named select", () => {
    const onChange = vi.fn();
    const { container } = render(<FieldSelect label="Site" icon="map-pin" value="s40" options={options} onChange={onChange} />);
    expect((screen.getByRole("combobox", { name: "Site" }) as HTMLSelectElement).value).toBe("s40");
    expect(container.querySelector(".kit-field")).toBeTruthy();
  });

  it("SortLabel carries the sort glyph", () => {
    const { container } = render(<SortLabel />);
    expect(screen.getByText("Sort by")).toBeTruthy();
    expect(container.querySelector("svg")).toBeTruthy();
  });
});

describe("FilterSection — left chevron, checkbox rows, quiet counts", () => {
  const opts = [{ value: "up", label: "Up", count: 6 }, { value: "down", label: "Down", count: 1 }];

  it("collapses from its header and says whether it is open", () => {
    render(<FilterSection title="Health" options={opts} selected={new Set(["up"])} onToggle={() => {}} />);
    const head = screen.getByRole("button", { name: "Health" });
    expect(head.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByRole("checkbox", { name: /Up/ })).toBeTruthy();
    fireEvent.click(head);
    expect(head.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByRole("checkbox", { name: /Up/ })).toBeNull();
  });

  it("reports a toggle and shows the counts", () => {
    const onToggle = vi.fn();
    render(<FilterSection title="Health" options={opts} selected={new Set(["up"])} onToggle={onToggle} />);
    expect((screen.getByRole("checkbox", { name: /Up/ }) as HTMLInputElement).checked).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: /Down/ }));
    expect(onToggle).toHaveBeenCalledWith("down", true);
    expect(screen.getByText("6")).toBeTruthy();
  });

  it("offers its action link", () => {
    const clear = vi.fn();
    render(<FilterSection title="Health" options={opts} selected={new Set()} onToggle={() => {}} action={{ label: "Clear", onClick: clear }} />);
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(clear).toHaveBeenCalled();
  });
});
