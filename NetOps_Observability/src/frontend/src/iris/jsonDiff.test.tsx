// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// jsonDiff.test.tsx — the before/after comparison (pure) and its two layouts
// (JsonDiff side by side; the lifted ConfigDiffView line by line).

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { DIFF_LIMITS, buildDiff, toUnified } from "./jsonDiff";
import JsonDiff from "./JsonDiff";
import { ConfigDiffView } from "../components/ConfigDiffView";
import { ConfigDiffView as ReExported } from "../pages/config/DeviceConfigPanel";
import { HOSTILE, HOSTILE_IMG } from "../test/irisFixtures";

afterEach(cleanup);

describe("buildDiff", () => {
  it("compares objects by path: changed / added / removed / same", () => {
    const d = buildDiff({ a: 1, b: { c: "x" }, gone: true }, { a: 2, b: { c: "x" }, add: [1] });
    expect(d.mode).toBe("structured");
    const byPath = Object.fromEntries(d.rows.map((r) => [r.path, r.kind]));
    expect(byPath).toEqual({ a: "changed", "b.c": "same", gone: "removed", "add[0]": "added" });
    expect([d.changed, d.added, d.removed]).toEqual([1, 1, 1]);
  });

  it("parses JSON strings as structured values", () => {
    expect(buildDiff('{"mtu":1500}', '{"mtu":9000}').rows).toEqual([{ path: "mtu", before: "1500", after: "9000", kind: "changed" }]);
  });

  it("diffs plain text line by line", () => {
    const d = buildDiff("a\nb\nc", "a\nB\nc");
    expect(d.mode).toBe("text");
    expect(d.rows.map((r) => r.kind)).toEqual(["same", "added", "removed", "same"]);
    expect(d.rows[1]).toEqual({ path: "line 2", before: null, after: "B", kind: "added" });
    expect(d.added).toBe(1);
    expect(d.removed).toBe(1);
  });

  it("treats a missing side as all-added / all-removed", () => {
    expect(buildDiff(null, { a: 1 }).rows).toEqual([{ path: "a", before: null, after: "1", kind: "added" }]);
    expect(buildDiff("x", "").rows[0].kind).toBe("removed");
  });

  it("is bounded: huge inputs set truncated instead of stalling", () => {
    const big = Object.fromEntries(Array.from({ length: DIFF_LIMITS.entries + 50 }, (_, i) => [`k${i}`, i]));
    expect(buildDiff(big, {}).truncated).toBe(true);
    const lines = Array.from({ length: DIFF_LIMITS.lines + 10 }, (_, i) => `l${i}`).join("\n");
    const t = buildDiff(lines, "");
    expect(t.truncated).toBe(true);
    expect(t.rows.length).toBeLessThanOrEqual(DIFF_LIMITS.lines);
    // Depth bound.
    let deep: Record<string, unknown> = { v: 1 };
    for (let i = 0; i < DIFF_LIMITS.depth + 3; i++) deep = { n: deep };
    expect(buildDiff(deep, {}).truncated).toBe(true);
  });

  it("toUnified prefixes every line so a value cannot forge a diff header", () => {
    const u = toUnified(buildDiff("--- evil\n@@ x", "+++ evil"));
    for (const line of u.split("\n")) expect(line.startsWith("  ") || line.startsWith("- ") || line.startsWith("+ ")).toBe(true);
  });
});

describe("JsonDiff", () => {
  it("renders side by side with the change named in words", () => {
    render(<JsonDiff before={{ mtu: 1500 }} after={{ mtu: 9000 }} />);
    expect(screen.getByRole("table", { name: /side by side/ })).toBeInTheDocument();
    expect(screen.getByText("1500")).toBeInTheDocument();
    expect(screen.getByText("9000")).toBeInTheDocument();
    expect(screen.getByText(/Changed/)).toBeInTheDocument();
    expect(screen.getByText("1 changed · 0 added · 0 removed")).toBeInTheDocument();
  });

  it("switches to the shared line-by-line view", () => {
    const { container } = render(<JsonDiff before={{ mtu: 1500 }} after={{ mtu: 9000 }} />);
    fireEvent.click(screen.getByRole("button", { name: "Line by line" }));
    const lines = Array.from(container.querySelectorAll(".cfg-diff-line")).map((l) => [l.className, l.textContent]);
    expect(lines).toEqual([
      ["cfg-diff-line cfg-diff-del", "- mtu: 1500"],
      ["cfg-diff-line cfg-diff-add", "+ mtu: 9000"],
    ]);
  });

  it("renders hostile before/after as inert text", () => {
    const { container } = render(<JsonDiff before={HOSTILE} after={HOSTILE_IMG} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(HOSTILE)).toBeInTheDocument();
    expect(screen.getByText(HOSTILE_IMG)).toBeInTheDocument();
  });

  it("says so when nothing was recorded", () => {
    render(<JsonDiff before={null} after={undefined} />);
    expect(screen.getByText(/No before or after was recorded/)).toBeInTheDocument();
  });

  it("says so when identical", () => {
    render(<JsonDiff before={{ a: 1 }} after={{ a: 1 }} />);
    expect(screen.getByText("Before and after are identical.")).toBeInTheDocument();
  });

  it("shows a visible notice when truncated", () => {
    const big = Object.fromEntries(Array.from({ length: DIFF_LIMITS.entries + 5 }, (_, i) => [`k${i}`, i]));
    render(<JsonDiff before={big} after={{}} />);
    expect(screen.getByRole("status")).toHaveTextContent(/too large to show in full/);
  });
});

describe("ConfigDiffView (lifted into components/, behaviour unchanged)", () => {
  it("is the same component the device Configuration tab exports", () => {
    expect(ReExported).toBe(ConfigDiffView);
  });

  it("colours lines by class, shows churn, and states server truncation", () => {
    const { container } = render(
      <ConfigDiffView title="v1 → v2" diff={{ unified: "--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new\n ctx", added: 1, removed: 1, truncated: true }} />,
    );
    const kinds = Array.from(container.querySelectorAll(".cfg-diff-line")).map((l) => l.className.replace("cfg-diff-line cfg-diff-", ""));
    expect(kinds).toEqual(["meta", "meta", "hunk", "del", "add", "ctx"]);
    expect(screen.getByText("+1 / −1")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/Truncated by the server/);
  });

  it("says the versions are identical for an empty diff", () => {
    render(<ConfigDiffView title="t" diff={{ unified: "", added: 0, removed: 0, truncated: false }} />);
    expect(screen.getByText(/The two versions are identical/)).toBeInTheDocument();
  });

  it("renders hostile diff text as text", () => {
    const { container } = render(<ConfigDiffView title="t" diff={{ unified: `+${HOSTILE}`, added: 1, removed: 0, truncated: false }} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain(HOSTILE);
  });
});
