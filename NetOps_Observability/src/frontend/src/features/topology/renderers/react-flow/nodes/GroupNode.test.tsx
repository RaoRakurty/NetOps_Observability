// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// GroupNode.test.tsx — site label type (owner, 2026-11-24): on a site box's
// label chip AND on a collapsed site card the site NAME reads at 14px and the
// secondary text (kind, device count, links) at 12px. Before this they were
// 9.5–11.5px, under the NOC-admin 14px standard.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { ReactFlowProvider, type NodeProps } from "@xyflow/react";
import { GroupNode, GroupLabelNode } from "./GroupNode";
import type { RFGroupData } from "../rfTypes";

afterEach(cleanup);

const NAME = "Site 50 · from vManage";

function props(collapsed: boolean): NodeProps {
  const data: RFGroupData = {
    group: { id: "site:x", label: NAME, group_type: "site", children: ["a", "b"], health: "ok", collapsed, source: "discovered" } as RFGroupData["group"],
    collapsed,
    emphasis: "normal",
    counts: { total: 2, critical: 0, warning: 0, links: 3 } as RFGroupData["counts"],
    health: "ok",
  };
  return { id: "site:x", data, type: "groupNode", selected: false, dragging: false, zIndex: 0,
    isConnectable: false, positionAbsoluteX: 0, positionAbsoluteY: 0, draggable: true, selectable: true, deletable: false } as unknown as NodeProps;
}

const px = (el: HTMLElement) => el.style.fontSize;

describe("site label type — name 14px, secondary 12px", () => {
  it("the expanded box's label chip", () => {
    render(<ReactFlowProvider><GroupLabelNode {...props(false)} /></ReactFlowProvider>);
    expect(px(screen.getByText(NAME))).toBe("14px");
    expect(px(screen.getByText("Discovered site"))).toBe("12px");
    expect(px(screen.getByText("· 2"))).toBe("12px");
  });

  it("the collapsed site card", () => {
    render(<ReactFlowProvider><GroupNode {...props(true)} /></ReactFlowProvider>);
    expect(px(screen.getByText(NAME))).toBe("14px");
    expect(px(screen.getByText("Discovered site"))).toBe("12px");
    expect(px(screen.getByText("2 nodes").parentElement as HTMLElement)).toBe("12px");
  });

  it("no site text on either chip is smaller than 12px", () => {
    for (const collapsed of [false, true]) {
      const { container } = render(<ReactFlowProvider>{collapsed
        ? <GroupNode {...props(true)} /> : <GroupLabelNode {...props(false)} />}</ReactFlowProvider>);
      for (const el of Array.from(container.querySelectorAll<HTMLElement>("span, button, div"))) {
        const f = parseFloat(el.style.fontSize);
        // The health badge (a 16px ring with "OK" / "!" / "✕") is a status
        // glyph, not site text — it carries its meaning in its title.
        const badge = el.style.borderRadius === "50%" && !!el.title;
        if (!Number.isNaN(f) && el.textContent && !badge) {
          expect(f, `"${el.textContent}" at ${f}px`).toBeGreaterThanOrEqual(12);
        }
      }
      cleanup();
    }
  });
});
