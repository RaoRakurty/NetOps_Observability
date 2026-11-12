// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// CitedText.test.tsx — inline evidence references in an Iris answer render as
// readable problem handles (owner report 2026-11-12: raw
// "[problem:<uuid>, problem:<uuid>]" tokens), linked through the allowlist,
// as escaped text only (OWASP LLM02).

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import CitedText, { citeHref, citeLabel, readableCitations, splitCitations } from "./CitedText";
import StatementText from "./StatementText";

afterEach(cleanup);

const A = "4fdcb775-6e0c-5827-8c23-31467149ebff";
const B = "033eced1-1111-4222-8333-444455556666";
const raw = `Two problems are confirmed [problem:${A}, problem:${B}]. Check the WAN link.`;

describe("CitedText", () => {
  it("renders a problem citation list as P-handles linked to each problem", () => {
    const { container } = render(<p><CitedText text={raw} citations={[{ id: `problem:${A}`, label: "WAN flap", href: `#/monitoring/correlations?id=${A}` }]} /></p>);
    const text = container.textContent ?? "";
    expect(text).toContain("P-4FDCB7");
    expect(text).toContain("P-033ECE");
    expect(text).not.toContain(A);
    expect(text).not.toContain("problem:");
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(2);
    // The answer's own citation href wins; otherwise the incident route.
    expect(links[0].getAttribute("href")).toBe(`#/monitoring/correlations?id=${A}`);
    expect(links[1].getAttribute("href")).toContain(encodeURIComponent(B));
    expect(text).toContain("Check the WAN link.");
  });

  it("leaves non-citation brackets and plain text exactly as typed", () => {
    const { container } = render(<p><CitedText text="see [1] and [note] here" /></p>);
    expect(container.textContent).toBe("see [1] and [note] here");
    expect(screen.queryAllByTestId("iris-inline-cite")).toHaveLength(0);
  });

  it("never renders model text as markup", () => {
    const evil = `<img src=x onerror=alert(1)> [problem:${A}]`;
    const { container } = render(<p><CitedText text={evil} /></p>);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<img src=x onerror=alert(1)>");
  });

  it("labels other evidence from the answer's citations; an id with no label stays as written", () => {
    expect(citeLabel("log:os:1", [{ id: "log:os:1", label: "Ethernet1/1 down" }])).toBe("Ethernet1/1 down");
    expect(citeLabel("scope:caller")).toBe("");
    expect(citeHref("scope:caller")).toBeNull();
    const { container } = render(<p><CitedText text="Peer idle [hypothesis:p1:1]." /></p>);
    expect(container.textContent).toBe("Peer idle [hypothesis:p1:1].");
    expect(container.firstChild?.childNodes).toHaveLength(1); // one text run, unchanged
    expect(citeHref("problem:" + A, [{ id: "problem:" + A, href: "javascript:alert(1)" }])).toContain("/#/investigate/rca?id=");
  });

  it("gives plain-text surfaces readable handles too", () => {
    expect(readableCitations(raw)).toBe("Two problems are confirmed (P-4FDCB7, P-033ECE). Check the WAN link.");
    expect(splitCitations("a [log:x; log:y] b")).toEqual(["a ", ["log:x", "log:y"], " b"]);
  });

  it("is used by StatementText, statements or not", () => {
    const { container } = render(<StatementText text={raw} />);
    expect(container.textContent).toContain("P-4FDCB7");
    expect(container.textContent).not.toContain(A);
    const sts = [{ text: `Two problems are confirmed [problem:${A}]. `, class: "CORRELIX_RCA", grounded: true }, { text: "Check the WAN link.", class: "RECOMMENDATION", grounded: true }];
    cleanup();
    const r2 = render(<StatementText text={sts.map((s) => s.text).join("")} statements={sts} />);
    expect(r2.container.textContent).toContain("P-4FDCB7");
    expect(r2.container.textContent).not.toContain(A);
  });
});
