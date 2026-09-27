// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// links.test.tsx — every Iris reference goes through safeCiteHref and a closed
// route map; ids are encoded, unknown kinds and off-origin hrefs are text.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { SafeLink, answerCiteHref, irisHref } from "./links";

afterEach(cleanup);

describe("irisHref", () => {
  it("maps the known kinds to same-origin routes", () => {
    expect(irisHref("incident", "abc")).toBe("/#/investigate/rca?id=abc");
    expect(irisHref("change", "c1")).toBe("/#/operations/digital-experience/changes?id=c1");
    expect(irisHref("device", "r1")).toBe("/#/infrastructure/devices?q=r1");
    expect(irisHref("site", "DFW")).toBe("/#/infrastructure/sites/sites?q=DFW");
  });

  it("encodes the id so it cannot break out of the query", () => {
    expect(irisHref("device", "a&b=<x>#y")).toBe("/#/infrastructure/devices?q=a%26b%3D%3Cx%3E%23y");
  });

  it("refuses unknown kinds and blank ids", () => {
    expect(irisHref("javascript", "x")).toBeNull();
    expect(irisHref("__proto__", "x")).toBeNull();
    expect(irisHref("device", "  ")).toBeNull();
  });
});

describe("SafeLink", () => {
  it.each(["javascript:alert(1)", "//evil.example/x", "/\\evil.example", "https://evil.example", "data:text/html,x"])(
    "renders %p as inert text",
    (href) => {
      const { container } = render(<SafeLink href={href}>ref</SafeLink>);
      expect(container.querySelector("a")).toBeNull();
      expect(screen.getByText("ref").tagName).toBe("SPAN");
    },
  );

  it("links a same-origin path", () => {
    render(<SafeLink href="/docs/x">doc</SafeLink>);
    expect(screen.getByRole("link", { name: "doc" })).toHaveAttribute("href", "/docs/x");
  });

  it("links a known entity", () => {
    render(
      <SafeLink kind="incident" id="i1">
        inc
      </SafeLink>,
    );
    expect(screen.getByRole("link", { name: "inc" })).toHaveAttribute("href", "/#/investigate/rca?id=i1");
  });
});

describe("answerCiteHref", () => {
  it("keeps the engine's in-app hash routes and same-origin paths", () => {
    expect(answerCiteHref("#/monitoring/correlations?id=abc")).toBe("#/monitoring/correlations?id=abc");
    expect(answerCiteHref(" /docs/iris ")).toBe("/docs/iris");
  });

  // A query citation carries href "" — as a link that is a full reload of the
  // app (the drawer and the route are lost). Hostile hrefs are why this exists.
  it.each(["", "   ", undefined, "#", "javascript:alert(1)", "//evil.example", "/\\evil.example", "https://evil.example", "data:text/html,x"])(
    "refuses %p",
    (href) => {
      expect(answerCiteHref(href)).toBeNull();
    },
  );
});
