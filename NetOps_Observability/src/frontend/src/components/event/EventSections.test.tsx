// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { Breakable, KvRow } from "./EventSections";

describe("Breakable identifiers", () => {
  it("wraps only after its separators and keeps the text whole", () => {
    const { container } = render(<p><Breakable text="cpu:vedge-51-0a0b4db5:device" /></p>);
    expect(container.textContent).toBe("cpu:vedge-51-0a0b4db5:device");
    expect(container.querySelectorAll("wbr")).toHaveLength(4);
  });
  it("leaves a plain word alone", () => {
    const { container } = render(<p><Breakable text="Critical" /></p>);
    expect(container.querySelector("wbr")).toBeNull();
  });
  it("escapes a hostile id as text", () => {
    const { container } = render(<p><Breakable text={'<img src=x onerror="1">:x'} /></p>);
    expect(container.querySelector("img")).toBeNull();
  });
});

describe("KvRow", () => {
  it("puts the copy control inline after an identifier", () => {
    const { container } = render(
      <dl><KvRow row={{ key: "event_id", label: "Event ID", value: "snmptrap:cisco:x:1.3.6", mono: true, copy: true }} /></dl>,
    );
    const line = container.querySelector(".evd-kv-line")!;
    expect(line.querySelector(".evd-kv-val.evd-ident")?.textContent).toBe("snmptrap:cisco:x:1.3.6");
    expect(line.querySelector("button[aria-label='Copy Event ID']")).not.toBeNull();
  });
  it("sets a number in Inter, not mono", () => {
    const { container } = render(<dl><KvRow row={{ key: "uptime", label: "Device Uptime", value: "16d 13h 59m" }} /></dl>);
    expect(container.querySelector(".evd-mono")).toBeNull();
  });
});
