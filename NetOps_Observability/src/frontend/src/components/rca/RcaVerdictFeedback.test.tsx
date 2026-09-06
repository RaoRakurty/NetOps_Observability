// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RcaVerdictFeedback.test.tsx — the operator verdict control (Project 2 P7).
//
// What is pinned here is the honesty contract, not the styling: the three
// choices are offered; a wrong/partial verdict cannot be filed without naming
// which claim was wrong; the POST body is exactly the shape the backend
// validates (verdict + wrong_part + reason + the version actually on screen,
// never a tenant); a 403 becomes a permission sentence, not a stack trace; the
// recorded verdict is read back from the server (newest first) rather than
// faked optimistically.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent } from "@testing-library/react";
import type { RcaFeedback } from "../../services/api";

const NEWER: RcaFeedback = {
  id: "fb-2", tenant_id: "acme", correlation_id: "c-1",
  verdict: "wrong", wrong_part: "owner", reason: "ISP was not at fault",
  correlation_version: 3, created_by: "alice", created_at: "2026-09-01T12:00:00Z",
};
const OLDER: RcaFeedback = {
  id: "fb-1", tenant_id: "acme", correlation_id: "c-1",
  verdict: "correct", correlation_version: 2, created_by: "bob", created_at: "2026-08-30T09:00:00Z",
};

function mockApi({ list, createErr }: { list: RcaFeedback[]; createErr?: Error }) {
  const create = vi.fn(() => (createErr ? Promise.reject(createErr) : Promise.resolve(NEWER)));
  const get = vi.fn(() => Promise.resolve({ correlation_id: "c-1", feedback: list, count: list.length }));
  vi.doMock("../../services/api", () => ({
    api: { correlationFeedback: get, correlationFeedbackCreate: create },
  }));
  return { create, get };
}

async function mount(props: { correlationVersion?: number } = {}) {
  const { default: Ctl } = await import("./RcaVerdictFeedback");
  return render(<Ctl correlationId="c-1" correlationVersion={props.correlationVersion ?? 3} />);
}

const btn = (name: string) => screen.getByRole("button", { name });

afterEach(() => { cleanup(); vi.resetModules(); vi.clearAllMocks(); });

describe("RcaVerdictFeedback — the control", () => {
  it("renders the question and the three verdict choices, none pressed", async () => {
    mockApi({ list: [] });
    await mount();
    expect(await screen.findByText("Was this verdict right?")).toBeTruthy();
    for (const label of ["Correct", "Partially", "Wrong"]) {
      expect(btn(label).getAttribute("aria-pressed")).toBe("false");
    }
    expect(await screen.findByText(/No operator verdict recorded on this case yet/)).toBeTruthy();
  });

  it("opens the inline part form only for Partially / Wrong, and marks it pressed", async () => {
    mockApi({ list: [] });
    await mount();
    await screen.findByText("Was this verdict right?");
    expect(screen.queryByText("Which part was wrong?")).toBeNull();
    fireEvent.click(btn("Wrong"));
    expect(screen.getByText("Which part was wrong?")).toBeTruthy();
    expect(btn("Wrong").getAttribute("aria-pressed")).toBe("true");
    expect(btn("Partially").getAttribute("aria-pressed")).toBe("false");
    for (const p of ["Cause", "Owner", "Affected", "Evidence", "Recovery"]) {
      expect(screen.getByRole("radio", { name: p })).toBeTruthy();
    }
  });

  it("refuses a wrong/partial verdict with no part named (nothing is POSTed)", async () => {
    const { create } = mockApi({ list: [] });
    await mount();
    await screen.findByText("Was this verdict right?");
    fireEvent.click(btn("Partially"));
    fireEvent.click(btn("Record verdict"));
    expect(await screen.findByText("Choose which part was wrong.")).toBeTruthy();
    expect(create).not.toHaveBeenCalled();
  });

  it("POSTs the exact body shape: verdict, wrong_part, reason and the on-screen version", async () => {
    const { create } = mockApi({ list: [] });
    await mount({ correlationVersion: 7 });
    await screen.findByText("Was this verdict right?");
    fireEvent.click(btn("Wrong"));
    fireEvent.click(screen.getByRole("radio", { name: "Owner" }));
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "  ISP was not at fault  " } });
    fireEvent.click(btn("Record verdict"));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0]).toEqual(["c-1", {
      verdict: "wrong", wrong_part: "owner", reason: "ISP was not at fault", correlation_version: 7,
    }]);
  });

  it("POSTs a bare correct verdict immediately, with no wrong_part", async () => {
    const { create } = mockApi({ list: [] });
    await mount({ correlationVersion: 4 });
    await screen.findByText("Was this verdict right?");
    fireEvent.click(btn("Correct"));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0]).toEqual(["c-1", { verdict: "correct", correlation_version: 4 }]);
    expect(screen.queryByText("Which part was wrong?")).toBeNull();
  });

  it("counts reason characters against the 500-character cap", async () => {
    mockApi({ list: [] });
    await mount();
    await screen.findByText("Was this verdict right?");
    fireEvent.click(btn("Wrong"));
    expect(screen.getByText("0/500 characters")).toBeTruthy();
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "abcde" } });
    expect(screen.getByText("5/500 characters")).toBeTruthy();
  });

  it("surfaces a 403 as a permission sentence and records nothing", async () => {
    mockApi({ list: [], createErr: new Error("403 Forbidden: alerts:write required") });
    await mount();
    await screen.findByText("Was this verdict right?");
    fireEvent.click(btn("Correct"));
    const live = await screen.findByText(/don't have permission/i);
    expect(live.textContent).toBe("You don't have permission to record a verdict on this case.");
    expect(screen.queryByText(/^Operator verdict:/)).toBeNull();
  });

  it("renders the recorded verdict newest-first, with part, reason, who and when", async () => {
    mockApi({ list: [NEWER, OLDER] });
    await mount();
    const latest = await screen.findByText(/^Operator verdict: Wrong/);
    expect(latest.textContent).toContain("owner");
    expect(latest.textContent).toContain("'ISP was not at fault'");
    expect(latest.textContent).toContain("alice");
    expect(latest.className).toContain("rw-fb-latest");
    // the older row stays available (append-only), but under the newest one
    expect(screen.getByText("1 earlier verdict")).toBeTruthy();
    expect(screen.getByText(/Operator verdict: Correct .*bob/)).toBeTruthy();
  });

  it("re-reads from the server after a submit and still allows a new verdict", async () => {
    const { create, get } = mockApi({ list: [NEWER] });
    await mount();
    await screen.findByText(/^Operator verdict: Wrong/);
    fireEvent.click(btn("Correct"));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2)); // mount + after submit
    expect(await screen.findByText("Verdict recorded.")).toBeTruthy();
    expect(btn("Wrong").hasAttribute("disabled")).toBe(false);
  });

  it("keeps a polite live region for the confirmation (4.1.3)", async () => {
    mockApi({ list: [] });
    const { container } = await mount();
    await screen.findByText("Was this verdict right?");
    expect(container.querySelector('[role="status"][aria-live="polite"]')).toBeTruthy();
  });

  // Snapshot of the control with the inline form open — the full markup an
  // operator sees. Deliberately the timestamp-free state: a snapshot carrying a
  // rendered local time would rot at the next timezone or year boundary.
  it("matches the control snapshot (form open)", async () => {
    mockApi({ list: [] });
    const { container } = await mount();
    await screen.findByText("Was this verdict right?");
    fireEvent.click(btn("Wrong"));
    expect(container.firstChild).toMatchSnapshot();
  });
});
