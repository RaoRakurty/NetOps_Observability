// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// NetworkContext.test.tsx — Administration → Iris → Network Context (N-F1).
//
// What has to hold: an author is never offered "Approve" on their own text; a
// reviewer's approval carries the version and hash of the text on screen; the
// byte counter blocks an oversize fact; fact text is rendered as TEXT; and the
// preview shows exactly what the server says Iris reads.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const orgContext = vi.fn();
const orgContextPreview = vi.fn();
const orgContextCreate = vi.fn();
const orgContextDraft = vi.fn();
const orgContextDiscard = vi.fn();
const orgContextAct = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    orgContext: (...a: unknown[]) => orgContext(...a),
    orgContextPreview: (...a: unknown[]) => orgContextPreview(...a),
    orgContextCreate: (...a: unknown[]) => orgContextCreate(...a),
    orgContextDraft: (...a: unknown[]) => orgContextDraft(...a),
    orgContextDiscard: (...a: unknown[]) => orgContextDiscard(...a),
    orgContextAct: (...a: unknown[]) => orgContextAct(...a),
  },
}));

import NetworkContext from "./NetworkContext";

const KINDS = [
  { kind: "topology_note", label: "Network layout note" },
  { kind: "terminology", label: "Our terminology" },
];

function fact(id: string, author: string, state: string, body: string, extra: Record<string, unknown> = {}) {
  return {
    id,
    scope: "tenant",
    kind: "topology_note",
    key: `key-${id}`,
    created_by: author,
    created_at: "2026-10-12T09:00:00Z",
    updated_at: "2026-10-12T09:00:00Z",
    versions: [{ version: 1, body, body_sha256: `sha-${id}`, state, author, created_at: "2026-10-12T09:00:00Z", ...extra }],
  };
}

function serve(facts: unknown[], you = "alice", block = "") {
  orgContext.mockResolvedValue({ facts, kinds: KINDS, you, limits: { body_bytes: 2000, key_bytes: 80, facts: 50 } });
  orgContextPreview.mockResolvedValue({ block, facts: block ? 1 : 0, omitted: 0 });
}

beforeEach(() => {
  vi.clearAllMocks();
  orgContextAct.mockResolvedValue({});
  orgContextCreate.mockResolvedValue({});
});
afterEach(cleanup);

describe("NetworkContext", () => {
  it("never offers the author an Approve button on their own text", async () => {
    serve([fact("f1", "alice", "pending", "core-02 is the DR site")]);
    render(<NetworkContext />);
    expect(await screen.findByText("Waiting for another administrator to review it.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.getByText("Nothing is waiting for your review.")).toBeTruthy();
  });

  it("approves exactly the version and text the reviewer is looking at", async () => {
    serve([fact("f1", "alice", "pending", "core-02 is the DR site")], "bob");
    render(<NetworkContext />);
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    await waitFor(() => expect(orgContextAct).toHaveBeenCalled());
    expect(orgContextAct).toHaveBeenCalledWith("f1", "approve", { version: 1, body_sha256: "sha-f1", reason: "" });
  });

  it("declining needs a note", async () => {
    serve([fact("f1", "alice", "pending", "x")], "bob");
    render(<NetworkContext />);
    const decline = (await screen.findByRole("button", { name: "Decline" })) as HTMLButtonElement;
    expect(decline.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Note (required to decline)"), { target: { value: "too vague" } });
    expect(decline.disabled).toBe(false);
  });

  it("blocks a fact over the byte limit and counts bytes, not characters", async () => {
    serve([]);
    render(<NetworkContext />);
    fireEvent.change(await screen.findByLabelText("Short name"), { target: { value: "k" } });
    const save = screen.getByRole("button", { name: "Save draft" }) as HTMLButtonElement;
    fireEvent.change(screen.getByLabelText("The fact"), { target: { value: "é".repeat(1000) } });
    expect(screen.getByText("2000 / 2000 bytes")).toBeTruthy();
    expect(save.disabled).toBe(false);
    fireEvent.change(screen.getByLabelText("The fact"), { target: { value: "é".repeat(1000) + "a" } });
    expect(save.disabled).toBe(true);
  });

  it("creates a site-scoped draft from the form", async () => {
    serve([]);
    render(<NetworkContext />);
    fireEvent.change(await screen.findByLabelText("Site (leave empty for the whole network)"), { target: { value: "dfw-hq" } });
    fireEvent.change(screen.getByLabelText("Short name"), { target: { value: "window" } });
    fireEvent.change(screen.getByLabelText("The fact"), { target: { value: "Sundays 02:00 UTC" } });
    fireEvent.click(screen.getByRole("button", { name: "Save draft" }));
    await waitFor(() =>
      expect(orgContextCreate).toHaveBeenCalledWith({ scope: "site:dfw-hq", kind: "topology_note", key: "window", body: "Sundays 02:00 UTC" }),
    );
  });

  it("renders fact text as text, never as markup", async () => {
    serve([fact("f1", "alice", "pending", '<img src=x onerror="window.__nctx=1">')], "bob");
    const { container } = render(<NetworkContext />);
    expect(await screen.findAllByText('<img src=x onerror="window.__nctx=1">')).not.toHaveLength(0);
    expect(container.querySelector("img")).toBeNull();
  });

  it("shows exactly what Iris reads", async () => {
    serve([fact("f1", "alice", "active", "core-02 is DR", { approver: "bob" })], "alice", "CUSTOMER-DECLARED CONTEXT …\n- Network layout note (whole network) — dr: core-02 is DR");
    render(<NetworkContext />);
    expect((await screen.findByTestId("nctx-preview")).textContent).toContain("core-02 is DR");
  });

  it("restore and stop need a reason and call the right verb", async () => {
    const f = fact("f1", "alice", "superseded", "old text", { approver: "bob" });
    f.versions.push({ version: 2, body: "new text", body_sha256: "s2", state: "active", author: "carol", created_at: "2026-10-12T09:00:00Z", approver: "alice" } as never);
    serve([f], "alice");
    render(<NetworkContext />);
    const restore = (await screen.findByRole("button", { name: "Restore this version" })) as HTMLButtonElement;
    expect(restore.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Reason (required to stop using or restore)"), { target: { value: "v2 wrong" } });
    fireEvent.click(restore);
    await waitFor(() => expect(orgContextAct).toHaveBeenCalledWith("f1", "rollback", { to_version: 1, reason: "v2 wrong" }));
  });

  it("a failed read says so instead of showing an empty page", async () => {
    orgContext.mockRejectedValue(new Error("503 Service Unavailable: network context needs the Postgres platform store"));
    orgContextPreview.mockResolvedValue({ block: "", facts: 0, omitted: 0 });
    render(<NetworkContext />);
    expect(await screen.findByRole("alert")).toBeTruthy();
  });
});
