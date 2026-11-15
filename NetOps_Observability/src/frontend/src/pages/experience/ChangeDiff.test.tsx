// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";

const changeDiff = vi.fn();
vi.mock("../../services/api", () => ({ api: { changeDiff: (...a: unknown[]) => changeDiff(...a) } }));

import ChangeDiff from "./ChangeDiff";

// Braces matter: a function RETURNED from beforeEach is run as a teardown, and
// mockReset() returns the mock — which would call it once more after the test.
beforeEach(() => {
  changeDiff.mockReset();
});
afterEach(() => cleanup());

describe("ChangeDiff", () => {
  it("loads on demand and shows a configuration diff as text", async () => {
    changeDiff.mockResolvedValue({ change_id: "c1", kind: "config", diff: {
      device_id: "edge-1", from_version: "a", to_version: "b", from_at: "", to_at: "", added: 1, removed: 0,
      unified: "+ <img src=x onerror=alert(1)>", truncated: false } });
    render(<ChangeDiff id="c1" />);
    expect(changeDiff).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("What changed"));
    expect(await screen.findByText(/\+1 \/ −0 lines/)).toBeInTheDocument();
    expect(changeDiff).toHaveBeenCalledWith("c1");
    expect(screen.getByTestId("change-diff").querySelector("img")).toBeNull();
    expect(screen.getByTestId("change-diff")).toHaveTextContent("<img src=x onerror=alert(1)>");
  });

  it("says when no comparison exists", async () => {
    changeDiff.mockResolvedValue({ change_id: "c1", kind: "config", diff: { unavailable: "configuration backup is not enabled on this deployment" } });
    render(<ChangeDiff id="c1" />);
    fireEvent.click(screen.getByText("What changed"));
    expect(await screen.findByText(/not enabled/)).toBeInTheDocument();
  });

  it("shows a value change and an operator-safe error", async () => {
    changeDiff.mockResolvedValueOnce({ change_id: "c2", kind: "values", before: "mtu 1500", after: "mtu 9000" });
    render(<ChangeDiff id="c2" />);
    fireEvent.click(screen.getByText("What changed"));
    expect(await screen.findByText("mtu 1500 → mtu 9000")).toBeInTheDocument();
    cleanup();
    changeDiff.mockRejectedValueOnce(new Error('502 Bad Gateway: {"error":"dial tcp 172.18.0.9:8080"}'));
    render(<ChangeDiff id="c3" />);
    fireEvent.click(screen.getByText("What changed"));
    const alert = await screen.findByRole("alert");
    expect(alert).not.toHaveTextContent("172.18.0.9");
  });

  it("reads once on arrival when opened by Iris, and the button still hides it", async () => {
    changeDiff.mockResolvedValue({ change_id: "c4", kind: "values", before: "a", after: "b" });
    render(<ChangeDiff id="c4" initiallyOpen />);
    expect(await screen.findByText("a → b")).toBeInTheDocument();
    expect(changeDiff).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByText("Hide"));
    expect(screen.queryByText("a → b")).toBeNull();
    fireEvent.click(screen.getByText("What changed"));
    expect(screen.getByText("a → b")).toBeInTheDocument();
    expect(changeDiff).toHaveBeenCalledTimes(1); // no second read
  });

  it("says another workspace's change (404) is not in yours, never a diff", async () => {
    changeDiff.mockRejectedValue(new Error("404 Not Found: not found"));
    render(<ChangeDiff id="chg-b" initiallyOpen />);
    expect(await screen.findByRole("alert")).toHaveTextContent("This change is not in your workspace, or it no longer exists.");
  });
});
