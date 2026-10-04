// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";

const changeDiff = vi.fn();
vi.mock("../../services/api", () => ({ api: { changeDiff: (...a: unknown[]) => changeDiff(...a) } }));

import ChangeDiff from "./ChangeDiff";

beforeEach(() => changeDiff.mockReset());
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
});
