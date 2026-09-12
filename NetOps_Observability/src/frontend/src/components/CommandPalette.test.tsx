// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import CommandPalette from "./CommandPalette";
import { ShellContext, ShellState } from "../context/shell";
import { NAV } from "../nav";

// ⌘K palette + unified search (Wave 6 #20): grouped results, keyboard
// navigation, and permanent-URL navigation on Enter.

const unifiedSearch = vi.fn();
const globalSearch = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    unifiedSearch: (...a: unknown[]) => unifiedSearch(...a),
    globalSearch: (...a: unknown[]) => globalSearch(...a),
  },
}));

const navigate = vi.fn();

function shell(): ShellState {
  return {
    range: { minutes: 60, label: "1h" },
    setRange: () => {},
    query: "*",
    setQuery: () => {},
    copilotOpen: false,
    setCopilotOpen: () => {},
    helpOpen: false,
    setHelpOpen: () => {},
    helpPath: "",
    openHelp: () => {},
    navigate,
  } as unknown as ShellState;
}

function openPalette() {
  render(
    <ShellContext.Provider value={shell()}>
      <CommandPalette nav={NAV} />
    </ShellContext.Provider>,
  );
  fireEvent.keyDown(window, { key: "k", ctrlKey: true });
}

beforeEach(() => {
  unifiedSearch.mockReset();
  globalSearch.mockReset();
  navigate.mockReset();
  vi.useFakeTimers({ shouldAdvanceTime: true });
});
afterEach(() => {
  vi.useRealTimers();
  cleanup();
});

describe("CommandPalette unified search", () => {
  it("groups live results by kind with headers, deep-linking permanent URLs", async () => {
    unifiedSearch.mockResolvedValue({
      query: "checkout",
      results: [
        { kind: "resource", id: "i-1", label: "checkout-web-1", sublabel: "aws · 1111", href: "resource/cloud/i-1" },
        { kind: "app", id: "checkout", label: "Checkout", sublabel: "payments", href: "monitoring/appobs/services" },
        { kind: "device", id: "checkout-sw", label: "checkout-sw", href: "infrastructure/devices?q=checkout-sw" },
      ],
    });
    globalSearch.mockResolvedValue({ query: "checkout", results: [] });

    openPalette();
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "checkout" } });
    vi.advanceTimersByTime(250);
    await waitFor(() => expect(screen.getByText("checkout-web-1")).toBeInTheDocument());

    // group headers in canonical order: Devices before Resources before Services
    const headers = screen.getAllByText(/^(Devices|Resources|Services)$/).map((el) => el.textContent);
    expect(headers).toEqual(["Devices", "Resources", "Services"]);

    // clicking the resource row navigates to its PERMANENT URL
    fireEvent.click(screen.getByText("checkout-web-1"));
    expect(navigate).toHaveBeenCalledWith("resource/cloud/i-1");
  });

  it("legacy alert/saved kinds ride along from the global resolver", async () => {
    unifiedSearch.mockResolvedValue({ query: "cpu", results: [] });
    globalSearch.mockResolvedValue({
      query: "cpu",
      results: [{ kind: "alert", id: "a1", title: "CPU high on edge-1", sub: "critical", route: "monitoring/triggered" }],
    });

    openPalette();
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "cpu high" } });
    vi.advanceTimersByTime(250);
    await waitFor(() => expect(screen.getByText("CPU high on edge-1")).toBeInTheDocument());
    expect(screen.getByText("Alerts")).toBeInTheDocument();
  });

  it("a failing search backend degrades to nav commands, never an error state", async () => {
    unifiedSearch.mockRejectedValue(new Error("500"));
    globalSearch.mockRejectedValue(new Error("500"));

    openPalette();
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "devices" } });
    vi.advanceTimersByTime(250);
    // nav destinations still filter/match; the logs handoff row is present
    await waitFor(() => expect(screen.getByText(/Search logs for/)).toBeInTheDocument());
  });
});
