// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import type { CorsOriginsView } from "../../services/api";
import { lineProblem, parseLines, problems, sourceLine } from "./corsOriginsModel";

const view = (o: Partial<CorsOriginsView> = {}): CorsOriginsView => ({
  origins: [],
  source: "none",
  env_origins: [],
  env_dropped: [],
  max_origins: 50,
  ...o,
});

const apiMock = vi.hoisted(() => ({
  corsOrigins: vi.fn(),
  saveCorsOrigins: vi.fn(),
  resetCorsOrigins: vi.fn(),
}));
vi.mock("../../services/api", () => ({ api: apiMock }));

import CorsOrigins from "./CorsOrigins";

describe("corsOriginsModel", () => {
  it("reads one address per line, ignoring blank lines", () => {
    expect(parseLines(" https://a.example.com \n\n https://b.example.com:8443\r\n")).toEqual([
      "https://a.example.com",
      "https://b.example.com:8443",
    ]);
  });

  it("names the mistake on each bad line, like the server", () => {
    expect(lineProblem("https://shop.example.com")).toBe("");
    expect(lineProblem("https://shop.example.com/")).toBe("");
    expect(lineProblem("http://localhost:5173")).toBe("");
    expect(lineProblem("*")).toMatch(/wildcard/);
    expect(lineProblem("https://*.example.com")).toMatch(/wildcard/);
    expect(lineProblem("http://shop.example.com")).toMatch(/use https/);
    expect(lineProblem("https://shop.example.com/checkout")).toMatch(/no path/);
    expect(lineProblem("https://u:p@shop.example.com")).toMatch(/password/);
    expect(lineProblem("ftp://shop.example.com")).toMatch(/https:\/\//);
    expect(lineProblem("shop.example.com")).toMatch(/write it like/);
    expect(lineProblem("https://shop.example.com?x=1")).toMatch(/only a scheme/);
    expect(problems(["https://a.example.com", "*"], 50)).toEqual(["* — no wildcards — list each app's address"]);
    expect(problems(["https://a.example.com", "https://b.example.com"], 1)).toEqual(["2 addresses — at most 1"]);
  });

  it("says where the list in force comes from", () => {
    expect(sourceLine(view({ source: "env", origins: ["https://a.example.com"] }))).toMatch(/installation/);
    expect(sourceLine(view({ source: "saved", origins: ["https://a.example.com"] }))).toMatch(/Saved here/);
    expect(sourceLine(view({ source: "saved", origins: [] }))).toMatch(/no app may send/);
    expect(sourceLine(view({ source: "none" }))).toMatch(/No app may send/);
  });
});

describe("CorsOrigins page", () => {
  beforeEach(() => {
    apiMock.corsOrigins.mockReset();
    apiMock.saveCorsOrigins.mockReset();
    apiMock.resetCorsOrigins.mockReset();
  });

  it("shows the list in force and saves a new one", async () => {
    apiMock.corsOrigins.mockResolvedValue(view({ source: "env", origins: ["https://env.example.com"], env_origins: ["https://env.example.com"] }));
    apiMock.saveCorsOrigins.mockResolvedValue(
      view({ source: "saved", origins: ["https://shop.example.com"], env_origins: ["https://env.example.com"], updated_by: "admin", updated_at: "2026-11-23T12:00:00Z" }),
    );
    render(<CorsOrigins />);
    const box = (await screen.findByTestId("cors-origins-input")) as HTMLTextAreaElement;
    expect(box.value).toBe("https://env.example.com");
    expect(screen.getByTestId("cors-source").textContent).toMatch(/installation/);
    const save = screen.getByRole("button", { name: "Save" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true); // nothing changed yet
    fireEvent.change(box, { target: { value: "https://shop.example.com\n" } });
    expect(save.disabled).toBe(false);
    fireEvent.click(save);
    await waitFor(() => expect(apiMock.saveCorsOrigins).toHaveBeenCalledWith(["https://shop.example.com"]));
    expect(await screen.findByText("Saved. In use now.")).toBeTruthy();
    expect(screen.getByText(/Last changed by admin/)).toBeTruthy();
  });

  it("will not send a list with a wildcard, and names the bad line", async () => {
    apiMock.corsOrigins.mockResolvedValue(view());
    render(<CorsOrigins />);
    const box = await screen.findByTestId("cors-origins-input");
    fireEvent.change(box, { target: { value: "https://ok.example.com\n*" } });
    expect(screen.getByTestId("cors-problems").textContent).toMatch(/no wildcards/);
    expect((screen.getByRole("button", { name: "Save" }) as HTMLButtonElement).disabled).toBe(true);
    expect(apiMock.saveCorsOrigins).not.toHaveBeenCalled();
  });

  it("says nothing changed when the server refuses the save", async () => {
    apiMock.corsOrigins.mockResolvedValue(view());
    apiMock.saveCorsOrigins.mockRejectedValue(new Error("500 Internal Server Error: the change was not made: the audit trail could not record it"));
    render(<CorsOrigins />);
    fireEvent.change(await screen.findByTestId("cors-origins-input"), { target: { value: "https://shop.example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect((screen.getByTestId("cors-origins-input") as HTMLTextAreaElement).value).toBe("https://shop.example.com");
  });

  it("returns to the installation value", async () => {
    apiMock.corsOrigins.mockResolvedValue(view({ source: "saved", origins: [], env_origins: ["https://env.example.com"] }));
    apiMock.resetCorsOrigins.mockResolvedValue(view({ source: "env", origins: ["https://env.example.com"], env_origins: ["https://env.example.com"] }));
    render(<CorsOrigins />);
    fireEvent.click(await screen.findByRole("button", { name: /Use the installation value \(1\)/ }));
    await waitFor(() => expect(apiMock.resetCorsOrigins).toHaveBeenCalled());
    expect(((await screen.findByTestId("cors-origins-input")) as HTMLTextAreaElement).value).toBe("https://env.example.com");
    // Already on the installation value: no reset button.
    expect(screen.queryByRole("button", { name: /Use the installation value/ })).toBeNull();
  });

  it("reports refused installation entries", async () => {
    apiMock.corsOrigins.mockResolvedValue(view({ source: "env", env_dropped: ['invalid web address: "*" — wildcards are never allowed'] }));
    render(<CorsOrigins />);
    expect((await screen.findByTestId("env-dropped")).textContent).toMatch(/wildcards/);
  });

  it("a non-platform-admin reads 'denied', not a failure", async () => {
    apiMock.corsOrigins.mockRejectedValue(new Error("403 Forbidden: forbidden"));
    render(<CorsOrigins />);
    expect(await screen.findByText("Only the platform administrator can change cross-origin access.")).toBeTruthy();
  });
});
