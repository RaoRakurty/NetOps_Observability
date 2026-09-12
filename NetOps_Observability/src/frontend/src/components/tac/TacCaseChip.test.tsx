// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TacCaseChip.test.tsx — the vendor case, as one line, in its four states.
//
// The rule under test is the one internal/tac/caselink.go exists to keep: a
// FAILED status read renders "status unknown since <time> — <cause>", never the
// status it last saw. Everything else here is the honest wording of the other
// three states, and the 60-second manual-refresh floor being reported as a WAIT
// rather than as a failure.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, act } from "@testing-library/react";
import type { TacCaseLink } from "../../services/api";

const tacCaseRefresh = vi.fn();
vi.mock("../../services/api", () => ({ api: { tacCaseRefresh: (...a: unknown[]) => tacCaseRefresh(...a) } }));

import TacCaseChip, { REFRESH_LABEL } from "./TacCaseChip";

const INC = "corr-abc1234567890";
const at = (h: number, m: number) => `2026-09-07T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:00Z`;

const link = (over: Partial<TacCaseLink> = {}): TacCaseLink => ({
  connector: "juniper",
  opened_at: at(9, 0),
  tier: "routine",
  attached: false,
  pollable: false,
  closed: false,
  ...over,
});

beforeEach(() => { tacCaseRefresh.mockReset(); });
afterEach(() => cleanup());

describe("the four states the chip renders", () => {
  it("1 · an open case: the number and the vendor's own status", () => {
    render(<TacCaseChip link={link({ case_id: "2026-0907-1234", status: "In Progress" })} />);
    expect(screen.getByTestId("tac-case-line")).toHaveTextContent("2026-0907-1234 · In Progress");
    expect(screen.getByTestId("tac-case-chip").getAttribute("data-state")).toBe("open");
  });

  it("2 · a failed read: unknown SINCE a time, with the cause, never the stale status", () => {
    render(<TacCaseChip link={link({
      case_id: "2026-0907-1234", status: "Open",
      last_checked_at: at(9, 41), last_error: "the vendor returned 503",
    })} />);
    const line = screen.getByTestId("tac-case-line");
    expect(line).toHaveTextContent("status unknown since 09:41 UTC on 7 Sep — the vendor returned 503");
    expect(line.textContent).not.toContain("Open");
    expect(screen.getByTestId("tac-case-chip").getAttribute("data-state")).toBe("unknown");
  });

  it("3 · an email-opened case with no number: the number is pending, not invented", () => {
    render(<TacCaseChip link={link({ connector: "email-arista" })} />);
    expect(screen.getByTestId("tac-case-line")).toHaveTextContent("opened by email · number pending");
    expect(screen.getByTestId("tac-case-chip").getAttribute("data-state")).toBe("pending-number");
  });

  it("4 · prepared and not opened: exactly that", () => {
    render(<TacCaseChip link={link({ connector: "cisco-smart-bonding" })} />);
    expect(screen.getByTestId("tac-case-line")).toHaveTextContent("prepared · not yet opened");
    expect(screen.getByTestId("tac-case-chip").getAttribute("data-state")).toBe("not-opened");
  });

  it("renders nothing at all when there is no case", () => {
    const { container } = render(<TacCaseChip link={null} />);
    expect(container.textContent).toBe("");
  });
});

describe("the server's own sentence wins where there is one", () => {
  // The state read, the confirm reply and the refresh reply all carry the chip
  // strings from the SAME Go functions. Preferring them is what keeps a
  // rewording to one place.
  it("renders the server's status_line and tooltip over the client mirror", () => {
    render(<TacCaseChip
      link={link({ case_id: "SR-9", status: "Open" })}
      statusLine="SR-9 · Awaiting customer"
      tooltip="via cisco-cxd · authenticated with basic"
    />);
    expect(screen.getByTestId("tac-case-line")).toHaveTextContent("SR-9 · Awaiting customer");
    expect(screen.getByTestId("tac-case-line").getAttribute("title"))
      .toBe("via cisco-cxd · authenticated with basic");
  });

  it("falls back to the mirror when the caller has no server string", () => {
    render(<TacCaseChip link={link({ case_id: "SR-9", status: "Open" })} statusLine="  " />);
    expect(screen.getByTestId("tac-case-line")).toHaveTextContent("SR-9 · Open");
  });

  it("takes the refresh reply's own strings", async () => {
    tacCaseRefresh.mockResolvedValue({
      case: link({ case_id: "SR-9", status: "Closed", pollable: true }),
      status_line: "SR-9 · Closed", tooltip: "closed — no longer refreshing",
    });
    render(<TacCaseChip link={link({ case_id: "SR-9", status: "Open", pollable: true })} incidentId={INC} />);
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: REFRESH_LABEL })); });
    await waitFor(() => expect(screen.getByTestId("tac-case-line")).toHaveTextContent("SR-9 · Closed"));
  });
});

describe("the tooltip", () => {
  it("says how it authenticated and how often it refreshes", () => {
    render(<TacCaseChip link={link({
      connector: "cisco-smart-bonding", case_id: "689123456", status: "Open",
      pollable: true, auth_mode: "oauth", cadence_label: "2 min", last_checked_at: at(9, 0),
    })} />);
    const title = screen.getByTestId("tac-case-line").getAttribute("title") ?? "";
    expect(title).toContain("via cisco-smart-bonding");
    expect(title).toContain("authenticated with oauth");
    expect(title).toContain("refreshing every 2 min");
    expect(title).toContain("last refreshed 09:00 UTC on 7 Sep");
  });
});

describe("Refresh now", () => {
  const open = link({ case_id: "SR-9", status: "Open", pollable: true });

  it("is offered only where the path can read a status back", () => {
    const { unmount } = render(<TacCaseChip link={open} incidentId={INC} />);
    expect(screen.getByTestId("tac-case-refresh")).toBeInTheDocument();
    unmount();
    render(<TacCaseChip link={link({ case_id: "SR-9", pollable: false })} incidentId={INC} />);
    expect(screen.queryByTestId("tac-case-refresh")).toBeNull();
  });

  it("is never offered in the list rendering — a row is not a control surface", () => {
    render(<TacCaseChip link={open} incidentId={INC} compact />);
    expect(screen.queryByTestId("tac-case-refresh")).toBeNull();
  });

  it("re-reads the case and hands the caller the SERVER's answer", async () => {
    const next = { ...open, status: "Closed", last_checked_at: at(10, 0) };
    tacCaseRefresh.mockResolvedValue({ case: next, status_line: "SR-9 · Closed", tooltip: "" });
    const onRefreshed = vi.fn();
    render(<TacCaseChip link={open} incidentId={INC} onRefreshed={onRefreshed} />);
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: REFRESH_LABEL })); });
    expect(tacCaseRefresh).toHaveBeenCalledWith(INC);
    await waitFor(() => expect(onRefreshed).toHaveBeenCalledWith(next));
  });

  // The 60-second floor is the vendor's rate limit being protected, and the
  // server says how long. It is a WAIT, not a failure, and it must not be
  // rendered as one.
  it("renders the server's own wait on a 429 instead of an error", async () => {
    tacCaseRefresh.mockRejectedValue(new Error(
      '429 Too Many Requests: {"error":"this case was refreshed less than a minute ago; try again in 43 seconds"}',
    ));
    render(<TacCaseChip link={open} incidentId={INC} />);
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: REFRESH_LABEL })); });
    const note = await screen.findByTestId("tac-case-refresh-note");
    expect(note).toHaveTextContent("try again in 43 seconds");
    expect(note.getAttribute("role")).toBe("status");
  });

  it("a read that failed for another reason says what did not happen", async () => {
    tacCaseRefresh.mockRejectedValue(new Error("503 Service Unavailable: {}"));
    render(<TacCaseChip link={open} incidentId={INC} />);
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: REFRESH_LABEL })); });
    expect(await screen.findByTestId("tac-case-refresh-note")).toHaveTextContent(/did not answer|could not be read/i);
  });
});

describe("the deep link", () => {
  it("renders only an https link — a vendor string cannot become a target", () => {
    const { unmount } = render(<TacCaseChip link={link({
      case_id: "SR-9", case_url: "https://vendor.example/case/SR-9",
    })} />);
    expect(screen.getByTestId("tac-case-link")).toHaveAttribute("href", "https://vendor.example/case/SR-9");
    unmount();
    // eslint-disable-next-line no-script-url
    render(<TacCaseChip link={link({ case_id: "SR-9", case_url: "javascript:alert(1)" })} />);
    expect(screen.queryByTestId("tac-case-link")).toBeNull();
  });

  it("renders a hostile status as TEXT, never as markup (§15 LLM02)", () => {
    render(<TacCaseChip link={link({ case_id: "SR-9", status: "<img src=x onerror=alert(1)>" })} />);
    const line = screen.getByTestId("tac-case-line");
    expect(line.querySelector("img")).toBeNull();
    expect(line.textContent).toContain("<img src=x onerror=alert(1)>");
  });
});
