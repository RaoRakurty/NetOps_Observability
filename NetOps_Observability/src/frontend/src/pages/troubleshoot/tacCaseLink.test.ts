// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// tacCaseLink.test.ts — the client-side mirror of Go's CaseLink.StatusLine and
// CaseLink.Tooltip, checked against the SAME behaviour cases
// src/backend/internal/tac/caselink_test.go asserts.
//
// WHY THE MIRROR NEEDS ITS OWN TEST. The chip renders in three places from data
// already on the page, so the sentence is computed on the client rather than
// fetched three times. The moment those two implementations disagree the
// product tells an operator two different things about one case — and the
// disagreement that matters most is the one caselink.go exists to prevent: a
// FAILED read must never be painted as the status it last saw.
//
// Every case below names the Go test it mirrors. When one of them changes in
// Go, this file is where it is meant to fail.

import { describe, it, expect } from "vitest";
import type { TacCaseLink } from "../../services/api";
import {
  CASE_CHIP_TONE,
  CASE_UNKNOWN_ON_RECORD,
  canRefresh,
  caseChipState,
  caseLinkFromIncident,
  caseStatusLine,
  caseStatusReadsClosed,
  caseTooltip,
  clipText,
  isZeroTime,
  utcStamp,
} from "./tacModel";

/** caselink_test.go's `at(h, m)` — 2026-09-07 in UTC. */
const at = (h: number, m: number): string =>
  `2026-09-07T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:00Z`;

const link = (over: Partial<TacCaseLink> = {}): TacCaseLink => ({
  connector: "juniper",
  opened_at: at(9, 0),
  tier: "routine",
  attached: false,
  pollable: false,
  closed: false,
  ...over,
});

describe("StatusLine mirrors internal/tac/caselink.go", () => {
  // TestStatusLineNeverShowsAStaleGreen.
  it("never shows a stale status after a failed read", () => {
    const l = link({
      connector: "juniper", case_id: "2026-0907-1234", status: "Open",
      last_checked_at: at(9, 41), last_error: "the vendor returned 503",
    });
    const line = caseStatusLine(l);
    expect(line).not.toContain("Open");
    expect(line).toContain("status unknown since");
    expect(line).toContain("503");
    // The stamp is Go's `15:04 MST on 2 Jan`, in UTC, character for character.
    expect(line).toContain("09:41 UTC on 7 Sep");
  });

  // A failed read with no successful read behind it says so, rather than
  // rendering an empty "since".
  it("says 'just now' when nothing has ever been read successfully", () => {
    const l = link({ case_id: "SR-1", last_error: "the vendor returned 503" });
    expect(caseStatusLine(l)).toBe("SR-1 · status unknown since just now — the vendor returned 503");
  });

  // TestStatusLineIsHonestAboutAnEmailOpenedCase.
  it("is honest about an email-opened case with no number", () => {
    expect(caseStatusLine(link({ connector: "email-arista" })))
      .toBe("opened by email · number pending");
  });

  // TestStatusLineRendersTheCaseAndItsStatus.
  it("renders the case and its status, and 'opened' when the vendor gave none", () => {
    expect(caseStatusLine(link({ case_id: "2026-0907-1234", status: "In Progress" })))
      .toBe("2026-0907-1234 · In Progress");
    expect(caseStatusLine(link({ case_id: "2026-0907-1234" })))
      .toBe("2026-0907-1234 · opened");
  });

  it("a case that was prepared and never opened says exactly that", () => {
    expect(caseStatusLine(link({ connector: "cisco-smart-bonding" })))
      .toBe("prepared · not yet opened");
    expect(caseStatusLine(null)).toBe("prepared · not yet opened");
  });

  // Go clips the cause at 120 bytes and appends an ellipsis.
  it("clips a long cause exactly the way Go does", () => {
    const long = "x".repeat(200);
    expect(clipText(long, 120)).toBe(`${"x".repeat(120)}…`);
    expect(caseStatusLine(link({ case_id: "SR-1", last_error: long })))
      .toContain(`${"x".repeat(120)}…`);
    expect(clipText("short", 120)).toBe("short");
  });
});

describe("Tooltip mirrors internal/tac/caselink.go", () => {
  // TestTooltipShowsAuthModeAndCadence.
  it("carries the connector, how it authenticated and how often it refreshes", () => {
    const l = link({
      connector: "cisco-smart-bonding", vendor: "cisco", case_id: "689123456",
      severity: "S1", status: "Open", pollable: true, auth_mode: "oauth",
      cadence_label: "2 min", last_checked_at: at(9, 0), tier: "emergency",
    });
    const tip = caseTooltip(l);
    for (const want of ["via cisco-smart-bonding", "authenticated with oauth", "refreshing every 2 min"]) {
      expect(tip).toContain(want);
    }
    expect(tip).toContain("last refreshed 09:00 UTC on 7 Sep");
  });

  it("a closed case says it is no longer refreshing", () => {
    const l = link({ closed: true, pollable: true, cadence_label: "2 min" });
    expect(caseTooltip(l)).toContain("closed — no longer refreshing");
    expect(caseTooltip(l)).not.toContain("refreshing every");
  });

  it("a path that publishes no status read says so instead of a cadence", () => {
    expect(caseTooltip(link({ pollable: false, cadence_label: "2 min" })))
      .toContain("publishes no status read");
  });

  // The degraded cadence must reach the operator, or a case that stopped moving
  // looks broken rather than throttled.
  it("carries the reason a cadence is not the tier's own", () => {
    const l = link({ pollable: true, cadence_label: "5 min", cadence_note: "vendor rate limit" });
    expect(caseTooltip(l)).toContain("refreshing every 5 min · vendor rate limit");
  });

  // An empty link still says the one true thing about it: nothing on this path
  // reads a status back. Go words it the same way, from the same branch.
  it("says the one true thing about a link carrying nothing else", () => {
    expect(caseTooltip(link({ connector: "" })))
      .toBe("this path publishes no status read; refresh it in the vendor's portal");
    expect(caseTooltip(null)).toBe("");
  });
});

describe("the four chip states", () => {
  it("names each state, and never paints a failed read as its last status", () => {
    expect(caseChipState(link({ connector: "email-arista" }))).toBe("pending-number");
    expect(caseChipState(link({ connector: "juniper" }))).toBe("not-opened");
    expect(caseChipState(link({ case_id: "SR-1", status: "Open" }))).toBe("open");
    expect(caseChipState(link({ case_id: "SR-1", status: "Open", last_error: "503" }))).toBe("unknown");
    expect(caseChipState(null)).toBe("not-opened");
  });

  it("gives every state a tone, and only the failed read the bad one", () => {
    expect(Object.keys(CASE_CHIP_TONE).sort())
      .toEqual(["not-opened", "open", "pending-number", "unknown"]);
    expect(CASE_CHIP_TONE.unknown).toContain("failed");
    expect(CASE_CHIP_TONE.open).toContain("done");
  });
});

describe("the refresh control is offered only where it could work", () => {
  it("needs a number, a pollable path and an open case", () => {
    expect(canRefresh(link({ case_id: "SR-1", pollable: true }))).toBe(true);
    expect(canRefresh(link({ case_id: "", pollable: true }))).toBe(false);
    expect(canRefresh(link({ case_id: "SR-1", pollable: false }))).toBe(false);
    expect(canRefresh(link({ case_id: "SR-1", pollable: true, closed: true }))).toBe(false);
    expect(canRefresh(null)).toBe(false);
  });
});

describe("CaseStatusClosed mirrors the Go vocabulary", () => {
  it("is generous about the words and conservative about the answer", () => {
    for (const s of ["Closed", "resolved", "Complete", "cancelled", "canceled", "Done"]) {
      expect(caseStatusReadsClosed(s)).toBe(true);
    }
    for (const s of ["", "Open", "In Progress", "Awaiting customer"]) {
      expect(caseStatusReadsClosed(s)).toBe(false);
    }
  });
});

describe("an incident row's own case", () => {
  it("maps a TAC connector's ticket onto the chip", () => {
    const l = caseLinkFromIncident({
      external_system: "cisco-smart-bonding",
      external_ticket_id: "689123456",
      external_url: "https://mycase.cloudapps.cisco.com/689123456",
      sync_status: "In Progress",
      last_synced_at: at(9, 41),
    });
    expect(l).not.toBeNull();
    expect(caseStatusLine(l)).toBe("689123456 · In Progress");
  });

  it("a failed read on the row says what the ROW knows and no more", () => {
    const l = caseLinkFromIncident({
      external_system: "juniper", external_ticket_id: "2026-0907-1234",
      sync_status: "unknown", last_synced_at: at(9, 41),
    });
    const line = caseStatusLine(l);
    expect(line).toContain("status unknown since 09:41 UTC on 7 Sep");
    expect(line).toContain(CASE_UNKNOWN_ON_RECORD);
  });

  it("'opened' on the row is the absence of a vendor status, not a status", () => {
    const l = caseLinkFromIncident({
      external_system: "juniper", external_ticket_id: "SR-9", sync_status: "opened",
    });
    expect(caseStatusLine(l)).toBe("SR-9 · opened");
  });

  // The ITSM projection files its own tickets through the same three fields.
  // Painting one of those as a vendor case would be a claim nobody made.
  it("refuses a ticket that did not come from a TAC vendor connector", () => {
    // ServiceNow and Jira are ambiguous — the auto-ticketing projection writes
    // the same three fields under the same names — so those rows keep the ITSM
    // pill they have always had.
    expect(caseLinkFromIncident({ external_system: "servicenow", external_ticket_id: "INC0012" })).toBeNull();
    expect(caseLinkFromIncident({ external_system: "jira", external_ticket_id: "NET-12" })).toBeNull();
    expect(caseLinkFromIncident({ external_system: "pagerduty", external_ticket_id: "P1" })).toBeNull();
    expect(caseLinkFromIncident({ external_system: "", external_ticket_id: "" })).toBeNull();
  });
});

describe("timestamps", () => {
  it("treats Go's zero time, a blank and an unparseable value as absent", () => {
    expect(isZeroTime("0001-01-01T00:00:00Z")).toBe(true);
    expect(isZeroTime("")).toBe(true);
    expect(isZeroTime(undefined)).toBe(true);
    expect(isZeroTime("not a time")).toBe(true);
    expect(isZeroTime(at(9, 0))).toBe(false);
    expect(utcStamp("")).toBe("");
  });

  it("renders in UTC whatever the reader's zone is", () => {
    expect(utcStamp("2026-01-02T23:05:00Z")).toBe("23:05 UTC on 2 Jan");
    expect(utcStamp("2026-12-31T00:00:00Z")).toBe("00:00 UTC on 31 Dec");
  });
});
