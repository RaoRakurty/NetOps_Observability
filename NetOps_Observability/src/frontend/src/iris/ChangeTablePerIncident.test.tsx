// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ChangeTablePerIncident.test.tsx — N-S3: "what changed 30 minutes before every
// SD-WAN incident this week". Rows are grouped by incident, each group links to
// its root-cause analysis, every row states how long before onset it happened,
// and the relation is never worded as a cause.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup, within } from "@testing-library/react";
import ChangeTable from "./ChangeTable";
import { defaultPlanFor, normalizeResult, type ResultSet } from "./presentation";
import { beforeOnsetText, isPerIncidentRow, relationText } from "./changes";
import { HOSTILE, baseResult, changeRow } from "../test/irisFixtures";

afterEach(cleanup);

const incA = "aaaaaaaa-0000-0000-0000-000000000001";
const incB = "bbbbbbbb-0000-0000-0000-000000000002";

function near(over: Record<string, unknown>) {
  return changeRow({ minutes_before_incident: 12, incident_id: incA, incident_display_id: "P-AAA001", incident_title: "SD-WAN tunnels down at site 80", ...over });
}

const rows = [
  near({ change_id: "chg-1042", relation: "chain_kind", chain_kind: "device_config_change", chain_step: 1 }),
  near({ change_id: "chg-1043", relation: "temporal", minutes_before_incident: 20 }),
  near({ change_id: "chg-1049", relation: "temporal", minutes_before_incident: 5, incident_id: incB, incident_display_id: "P-BBB002", incident_title: "BFD flaps on mpls" }),
];

describe("per-incident change wording", () => {
  it("never words a chain-kind match as a cause", () => {
    expect(relationText({ relation: "chain_kind" })).toBe("Same kind as a root-cause step — not proven cause");
    expect(relationText({ relation: "temporal" })).toBe("Happened before — not proven cause");
  });

  it("states the time before onset", () => {
    expect(beforeOnsetText({ minutes_before_incident: 12 })).toBe("12 min before onset");
    expect(beforeOnsetText({ minutes_before_incident: 0 })).toBe("At onset");
    expect(beforeOnsetText({ minutes_before_incident: -3 })).toBe("3 min after onset");
    expect(beforeOnsetText({ minutes_before_incident: HOSTILE })).toBeNull();
    expect(beforeOnsetText({})).toBeNull();
  });

  it("recognises only rows that name their incident", () => {
    expect(isPerIncidentRow(rows[0])).toBe(true);
    expect(isPerIncidentRow(changeRow())).toBe(false);
    expect(isPerIncidentRow(changeRow({ incident_id: incA }))).toBe(false);
  });
});

describe("ChangeTable grouped by incident", () => {
  it("renders one section per incident, in result order, each linked to its RCA", () => {
    render(<ChangeTable rows={rows} />);
    const sections = screen.getAllByRole("region");
    expect(sections.map((s) => s.getAttribute("aria-label"))).toEqual(["Changes before P-AAA001", "Changes before P-BBB002"]);
    const link = within(sections[0]).getByRole("link", { name: "P-AAA001" });
    expect(link.getAttribute("href")).toBe(`/#/investigate/rca?id=${incA}`);
    expect(within(sections[0]).getByText(/2 changes before it/)).toBeInTheDocument();
    expect(within(sections[1]).getByText(/1 change before it/)).toBeInTheDocument();
  });

  it("adds the Before onset column and words both relations honestly", () => {
    render(<ChangeTable rows={rows} />);
    const sec = screen.getAllByRole("region")[0];
    const headers = within(sec).getAllByRole("columnheader").map((h) => h.textContent?.replace(/[↕▲▼]/g, "").trim());
    expect(headers.slice(0, 2)).toEqual(["Time", "Before onset"]);
    expect(within(sec).getByText("12 min before onset")).toBeInTheDocument();
    expect(within(sec).getByText("Same kind as a root-cause step — not proven cause")).toBeInTheDocument();
    expect(within(sec).getByText("Happened before — not proven cause")).toBeInTheDocument();
    expect(screen.queryByText(/caused/i)).toBeNull();
  });

  it("keeps hostile incident text as text", () => {
    render(<ChangeTable rows={[near({ incident_title: HOSTILE, incident_display_id: HOSTILE })]} />);
    expect(document.querySelector("script")).toBeNull();
    expect(document.querySelector("img[onerror]")).toBeNull();
  });

  it("is the plain table when rows do not name an incident", () => {
    render(<ChangeTable rows={[changeRow()]} />);
    expect(screen.queryByRole("region")).toBeNull();
    expect(screen.queryByRole("columnheader", { name: /Before onset/ })).toBeNull();
  });
});

describe("default plan", () => {
  function result(rs: Record<string, unknown>[]): ResultSet {
    const n = normalizeResult(baseResult({ query_type: "change_list", rows: rs }));
    if (!n.ok) throw new Error("fixture");
    return n.result;
  }

  it("draws per-incident changes as the grouped table first", () => {
    const p = defaultPlanFor(result(rows));
    expect(p.primary_view).toBe("TABLE");
    expect(p.secondary_view).toBe("TIMELINE");
    expect(p.title).toBe("Changes before each incident");
  });

  it("keeps the timeline for an ordinary change list", () => {
    expect(defaultPlanFor(result([changeRow(), changeRow({ change_id: "c2" })])).primary_view).toBe("TIMELINE");
  });
});
