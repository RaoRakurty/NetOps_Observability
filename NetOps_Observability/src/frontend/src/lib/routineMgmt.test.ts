// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, afterEach, vi } from "vitest";
import {
  ROUTINE_RULES, ROUTINE_STORAGE_KEY, loadShowRoutine, routineNote, routineReason, saveShowRoutine,
} from "./routineMgmt";
import { toEventView } from "./eventModel";

afterEach(() => {
  vi.restoreAllMocks();
  try { window.localStorage.clear(); } catch { /* jsdom always has it */ }
});

describe("routineReason: one plain line per server rule", () => {
  it("words each rule the server names, and nothing else", () => {
    expect(routineReason([ROUTINE_RULES.poll])).toMatch(/^Routine: an SNMP monitoring poll/);
    expect(routineReason([ROUTINE_RULES.monitoring])).toMatch(/Correlix's own address/);
    expect(routineReason([ROUTINE_RULES.controller])).toMatch(/SD-WAN controller/);
    expect(routineReason([ROUTINE_RULES.detail])).toMatch(/login that opened it is shown on its own/);
    expect(routineReason(["some_other_named_query"])).toBeNull();
    expect(routineReason([])).toBeNull();
    expect(routineReason(undefined)).toBeNull();
    expect(routineReason(null)).toBeNull();
  });

  it("the event view carries the reason only for a record the server classed", () => {
    const src = { timestamp: "2026-11-11T09:00:00Z", hostname: "vEdge-51", event_category: "management_audit", event_type: "audit_session_created_snmp", message: "audit user: x/1 created new session via snmp" };
    const routine = toEventView({ _index: "netops-syslog-acme-2026.11.11", _id: "r1", _source: src, matched_queries: [ROUTINE_RULES.poll] });
    expect(routine.routineReason).toMatch(/SNMP monitoring poll/);
    // The same record without the server's word is NOT guessed routine here.
    expect(toEventView({ _index: "netops-syslog-acme-2026.11.11", _id: "r1", _source: src }).routineReason).toBeNull();
  });
});

describe("routineNote: what the toggle says", () => {
  it("says how many were hidden or shown, with the right plural", () => {
    expect(routineNote({ included: false, count: 1234 })).toBe("1,234 routine management sessions hidden.");
    expect(routineNote({ included: false, count: 1 })).toBe("1 routine management session hidden.");
    expect(routineNote({ included: true, count: 10617 })).toBe("Includes 10,617 routine management sessions.");
    expect(routineNote({ included: true, count: 0 })).toBe("No routine management sessions match this search.");
    expect(routineNote(null)).toBe("");
    expect(routineNote({ included: false, count: Number.NaN })).toBe("No routine management sessions match this search.");
  });
});

describe("the remembered choice", () => {
  it("is off by default and survives a reload", () => {
    expect(loadShowRoutine()).toBe(false);
    saveShowRoutine(true);
    expect(window.localStorage.getItem(ROUTINE_STORAGE_KEY)).toBe("1");
    expect(loadShowRoutine()).toBe(true);
    saveShowRoutine(false);
    expect(window.localStorage.getItem(ROUTINE_STORAGE_KEY)).toBeNull();
    expect(loadShowRoutine()).toBe(false);
  });

  it("a browser that refuses storage reads off and never throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("SecurityError"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("QuotaExceededError"); });
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => { throw new Error("SecurityError"); });
    expect(loadShowRoutine()).toBe(false);
    expect(() => saveShowRoutine(true)).not.toThrow();
    expect(() => saveShowRoutine(false)).not.toThrow();
  });
});
