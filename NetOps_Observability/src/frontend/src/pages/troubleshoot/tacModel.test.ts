// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// tacModel.test.ts — the pure model behind the TAC escalation panel.
//
// The properties pinned here are the ones the honesty of the whole surface rests
// on, and every one of them is a decision that must be testable without a DOM:
//  · an unbound step ALWAYS carries a reason
//  · "documented, not verified" is what a doc_claimed command is called
//  · a paste is only ever invited for something that was NOT collected
//  · an empty target field is dropped from the plan request, never sent blank
//  · the download name comes from a closed character set, so a remote string
//    cannot steer a file path
//  · a size or a duration that was never estimated says so instead of "0"
//  · a plan row carries ONE status word, ONE reference and no machine ids
//    (owner, 2026-09-06: the preview printed the dialect's whole citation list
//    on every row — 8,418 links — and was unusable)

import { describe, it, expect } from "vitest";
import type { TacPlan, TacState, TacStep, TacConnectorInfo } from "../../services/api";
import {
  COLLECT_FAILED,
  CONNECTOR_CANNOT_CREATE,
  CONNECTOR_NOT_CONFIGURED,
  DOC_CLAIMED_LABEL,
  MAX_PASTE_OUTPUTS,
  NOTHING_SCORED_NOTE,
  PLAN_LEGEND,
  SECTION_ORDER,
  STATUS_CHIP,
  UNBOUND_STEP_REASON,
  VERIFIED_LABEL,
  buildPasteOutputs,
  buildPlanRequest,
  collectErrorMessage,
  bundleFileName,
  cappedNote,
  classificationNote,
  connectorCapabilityLine,
  connectorNote,
  evidenceLine,
  hasCapability,
  humanBytes,
  humanSeconds,
  isCollecting,
  isMissingField,
  pasteIntents,
  phaseLabel,
  planHeadline,
  planVersionTitle,
  reasonLine,
  stepReference,
  stepStatus,
  stepTooltip,
  topologyLine,
  unavailableLine,
  unboundReason,
  verifiedLabel,
} from "./tacModel";

const step = (over: Partial<TacStep> = {}): TacStep => ({
  intent: "ospf.neighbors", title: "OSPF neighbours", section: "deep-dive",
  bound: true, command: "show ip ospf neighbor", verified: "capture", ...over,
});

const connector = (over: Partial<TacConnectorInfo> = {}): TacConnectorInfo => ({
  id: "portal-text", display: "Vendor portal text", capabilities: ["link"],
  max_attachment_bytes: 0, profile: "link_only", configured: true, ...over,
});

// ── formatting ───────────────────────────────────────────────────────────────

describe("humanBytes", () => {
  it.each([
    [0, "0 B"],
    [512, "512 B"],
    [2048, "2.0 KB"],
    [15 * 1024, "15 KB"],
    [3 * 1024 * 1024, "3.0 MB"],
  ])("%d → %s", (n, want) => expect(humanBytes(n)).toBe(want));

  it("says a size was never estimated rather than printing a zero", () => {
    expect(humanBytes(undefined)).toBe("size not estimated");
    expect(humanBytes(-1)).toBe("size not estimated");
  });
});

describe("humanSeconds", () => {
  it.each([
    [45, "about 45 s"],
    [60, "about 1 min"],
    [150, "about 2 min 30 s"],
  ])("%d → %s", (n, want) => expect(humanSeconds(n)).toBe(want));

  it("says a duration was never estimated rather than claiming zero seconds", () => {
    expect(humanSeconds(0)).toBe("time not estimated");
    expect(humanSeconds(undefined)).toBe("time not estimated");
  });
});

// ── provenance of a command ──────────────────────────────────────────────────

describe("verifiedLabel", () => {
  it("names a captured command verified and a documented one unverified", () => {
    expect(verifiedLabel("capture")).toBe(VERIFIED_LABEL);
    expect(verifiedLabel("doc_claimed")).toBe(DOC_CLAIMED_LABEL);
  });
  it("claims nothing when the server said nothing", () => {
    expect(verifiedLabel(undefined)).toBe("");
    expect(verifiedLabel("")).toBe("");
  });
});

describe("unboundReason", () => {
  it("passes the server's own reason through", () => {
    expect(unboundReason(step({ bound: false, note: "no binding on this dialect" })))
      .toBe("no binding on this dialect");
  });
  it("never leaves an unbound step without a reason", () => {
    expect(unboundReason(step({ bound: false, note: "  " }))).toBe(UNBOUND_STEP_REASON);
  });
});

// ── plan shaping ─────────────────────────────────────────────────────────────

describe("the plan table", () => {
  it("keeps the collection order the sections define", () => {
    expect(SECTION_ORDER).toEqual(["baseline", "deep-dive", "optional", "topology"]);
  });

  it("gives every step exactly one status word, and never a blank one", () => {
    expect(stepStatus("capture")).toBe("verified");
    expect(stepStatus("doc_claimed")).toBe("vendor-docs");
    expect(stepStatus("")).toBe("unverified");
    expect(stepStatus(undefined)).toBe("unverified");
    expect(Object.values(STATUS_CHIP)).toEqual(["Verified", "From vendor docs", "Not verified"]);
    // The legend explains all three, once, and never becomes a per-row note.
    for (const word of Object.values(STATUS_CHIP)) {
      expect(PLAN_LEGEND).toContain(word);
    }
  });

  it("links at most ONE page, however many the pack cites", () => {
    const many = Array.from({ length: 400 }, (_, i) => ({
      title: `page ${i}`, url: `https://example.invalid/p-${i}`,
    }));
    const ref = stepReference(step({ sources: many }));
    expect(ref?.url).toBe("https://example.invalid/p-0");
    expect(stepReference(step({ sources: [] }))).toBeNull();
    expect(stepReference(step())).toBeNull();
  });

  it("refuses a citation that is not an https page, rather than rendering it", () => {
    expect(stepReference(step({ sources: [{ title: "x", url: "javascript:alert(1)" }] }))).toBeNull();
    expect(stepReference(step({ sources: [{ title: "x", url: "http://example.invalid/p" }] }))).toBeNull();
  });

  it("keeps the machine ids in the tooltip, not on the row", () => {
    expect(stepTooltip(step({ intent: "ospf.neighbors", section: "deep-dive" })))
      .toBe("ospf.neighbors · this issue");
    expect(stepTooltip(step({ intent: "system.version", section: "baseline" })))
      .toBe("system.version · always collected");
  });

  it("says how many checks a platform cannot do, in one line, in plain words", () => {
    expect(unavailableLine(72, "Nokia SR Linux")).toBe("72 checks are not available on Nokia SR Linux");
    expect(unavailableLine(1, "Nokia SR Linux")).toBe("1 check is not available on Nokia SR Linux");
    expect(unavailableLine(3, "  ")).toBe("3 checks are not available on this platform");
    expect(topologyLine(1)).toBe("1 topology fact goes into the bundle");
    expect(topologyLine(4)).toBe("4 topology facts go into the bundle");
  });

  it("puts the class, the device, the CLI and the estimate on one header line", () => {
    const p = {
      class_title: "OSPF adjacency will not form or is stuck",
      hostname: "spine1", device_id: "dev-1",
      dialect: "nokia-srlinux", dialect_display: "Nokia SR Linux",
      estimated_bytes: 2048, estimated_seconds: 45,
      plan_version: "plan-v1", catalog_version: "issues-v1", engine_version: "engine-v1",
    } as unknown as TacPlan;
    expect(planHeadline(p)).toBe(
      "OSPF adjacency will not form or is stuck on spine1 · Nokia SR Linux · 2.0 KB · about 45 s",
    );
    expect(planVersionTitle(p)).toBe("plan plan-v1 · issues issues-v1 · engine engine-v1");
    expect(planHeadline(undefined)).toBe("");
    expect(planVersionTitle(undefined)).toBe("");
  });
});

describe("buildPlanRequest", () => {
  it("drops empty target fields instead of sending them blank", () => {
    const req = buildPlanRequest("leaf1", "ospf-adjacency", true, {
      interface: " Gi0/1 ", peer: "", prefix: "   ", vrf: "blue",
    });
    expect(req).toEqual({
      device_id: "leaf1", include_optional: true, class_id: "ospf-adjacency",
      target: { interface: "Gi0/1", vrf: "blue" },
    });
  });
  it("omits the target entirely when nothing was typed", () => {
    expect(buildPlanRequest("leaf1", "", false, {}))
      .toEqual({ device_id: "leaf1", include_optional: false });
  });
});

// ── collection ───────────────────────────────────────────────────────────────

describe("isCollecting", () => {
  it.each([
    ["running", true],
    ["done", false],
    ["failed", false],
  ] as const)("job %s → %s", (status, want) => {
    expect(isCollecting({ job: { status } } as unknown as TacState)).toBe(want);
  });
  it("is false with no escalation at all", () => {
    expect(isCollecting(null)).toBe(false);
  });
});

describe("phaseLabel", () => {
  it("uses collection words, and calls an error what it is", () => {
    expect(phaseLabel("start")).toBe("running");
    expect(phaseLabel("done")).toBe("collected");
    expect(phaseLabel("error")).toBe("not collected");
  });
});

describe("pasteIntents", () => {
  const plan = {
    steps: [
      step({ intent: "system.version", section: "baseline" }),
      step({ intent: "ospf.neighbors", section: "deep-dive" }),
      step({ intent: "site", section: "topology" }),
    ],
    unbound: [step({ intent: "ospf.database", bound: false, command: undefined })],
  } as unknown as TacPlan;

  it("invites a paste for the unbound intents and everything not collected", () => {
    expect(pasteIntents(plan, null).map((s) => s.intent))
      .toEqual(["ospf.database", "system.version", "ospf.neighbors"]);
  });

  it("never invites a paste for something already collected", () => {
    const state = {
      capture: { commands: [{ intent: "system.version", output: "IOS-XE 17.9", error: "" }] },
    } as unknown as TacState;
    expect(pasteIntents(plan, state).map((s) => s.intent)).toEqual(["ospf.database", "ospf.neighbors"]);
  });

  it("still invites a paste for a command the device refused", () => {
    const state = {
      capture: { commands: [{ intent: "ospf.neighbors", output: "", error: "invalid input" }] },
    } as unknown as TacState;
    expect(pasteIntents(plan, state).map((s) => s.intent)).toContain("ospf.neighbors");
  });

  it("has nothing to offer without a plan", () => {
    expect(pasteIntents(undefined, null)).toEqual([]);
  });
});

describe("buildPasteOutputs", () => {
  it("sends only what was typed, with its command", () => {
    const steps = [step({ intent: "a", command: "show a" }), step({ intent: "b", command: "show b" })];
    expect(buildPasteOutputs(steps, { a: " out-a ", b: "   " }))
      .toEqual([{ intent: "a", command: "show a", output: "out-a" }]);
  });
  it("refuses more pasted outputs than the server accepts in one request", () => {
    const steps = Array.from({ length: MAX_PASTE_OUTPUTS + 5 }, (_, i) => step({ intent: `i${i}` }));
    const typed = Object.fromEntries(steps.map((s) => [s.intent, "x"]));
    expect(buildPasteOutputs(steps, typed)).toHaveLength(MAX_PASTE_OUTPUTS);
  });
});

// ── bundle naming ────────────────────────────────────────────────────────────

describe("bundleFileName", () => {
  it("names the file after the incident and the profile", () => {
    expect(bundleFileName("INC-2026-0007", "email")).toBe("correlix-tac-INC-2026-0007-email.zip");
  });
  it("strips anything a path could be steered with", () => {
    expect(bundleFileName("../../etc/passwd", "full")).toBe("correlix-tac-etc-passwd-full.zip");
    expect(bundleFileName("", "")).toBe("correlix-tac-incident-full.zip");
  });
});

// ── connectors ───────────────────────────────────────────────────────────────

describe("connector honesty", () => {
  it("says plainly when a connector cannot open the case itself", () => {
    expect(connectorCapabilityLine(connector({ capabilities: ["link"] })))
      .toContain(CONNECTOR_CANNOT_CREATE);
  });
  it("lists what a full connector actually does", () => {
    const line = connectorCapabilityLine(connector({ capabilities: ["create", "attach", "poll_status"] }));
    expect(line).toBe("opens the case · attaches the bundle · reads the case status back");
    expect(line).not.toContain(CONNECTOR_CANNOT_CREATE);
  });
  it("prefers the connector's own note and falls back to the unconfigured state", () => {
    expect(connectorNote(connector({ note: "Bring a ServiceNow token." }))).toBe("Bring a ServiceNow token.");
    expect(connectorNote(connector({ configured: false }))).toBe(CONNECTOR_NOT_CONFIGURED);
    expect(connectorNote(connector({ configured: true }))).toBe("");
  });
  it("reads capabilities as a closed set", () => {
    expect(hasCapability(connector({ capabilities: ["create"] }), "create")).toBe(true);
    expect(hasCapability(connector({ capabilities: [] }), "attach")).toBe(false);
  });
  it("marks the fields the vendor requires", () => {
    expect(isMissingField({ missing_fields: ["serial_number"] }, "serial_number")).toBe(true);
    expect(isMissingField({}, "serial_number")).toBe(false);
  });
});

// ── classification ───────────────────────────────────────────────────────────

describe("classificationNote", () => {
  it("passes the server's note through when it classified", () => {
    expect(classificationNote({ classified: true, note: "Two signatures agreed." } as never))
      .toBe("Two signatures agreed.");
  });
  it("says nothing scored rather than inventing a class", () => {
    expect(classificationNote({ classified: false, note: "" } as never)).toBe(NOTHING_SCORED_NOTE);
  });
});

describe("reasonLine + evidenceLine", () => {
  it("names the evidence kind, its exact id and its weight", () => {
    expect(reasonLine({ kind: "signature", ref: "ospf-exstart-mtu", weight: 5 }))
      .toBe("signature ospf-exstart-mtu · weight 5");
  });
  it("says what it was classified WITHOUT, not only what it had", () => {
    const l = evidenceLine(["case timeline"], ["correlation object (not readable for this id)"]);
    expect(l.on).toBe("Classified on: case timeline");
    expect(l.without).toContain("Classified without:");
  });
  it("admits when nothing backed the classification", () => {
    expect(evidenceLine([], []).on).toBe("Classified on no stored evidence at all.");
    expect(evidenceLine([], []).without).toBe("");
  });
});

// ── list bounding ────────────────────────────────────────────────────────────

describe("cappedNote", () => {
  it("says the trim is a display trim, not a collection trim", () => {
    const n = cappedNote(80, 130, "steps");
    expect(n).toContain("80 of 130 steps");
    expect(n).toContain("the rest are in the plan and in the bundle");
  });
});

// ── the 503 that is a product state, not a failure ───────────────────────────

describe("collectErrorMessage", () => {
  const NOTE =
    "Live collection is not wired on this deployment (FEATURE_PROTOCOL_DIAG_COLLECT is off, or no read-only " +
    "SSH account is provisioned). The plan, the bundle and the case text still work — collect the outputs by " +
    "hand and paste them into the collect step.";

  it("shows the server's own note from the refusal, however long it is", () => {
    const e = new Error(`503 Service Unavailable: ${JSON.stringify({ error: NOTE })}`);
    expect(collectErrorMessage(e, "")).toBe(NOTE);
  });

  it("falls back to the note the state read already carried", () => {
    expect(collectErrorMessage(new Error("503 Service Unavailable: "), NOTE)).toBe(NOTE);
  });

  it("keeps the generic sentence for anything that is not a 503", () => {
    expect(collectErrorMessage(new Error("TypeError: fetch failed"), NOTE)).toBe(COLLECT_FAILED);
  });
});

// ── the command review + templates (tracker 250) ─────────────────────────────

import type { TacLineVerdict, TacTemplate } from "../../services/api";
import {
  CUSTOM_COMMAND_NOTE,
  MAX_REVIEW_COMMANDS,
  buildReviewedSteps,
  buildTemplateWrite,
  editSummary,
  moveCommand,
  originLabel,
  planCommands,
  reviewChanged,
  templateLabel,
  verdictLine,
} from "./tacModel";

const reviewPlan = (steps: Partial<TacStep>[]): TacPlan =>
  ({
    id: "p", incident_id: "i", device_id: "d", hostname: "h", platform: "p",
    dialect: "cisco-iosxe", dialect_display: "Cisco IOS-XE", has_plan: true,
    class_id: "c", class_title: "C", target: {}, include_optional: false,
    steps: steps.map((s) => ({ intent: "x", title: "X", section: "baseline", bound: true, ...s })) as TacStep[],
    unbound: [], topology: [], estimated_bytes: 0, estimated_seconds: 0,
    redaction_note: "", note: "", catalog_version: "v", engine_version: "v",
  }) as TacPlan;

describe("the review list is exactly the commands that will run", () => {
  it("takes the plan's commands in order and drops topology rows", () => {
    const p = reviewPlan([
      { command: "show version" },
      { command: "", section: "topology" },
      { command: "show ip ospf neighbor" },
    ]);
    expect(planCommands(p)).toEqual(["show version", "show ip ospf neighbor"]);
    expect(planCommands(undefined)).toEqual([]);
  });

  it("reorders without ever losing a command", () => {
    const list = ["a", "b", "c"];
    expect(moveCommand(list, 2, 0)).toEqual(["c", "a", "b"]);
    expect(moveCommand(list, 0, 2)).toEqual(["b", "c", "a"]);
    // An out-of-range or no-op move leaves the list untouched — a reorder must
    // never silently drop a line.
    expect(moveCommand(list, -1, 0)).toBe(list);
    expect(moveCommand(list, 0, 9)).toBe(list);
    expect(moveCommand(list, 1, 1)).toBe(list);
    expect(list).toEqual(["a", "b", "c"]);
  });

  it("knows whether the operator actually changed anything", () => {
    const p = reviewPlan([{ command: "show version" }, { command: "show ip route" }]);
    expect(reviewChanged(p, ["show version", "show ip route"])).toBe(false);
    expect(reviewChanged(p, ["Show  version", "show ip route"])).toBe(false); // same command
    expect(reviewChanged(p, ["show ip route", "show version"])).toBe(true);   // reorder
    expect(reviewChanged(p, ["show version"])).toBe(true);                    // removal
    expect(reviewChanged(p, ["show version", "show ip route", "show clock"])).toBe(true);
  });
});

describe("a refusal names the rule, never just 'invalid'", () => {
  const refused: TacLineVerdict = {
    index: 1, command: "configure terminal", ok: false, family: "config", rule: "configure",
    reason: "refused by the output-only policy (config): it changes configuration or clears state — rule `configure`",
  };

  it("shows the server's own sentence for a refused line", () => {
    expect(verdictLine(refused)).toContain("config");
    expect(verdictLine(refused)).toContain("rule `configure`");
  });

  it("falls back to the family and the rule when the server sent no sentence", () => {
    expect(verdictLine({ index: 0, command: "reload", ok: false, family: "restart", rule: "reload" }))
      .toContain("restart");
    expect(verdictLine({ index: 0, command: "reload", ok: false, family: "restart", rule: "reload" }))
      .toContain("rule `reload`");
    expect(verdictLine({ index: 0, command: "x", ok: false })).toBe("refused");
    expect(verdictLine(undefined)).toBe("");
  });

  it("labels an accepted line by origin and never hides an unverified command", () => {
    expect(originLabel({ index: 0, command: "show version", ok: true, origin: "catalog" }))
      .toBe("Correlix command");
    expect(originLabel({ index: 0, command: "show x", ok: true, origin: "custom" })).toBe("your command");
    expect(originLabel(refused)).toBe("");
    // A custom line with no server note still says it was never run here.
    expect(verdictLine({ index: 0, command: "show x", ok: true, origin: "custom" })).toBe(CUSTOM_COMMAND_NOTE);
  });
});

describe("templates carry their provenance in the picker", () => {
  const base: TacTemplate = {
    id: "t", dialect: "cisco-iosxe", name: "n", source: "tenant", steps: [], version: 3,
  };

  it("labels a Correlix default by version", () => {
    expect(templateLabel({ ...base, source: "correlix-default", version: 1 })).toBe("Correlix default v1");
  });

  it("labels a tenant template by owner and last update", () => {
    const label = templateLabel({ ...base, created_by: "noc@acme", updated_at: "2026-09-05T10:00:00Z" });
    expect(label).toContain("saved by noc@acme");
    expect(label).toContain("updated");
    expect(label).toContain("v3");
  });

  it("says the set is the team's even when no author was recorded", () => {
    expect(templateLabel(base)).toContain("saved by your team");
  });
});

describe("the write bodies carry no tenant and no unbounded list", () => {
  it("trims, drops blanks and caps the command list", () => {
    const many = Array.from({ length: MAX_REVIEW_COMMANDS + 20 }, (_, i) => `show ${i}`);
    const body = buildTemplateWrite("cisco-iosxe", "  ACME  ", " ours ", "correlix:cisco-iosxe:baseline", [
      "  show version  ", "", "   ", ...many,
    ]);
    expect(body.name).toBe("ACME");
    expect(body.description).toBe("ours");
    expect(body.based_on).toBe("correlix:cisco-iosxe:baseline");
    expect(body.steps.length).toBe(MAX_REVIEW_COMMANDS);
    expect(body.steps[0]).toEqual({ command: "show version" });
    // There is no tenant field to send, by construction.
    expect(Object.keys(body)).not.toContain("tenant_id");
  });

  it("builds the reviewed step list the same way", () => {
    expect(buildReviewedSteps([" show version ", "", "show clock"]))
      .toEqual([{ command: "show version" }, { command: "show clock" }]);
  });
});

describe("the bundle's edit record is summarised for the operator", () => {
  it("counts what the bundle will say", () => {
    const p = reviewPlan([{ command: "show version" }]);
    p.reviewed = true;
    p.edits = [
      { kind: "removed", command: "show ip route" },
      { kind: "removed", command: "show clock" },
      { kind: "added", command: "show ip nhrp brief", origin: "custom" },
    ];
    expect(editSummary(p)).toBe("Recorded in the bundle: 1 added · 2 removed.");
  });

  it("says nothing when nothing was edited — an empty edit list is a statement", () => {
    expect(editSummary(reviewPlan([{ command: "show version" }]))).toBe("");
    expect(editSummary(undefined)).toBe("");
  });
});
