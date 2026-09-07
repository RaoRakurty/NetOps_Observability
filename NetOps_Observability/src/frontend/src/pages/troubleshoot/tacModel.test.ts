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
import type {
  TacCaptureProgress, TacCommandCapture, TacConnectorInfo, TacPlan, TacState, TacStep,
} from "../../services/api";
import {
  COLLECT_FAILED,
  CONNECTOR_CHIP,
  CONNECTOR_IDS,
  CONNECTOR_NOT_CONFIGURED,
  CONNECTOR_UNREADABLE,
  DOC_CLAIMED_LABEL,
  NOTHING_SCORED_NOTE,
  PLAN_LEGEND,
  SECTION_ORDER,
  buildCaptureWrite,
  captureBarPercent,
  captureRowStatus,
  captureRows,
  commandCountLine,
  failedCommandLine,
  failedCommands,
  parseCaptureRefusals,
  refusalLine,
  selectedCapture,
  STATUS_CHIP,
  UNBOUND_STEP_REASON,
  VERIFIED_LABEL,
  boundSteps,
  buildPlanRequest,
  ceilingSuffix,
  collectErrorMessage,
  bundleFileName,
  cappedNote,
  classificationNote,
  connectorApplies,
  connectorCapabilityLine,
  connectorState,
  connectorStatusNote,
  connectorTopic,
  dialectVendor,
  evidenceLine,
  hasCapability,
  humanBytes,
  humanSeconds,
  isCollecting,
  isMissingField,
  missingOutputs,
  missingOutputsLine,
  newestBundleBytes,
  pasteOffered,
  pasteOptionLabel,
  phaseLabel,
  splitConnectors,
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

// ── the paste path (owner, 2026-09-06) ──────────────────────────────────────
//
// The regression this pins: a Nokia SR Linux plan has 23 bound steps and 72
// unbound intents, and every one of the 95 used to become a labelled textarea.

describe("missingOutputs", () => {
  const nokiaPlan = {
    steps: [
      step({ intent: "system.version", section: "baseline", command: "show version" }),
      step({ intent: "ospf.neighbors", section: "deep-dive", command: "show network-instance protocols ospf neighbor" }),
      step({ intent: "site", section: "topology", command: "show system information" }),
    ],
    unbound: Array.from({ length: 72 }, (_, i) =>
      step({ intent: `platform.unbound${i}`, bound: false, command: undefined })),
  } as unknown as TacPlan;

  it("offers ONLY the plan's bound steps — never an unbound intent", () => {
    const targets = missingOutputs(nokiaPlan, null);
    expect(targets.map((t) => t.intent)).toEqual(["system.version", "ospf.neighbors"]);
    expect(targets.some((t) => t.intent.startsWith("platform.unbound"))).toBe(false);
    expect(boundSteps(nokiaPlan)).toHaveLength(2);
  });

  it("drops a step the collection already brought back", () => {
    const state = {
      capture: { commands: [{ intent: "system.version", output: "SR Linux 24.3", error: "" }] },
    } as unknown as TacState;
    expect(missingOutputs(nokiaPlan, state).map((t) => t.intent)).toEqual(["ospf.neighbors"]);
  });

  it("keeps a step the device refused", () => {
    const state = {
      capture: { commands: [{ intent: "ospf.neighbors", output: "", error: "invalid input" }] },
    } as unknown as TacState;
    expect(missingOutputs(nokiaPlan, state).map((t) => t.intent)).toContain("ospf.neighbors");
  });

  it("has nothing to offer without a plan", () => {
    expect(missingOutputs(undefined, null)).toEqual([]);
  });
});

describe("pasteOffered", () => {
  const plan = {
    steps: [step({ intent: "system.version", section: "baseline", command: "show version" })],
    unbound: [],
  } as unknown as TacPlan;

  it("is offered when this deployment cannot collect at all", () => {
    expect(pasteOffered(false, plan, null)).toBe(true);
  });

  it("is NOT a default wall when collection works and nothing has run", () => {
    expect(pasteOffered(true, plan, null)).toBe(false);
  });

  it("is offered when a step failed", () => {
    const state = {
      capture: { commands: [{ intent: "system.version", output: "", error: "timed out" }] },
    } as unknown as TacState;
    expect(pasteOffered(true, plan, state)).toBe(true);
  });

  it("disappears once every bound step has output", () => {
    const state = {
      capture: { commands: [{ intent: "system.version", output: "IOS-XE", error: "" }] },
    } as unknown as TacState;
    expect(pasteOffered(false, plan, state)).toBe(false);
    expect(pasteOffered(true, plan, state)).toBe(false);
  });
});

describe("the paste target's words", () => {
  it("names what it collects and the command — never the intent id", () => {
    const label = pasteOptionLabel(step({ intent: "ospf.neighbors", title: "OSPF neighbours", command: "show ip ospf neighbor" }));
    expect(label).toBe("OSPF neighbours · show ip ospf neighbor");
    expect(label).not.toContain("ospf.neighbors");
  });
  it("counts what is left rather than drawing a box for each", () => {
    expect(missingOutputsLine(3, 23)).toBe("3 of 23 outputs still missing");
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
  it("says what a connector does in ONE plain sentence", () => {
    expect(connectorCapabilityLine(connector({ capabilities: ["create", "attach", "poll_status"] })))
      .toBe("Opens the case and attaches the bundle");
    expect(connectorCapabilityLine(connector({ capabilities: ["attach"] })))
      .toBe("Attaches to an existing case");
    expect(connectorCapabilityLine(connector({ capabilities: ["create"] })))
      .toBe("Opens the case");
    expect(connectorCapabilityLine(connector({ capabilities: ["link"] })))
      .toBe("Prepares the text and bundle for you to paste");
  });

  // The 2026-09-06 regression, as a unit: a tenant that has stored nothing is
  // "Not configured" (a state), never "Unavailable" (an unreadable store).
  it("separates a state from an error", () => {
    expect(connectorState(connector({ configured: true, capabilities: ["create", "attach"] }))).toBe("ready");
    expect(connectorState(connector({ configured: true, capabilities: ["attach"] }))).toBe("attach-only");
    expect(connectorState(connector({ configured: false }))).toBe("not-configured");
    expect(connectorState(connector({ configured: false, unavailable: true }))).toBe("unavailable");
    expect(CONNECTOR_CHIP.ready).toBe("Ready");
    expect(CONNECTOR_CHIP["not-configured"]).toBe("Not configured");
    expect(CONNECTOR_CHIP["attach-only"]).toBe("Attach only");
    expect(CONNECTOR_CHIP.unavailable).toBe("Unavailable");
  });

  it("shows the server's own reason, and never the research paragraph", () => {
    const research = "NSP publishes exactly five APIs … (checked 2026-09-05).";
    expect(connectorStatusNote(connector({ configured: false, note: research, status_note: "No credentials for this tenant yet." })))
      .toBe("No credentials for this tenant yet.");
    expect(connectorStatusNote(connector({ configured: false, note: research }))).toBe(CONNECTOR_NOT_CONFIGURED);
    expect(connectorStatusNote(connector({ configured: false, unavailable: true }))).toBe(CONNECTOR_UNREADABLE);
    expect(connectorStatusNote(connector({ configured: true }))).toBe("");
  });

  // The owner's complaint, as a unit test: a Nokia escalation offers the Nokia
  // path, the tenant's CONFIGURED ITSM, and the generic one — not all twelve.
  it("shows only the connectors a device can use", () => {
    const all = [
      connector({ id: "portal-nokia", vendor: "nokia", configured: true, capabilities: [] }),
      connector({ id: "servicenow", vendor: "servicenow", configured: true, capabilities: ["create", "attach"] }),
      connector({ id: "jira", vendor: "jira", configured: false, capabilities: ["create", "attach"] }),
      connector({ id: "portal-fortinet", vendor: "fortinet", configured: true, capabilities: [] }),
      connector({ id: "email-arista", vendor: "arista", configured: false, capabilities: ["create", "attach"] }),
      connector({ id: "cisco-cxd", vendor: "cisco", configured: false, capabilities: ["attach"] }),
      connector({ id: "portal-text", vendor: "", configured: true, capabilities: ["link"] }),
    ];
    const { rows, others } = splitConnectors(all, dialectVendor("nokia-srlinux"));
    expect(rows.map((r) => r.id)).toEqual(["portal-nokia", "servicenow", "portal-text"]);
    expect(others.map((r) => r.id)).toEqual(["jira", "portal-fortinet", "email-arista", "cisco-cxd"]);
  });

  it("reads the vendor off the dialect slug", () => {
    expect(dialectVendor("nokia-srlinux")).toBe("nokia");
    expect(dialectVendor("cisco-iosxe")).toBe("cisco");
    expect(dialectVendor("")).toBe("");
  });

  it("keeps an unreadable ITSM connector in view — an error is not hidden", () => {
    const { rows } = splitConnectors(
      [connector({ id: "jira", vendor: "jira", configured: false, unavailable: true, capabilities: ["create"] })],
      "nokia",
    );
    expect(rows.map((r) => r.id)).toEqual(["jira"]);
    expect(connectorApplies(connector({ id: "portal-fortinet", vendor: "fortinet" }), "nokia")).toBe(false);
  });

  it("names the ceiling only when the bundle would not fit", () => {
    const email = connector({ id: "email-arista", max_attachment_bytes: 14_000_000 });
    expect(ceilingSuffix(email, 4096)).toBe("");
    expect(ceilingSuffix(email, 20_000_000)).toBe("over the 13 MB limit");
    expect(ceilingSuffix(connector({ max_attachment_bytes: 0 }), 20_000_000)).toBe("");
  });

  it("takes the newest bundle as the size to compare", () => {
    expect(newestBundleBytes([
      { bytes: 100, created_at: "2026-09-05T10:00:00Z" },
      { bytes: 900, created_at: "2026-09-05T11:00:00Z" },
    ])).toBe(900);
    expect(newestBundleBytes([])).toBe(0);
  });

  it("keys every connector's explanation on its id", () => {
    expect(connectorTopic("portal-nokia")).toBe("tac.connector.portal-nokia");
    expect(CONNECTOR_IDS).toContain("portal-text");
    expect(CONNECTOR_IDS).toHaveLength(12);
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


// ── captures (docs/design/TAC_CAPTURES_2026-09-06.md) ────────────────────────

describe("a capture row states its own state and nothing else", () => {
  const cap = (id: string, source: TacCommandCapture["source"], n: number): TacCommandCapture => ({
    id, name: id, source, dialect: "cisco-iosxe",
    commands: Array.from({ length: n }, (_, i) => ({ command: `show ${i}` })),
  });
  const progress = (over: Partial<TacCaptureProgress> = {}): TacCaptureProgress => ({
    capture_id: "capture:vendor-default", status: "done", total: 2, done: 2, failed: 0,
    commands: [], ...over,
  });

  it("counts commands, singular when it is one", () => {
    expect(commandCountLine(1)).toBe("1 command");
    expect(commandCountLine(12)).toBe("12 commands");
    expect(commandCountLine(0)).toBe("0 commands");
  });

  it("gives every row that did NOT run the queued state, never a borrowed verdict", () => {
    const p = progress({ status: "done" });
    expect(captureRowStatus("capture:vendor-default", "capture:vendor-default", p)).toBe("done");
    expect(captureRowStatus("tpl-1", "capture:vendor-default", p)).toBe("queued");
    expect(captureRowStatus("capture:vendor-default", "", undefined)).toBe("queued");
  });

  it("lists ONLY failures, and only on a partial or failed run", () => {
    const fails = [{ command: "show logging", status: "failed" as const, reason: "timed out" }];
    expect(failedCommands("c", "c", progress({ status: "done", commands: fails }))).toEqual([]);
    expect(failedCommands("c", "c", progress({ status: "running", commands: fails }))).toEqual([]);
    expect(failedCommands("c", "c", progress({ status: "partial", commands: fails }))).toEqual(fails);
    expect(failedCommands("c", "c", progress({ status: "failed", commands: fails }))).toEqual(fails);
    // Another row's failures are never shown under this one.
    expect(failedCommands("other", "c", progress({ status: "failed", commands: fails }))).toEqual([]);
  });

  it("names the command and its plain reason, and never renders a blank reason", () => {
    expect(failedCommandLine({ command: "show logging", status: "failed", reason: "timed out" }))
      .toBe("show logging — timed out");
    expect(failedCommandLine({ command: "show logging", status: "failed" }))
      .toBe("show logging — it did not run");
  });

  it("fills the bar for a row with no total — an empty bar would read as failure", () => {
    expect(captureBarPercent(undefined)).toBe(100);
    expect(captureBarPercent(progress({ total: 0, done: 0 }))).toBe(100);
    expect(captureBarPercent(progress({ total: 4, done: 1, failed: 1 }))).toBe(50);
    expect(captureBarPercent(progress({ total: 2, done: 2 }))).toBe(100);
  });

  it("orders the rows Correlix · uploaded · this tenant's own", () => {
    const rows = captureRows(
      cap("capture:vendor-default", "vendor-default", 2),
      cap("upload:txt", "uploaded", 3),
      [cap("tpl-1", "template", 1)],
    );
    expect(rows.map((r) => r.id)).toEqual(["capture:vendor-default", "upload:txt", "tpl-1"]);
    // A derived capture with no bound command is not a row: "none" is a state
    // the step states, not an empty list it renders.
    expect(captureRows(cap("capture:vendor-default", "vendor-default", 0), null, []).length).toBe(0);
  });

  it("falls back to the first row rather than to nothing", () => {
    const rows = captureRows(cap("capture:vendor-default", "vendor-default", 2), null, [cap("tpl-1", "template", 1)]);
    expect(selectedCapture(rows, "tpl-1")?.id).toBe("tpl-1");
    expect(selectedCapture(rows, "gone")?.id).toBe("capture:vendor-default");
    expect(selectedCapture([], "tpl-1")).toBeUndefined();
  });
});

describe("an upload is refused whole, by line and by rule", () => {
  const refusal = (body: string) => new Error(`400 Bad Request: ${body}`);

  it("reads the server's per-line refusals out of the failure", () => {
    const got = parseCaptureRefusals(refusal(JSON.stringify({
      error: "no", refusals: [{ line: 5, command: "configure terminal", family: "config", rule: "configure", reason: "it changes configuration" }],
    })));
    expect(got).toHaveLength(1);
    expect(got[0].line).toBe(5);
  });

  it("returns nothing rather than guessing when the body is not a refusal", () => {
    expect(parseCaptureRefusals(refusal("plain text"))).toEqual([]);
    expect(parseCaptureRefusals(refusal("{not json"))).toEqual([]);
    expect(parseCaptureRefusals(new Error("TypeError: fetch failed"))).toEqual([]);
  });

  it("names the line in the operator's own file, the command and the rule", () => {
    expect(refusalLine({ line: 5, command: "configure terminal", family: "config", rule: "configure", reason: "it changes configuration" }))
      .toBe("Line 5: configure terminal — it changes configuration (rule `configure`)");
    // The rule is not repeated when the server's reason already carries it.
    expect(refusalLine({ line: 2, command: "reload", rule: "reload", reason: "rule `reload` refused it" }))
      .toBe("Line 2: reload — rule `reload` refused it");
  });
});

describe("saving an uploaded capture", () => {
  it("trims, drops empties and sends NO tenant", () => {
    const body = buildCaptureWrite(" cisco-iosxe ", "  ACME  ", [
      { command: " show version " }, { command: "  " }, { command: "show logging", note: " why " },
    ]);
    expect(body).toEqual({
      dialect: "cisco-iosxe", name: "ACME",
      commands: [{ command: "show version", note: undefined }, { command: "show logging", note: "why" }],
    });
    expect(Object.keys(body)).not.toContain("tenant_id");
  });
});
