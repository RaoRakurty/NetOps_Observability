// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// tacModel — the pure model behind the TAC escalation panel.
//
// Design of record: docs/design/TAC_ESCALATION_2026-09-05.md. Everything that
// DECIDES what the operator reads lives here as pure functions and exported
// constants, so it is unit-testable without a DOM and so the panel's honest
// states are asserted by IMPORT rather than by copy-pasted literals.
//
// THE HONESTY RULE, restated for this surface. Each step of the escalation has
// exactly one thing it may say when it cannot do its job, and it says what did
// not happen:
//   · nothing scored              → the server's own note, never an invented class
//   · this platform has no plan   → said out loud, with the paste path offered
//   · an intent has no binding    → listed as unbound WITH its reason
//   · a command came from a manual → "documented, not verified"
//   · live collection is unwired  → the server's own collect_note, paste stays open
//   · a connector has no creds    → greyed with the connector's own note
// None of these is a failure to hide; each is a product state with a sentence.

import { httpFailure, operatorError } from "../../lib/errors";
import type {
  TacCaseCapability,
  TacClassification,
  TacConnectorInfo,
  TacLineVerdict,
  TacPlan,
  TacPlanRequest,
  TacProgress,
  TacSection,
  TacSource,
  TacState,
  TacStep,
  TacTarget,
  TacCaptureProgress,
  TacCaptureRefusal,
  TacCaptureSource,
  TacCaptureStatus,
  TacCaseLink,
  TacCommandCapture,
  TacCommandStatus,
  TacConfirmRequest,
  TacDryRunCall,
  TacDryRunOutcome,
  TacDryRunReport,
  TacEscalateRequest,
  TacProposal,
  TacRequiredField,
  TacTemplate,
  TacTemplateWrite,
  TacVerified,
} from "../../services/api";

// ── honest-state copy (imported by the panel AND by its tests) ───────────────

/** No escalation exists yet and the server sent no note of its own. */
export const NOT_ESCALATED_NOTE =
  "This incident has not been escalated yet. Classifying it starts the escalation.";

/** A TAC escalation hangs off a correlated incident; a symptom alone has none. */
export const ESCALATION_NEEDS_CASE =
  "An escalation is built from a correlated incident — pick an open case above to escalate one.";

export const STATE_READ_FAILED = "The escalation could not be read.";
export const CLASSIFY_FAILED = "The evidence could not be classified.";
export const PLAN_FAILED = "The command plan could not be built.";
export const COLLECT_FAILED = "The collection could not be started.";
export const CANCEL_FAILED = "The collection could not be stopped.";
export const BUNDLE_FAILED = "The bundle could not be downloaded.";
export const CASE_FORM_FAILED = "The case form could not be prepared.";
export const CASE_SUBMIT_FAILED = "The case could not be opened.";
export const DEVICES_FAILED = "Your device inventory could not be read — type the device id instead.";

/** `classified:false` with an empty server note. The class is never invented. */
export const NOTHING_SCORED_NOTE =
  "No evidence matched a known issue class, so this escalates as the general class. Override it below if you know better.";

/** `has_plan:false` — the dialect carries no authored command set.
 *
 *  It used to promise the paste step. It cannot: the paste step names a COMMAND
 *  for each output it accepts, and a platform with no authored plan binds no
 *  command to name (owner, 2026-09-06). Add the commands you want in the review
 *  step instead — that path is real, and the case text and bundle still work. */
export const NO_AUTHORED_PLAN_NOTE =
  "There is no authored command set for this platform. Add the commands yourself in the review step below.";

/** Shown beside the device picker before a plan exists. */
export const PLAN_NEEDS_DEVICE = "Choose the device the outputs come from, then build the plan.";

/** A step whose intent this dialect binds no command for, with no server reason. */
export const UNBOUND_STEP_REASON = "This platform binds no command for this intent.";

export const VERIFIED_LABEL = "verified on this platform";
export const DOC_CLAIMED_LABEL = "documented, not verified";

/** The paste path. It is offered only where a command could NOT be run for us —
 *  never as a default wall of boxes (owner, 2026-09-06: a Nokia plan rendered a
 *  textarea for all 72 unbound intents, labelled with raw intent ids). */
export const PASTE_INVITE = "Paste an output Correlix could not collect.";

/** Nothing is missing: every planned command came back with output. */
export const PASTE_NOTHING_MISSING = "Every planned output has been collected.";

/** Nothing has been collected, so there is nothing to bundle or attach yet. */
export const NO_CAPTURE_YET =
  "Nothing has been collected yet — start the collection or paste the outputs above.";

export const NO_BUNDLE_YET = "No bundle yet.";

/** No connector at all on this deployment. The download path still works, and
 *  what a case connector IS lives behind the (i). */
export const NO_CASE_CONNECTOR = "No connector configured — download the bundle instead.";

/** A connector the tenant has brought no credentials for. The server sends its
 *  own `status_note`; this is the fallback for a build that does not yet. */
export const CONNECTOR_NOT_CONFIGURED =
  "No credentials for this tenant yet — bring your own to use it.";

/** Submitting is always a person's press (design §4). */
export const CASE_HUMAN_APPROVED =
  "Review every field first — Correlix never opens a case on its own.";

// Iris → Knowledge.
export const KNOWLEDGE_FAILED = "The coverage catalogue could not be read.";
export const KNOWLEDGE_GROWTH_NOTE =
  "Coverage grows from owner runbooks: vendor research is filed under ai/tac/research/<vendor>.yaml and merged into the classes and the per-dialect plans by scripts/tac-merge-research.py.";
// ── the learning backlog (tracker 243) ───────────────────────────────────────
//
// W1 could only say "not yet tracked", because nothing counted unrecognised
// output and a 0 would have read as "there is none". W3 counts it, so the page
// now distinguishes THREE states that a single number would have flattened:
// the backlog does not exist on this build, it exists and nothing has been
// collected yet, and it exists and everything collected was recognised.

/** The api does not carry the backlog at all (an older build). */
export const BACKLOG_UNTRACKED =
  "This build does not read collections for unrecognised output.";
/** The backlog exists and no collection has run yet. */
export const BACKLOG_EMPTY = "Nothing collected yet, so nothing has been read.";
/** The backlog exists, collections have run, and every output was recognised. */
export const BACKLOG_CLEAN = "Every collected output was recognised.";
export const BACKLOG_FAILED = "The learning backlog could not be read.";

/** What each gap kind means as a work item — the point of separating them. */
export const GAP_KIND_LABEL: Record<string, string> = {
  no_parser: "No parser for this concept",
  no_dialect: "No parser on this platform",
  unparsed: "Parser could not read it",
};

/** A candidate is a proposal. Stated wherever candidates are listed. */
export const CANDIDATE_NOTE = "A candidate is a proposal, never a rule.";
export const CANDIDATE_NONE = "No answer has been written down yet.";
export const CANDIDATE_EXPORT_FAILED = "The research file could not be built.";
export const NO_UNPLANNED_DIALECTS =
  "Every platform Correlix recognises carries an authored plan.";
/** The owner's 2026-09-05 output-only command rule, as the coverage page states
 *  it. The page shows COUNTS and never a command: a command in one of the three
 *  families is not knowledge Correlix holds, and this page is knowledge. */
export const COMMAND_POLICY_NOTE =
  "Correlix collects outputs only. A command that changes configuration, that restarts or reboots the device, or that addresses a daemon is not merely refused — it is not carried at all: it is removed from the research corpus, never merged, and never rendered. Only the count is kept. Ping and traceroute are allowed, with bounded parameters.";
export const COMMAND_POLICY_NO_EXCLUSIONS =
  "Nothing has been excluded on this build.";

// ── bounds (the server's own, mirrored so the UI refuses before the wire) ────

/** internal/tac: at most 40 pasted outputs, 256 KiB each, per request. The UI
 *  files ONE at a time, so only the per-output cap binds it. */
export const MAX_PASTE_CHARS = 256 * 1024;

/**
 * How many rows one plan section or one progress list renders. A plan is
 * bounded by its catalogue (tens of steps), but the ceiling is stated rather
 * than assumed, and the overflow line says the collection still runs all of
 * them — the list is trimmed, not the work.
 */
export const ROW_RENDER_CAP = 80;

/** The overflow sentence for a list trimmed at ROW_RENDER_CAP. */
export function cappedNote(shown: number, total: number, noun: string): string {
  return `Showing the first ${shown} of ${total} ${noun} — the rest are in the plan and in the bundle.`;
}

// ── formatting ──────────────────────────────────────────────────────────────

/** Human bytes. 0 is a measured zero and reads as "0 B", never as absent. */
export function humanBytes(n: number | undefined | null): string {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) return "size not estimated";
  if (v < 1024) return `${Math.round(v)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let x = v / 1024;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i += 1;
  }
  return `${x < 10 ? x.toFixed(1) : Math.round(x)} ${units[i]}`;
}

/** Human duration for an estimate. */
export function humanSeconds(n: number | undefined | null): string {
  const v = Math.round(Number(n));
  if (!Number.isFinite(v) || v <= 0) return "time not estimated";
  if (v < 60) return `about ${v} s`;
  const m = Math.floor(v / 60);
  const s = v % 60;
  return s === 0 ? `about ${m} min` : `about ${m} min ${s} s`;
}

/** What a step's `verified` flag means to a person. */
export function verifiedLabel(v: TacVerified | "" | undefined): string {
  if (v === "capture") return VERIFIED_LABEL;
  if (v === "doc_claimed") return DOC_CLAIMED_LABEL;
  return "";
}

// ── the plan table (owner, 2026-09-06: "bunch of links … this page is unusable")
//
// The plan preview used to print, under every command, the whole citation list
// the dialect inherited — 8,418 links on one Nokia SR Linux plan — plus the
// intent id, a badge, a repeated note and the same caveat sentence on 23 rows.
// It is now a table with four columns and ONE small chip, and everything that
// was said twice is said once: the chip legend sits under the table, the intent
// id and the collection stage live in the row's tooltip for support, and a step
// links at most its first citation.

/** The three things a plan row can honestly say about its command. */
export type TacStepStatus = "verified" | "vendor-docs" | "unverified";

/** The chip word for each. Three words, one per state, never a sentence. */
export const STATUS_CHIP: Record<TacStepStatus, string> = {
  verified: "Verified",
  "vendor-docs": "From vendor docs",
  unverified: "Not verified",
};

/** One legend line, printed ONCE under the table instead of on every row. */
export const PLAN_LEGEND =
  "Verified — Correlix has run this command on this platform. From vendor docs — the vendor publishes it and Correlix has not run it here. Not verified — neither.";

/** What a step's `verified` flag maps to. An absent flag is "Not verified":
 *  a blank would read as "fine", and it is not. */
export function stepStatus(v: TacVerified | "" | undefined): TacStepStatus {
  if (v === "capture") return "verified";
  if (v === "doc_claimed") return "vendor-docs";
  return "unverified";
}

/** The plain word for a collection stage, used only in the row tooltip. */
export const SECTION_STAGE: Record<TacSection, string> = {
  baseline: "always collected",
  "deep-dive": "this issue",
  optional: "optional",
  topology: "topology",
};

/** The row's support tooltip: the machine ids a person never needs on screen
 *  but a support engineer reading over their shoulder does. */
export function stepTooltip(step: TacStep): string {
  const stage = SECTION_STAGE[step.section] ?? step.section;
  return `${step.intent} · ${stage}`;
}

/** The ONE reference a row may link. The rest of a citation list is the pack's
 *  bibliography and belongs on the pack, not on 23 command rows. */
export function stepReference(step: TacStep): TacSource | null {
  const first = (step.sources ?? [])[0];
  if (!first || !/^https:\/\//.test(first.url ?? "")) return null;
  return first;
}

/** The one line that replaces a full list of unbound intents. */
export function unavailableLine(count: number, platform: string): string {
  const where = (platform || "").trim() || "this platform";
  return count === 1
    ? `1 check is not available on ${where}`
    : `${count} checks are not available on ${where}`;
}

/** The one line that replaces the topology list. */
export function topologyLine(count: number): string {
  return count === 1 ? "1 topology fact goes into the bundle" : `${count} topology facts go into the bundle`;
}

/** The plan header, in one line: what, where, on which CLI, how long. */
export function planHeadline(plan: TacPlan | undefined): string {
  if (!plan) return "";
  const where = plan.hostname || plan.device_id;
  const dialect = plan.dialect_display || plan.dialect;
  const parts = [where ? `${plan.class_title} on ${where}` : plan.class_title, dialect].filter(Boolean);
  parts.push(`${humanBytes(plan.estimated_bytes)} · ${humanSeconds(plan.estimated_seconds)}`);
  return parts.join(" · ");
}

/** The version strings, for the header's tooltip. They are provenance, not copy:
 *  an operator never reads them and a support engineer always needs them. */
export function planVersionTitle(plan: TacPlan | undefined): string {
  if (!plan) return "";
  return [
    plan.plan_version ? `plan ${plan.plan_version}` : "",
    plan.catalog_version ? `issues ${plan.catalog_version}` : "",
    plan.engine_version ? `engine ${plan.engine_version}` : "",
  ].filter(Boolean).join(" · ");
}

/** The short sentence the Bundle step states once. The server's own full
 *  promise stays on the page, one disclosure away — it is never replaced. */
export const REDACTION_SHORT =
  "Passwords, keys and community strings are masked. Names and addresses are kept.";

/** The reason an unbound step carries, never blank. */
export function unboundReason(step: TacStep): string {
  return (step.note || "").trim() || UNBOUND_STEP_REASON;
}

// ── plan sections ───────────────────────────────────────────────────────────

export const SECTION_ORDER: TacSection[] = ["baseline", "deep-dive", "optional", "topology"];

/** The plan request body — empty target fields are omitted, never sent blank. */
export function buildPlanRequest(
  deviceId: string,
  classId: string,
  includeOptional: boolean,
  target: TacTarget,
): TacPlanRequest {
  const t: TacTarget = {};
  (Object.keys(target) as (keyof TacTarget)[]).forEach((k) => {
    const v = (target[k] ?? "").trim();
    if (v) t[k] = v;
  });
  const req: TacPlanRequest = { device_id: deviceId.trim(), include_optional: includeOptional };
  if (classId.trim()) req.class_id = classId.trim();
  if (Object.keys(t).length > 0) req.target = t;
  return req;
}

// ── collection ──────────────────────────────────────────────────────────────

/** True while the server says a collection is running — the only thing that
 *  keeps the 2 s state read alive. */
export function isCollecting(state: TacState | null | undefined): boolean {
  return state?.job?.status === "running";
}

/** The operator's word for a progress phase. */
export function phaseLabel(phase: TacProgress["phase"]): string {
  if (phase === "start") return "running";
  if (phase === "done") return "collected";
  return "not collected";
}

// ── the paste path (owner, 2026-09-06) ──────────────────────────────────────
//
// It used to render one textarea per intent in the whole class — on a Nokia SR
// Linux escalation that is 23 bound steps plus 72 UNBOUND ones, each labelled
// with a raw intent id (platform.bios, install.status, redundancy.state…) and
// no command. A wall of boxes for work Correlix already said it cannot do.
//
// Three rules now hold, and each is a function here so the panel decides
// nothing:
//   1. the paste path appears only when the gateway could not collect — the
//      deployment has no runner, or a step failed or timed out;
//   2. only the plan's BOUND steps that still lack output are offered, named by
//      what they collect and the command (ids stay in the tooltip);
//   3. an unbound intent NEVER appears — it is already counted by the plan's
//      "n checks are not available on <platform>" line.

/** The plan's runnable steps: a real command, not topology context. */
export function boundSteps(plan: TacPlan | undefined): TacStep[] {
  return (plan?.steps ?? []).filter((s) => s.section !== "topology" && (s.command ?? "").trim() !== "");
}

/** The intents the capture actually brought back with content. */
function collectedIntents(state: TacState | null | undefined): Set<string> {
  return new Set(
    (state?.capture?.commands ?? [])
      .filter((c) => !c.error && (c.output ?? "") !== "")
      .map((c) => c.intent),
  );
}

/** The bound steps that still have no output — the ONLY paste targets. */
export function missingOutputs(plan: TacPlan | undefined, state: TacState | null | undefined): TacStep[] {
  const have = collectedIntents(state);
  const seen = new Set<string>();
  return boundSteps(plan).filter((s) => {
    if (have.has(s.intent) || seen.has(s.intent)) return false;
    seen.add(s.intent);
    return true;
  });
}

/** True when a step of the last collection failed or timed out — a reason to
 *  offer the paste path even on a deployment that CAN collect. */
export function collectionFellShort(state: TacState | null | undefined): boolean {
  if (state?.job?.status === "failed") return true;
  return (state?.capture?.commands ?? []).some((c) => Boolean(c.error) || (c.output ?? "") === "");
}

/**
 * Whether the paste path is offered at all. It is not a default: either this
 * deployment cannot collect, or a collection ran and did not bring everything
 * back. And in both cases something must actually still be missing.
 */
export function pasteOffered(
  canCollect: boolean,
  plan: TacPlan | undefined,
  state: TacState | null | undefined,
): boolean {
  if (missingOutputs(plan, state).length === 0) return false;
  return !canCollect || collectionFellShort(state);
}

/** "3 of 23 outputs still missing" — the count, never a wall of boxes. */
export function missingOutputsLine(missing: number, total: number): string {
  return `${missing} of ${total} outputs still missing`;
}

/** How one paste target is named: what it collects, then the command. Never the
 *  intent id — that rides on the option's tooltip for support. */
export function pasteOptionLabel(step: TacStep): string {
  const what = (step.title || "").trim() || step.intent;
  const cmd = (step.command || "").trim();
  return cmd ? `${what} · ${cmd}` : what;
}

// ── bundle ──────────────────────────────────────────────────────────────────

export const BUNDLE_PROFILES: { id: string; label: string; hint: string }[] = [
  { id: "full", label: "Full", hint: "everything collected" },
  { id: "email", label: "Email", hint: "trimmed to 14 MB" },
  { id: "link_only", label: "Link only", hint: "case text and manifest" },
];

/** A safe download name. Only the closed character set survives, so a remote
 *  string can never steer the file path. */
export function bundleFileName(incidentRef: string, profile: string): string {
  const safe = (s: string) =>
    (s || "")
      .replace(/[^A-Za-z0-9._-]+/g, "-")   // anything outside the closed set
      .replace(/\.{2,}/g, "-")             // no traversal-looking runs survive
      .replace(/-{2,}/g, "-")
      .replace(/^[-.]+|[-.]+$/g, "")
      .slice(0, 60);
  const ref = safe(incidentRef) || "incident";
  const prof = safe(profile) || "full";
  return `correlix-tac-${ref}-${prof}.zip`;
}

// ── case connectors ─────────────────────────────────────────────────────────

export function hasCapability(info: TacConnectorInfo, cap: TacCaseCapability): boolean {
  return (info.capabilities ?? []).includes(cap);
}

/**
 * What a connector does, in one plain sentence.
 *
 * It used to enumerate every verb it claimed and then append a caveat — a
 * two-clause sentence per row, twelve rows deep. An operator choosing a path
 * needs one thing: does this open the case, add to a case I already have, or
 * just hand me the text?
 */
export function connectorCapabilityLine(info: TacConnectorInfo): string {
  const create = hasCapability(info, "create");
  const attach = hasCapability(info, "attach");
  if (create && attach) return "Opens the case and attaches the bundle";
  if (create) return "Opens the case";
  if (attach) return "Attaches to an existing case";
  return "Prepares the text and bundle for you to paste";
}

/** The four states a connector row can be in. "Unavailable" is an ERROR — the
 *  stored configuration could not be read — and is never used for a tenant that
 *  simply has no credentials (owner, 2026-09-06). */
export type ConnectorState = "ready" | "attach-only" | "not-configured" | "unavailable";

/** One chip word per state. Never a sentence. */
export const CONNECTOR_CHIP: Record<ConnectorState, string> = {
  ready: "Ready",
  "attach-only": "Attach only",
  "not-configured": "Not configured",
  unavailable: "Unavailable",
};

export function connectorState(info: TacConnectorInfo): ConnectorState {
  if (info.unavailable) return "unavailable";
  if (!info.configured) return "not-configured";
  return hasCapability(info, "attach") && !hasCapability(info, "create") ? "attach-only" : "ready";
}

/** The short reason for the CURRENT state — the server's own sentence when it
 *  sent one, ours when it did not. The connector's standing vendor research
 *  (`note`) is deliberately NOT this: it lives behind the row's (i). */
export function connectorStatusNote(info: TacConnectorInfo): string {
  const own = (info.status_note || "").trim();
  if (own) return own;
  if (info.unavailable) return CONNECTOR_UNREADABLE;
  return info.configured ? "" : CONNECTOR_NOT_CONFIGURED;
}

/** The unreadable-configuration state, when the server named no cause. */
export const CONNECTOR_UNREADABLE =
  "The stored configuration for this connector could not be read.";

/** Where a person brings credentials. */
export const TICKET_DELIVERY_ROUTE = "#/admin/ticket-delivery";
export const TICKET_DELIVERY_LABEL = "Ticket delivery";

/** The disclosure that holds every connector this device has no use for. */
export function showAllConnectorsLabel(n: number): string {
  return `Show all connectors (${n})`;
}

/** The authored explanation for one connector — the research paragraph that
 *  came off the step. One file per connector under ai/skills/explain/. */
export function connectorTopic(id: string): string {
  return `tac.connector.${id}`;
}

/**
 * Every connector id the panel may render, and therefore every explain file
 * that must exist. It is a LIST rather than a template-literal at the call site
 * on purpose: AskIris.test.tsx reads it and fails when a file is missing, which
 * an interpolated topic would silently skip.
 */
export const CONNECTOR_IDS: readonly string[] = [
  "servicenow", "jira", "email-arista", "email-cisco",
  "cisco-cxd", "cisco-smart-bonding", "juniper",
  "portal-fortinet", "portal-huawei", "portal-nokia", "portal-paloalto",
  "portal-text",
] as const;

/** The generic path, always present and always configured. */
export const PORTAL_TEXT_ID = "portal-text";

/** The ITSM connectors — a tenant's own ticketing system, relevant at any
 *  vendor's device once it is configured. */
const ITSM_IDS = new Set(["servicenow", "jira"]);

/** The vendor a dialect belongs to: "nokia-srlinux" → "nokia". The dialect slug
 *  is `<vendor>-<platform>` (internal/tac.DialectSlug), so the first segment is
 *  the vendor and nothing needs a second lookup table. */
export function dialectVendor(dialect: string): string {
  return (dialect || "").trim().toLowerCase().split("-")[0] ?? "";
}

/**
 * Does this connector apply to the device being escalated?
 *
 * Three things do (owner, 2026-09-06): the device vendor's own path(s), the
 * tenant's CONFIGURED ITSM connectors, and the generic portal path. Everything
 * else is a different vendor's support desk and belongs behind a disclosure —
 * a Nokia escalation has no use for Fortinet's portal field list.
 */
export function connectorApplies(info: TacConnectorInfo, vendor: string): boolean {
  if (info.id === PORTAL_TEXT_ID) return true;
  if (ITSM_IDS.has(info.id)) return Boolean(info.configured) || Boolean(info.unavailable);
  const v = (info.vendor || "").trim().toLowerCase();
  return v !== "" && v === (vendor || "").trim().toLowerCase();
}

/** The connectors split into the ones this device can use and the rest. Order
 *  is preserved: the server sends them cheapest-tier first. */
export function splitConnectors(
  connectors: TacConnectorInfo[] | undefined,
  vendor: string,
): { rows: TacConnectorInfo[]; others: TacConnectorInfo[] } {
  const rows: TacConnectorInfo[] = [];
  const others: TacConnectorInfo[] = [];
  for (const c of connectors ?? []) (connectorApplies(c, vendor) ? rows : others).push(c);
  return { rows, others };
}

/** The size of the newest bundle built for this escalation, or 0. It is what a
 *  ceiling is compared against — a limit nothing exceeds is not worth a word. */
export function newestBundleBytes(bundles: { bytes: number; created_at?: string }[] | undefined): number {
  let best = 0;
  let when = "";
  for (const b of bundles ?? []) {
    const at = b.created_at ?? "";
    if (best === 0 || at >= when) { best = b.bytes; when = at; }
  }
  return best;
}

/**
 * The attachment ceiling, and ONLY when it bites. A row that says "attachment
 * ceiling 8.0 GB" on a 4 KB bundle taught nothing; a row that says the bundle
 * is over the limit changes what the operator does next.
 */
export function ceilingSuffix(info: TacConnectorInfo, bundleBytes: number): string {
  const max = Number(info.max_attachment_bytes);
  if (!Number.isFinite(max) || max <= 0 || bundleBytes <= 0 || bundleBytes <= max) return "";
  return `over the ${humanBytes(max)} limit`;
}

/** A field the vendor requires and the platform could not fill. */
export function isMissingField(form: { missing_fields?: string[] | null }, field: string): boolean {
  return (form.missing_fields ?? []).includes(field);
}

// ── classification ──────────────────────────────────────────────────────────

/** The note under the class. `classified:false` never borrows verdict language. */
export function classificationNote(c: TacClassification | undefined): string {
  if (!c) return "";
  if (c.classified) return (c.note || "").trim();
  return (c.note || "").trim() || NOTHING_SCORED_NOTE;
}

/** "signature ospf-exstart-mtu (weight 5)" — the exact evidence row that scored. */
export function reasonLine(r: { kind: string; ref: string; weight: number }): string {
  return `${r.kind} ${r.ref} · weight ${r.weight}`;
}

/** What the classification stood on, and what it did not have. Both are shown:
 *  "classified without X" is a fact the operator is entitled to. */
export function evidenceLine(sources: string[], missing: string[]): { on: string; without: string } {
  return {
    on: sources.length ? `Classified on: ${sources.join(" · ")}` : "Classified on no stored evidence at all.",
    without: missing.length ? `Classified without: ${missing.join(" · ")}` : "",
  };
}

// ── command review + templates (tracker 250) ────────────────────────────────
//
// The owner's rule, and the reason this step exists at all: the NOC admin sees
// the exact commands before submit, may change the set, and may save the set as
// a per-vendor template. The flexibility ends where the output-only policy
// begins — and it ends SERVER-SIDE. Everything here is presentation: the client
// shows the verdict the server returned and refuses nothing on its own
// authority, because a client-side rule is a courtesy and never an enforcement.

export const REVIEW_INTRO =
  "These are the exact commands Correlix will run, in this order. Remove what you do not want, add your own, reorder them — every line is checked against Correlix's output-only policy as you type, and again on the server before anything runs.";

/** The one sentence that bounds every line, stated where the operator edits. */
export const REVIEW_POLICY_NOTE =
  "Output only: nothing that changes configuration, restarts or reboots, or addresses a daemon — on any platform, in any template. A ping or traceroute is allowed with bounded parameters.";

export const REVIEW_REFUSED =
  "One or more commands were refused. Fix or remove them — Correlix will not run part of a list and drop the rest.";

export const VALIDATE_FAILED = "The commands could not be checked. They are checked again on the server before anything runs.";
export const TEMPLATES_FAILED = "Your saved command templates could not be read.";
export const TEMPLATE_SAVE_FAILED = "The command template could not be saved.";
export const TEMPLATE_NEEDS_NAME = "Give the template a name before saving it.";
export const REVIEW_EMPTY = "A command set with no commands collects nothing — add at least one.";

/** internal/tac: at most 200 commands in one reviewed list or template. */
export const MAX_REVIEW_COMMANDS = 200;

/** A custom line's caveat, restated for the UI when the server sent none. */
export const CUSTOM_COMMAND_NOTE =
  "written by your team — Correlix has never run this command on this platform";

/** The commands a plan will run, in order, as the review step's starting point.
 *  Topology rows are model context, not commands, so they never appear. */
export function planCommands(plan: TacPlan | undefined): string[] {
  return (plan?.steps ?? [])
    .filter((s) => s.section !== "topology" && (s.command ?? "").trim() !== "")
    .map((s) => (s.command ?? "").trim());
}

/** Move one entry of a list. An out-of-range index leaves the list untouched —
 *  a reorder must never silently drop a command. */
export function moveCommand(list: string[], from: number, to: number): string[] {
  if (from < 0 || from >= list.length || to < 0 || to >= list.length || from === to) return list;
  const out = list.slice();
  const [item] = out.splice(from, 1);
  out.splice(to, 0, item);
  return out;
}

/** The verdict shown beside one line. A refusal names the FAMILY and the RULE —
 *  "invalid" would tell an operator nothing about what Correlix will not do. */
export function verdictLine(v: TacLineVerdict | undefined): string {
  if (!v) return "";
  if (v.ok) return (v.note || "").trim() || (v.origin === "custom" ? CUSTOM_COMMAND_NOTE : "");
  const reason = (v.reason || "").trim();
  if (reason) return reason;
  if (v.family) return `refused by the output-only policy (${v.family})${v.rule ? ` — rule \`${v.rule}\`` : ""}`;
  return "refused";
}

/** The short badge on an accepted line. */
export function originLabel(v: TacLineVerdict | undefined): string {
  if (!v || !v.ok) return "";
  return v.origin === "custom" ? "your command" : "Correlix command";
}

/** How a template is labelled in the picker. A Correlix default says so with its
 *  version; a tenant template says who owns it and when it last changed. */
export function templateLabel(t: TacTemplate): string {
  if (t.source === "correlix-default") return `Correlix default v${t.version}`;
  const by = (t.created_by || "").trim();
  const when = (t.updated_at || "").trim();
  const parts = [by ? `saved by ${by}` : "saved by your team"];
  if (when) {
    const d = new Date(when);
    if (!Number.isNaN(d.getTime())) parts.push(`updated ${d.toLocaleString()}`);
  }
  parts.push(`v${t.version}`);
  return parts.join(" · ");
}

/** The save/update body. Commands are trimmed and empties dropped; the tenant is
 *  NOT a field — ownership is stamped from the token server-side. */
export function buildTemplateWrite(
  dialect: string,
  name: string,
  description: string,
  basedOn: string,
  commands: string[],
): TacTemplateWrite {
  return {
    dialect: dialect.trim(),
    name: name.trim(),
    description: description.trim(),
    based_on: basedOn.trim(),
    steps: commands
      .map((c) => c.trim())
      .filter((c) => c !== "")
      .slice(0, MAX_REVIEW_COMMANDS)
      .map((command) => ({ command })),
  };
}

/** The reviewed list for collect. Same trimming, same cap — and the server
 *  re-validates every line regardless. */
export function buildReviewedSteps(commands: string[]): { command: string }[] {
  return commands
    .map((c) => c.trim())
    .filter((c) => c !== "")
    .slice(0, MAX_REVIEW_COMMANDS)
    .map((command) => ({ command }));
}

/** The comparison form of a command — whitespace collapsed, case folded. It
 *  mirrors internal/tac's normCommandKey exactly: `show ip bgp` and
 *  `Show  ip  bgp` are the same command, and an edit list that reported them as
 *  a removal plus an addition would be noise in the bundle's provenance. */
function commandKey(s: string): string {
  return s.trim().toLowerCase().split(/\s+/).join(" ");
}

/** True when the reviewed list differs from what the engine proposed — the
 *  condition under which collect must send the list rather than the plan. */
export function reviewChanged(plan: TacPlan | undefined, commands: string[]): boolean {
  const before = planCommands(plan);
  const after = commands.map((c) => c.trim()).filter((c) => c !== "");
  if (before.length !== after.length) return true;
  return before.some((c, i) => commandKey(c) !== commandKey(after[i]));
}

/** The one-line summary of the edits a bundle will record. */
export function editSummary(plan: TacPlan | undefined): string {
  const edits = plan?.edits ?? [];
  if (edits.length === 0) return "";
  const counts = { added: 0, removed: 0, reordered: 0 };
  for (const e of edits) counts[e.kind] += 1;
  const parts: string[] = [];
  if (counts.added) parts.push(`${counts.added} added`);
  if (counts.removed) parts.push(`${counts.removed} removed`);
  if (counts.reordered) parts.push("reordered");
  return parts.length ? `Recorded in the bundle: ${parts.join(" · ")}.` : "";
}


// ── captures (docs/design/TAC_CAPTURES_2026-09-06.md) ────────────────────────
//
// The owner's rule, verbatim: "Process of extracting the commands and building
// default template even before case opening is your job. This process should be
// not visible to customer." So the escalation step no longer shows a plan, an
// intent id, a citation or a verification chip. It shows CAPTURES: a name, a
// command count, a coloured status, and a chevron that reveals the commands.
//
// Everything that used to be inline is still reachable — behind one control —
// and nothing was deleted from the product. What changed is what a person is
// made to read before they can escalate.

/** The heading of the one control that reveals the engine's own working. */
export const BEHIND_LABEL = "What Correlix is doing";

/** The upload control's own line: what it takes, in the formats' own names. */
export const UPLOAD_FORMATS_LINE = "Accepts txt, csv, json, yaml and docx.";

/** Nothing to run yet: the platform bound no command. Honest, not empty. */
export const CAPTURES_NONE = "No commands for this platform yet.";

/** Pick the device first — the capture is per platform. */
export const CAPTURES_NEED_DEVICE = "Choose the device to collect from.";

export const UPLOAD_FAILED = "That file could not be read.";
export const CAPTURE_SAVE_FAILED = "The capture could not be saved.";
export const CAPTURES_FAILED = "Your saved captures could not be read.";

/** One word per status. Never a sentence, never SHOUTED. */
export const CAPTURE_STATUS_LABEL: Record<TacCaptureStatus, string> = {
  queued: "Queued",
  running: "Running",
  done: "Done",
  partial: "Partial",
  failed: "Failed",
};

/** Where a capture came from, in the customer's words rather than the enum's. */
export const CAPTURE_SOURCE_LABEL: Record<TacCaptureSource, string> = {
  "vendor-default": "Correlix",
  uploaded: "Uploaded",
  template: "Your team",
};

/** "12 commands" — a count, singular when it is one. */
export function commandCountLine(n: number): string {
  return n === 1 ? "1 command" : `${n} commands`;
}

/** The bar's width, as a percentage of the capture's own total. A capture with
 *  no total reads as full: a bar that renders 0 % on a queued row would look
 *  like a failure, and queued is not one. */
export function captureBarPercent(p: TacCaptureProgress | undefined): number {
  if (!p || p.total <= 0) return 100;
  const finished = Math.min(p.total, p.done + p.failed);
  return Math.round((finished / p.total) * 100);
}

/**
 * The status of ONE row.
 *
 * Only the capture the collection actually ran carries a state; every other row
 * is queued, because nothing has been asked of it. Inventing a "done" on a row
 * that never ran would be the kind of filled-in-to-look-finished state this
 * whole surface exists to avoid.
 */
export function captureRowStatus(
  captureId: string,
  activeId: string,
  progress: TacCaptureProgress | undefined,
): TacCaptureStatus {
  if (!progress || captureId !== activeId) return "queued";
  return progress.status;
}

/** The commands to list under a row: ONLY the ones that failed. A clean run
 *  lists nothing — its output is in the bundle, and rendering it here is the
 *  wall of text the redesign removed. */
export function failedCommands(
  captureId: string,
  activeId: string,
  progress: TacCaptureProgress | undefined,
): TacCommandStatus[] {
  if (!progress || captureId !== activeId) return [];
  if (progress.status !== "partial" && progress.status !== "failed") return [];
  return progress.commands ?? [];
}

/** One failed command's line: the command, then its plain reason. */
export function failedCommandLine(c: TacCommandStatus): string {
  const cmd = (c.command || "").trim();
  const reason = (c.reason || "").trim() || "it did not run";
  return cmd ? `${cmd} — ${reason}` : reason;
}

/** The captures offered for this escalation, in the order they are offered:
 *  Correlix's own first (it is what runs unless somebody chooses otherwise),
 *  then an upload if one is in hand, then this tenant's saved sets. */
export function captureRows(
  vendorDefault: TacCommandCapture | undefined,
  uploaded: TacCommandCapture | null,
  saved: TacCommandCapture[] | undefined,
): TacCommandCapture[] {
  const out: TacCommandCapture[] = [];
  if (vendorDefault && vendorDefault.commands.length > 0) out.push(vendorDefault);
  if (uploaded) out.push(uploaded);
  for (const c of saved ?? []) out.push(c);
  return out;
}

/** The capture the collection will run, given what the operator picked. It
 *  falls back to the first row rather than to nothing: a selection that no
 *  longer exists must never silently become "collect everything". */
export function selectedCapture(
  rows: TacCommandCapture[],
  selectedId: string,
): TacCommandCapture | undefined {
  return rows.find((c) => c.id === selectedId) ?? rows[0];
}

/** The refused lines out of an upload's 400 body. The server reports them
 *  against the line number IN THE UPLOADED FILE; this only reads them. */
export function parseCaptureRefusals(e: unknown): TacCaptureRefusal[] {
  const f = httpFailure(e);
  if (!f || !f.body.startsWith("{")) return [];
  try {
    const parsed = JSON.parse(f.body) as { refusals?: TacCaptureRefusal[] };
    return Array.isArray(parsed.refusals) ? parsed.refusals : [];
  } catch {
    return [];
  }
}

/** One refusal, as the operator reads it: the line in THEIR file, the command,
 *  the reason, and the rule that refused it by name. */
export function refusalLine(r: TacCaptureRefusal): string {
  const rule = (r.rule || "").trim();
  const base = `Line ${r.line}: ${r.command} — ${r.reason}`;
  return rule && !r.reason.includes(rule) ? `${base} (rule \`${rule}\`)` : base;
}

/** The body that saves an uploaded capture as one of this tenant's own. The
 *  tenant is NOT a field — ownership is stamped from the token server-side. */
export function buildCaptureWrite(
  dialect: string,
  name: string,
  commands: TacCommandCapture["commands"],
): { dialect: string; name: string; commands: { command: string; note?: string }[] } {
  return {
    dialect: dialect.trim(),
    name: name.trim(),
    commands: commands
      .map((c) => ({ command: c.command.trim(), note: (c.note || "").trim() || undefined }))
      .filter((c) => c.command !== ""),
  };
}

// ── errors ──────────────────────────────────────────────────────────────────

/** Every failure on this surface goes through here, so a wrap chain or a raw
 *  status never reaches an operator. */
export function tacError(e: unknown, fallback: string): string {
  return operatorError(e, fallback);
}

/** The `error` string out of a server body, verbatim. Used ONLY where the whole
 *  point is to show the server's own sentence. */
function serverErrorText(body: string): string {
  const raw = (body || "").trim();
  if (!raw) return "";
  if (raw.startsWith("{")) {
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      const v = parsed?.error;
      return typeof v === "string" ? v.trim() : "";
    } catch {
      return "";
    }
  }
  return raw;
}

/**
 * A 503 from collect is a PRODUCT state, not a failure to explain away: this
 * deployment has no read-only runner, and the server says exactly why in a
 * sentence longer than the generic operator-error path is willing to print. So
 * the note is taken verbatim — from the refusal's own body, or from the note the
 * state read already carried — and only anything else falls back to the generic
 * sentence.
 */
export function collectErrorMessage(e: unknown, serverNote: string): string {
  const f = httpFailure(e);
  if (f && f.status === 503) {
    const note = serverErrorText(f.body) || (serverNote || "").trim();
    if (note) return note;
  }
  return operatorError(e, COLLECT_FAILED);
}

// ── the ONE ACTION (internal/tac/escalate.go, owner 2026-09-06) ─────────────
//
// The owner's goal, verbatim: "We are just trying to close that initial time
// lag, so ease of collecting data and open the case with one or two clicks,
// that's the goal."
//
// So the panel has ONE primary action and ONE confirmation screen. Everything
// between them — classify, plan, capture, route, collect, bundle, fill the form
// — is the server's, and the client never decides any of it. In particular the
// ROUTE is not computed here: the fallback ladder, the connector capabilities
// and the tenant's settings all live server-side, and a client that recomputed
// them would get it subtly different from the server that then acts.

/** The primary action's label. One button, one press, no second decision. */
export const ESCALATE_ACTION = "Escalate to TAC";

/** What the button is doing while the server classifies, plans and collects. */
export const ESCALATE_RUNNING = "Escalating…";

export const ESCALATE_FAILED = "The escalation could not be started.";
export const PREPARE_FAILED = "The case could not be prepared for review.";
export const CONFIRM_FAILED = "The case could not be opened.";
export const REFRESH_FAILED = "The case status could not be read.";

/** Nothing has been sent yet, and the button is what sends it. Stated above
 *  the button on the confirmation screen, beside the server's own sentence. */
export const CONFIRM_HEADING = "Review before sending";

/** The one control that sends. */
export const CONFIRM_ACTION = "Open case";
export const CONFIRM_RUNNING = "Opening…";

/** The confirmation screen exists but the vendor will refuse. The blockers are
 *  listed BY NAME beneath it, each with a link to where it is set. */
export const CONFIRM_BLOCKED = "This case is missing what the vendor requires.";

/** A route that opens nothing is a COMPLETE outcome, not a failure. */
export const ROUTE_PORTAL_ACTION = "Copy the case text";

/** How the route's own sentence is introduced. The server writes the sentence;
 *  this is only the word before it. */
export const ROUTE_LABEL = "Route";

/** The escalation is running and the confirmation screen is not ready yet. */
export const PREPARING_NOTE = "Collecting, then building the case for review.";

/** The escalate body. Empty fields are omitted, never sent blank, and the
 *  tenant is NEVER a field — ownership is stamped from the token server-side. */
export function buildEscalateRequest(
  deviceId: string,
  classId: string,
  includeOptional: boolean,
  target: TacTarget,
  over: {
    connectorId?: string; captureId?: string; severity?: string; title?: string;
  } = {},
): TacEscalateRequest {
  const t: TacTarget = {};
  (Object.keys(target) as (keyof TacTarget)[]).forEach((k) => {
    const v = (target[k] ?? "").trim();
    if (v) t[k] = v;
  });
  const req: TacEscalateRequest = { device_id: deviceId.trim(), include_optional: includeOptional };
  if (classId.trim()) req.class_id = classId.trim();
  if ((over.connectorId ?? "").trim()) req.connector_id = over.connectorId!.trim();
  if ((over.captureId ?? "").trim()) req.capture_id = over.captureId!.trim();
  if ((over.severity ?? "").trim()) req.severity = over.severity!.trim();
  if ((over.title ?? "").trim()) req.title = over.title!.trim();
  if (Object.keys(t).length > 0) req.target = t;
  return req;
}

/** The confirm body from the operator's edited fields. Trimmed, never padded:
 *  a field the person cleared is sent empty and the server refuses it by name
 *  rather than quietly reusing what it prepared. */
export function buildConfirmRequest(
  fields: TacConfirmRequest["form"],
  upload: { token?: string; host?: string } = {},
): TacConfirmRequest {
  const body: TacConfirmRequest = {
    form: {
      title: (fields.title ?? "").trim(),
      severity: (fields.severity ?? "").trim(),
      product: (fields.product ?? "").trim(),
      serial_number: (fields.serial_number ?? "").trim(),
      contract_id: (fields.contract_id ?? "").trim(),
      contact_name: (fields.contact_name ?? "").trim(),
      contact_email: (fields.contact_email ?? "").trim(),
      existing_case_number: (fields.existing_case_number ?? "").trim(),
    },
  };
  if ((upload.token ?? "").trim()) body.upload_token = upload.token!.trim();
  if ((upload.host ?? "").trim()) body.upload_host = upload.host!.trim();
  return body;
}

/** One blocker, as the operator reads it: what is missing and the vendor's own
 *  reason. The settings destination is a LINK beside it, never inside the
 *  sentence — an operator acts on a control, not on a paragraph. */
export function blockerLine(f: TacRequiredField): string {
  const label = (f.label || f.key || "").trim();
  const why = (f.why || "").trim();
  return why ? `${label} — ${why}` : label;
}

/** Where a blocker is set. The server names the destination in words
 *  ("Administration → Ticket delivery → Vendor contracts"); the route is ours,
 *  and an unrecognised hint gets NO link rather than a guessed one. */
export const SETTINGS_ROUTES: Readonly<Record<string, string>> = Object.freeze({
  "ticket delivery": TICKET_DELIVERY_ROUTE,
  "vendor contracts": TICKET_DELIVERY_ROUTE,
  "case connectors": TICKET_DELIVERY_ROUTE,
  "tac routing": TICKET_DELIVERY_ROUTE,
  inventory: "#/inventory/devices",
});

/** The href for a settings hint, or "" when nothing in it is recognised. */
export function settingsHref(hint: string): string {
  const h = (hint || "").toLowerCase();
  for (const key of Object.keys(SETTINGS_ROUTES)) {
    if (h.includes(key)) return SETTINGS_ROUTES[key];
  }
  return "";
}

/** The severity control: the vendor's own vocabulary when it publishes one,
 *  free text when it does not. Empty is a FACT about the vendor, not a gap. */
export function severityChoices(info: TacConnectorInfo | undefined): string[] {
  return (info?.severity_values ?? []).filter((v) => (v || "").trim() !== "");
}

/** Does this connector need the case it is attaching to? Cisco CXD and an
 *  email thread's reference id do; nothing else may ask for one. */
export function needsExistingCase(
  info: TacConnectorInfo | undefined,
  proposal: TacProposal | null,
): boolean {
  if ((proposal?.blockers ?? []).some((b) => b.key === "existing_case_number")) return true;
  if ((proposal?.form.missing_fields ?? []).includes("existing_case_number")) return true;
  if (!info) return false;
  return hasCapability(info, "attach") && !hasCapability(info, "create");
}

// ── the case chip (internal/tac/caselink.go) ────────────────────────────────
//
// This is a MIRROR of Go's CaseLink.StatusLine and CaseLink.Tooltip, and it is
// tested against the same cases caselink_test.go asserts. It exists on the
// client for one reason: the chip renders in three places (the escalation
// panel, the answer card and the Operations incident list) from data that is
// already on the page, and a round-trip per chip to fetch a sentence the server
// already computed would be three reads per row.
//
// The rule it carries is the file's whole point: a FAILED read is never a stale
// status. "2026-0907-1234 · status unknown since 09:41 UTC on 7 Sep — the vendor
// returned 503" is honest; yesterday's "Open" rendered as current is the failure
// mode this mirror must reproduce exactly.

const UTC_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** Go's zero time, as encoding/json renders it. A field carrying it is absent. */
const GO_ZERO_TIME = "0001-01-01T00:00:00Z";

/** True when a timestamp field carries nothing — absent, blank, or Go's zero. */
export function isZeroTime(iso: string | undefined | null): boolean {
  const v = (iso ?? "").trim();
  if (v === "" || v === GO_ZERO_TIME) return true;
  return Number.isNaN(new Date(v).getTime());
}

/** `time.Format("15:04 MST on 2 Jan")` in UTC, character for character. */
export function utcStamp(iso: string | undefined | null): string {
  if (isZeroTime(iso)) return "";
  const d = new Date((iso ?? "").trim());
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  return `${hh}:${mm} UTC on ${d.getUTCDate()} ${UTC_MONTHS[d.getUTCMonth()]}`;
}

/** Go's clip(s, n): the same ellipsis at the same byte count. */
export function clipText(s: string, n: number): string {
  const v = s ?? "";
  return v.length <= n ? v : `${v.slice(0, n)}…`;
}

/** The four states a case chip can be in. Each is a different SENTENCE and a
 *  different tone, so the two must be decided once and read from here. */
export type CaseChipState = "pending-number" | "not-opened" | "unknown" | "open";

/** Which state a link is in. `unknown` outranks a known status: a failed read
 *  must never be painted as the status it last saw. */
export function caseChipState(link: TacCaseLink | null | undefined): CaseChipState {
  if (!link) return "not-opened";
  const id = (link.case_id ?? "").trim();
  if (id === "") {
    return (link.connector ?? "").startsWith("email-") ? "pending-number" : "not-opened";
  }
  return (link.last_error ?? "").trim() !== "" ? "unknown" : "open";
}

/** The chip's sentence — the mirror of Go's CaseLink.StatusLine. */
export function caseStatusLine(link: TacCaseLink | null | undefined): string {
  if (!link) return "prepared · not yet opened";
  const id = (link.case_id ?? "").trim();
  const connector = (link.connector ?? "").trim();
  const lastError = (link.last_error ?? "").trim();
  const status = (link.status ?? "").trim();
  if (id === "" && connector !== "" && connector.startsWith("email-")) {
    return "opened by email · number pending";
  }
  if (id === "") return "prepared · not yet opened";
  if (lastError !== "") {
    const since = isZeroTime(link.last_checked_at) ? "just now" : utcStamp(link.last_checked_at);
    return `${id} · status unknown since ${since} — ${clipText(lastError, 120)}`;
  }
  if (status === "") return `${id} · opened`;
  return `${id} · ${status}`;
}

/** The chip's hover text — the mirror of Go's CaseLink.Tooltip: how it
 *  authenticated and how often it refreshes, which is exactly what an operator
 *  asks when the number stops moving. */
export function caseTooltip(link: TacCaseLink | null | undefined): string {
  if (!link) return "";
  const parts: string[] = [];
  if ((link.connector ?? "").trim() !== "") parts.push(`via ${link.connector}`);
  if ((link.auth_mode ?? "").trim() !== "") parts.push(`authenticated with ${link.auth_mode}`);
  if (link.closed) {
    parts.push("closed — no longer refreshing");
  } else if (!link.pollable) {
    parts.push("this path publishes no status read; refresh it in the vendor's portal");
  } else if ((link.cadence_label ?? "").trim() !== "") {
    const note = (link.cadence_note ?? "").trim();
    parts.push(`refreshing every ${link.cadence_label}${note ? ` · ${note}` : ""}`);
  }
  if (!isZeroTime(link.last_checked_at)) parts.push(`last refreshed ${utcStamp(link.last_checked_at)}`);
  return parts.join(" · ");
}

/** The chip's tone class. A failed read is bad news; a closed case is quiet. */
export const CASE_CHIP_TONE: Record<CaseChipState, string> = {
  "pending-number": "tac-chip-queued",
  "not-opened": "tac-chip-not-configured",
  unknown: "tac-chip-failed",
  open: "tac-chip-done",
};

/** A path that publishes no status read offers no refresh control — a button
 *  that could only ever fail is worse than the sentence saying why. */
export function canRefresh(link: TacCaseLink | null | undefined): boolean {
  return Boolean(link && (link.case_id ?? "").trim() !== "" && link.pollable && !link.closed);
}

/** The 60-second floor, as the operator reads it. The SERVER decides; this only
 *  renders its answer, and falls back to the floor when it named no number. */
export function refreshWaitMessage(e: unknown): string {
  const f = httpFailure(e);
  if (!f || f.status !== 429) return "";
  const body = f.body.startsWith("{") ? serverErrorText(f.body) : f.body.trim();
  return body || "This case was refreshed less than a minute ago.";
}

/**
 * The case the INCIDENT RECORD carries, as a CaseLink.
 *
 * The Operations list reads incidents, not the escalation's case register, and
 * an incident row keeps only what MarkSync writes: the connector, the number,
 * the deep link and a status word. So a failed read arrives here as the literal
 * word "unknown" WITHOUT the vendor's own sentence — the register holds that,
 * this row does not — and the chip says exactly that much and no more.
 *
 * Returns null for a row whose ticket did not come from a TAC connector: the
 * ITSM projection files its own tickets through the same fields, and painting
 * one of those as a vendor case would be a claim nobody made.
 */
export function caseLinkFromIncident(row: {
  external_system?: string;
  external_ticket_id?: string;
  external_url?: string;
  sync_status?: string;
  last_synced_at?: string;
}): TacCaseLink | null {
  const connector = (row.external_system ?? "").trim();
  if (connector === "" || !TAC_CONNECTOR_ID_SET.has(connector)) return null;
  const status = (row.sync_status ?? "").trim();
  const unknown = status.toLowerCase() === "unknown";
  return {
    connector,
    case_id: (row.external_ticket_id ?? "").trim(),
    case_url: (row.external_url ?? "").trim(),
    opened_at: row.last_synced_at ?? "",
    status: unknown || status === "opened" ? "" : status,
    tier: "routine",
    attached: false,
    last_checked_at: row.last_synced_at ?? "",
    last_error: unknown ? CASE_UNKNOWN_ON_RECORD : "",
    pollable: false,
    closed: !unknown && caseStatusReadsClosed(status),
  };
}

/** The cause a failed read leaves on an INCIDENT ROW. The vendor's own sentence
 *  stays in the escalation's case register; the row knows only that the read
 *  did not answer, and says so rather than borrowing a cause it never saw. */
export const CASE_UNKNOWN_ON_RECORD = "the last status read did not answer";

/**
 * The connector ids an INCIDENT ROW may be read as a vendor case.
 *
 * It is CONNECTOR_IDS minus the two ITSM ones. ServiceNow and Jira open TAC
 * cases too, but the auto-ticketing projection files its own tickets through
 * the very same three incident fields under the very same system names — so a
 * "servicenow" row is genuinely ambiguous, and the honest reading of an
 * ambiguous row is the ITSM pill it has always had. The vendor paths are not
 * ambiguous: nothing else writes them.
 */
const TAC_CONNECTOR_ID_SET = new Set<string>(
  CONNECTOR_IDS.filter((id) => id !== "servicenow" && id !== "jira"),
);

/** Mirrors internal/tac.CaseStatusClosed: generous about the vocabulary,
 *  conservative about the answer — an unrecognised status is OPEN. */
export function caseStatusReadsClosed(status: string): boolean {
  const s = (status || "").trim().toLowerCase();
  if (s === "") return false;
  return ["closed", "resolved", "complete", "cancelled", "canceled", "done"].some((w) => s.includes(w));
}

// ── the dry run (internal/tac/dryrun.go) ────────────────────────────────────
//
// Owner, 2026-09-07: "I don't have vendor smart contracts to login. If there is
// any way to ensure API calls work that should be good for now."
//
// A customer who has just pasted a client secret has, otherwise, exactly one way
// to find out whether it works: open a real case at three in the morning during
// an outage. So the confirmation screen carries a SECONDARY control that
// authenticates for real and then DESCRIBES the request a submit would make,
// with every secret redacted. It stays secondary: Open case is the action this
// screen exists for, and a dry run is what you do before the outage.
//
// The claim the screen makes — "Nothing was created" — is the SERVER'S
// (`created_nothing`), not a client-side assertion about code it cannot see.

export const DRY_RUN_ACTION = "Dry run";
export const DRY_RUN_RUNNING = "Checking…";
export const DRY_RUN_FAILED = "The dry run could not be made.";

/** The whole point, in three words. Rendered from the server's own flag. */
export const DRY_RUN_CREATED_NOTHING = "Nothing was created.";

/** One sentence per outcome. The server's own note follows it — this is the
 *  word Correlix puts on the state, that is what the vendor said. */
export const DRY_RUN_SENTENCE: Readonly<Record<TacDryRunOutcome, string>> = Object.freeze({
  ok: "The vendor accepted the credential.",
  incomplete: "This case is missing what the vendor requires.",
  not_configured: "Nothing to check yet.",
  refused: "The vendor refused these credentials.",
  unreachable: "The vendor could not be reached.",
  unsupported: "This path has nothing to check.",
});

/** Chip tone per outcome. Only a real refusal or outage is bad news; a path
 *  that publishes nothing to check is a complete answer, not a failure. */
export function dryRunTone(outcome: TacDryRunOutcome): string {
  if (outcome === "ok") return "tac-chip-done";
  if (outcome === "refused" || outcome === "unreachable") return "tac-chip-failed";
  if (outcome === "incomplete") return "tac-chip-partial";
  return "tac-chip-queued";
}

/** One call's summary line: what it is, how it would go out, and whether the
 *  dry run ACTUALLY made it. Only the authenticate step is ever performed, and
 *  the row says which it was rather than leaving it to be assumed. */
export function dryRunCallLine(c: TacDryRunCall): string {
  const made = c.performed ? "made" : "described";
  return `${c.step} · ${c.method} ${c.url} · ${made}`;
}

/** How long the authenticate call took, when one was made. */
export function dryRunElapsed(report: TacDryRunReport): string {
  const ms = Number(report.elapsed_ms);
  if (!Number.isFinite(ms) || ms <= 0) return "";
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;
}
