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
  TacPlan,
  TacPlanRequest,
  TacProgress,
  TacSection,
  TacState,
  TacStep,
  TacTarget,
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

/** `has_plan:false` — the dialect carries no authored command set. */
export const NO_AUTHORED_PLAN_NOTE =
  "There is no authored command set for this platform. Every intent is listed unbound below; collect the outputs in your own session and paste them in the collect step.";

/** Shown beside the device picker before a plan exists. */
export const PLAN_NEEDS_DEVICE = "Choose the device the outputs come from, then build the plan.";

/** A step whose intent this dialect binds no command for, with no server reason. */
export const UNBOUND_STEP_REASON = "This platform binds no command for this intent.";

export const VERIFIED_LABEL = "verified on this platform";
export const DOC_CLAIMED_LABEL = "documented, not verified";

/** The paste path, offered wherever a command cannot be run for us. */
export const PASTE_INVITE =
  "Paste the output from your own session. Anything left empty is simply not collected.";

/** Nothing has been collected, so there is nothing to bundle or attach yet. */
export const NO_CAPTURE_YET =
  "Nothing has been collected yet — start the collection or paste the outputs above.";

export const NO_BUNDLE_YET = "No bundle has been built for this escalation yet.";

/** A connector the tenant has brought no credentials for. */
export const CONNECTOR_NOT_CONFIGURED =
  "Not configured for this tenant — bring your own credentials to use it.";

/** A connector that can prepare the text but cannot open the case itself. */
export const CONNECTOR_CANNOT_CREATE =
  "This connector cannot open the case itself; it prepares the case text and the bundle for the vendor's portal.";

/** Submitting is always a person's press (design §4). */
export const CASE_HUMAN_APPROVED =
  "Review every field first — Correlix never opens a case on its own.";

// Iris → Knowledge.
export const KNOWLEDGE_FAILED = "The coverage catalogue could not be read.";
export const KNOWLEDGE_GROWTH_NOTE =
  "Coverage grows from owner runbooks: vendor research is filed under ai/tac/research/<vendor>.yaml and merged into the classes and the per-dialect plans by scripts/tac-merge-research.py.";
/** The unknown-output backlog is NOT counted anywhere yet, and a 0 would read
 *  as "there is none". Say the truth instead. */
export const BACKLOG_NOT_TRACKED =
  "Not yet tracked — outputs the parsers do not recognise are not counted anywhere yet, so no number is shown here.";
export const NO_UNPLANNED_DIALECTS =
  "Every platform Correlix recognises carries an authored plan.";

// ── bounds (the server's own, mirrored so the UI refuses before the wire) ────

/** internal/tac: at most 40 pasted outputs, 256 KiB each, per request. */
export const MAX_PASTE_OUTPUTS = 40;
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

/** The reason an unbound step carries, never blank. */
export function unboundReason(step: TacStep): string {
  return (step.note || "").trim() || UNBOUND_STEP_REASON;
}

// ── plan sections ───────────────────────────────────────────────────────────

export const SECTION_ORDER: TacSection[] = ["baseline", "deep-dive", "optional", "topology"];

export const SECTION_TITLE: Record<TacSection, string> = {
  baseline: "Baseline — collected for every class",
  "deep-dive": "Deep dive — this issue class",
  optional: "Optional — large or slow captures",
  topology: "Topology — from Correlix's own model",
};

/** Steps grouped into the four sections, each in the plan's own order. */
export function groupSteps(steps: TacStep[] | undefined): Record<TacSection, TacStep[]> {
  const out: Record<TacSection, TacStep[]> = { baseline: [], "deep-dive": [], optional: [], topology: [] };
  for (const s of steps ?? []) {
    const sec = SECTION_ORDER.includes(s.section) ? s.section : "baseline";
    out[sec].push(s);
  }
  return out;
}

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

/**
 * The intents the operator may paste for: every unbound step of the plan, plus
 * every planned command the capture did not bring back. It is the honest
 * inverse of what the runner managed — it never invites a paste for something
 * already collected.
 */
export function pasteIntents(plan: TacPlan | undefined, state: TacState | null | undefined): TacStep[] {
  if (!plan) return [];
  const captured = new Set(
    (state?.capture?.commands ?? [])
      .filter((c) => !c.error && (c.output ?? "") !== "")
      .map((c) => c.intent),
  );
  const wanted: TacStep[] = [
    ...(plan.unbound ?? []),
    ...(plan.steps ?? []).filter((s) => s.section !== "topology"),
  ];
  const seen = new Set<string>();
  return wanted.filter((s) => {
    if (captured.has(s.intent) || seen.has(s.intent)) return false;
    seen.add(s.intent);
    return true;
  });
}

/** The collect body for pasted output: non-empty entries only, server-bounded. */
export function buildPasteOutputs(
  steps: TacStep[],
  typed: Record<string, string>,
): { intent: string; command: string; output: string }[] {
  const out: { intent: string; command: string; output: string }[] = [];
  for (const s of steps) {
    const text = (typed[s.intent] ?? "").trim();
    if (!text) continue;
    if (out.length >= MAX_PASTE_OUTPUTS) break;
    out.push({ intent: s.intent, command: s.command ?? "", output: text.slice(0, MAX_PASTE_CHARS) });
  }
  return out;
}

// ── bundle ──────────────────────────────────────────────────────────────────

export const BUNDLE_PROFILES: { id: string; label: string; hint: string }[] = [
  { id: "full", label: "Full", hint: "everything collected — for an API upload" },
  { id: "email", label: "Email", hint: "trimmed to 14 MB so it survives mail gateways" },
  { id: "link_only", label: "Link only", hint: "the case text and the manifest, without the outputs" },
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

/** What a connector can honestly do, in the operator's words. */
export function connectorCapabilityLine(info: TacConnectorInfo): string {
  const can: string[] = [];
  if (hasCapability(info, "create")) can.push("opens the case");
  if (hasCapability(info, "attach")) can.push("attaches the bundle");
  if (hasCapability(info, "poll_status")) can.push("reads the case status back");
  if (hasCapability(info, "link")) can.push("records the case link");
  if (can.length === 0) return CONNECTOR_CANNOT_CREATE;
  const line = can.join(" · ");
  return hasCapability(info, "create") ? line : `${line}. ${CONNECTOR_CANNOT_CREATE}`;
}

/** The note under a connector: its own words when it has them, ours otherwise. */
export function connectorNote(info: TacConnectorInfo): string {
  if (info.note && info.note.trim()) return info.note.trim();
  return info.configured ? "" : CONNECTOR_NOT_CONFIGURED;
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
