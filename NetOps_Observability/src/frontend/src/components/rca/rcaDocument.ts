// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// rcaDocument.ts — the pure derivations behind the NOC RCA document (owner
// decisions D1/D3/D4, 2026-11-11). Mirrors backend/internal/rca/
// rca_noc_document.go so the RCA view and the PDF read the same way:
//
//  · background stories (standing security posture/exposure findings) leave the
//    causal ranking — never the headline, never impact, never a break;
//  · when the persisted top was a background story, the headline tier is the
//    causal leader's own gate, capped at the object tier;
//  · who is affected reads ONLY impact evidence — the verdict is never an input;
//  · every observation names its source in plain words.
//
// Pure functions over the object + timeline — no React, no I/O.

import type { CorrSignal } from "../../services/api";
import { entityLabel, kindLabel, hypothesisNocTitle } from "./labels";
import { isContextStory } from "./rcaPhrases";

export interface RankedHyp {
  id: string;
  title: string;
  confidence: number;
  // The template's clause coverage (engine scoring); absent on older objects.
  coverage?: number;
  confidenceLabel: string;
  contradicted: boolean;
  contradictions: string[];
  satisfied: string[];
  missing: string[];
  operatorPhrase: string;
  contextStory: boolean;
  tier: string;
  owner: string;
  firstSteps: string[];
  reasons: string[];
  independentPair: string[];
}

const arr = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => String(x ?? "")).filter(Boolean) : []);

// The engine's ceiling for what optional clauses alone can score (mirror of
// rcaOptionalBonusCap in internal/rca/rca_report_wording.go).
const OPTIONAL_BONUS_CAP = 0.1;

/**
 * RCA document v2 §3.3 — none of the template's REQUIRED observations was seen;
 * it ranked only through an optional clause. Mirror of the server's
 * rcaNoRequiredClauseSatisfied: coverage at or under the optional-bonus cap and
 * below one clause's worth (1 / clauses). A "satisfied" entry can be an optional
 * clause, so an empty-satisfied test alone would miss MAC flap / OSPF / DNS on
 * P-3E0400, which each matched an optional interface or resource clause.
 */
export function noRequiredClauseSatisfied(h: Pick<RankedHyp, "missing" | "satisfied" | "contradicted" | "confidence" | "coverage">): boolean {
  if (h.missing.length === 0 || h.contradicted) return false;
  const cov = h.coverage ?? h.confidence;
  if (cov > OPTIONAL_BONUS_CAP + 1e-9) return false;
  return cov < 1 / (h.missing.length + h.satisfied.length) - 1e-9;
}

/** The persisted ranking, typed. Malformed/absent → []. */
export function parseRanking(hypotheses: string | undefined | null): RankedHyp[] {
  let raw: unknown[] = [];
  try {
    const blob = JSON.parse(hypotheses || "{}");
    raw = Array.isArray(blob?.ranking?.hypotheses) ? blob.ranking.hypotheses : [];
  } catch { return []; }
  return raw.filter((h): h is Record<string, unknown> => !!h && typeof h === "object").map((h) => {
    const v = (h.verdict && typeof h.verdict === "object" ? h.verdict : {}) as Record<string, unknown>;
    return {
      id: String(h.id ?? ""),
      title: String(h.title ?? ""),
      confidence: Number(h.confidence ?? 0) || 0,
      ...(typeof h.coverage === "number" && Number.isFinite(h.coverage) ? { coverage: h.coverage } : {}),
      confidenceLabel: String(h.confidence_label ?? ""),
      contradicted: !!h.contradicted,
      contradictions: arr(h.contradictions),
      satisfied: arr(h.satisfied),
      missing: arr(h.missing),
      operatorPhrase: String(h.operator_phrase ?? ""),
      contextStory: h.context_story === true,
      tier: String(v.verdict_tier ?? ""),
      owner: String(v.owner ?? ""),
      firstSteps: arr(v.first_steps),
      reasons: arr(v.reasons),
      independentPair: arr(v.independent_pair),
    };
  });
}

/** Split background stories off the causal ranking. */
export function splitRanking(ranked: RankedHyp[]): { causal: RankedHyp[]; background: RankedHyp[] } {
  const causal: RankedHyp[] = [];
  const background: RankedHyp[] = [];
  for (const h of ranked) (isContextStory(h.id, h.contextStory) ? background : causal).push(h);
  return { causal, background };
}

const TIER_RANK: Record<string, number> = { undetermined: 0, suspected: 1, confirmed: 2 };

/** The verdict the document may speak (see the module comment). */
export function headlineTier(objectTier: string | undefined, ranked: RankedHyp[], causal: RankedHyp[], topId?: string): string {
  const obj = (objectTier ?? "").toLowerCase();
  // The persisted top is a background story when the ranking's leader is one,
  // or — for a blob that carries no ranking — when the object's top id is one.
  const topIsStory = ranked.length ? isContextStory(ranked[0].id, ranked[0].contextStory) : isContextStory(topId);
  if (!topIsStory) return obj;
  if (!causal.length) return "undetermined";
  let t = causal[0].tier.toLowerCase();
  if (!(t in TIER_RANK)) t = causal[0].satisfied.length || causal[0].confidence > 0 ? "suspected" : "undetermined";
  return (TIER_RANK[t] ?? 0) > (TIER_RANK[obj] ?? 0) ? obj : t;
}

/** The causal hypothesis that leads: the persisted top when it is causal, else
 *  the first causal one. undefined when only background stories ranked. */
export function headlineOf(topId: string | undefined, causal: RankedHyp[]): RankedHyp | undefined {
  return causal.find((h) => h.id === topId) ?? causal[0];
}

// ── plain-words sources ────────────────────────────────────────────────────

/** A controller named from its observer id, in vendor words (multi-vendor). */
export function controllerName(observer: string | undefined): string {
  const o = (observer ?? "").toLowerCase();
  const table: Array<[string, string]> = [
    ["vmanage", "vManage"], ["meraki", "Meraki Dashboard"], ["dnac", "Catalyst Center"],
    ["catalyst", "Catalyst Center"], ["mist", "Juniper Mist"], ["aruba", "Aruba Central"],
    ["versa", "Versa Director"], ["fortimanager", "FortiManager"], ["panorama", "Panorama"],
    ["nsp", "Nokia NSP"], ["cloudvision", "Arista CloudVision"], ["cvp", "Arista CloudVision"],
  ];
  for (const [tok, name] of table) if (o.includes(tok)) return name;
  return "The controller";
}

/** Who saw an observation, as the opening of a sentence: "vManage reported",
 *  "The device's own counters showed", … */
export function plainSource(s: Pick<CorrSignal, "collection_path" | "source" | "modality_class" | "observer_id" | "observer_type">): string {
  const path = (s.collection_path ?? "").toLowerCase();
  const src = (s.source ?? "").toLowerCase();
  const lane = (s.modality_class ?? "").toLowerCase();
  const obs = s.observer_id ?? "";
  if (lane === "security" || src === "security") return "A security rule found";
  if (path.startsWith("via_controller") || src === "controller" || (s.observer_type ?? "").toLowerCase() === "controller") return `${controllerName(obs)} reported`;
  if (path.startsWith("via_cloud_api") || src === "cloud") return "The cloud provider's API reported";
  if (src === "syslog") return "The device's own log recorded";
  if (src === "trap") return "The device's own alarm reported";
  if (src === "verification" || lane === "active_verification") return "A read-only check on the device showed";
  if (src === "bgp") return "The BGP route monitor saw";
  if (src === "flow" || lane === "passive_flow") return "Traffic records showed";
  if (src === "probe" || lane === "active_probe") return obs ? `Active checks from ${entityLabel(obs)} measured` : "Active checks measured";
  if (src === "metric" || lane === "device_telemetry") return "The device's own counters showed";
  if (lane === "control_plane") return "The device's routing events showed";
  if (lane === "management_plane") return `${controllerName(obs)} reported`;
  return "A monitoring source saw";
}

/** A standing finding (posture / exposure): a property of the device, not an event. */
export function isStandingFindingKind(kind: string): boolean {
  return kind === "security_posture" || kind === "security_exposure";
}

/** A finding that carries its own first-seen time (a dated event). */
export function hasFirstSeen(s: { attrs?: string }): boolean {
  const a = attrsOf(s);
  return ["first_seen", "first_seen_at", "onset", "onset_ts"].some((k) => typeof a[k] === "string" && (a[k] as string).trim() !== "");
}

const lower1 = (s: string): string => (s && /^[A-Z][a-z]/.test(s) ? s.charAt(0).toLowerCase() + s.slice(1) : s);

export interface KnowRow { source: string; text: string }

/** Section 5 — the observations that matched the headline's clauses, grouped by
 *  who saw them. Standing findings never appear (they are background). */
export function buildHowWeKnow(signals: CorrSignal[], headline: RankedHyp | undefined): { rows: KnowRow[]; oneWitness?: string } {
  const match = new Set<string>();
  for (const c of headline?.satisfied ?? []) for (const alt of c.split("|")) match.add(alt.trim());
  const counts = new Map<string, { source: string; kind: string; n: number }>();
  const controllers = new Set<string>();
  let direct = false;
  for (const s of signals) {
    if (!s.attached || s.kind.endsWith("_clear")) continue;
    if (match.size && !match.has(s.kind)) continue;
    if (isStandingFindingKind(s.kind)) continue;
    const source = plainSource(s);
    const key = `${source}|${s.kind}`;
    const g = counts.get(key) ?? { source, kind: s.kind, n: 0 };
    g.n++;
    counts.set(key, g);
    const viaCtl = (s.collection_path ?? "").toLowerCase().startsWith("via_controller") || (s.source ?? "").toLowerCase() === "controller";
    if (viaCtl) controllers.add(source.replace(/ reported$/, "")); else direct = true;
  }
  const rows = [...counts.values()]
    .sort((a, b) => (a.source === b.source ? a.kind.localeCompare(b.kind) : a.source.localeCompare(b.source)))
    .slice(0, 8)
    .map((g) => ({ source: g.source, text: `${g.source} ${lower1(kindLabel(g.kind))} (${g.n === 1 ? "one observation" : `${g.n} observations`}).` }));
  const oneWitness = !direct && controllers.size === 1 && rows.length
    ? `Every observation above came through ${[...controllers][0]}, so together they count as one witness.`
    : undefined;
  return { rows, oneWitness };
}

export interface BackgroundItem { kind: "context_story" | "standing_finding"; title: string; detail: string; source: string; firstSeen?: string }

const BACKGROUND_NOTE = "Background on this device, not a cause. A standing finding has no start time and no mechanism, so it is never treated as the cause of a network fault. It may be unrelated.";

function attrsOf(s: { attrs?: string }): Record<string, unknown> {
  try { const a = JSON.parse(s.attrs || "{}"); return a && typeof a === "object" ? a : {}; } catch { return {}; }
}

/** Who recorded a background finding, as a noun phrase ("Seen by: …"). */
function backgroundSource(s: Pick<CorrSignal, "modality_class" | "source" | "observer_id" | "collection_path" | "observer_type">): string {
  const lane = (s.modality_class ?? "").toLowerCase();
  if (lane === "security" || (s.source ?? "").toLowerCase() === "security") return "a security rule checked against the device's configuration";
  return plainSource(s).replace(/ (reported|showed|recorded|found|measured|saw)$/, "");
}

/** Section 7 — background stories and standing security findings. */
export function buildBackground(stories: RankedHyp[], signals: CorrSignal[]): BackgroundItem[] {
  const out: BackgroundItem[] = [];
  for (const h of stories) {
    if (h.confidence <= 0 && !h.satisfied.length) continue;
    const phrase = h.operatorPhrase.trim();
    out.push({
      kind: "context_story",
      title: hypothesisNocTitle(h.id, h.title),
      detail: `${phrase ? (phrase.endsWith(".") ? phrase : phrase + ".") + " " : ""}${BACKGROUND_NOTE}`,
      source: "security findings evaluated against this device",
    });
  }
  const groups = new Map<string, BackgroundItem & { n: number }>();
  for (const s of signals) {
    const lane = (s.modality_class ?? "").toLowerCase();
    if (s.kind.endsWith("_clear") || s.kind === "security_signal") continue;
    if (!isStandingFindingKind(s.kind) && lane !== "security") continue;
    const a = attrsOf(s);
    const title = typeof a.control_title === "string" && a.control_title.trim() ? a.control_title.trim() : kindLabel(s.kind);
    const first = ["first_seen", "first_seen_at", "onset", "onset_ts"].map((k) => a[k]).find((v) => typeof v === "string" && v.trim()) as string | undefined;
    const key = `${s.kind}|${title}`;
    const g = groups.get(key) ?? { kind: "standing_finding" as const, title, detail: "", source: backgroundSource(s), n: 0 };
    g.n++;
    if (first && (!g.firstSeen || first < g.firstSeen)) g.firstSeen = first;
    groups.set(key, g);
  }
  for (const [, g] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const obs = g.n === 1 ? "one observation" : `${g.n} observations`;
    out.push({
      kind: "standing_finding", title: g.title, source: g.source,
      ...(g.firstSeen ? { firstSeen: g.firstSeen } : {}),
      detail: g.firstSeen
        ? `${kindLabel(g.title === kindLabel(g.title) ? g.title : g.title)} — ${obs}, first seen ${g.firstSeen}. Recorded as background.`
        : `Standing finding (${obs}) — recorded as background, not a cause.`,
    });
  }
  return out.slice(0, 8);
}

export interface OtherExplanation { title: string; why: string }

/** Section 8 — the other causal explanations, each with why it is not the answer. */
export function buildOthers(causal: RankedHyp[], headline: RankedHyp | undefined): OtherExplanation[] {
  return causal
    .filter((h) => h !== headline && (h.confidence > 0 || h.satisfied.length > 0 || h.contradicted))
    .slice(0, 5)
    .map((h) => {
      const title = hypothesisNocTitle(h.id, h.title);
      const human = (xs: string[]) => xs.slice(0, 3).map((k) => k.split("|").map((p) => kindLabel(p.trim())).join(" or ")).join("; ");
      let why: string;
      if (h.contradicted && h.contradictions.length) why = `Ruled out — evidence against it: ${human(h.contradictions)}.`;
      else if (h.contradicted) why = "Ruled out — the evidence contradicts it.";
      else if (/experience|degraded/i.test(h.id)) why = "Describes what was seen, not why — it is not a cause.";
      // RCA document v2 §3.3: a template with NO required evidence satisfied was
      // never observed — it is the nearest competitor, never "observed"/"active".
      else if (noRequiredClauseSatisfied(h)) why = `Nearest competitor — not observed: none of its required evidence was seen (${human(h.missing)}).`;
      else if (h.missing.length) why = `Ranked lower — still missing: ${human(h.missing)}.`;
      else why = "Ranked lower — it matches less of the evidence than the leading explanation.";
      return { title, why };
    });
}

export type AxisState = "measured" | "indicated" | "not measured";
export interface AffectedAxis { axis: string; state: AxisState; detail: string }

/** The server report's impact axes, when the workspace has them. */
export interface ImpactAxesFromReport { real_user?: string; synthetic?: string }

const REAL_USER_KINDS = new Set(["lb_5xx", "lb_target_unhealthy", "app_error_rate_high", "app_latency_high", "lb_4xx_high"]);

/** Section 2 — who is affected, each axis measured / indicated / not measured.
 *  Reads ONLY impact evidence (or the server's impact axes) — never the verdict,
 *  and never security evidence. */
export function buildAffectedAxes(
  signals: CorrSignal[], sites: string[], apps: string[], fromReport?: ImpactAxesFromReport,
): AffectedAxis[] {
  const att = signals.filter((s) => s.attached && !s.kind.endsWith("_clear"));
  const realUser = att.filter((s) => REAL_USER_KINDS.has(s.kind) || (s.kind === "cloud_health" && s.entity_type === "app")).length;
  const synthetic = att.filter((s) => (s.kind.startsWith("synthetic_") || s.kind.startsWith("probe_")) && ((s as { probe_scope?: string }).probe_scope ?? "") === "customer_path").length;
  const flow = att.filter((s) => s.modality_class === "passive_flow").length;
  const out: AffectedAxis[] = [];
  const ru = fromReport?.real_user;
  if (ru === "confirmed") out.push({ axis: "Real users", state: "measured", detail: "Real-user evidence shows users were affected; the number of users is not measured." });
  else if (ru === "none_detected") out.push({ axis: "Real users", state: "measured", detail: "Real-traffic telemetry covered the whole window and showed no user impact." });
  else if (ru === "detected" || ru === "indicator_detected" || (!ru && realUser > 0)) out.push({ axis: "Real users", state: "indicated", detail: "Real-user errors or traffic changes appeared, but no independent measurement confirms users were affected." });
  else out.push({ axis: "Real users", state: "not measured", detail: "No real-user telemetry covered this case. Not measured is not the same as not affected." });
  const syn = fromReport?.synthetic;
  if (syn === "confirmed" || (!syn && synthetic > 0)) out.push({ axis: "Synthetic checks", state: "measured", detail: `Configured checks failed${synthetic ? ` (${synthetic === 1 ? "one failed observation" : `${synthetic} failed observations`})` : ""}.` });
  else if (syn === "none_detected") out.push({ axis: "Synthetic checks", state: "measured", detail: "Synthetic checks ran through the window and none failed." });
  else out.push({ axis: "Synthetic checks", state: "not measured", detail: "No synthetic check covered this case." });
  out.push(flow > 0
    ? { axis: "Real traffic (flow records)", state: "indicated", detail: "Traffic volume changed. This is an indicator — demand shifts and collection loss look the same." }
    : { axis: "Real traffic (flow records)", state: "not measured", detail: "No traffic-flow change is attached to this case." });
  out.push(sites.length
    ? { axis: "Sites", state: "indicated", detail: `${sites.slice(0, 5).join(", ")} — named by the evidence; other sites are not counted.` }
    : { axis: "Sites", state: "not measured", detail: "No site is named by the evidence." });
  out.push(apps.length
    ? { axis: "Applications", state: "indicated", detail: `${apps.slice(0, 5).join(", ")} — named by the evidence.` }
    : { axis: "Applications", state: "not measured", detail: "No application is named by the evidence." });
  return out;
}

/** The impact half of a sentence, read ONLY from the axes. */
export function impactSentence(axes: AffectedAxis[]): string {
  const st = (a: string) => axes.find((x) => x.axis === a)?.state;
  if (st("Real users") === "measured" && /affected/.test(axes.find((x) => x.axis === "Real users")?.detail ?? "") && !/no user impact/.test(axes.find((x) => x.axis === "Real users")?.detail ?? "")) return "Customer impact is measured.";
  if (st("Synthetic checks") === "measured" && /failed/.test(axes.find((x) => x.axis === "Synthetic checks")?.detail ?? "") && !/none failed/.test(axes.find((x) => x.axis === "Synthetic checks")?.detail ?? "")) return "Failed checks are measured; real-user impact is not measured.";
  if (axes.some((x) => (x.axis === "Real users" || x.axis === "Real traffic (flow records)") && x.state === "indicated")) return "Impact is indicated but not measured.";
  return "Customer impact is not measured.";
}
