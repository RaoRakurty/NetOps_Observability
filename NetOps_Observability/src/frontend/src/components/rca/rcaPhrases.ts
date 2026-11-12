// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// The four fixed confidence phrases (owner decision D4, 2026-11-11) and the
// context-story test (decision D1). THE TypeScript definition — the RCA view
// reads it; the Go mirror is backend/internal/noclabel/confidence.go (used by
// the server report, the PDF and Iris). When one side changes, change the other.
//
// Strongest first:
//   Confirmed cause · Likely cause · Possibly because of X · Cause not determined
//
// The level comes from the engine's verdict tier and confidence_label, never
// from the ranking number (a heuristic rank, not a probability).

export type ConfidenceLevel = "confirmed" | "likely" | "suspected" | "undetermined";

export const PHRASE_CONFIRMED = "Confirmed cause";
export const PHRASE_LIKELY = "Likely cause";
export const PHRASE_POSSIBLY = "Possibly because of";
export const PHRASE_NOT_DETERMINED = "Cause not determined";

/** Engine tier + confidence_label → level. confirmed → confirmed; likely →
 *  likely; suspected → suspected; anything else → undetermined. */
export function levelFor(tier: string | undefined, label: string | undefined): ConfidenceLevel {
  const t = (tier ?? "").trim().toLowerCase();
  const l = (label ?? "").trim().toLowerCase();
  if (t === "confirmed") return "confirmed";
  if (l === "likely") return "likely";
  if (t === "suspected" || l === "suspected") return "suspected";
  if (t === "" && l === "confirmed") return "confirmed";
  return "undetermined";
}

/** Lower-case the first letter of a plain sentence-cased first word; leave
 *  acronyms and proper names ("BGP …", "IPsec …") alone. */
function midSentence(s: string): string {
  if (!s) return s;
  const first = s.split(/[ \t]/)[0];
  if (!/^[A-Z]/.test(first)) return s;
  if (/[A-Z]/.test(first.slice(1))) return s;
  return s.charAt(0).toLowerCase() + s.slice(1);
}

/** Level → its fixed phrase. "Possibly because of" needs the cause in NOC
 *  words; with none it reads "Cause not determined" — never a dangling phrase. */
export function phraseFor(level: ConfidenceLevel, cause?: string): string {
  const c = (cause ?? "").trim().replace(/\.+$/, "");
  switch (level) {
    case "confirmed": return PHRASE_CONFIRMED;
    case "likely": return PHRASE_LIKELY;
    case "suspected": return c ? `${PHRASE_POSSIBLY} ${midSentence(c)}` : PHRASE_NOT_DETERMINED;
    default: return PHRASE_NOT_DETERMINED;
  }
}

/** One-call form: engine tier + label (+ cause for the suspected phrase). */
export function confidencePhrase(tier: string | undefined, label: string | undefined, cause?: string): string {
  return phraseFor(levelFor(tier, label), cause);
}

/** Background-story templates persisted BEFORE the engine emitted
 *  `context_story: true` (owner D1). The dated threat-signal story is not here. */
export const CONTEXT_STORY_FALLBACK_IDS: ReadonlySet<string> = new Set([
  "sig.ent.security.exposure-story",
  "sig.ent.security.hardening-drift-story",
]);

/** A background story: the engine's flag, or a pre-flag template id. */
export function isContextStory(id: string | undefined, flagged?: boolean): boolean {
  return !!flagged || CONTEXT_STORY_FALLBACK_IDS.has((id ?? "").trim());
}

/** The RCA document's section names, in reading order (UI + PDF). */
export const RCA_SECTION_NAMES = [
  "What broke",
  "Who is affected",
  "When",
  "Cause and how sure we are",
  "How we know",
  "Where the break is",
  "Background on this device (not a cause)",
  "Other explanations considered",
  "Who owns the fix",
  "What to do now · Watch for recurrence",
] as const;

/** Section 4's checklist heading — owner-mandated wording (2026-11-11). */
export const WOULD_CONFIRM_LABEL = "What would confirm it";

/** The one-page "How to read this RCA" guide (UI help panel + PDF last page). */
export const HOW_TO_READ: readonly string[] = [
  "Read sections 1 and 2 first: is this mine, and who is hurting?",
  "Take section 4's phrase literally. \"Confirmed cause\" means two independent sources measured the same fault. \"Possibly because of X\" means work the \"What would confirm it\" list before escalating.",
  "Section 5 names the sources. Several observations that all came through one controller count as one witness.",
  "On the path, red is a measured break and dotted is inferred.",
  "Section 7 is background and may be unrelated: do not file it as the cause.",
  "Section 9 says who to call.",
];
