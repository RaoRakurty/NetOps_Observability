// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// CitedText — an Iris narrative with its inline evidence references rendered
// as readable chips (owner report 2026-11-12: answers showed raw tokens such
// as "[problem:4fdcb775-6e0c-5827-8c23-31467149ebff, problem:033eced1-…]").
//
// The server's grounding check has already removed every reference the model
// invented (ai.VerifyGrounding keeps only ids from the answer's own evidence),
// so this component only RENDERS what survived: a problem id becomes its
// operator handle (P-4FDCB7) linked to that problem, any other evidence id
// becomes a short chip labelled from the answer's own citation list. Every
// string is an escaped React text node and every href passes the same
// allowlist as the citation chips (OWASP LLM02 — never dangerouslySetInnerHTML).
// A bracket that is not a citation ("[1]", "[note]") is shown as typed.

import type { ReactNode } from "react";
import { friendlyProblemId } from "../components/rca/labels";
import { answerCiteHref, irisHref } from "./links";

/** One citation the answer carries (the subset this component reads). */
export type CiteRef = { id: string; label?: string; href?: string };

// A bracket of one or more evidence ids: "[kind:detail]" or
// "[kind:a, kind:b]". The id grammar matches the server's (a kind, a colon,
// then no whitespace, comma, semicolon or bracket).
const CITE_ID = String.raw`[a-z][a-z0-9_]*:[^\s,;\[\]]+`;
const CITE_GROUP = new RegExp(String.raw`\[\s*(${CITE_ID}(?:\s*[,;]\s*${CITE_ID})*)\s*\]`, "gi");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The readable label of one evidence id, or "" when there is none to give
 *  (the id is then shown exactly as the answer wrote it). */
export function citeLabel(id: string, cites: CiteRef[] = []): string {
  const [kind, ...rest] = id.split(":");
  const detail = rest.join(":");
  if (kind.toLowerCase() === "problem" && UUID.test(detail)) return friendlyProblemId(detail);
  const c = cites.find((x) => x.id.toLowerCase() === id.toLowerCase());
  const label = (c?.label || "").trim();
  if (label) return label.length > 32 ? label.slice(0, 32) + "…" : label;
  return "";
}

/** The safe href of one evidence id, or null (rendered as text). */
export function citeHref(id: string, cites: CiteRef[] = []): string | null {
  const c = cites.find((x) => x.id.toLowerCase() === id.toLowerCase());
  const own = answerCiteHref(c?.href);
  if (own) return own;
  const [kind, ...rest] = id.split(":");
  const detail = rest.join(":");
  if (kind.toLowerCase() === "problem" && UUID.test(detail)) return irisHref("incident", detail);
  return null;
}

/** The text split into prose and citation groups (each group a list of ids). */
export function splitCitations(text: string): Array<string | string[]> {
  return groups(text).map((g) => (typeof g === "string" ? g : g.ids));
}

type Group = string | { raw: string; ids: string[] };

function groups(text: string): Group[] {
  const out: Group[] = [];
  let last = 0;
  for (const m of text.matchAll(CITE_GROUP)) {
    const at = m.index ?? 0;
    if (at > last) out.push(text.slice(last, at));
    out.push({ raw: m[0], ids: m[1].split(/\s*[,;]\s*/).filter(Boolean) });
    last = at + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/** Plain text with every citation group that has readable handles replaced
 *  by them ("… flapping (P-4FDCB7, P-033ECE)") — for a surface that is not
 *  React. An id with no handle is kept as written. */
export function readableCitations(text: string, cites: CiteRef[] = []): string {
  return groups(text)
    .map((g) => {
      if (typeof g === "string") return g;
      const labels = g.ids.map((id) => citeLabel(id, cites) || id);
      return labels.some((l, i) => l !== g.ids[i]) ? `(${labels.join(", ")})` : g.raw;
    })
    .join("");
}

export default function CitedText({ text, citations, onCite }: { text: string; citations?: CiteRef[]; onCite?: () => void }) {
  // Prose and groups with nothing readable to show stay one text run, exactly
  // as written; only a group with at least one handle becomes chips.
  const nodes: ReactNode[] = [];
  let run = "";
  groups(text).forEach((g, i) => {
    if (typeof g === "string" || g.ids.every((id) => !citeLabel(id, citations))) {
      run += typeof g === "string" ? g : g.raw;
      return;
    }
    if (run) nodes.push(run);
    run = "";
    nodes.push(
      <span key={`c${i}`} className="op-inline-cites" data-testid="iris-inline-cite">
        {g.ids.map((id, j) => {
          const label = citeLabel(id, citations);
          const href = label ? citeHref(id, citations) : null;
          return (
            <span key={id + j}>
              {j > 0 && ", "}
              {!label ? id : href ? (
                <a className="op-inline-cite" href={href} title={label} onClick={onCite}>{label}</a>
              ) : (
                <span className="op-inline-cite" title={label}>{label}</span>
              )}
            </span>
          );
        })}
      </span>,
    );
  });
  if (run) nodes.push(run);
  return <>{nodes}</>;
}
