// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// StatementText — an Iris narrative with the server's STATEMENT CLASS shown
// beside every sentence (tracker 337 N-B4).
//
// The server classifies each sentence — Observed, Correlix analysis, Derived,
// Past investigation, Documentation, Recommendation — and says whether it is
// grounded in evidence of its class. This component only RENDERS that: every
// string is server data shown as an escaped React text node, the class is a
// WORD (never colour alone), a sentence with no evidence of its own says so,
// and the server's per-sentence notes (a reworded change, a downgraded claim)
// are listed under the text. Fonts stay on the 14 / 16 px scale.
//
// Defensive by construction: when the statements are absent, or do not spell
// the text exactly (an older or mismatched payload), the plain text is shown
// unchanged — the classes never alter what the operator reads.

import type { AiStatement } from "../services/api";

const muted14 = { fontSize: 14, lineHeight: 1.5, color: "var(--muted)" } as const;
const tag14 = {
  fontSize: 14,
  lineHeight: 1.3,
  color: "var(--muted)",
  border: "1px solid var(--panel-border, var(--border))",
  borderRadius: 4,
  padding: "0 4px",
  marginLeft: 4,
  whiteSpace: "nowrap",
} as const;

/** The operator's word for each statement class. An unknown class from a
 *  newer backend is shown verbatim (escaped), never dropped. */
export const CLASS_WORD: Record<string, string> = {
  OBSERVED: "Observed",
  CORRELIX_RCA: "Correlix analysis",
  DERIVED: "Derived",
  HISTORICAL: "Past investigation",
  DOCUMENTATION: "Documentation",
  RECOMMENDATION: "Recommendation",
};

export function classWord(cls: string | undefined): string {
  const c = (cls || "").trim();
  return CLASS_WORD[c] ?? c;
}

/** The tag shown after one sentence. */
export function statementTag(st: AiStatement): string {
  const word = classWord(st.class);
  return st.grounded ? word : `${word} · no evidence cited`;
}

/** True when the statements spell the text exactly — the only case in which
 *  they are rendered. */
export function statementsMatch(text: string, statements: AiStatement[] | undefined): boolean {
  if (!statements || statements.length === 0) return false;
  return statements.map((s) => s.text ?? "").join("") === text;
}

export default function StatementText({ text, statements, className }: {
  text: string;
  statements?: AiStatement[];
  className?: string;
}) {
  if (!statementsMatch(text, statements)) {
    return <div className={className}>{text}</div>;
  }
  const sts = statements as AiStatement[];
  const notes = Array.from(new Set(sts.map((s) => (s.note || "").trim()).filter(Boolean)));
  return (
    <div className={className} data-testid="iris-statements">
      {sts.map((st, i) => {
        const body = st.text.replace(/\s+$/, "");
        const trail = st.text.slice(body.length);
        return (
          <span key={i} data-testid="iris-stmt" data-class={st.class} data-grounded={st.grounded ? "yes" : "no"}>
            {body}
            <span style={tag14} data-testid="iris-stmt-class" title={st.note || undefined}>{statementTag(st)}</span>
            {trail}
          </span>
        );
      })}
      {notes.length > 0 && (
        <ul style={{ ...muted14, margin: "6px 0 0", paddingLeft: 18 }} data-testid="iris-stmt-notes">
          {notes.map((n) => <li key={n} style={muted14}>{n}</li>)}
        </ul>
      )}
    </div>
  );
}
