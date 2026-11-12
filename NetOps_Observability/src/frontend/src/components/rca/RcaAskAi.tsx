// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, StreamBrokenError, type AiAnswer, type AiCitation } from "../../services/api";
import Icon from "../Icon";
import { useAIEntitlements } from "../../lib/aiEntitlements";
import { httpFailure, operatorError } from "../../lib/errors";
import IrisProgress, { type ProgressStep } from "../../iris/IrisProgress";
import { applyEvent } from "../../iris/progressStream";
import { answerCiteHref } from "../../iris/links";
import { friendlyProblemId } from "./labels";

// RcaAskAi — Iris docked in the RCA view, scoped to THIS problem (RCA document
// v2 §5). A conversation, not a one-shot card:
//
//  · every turn sends `context.correlation_id` — the problem in view is the
//    default subject of every question ("Explain this problem" is the grounded
//    explanation of the problem, never product help — the routing is server
//    side, WS-D);
//  · follow-ups ride the server conversation (`conversation_id`), so "and who
//    owns it?" resolves against what was already said;
//  · suggested questions cover what a NOC engineer asks next;
//  · progress streams while Iris reads the evidence (aiAskStream), with one
//    fallback to the plain ask when a proxy cuts the stream;
//  · citations are links back into the evidence (P-xxxx, the evidence views) —
//    hrefs pass the same same-origin allowlist every Iris answer uses;
//  · the footer says what answered (a named model, or evidence only) and takes
//    a thumbs up / down.
//
// SECURITY (CLAUDE.md §15 LLM02): model text renders ONLY as escaped React text
// — never dangerouslySetInnerHTML, never parsed as markup. The question is sent
// verbatim; the server owns the system prompt and the grounding. Errors reach
// the screen through operatorError, never as the raw api envelope.

export const RCA_SUGGESTED_QUESTIONS: readonly string[] = [
  "Explain this problem",
  "Why is this only suspected?",
  "What should I check next?",
  "Who is affected?",
  "What changed before this?",
  "Top talkers on the affected link",
];

const MAX_QUESTION = 2000;   // the server bounds it too; this keeps the box honest
const MAX_TURNS = 40;        // a long conversation keeps its newest turns on screen

interface Turn {
  id: number;
  question: string;
  answer?: AiAnswer;
  error?: string;
  rated?: "up" | "down";
}

// A citation's visible label: a problem id reads as its NOC handle (P-xxxx).
function citeLabel(c: AiCitation): string {
  const label = (c.label || "").trim();
  if (label) return label;
  const id = (c.id || "").trim();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(id) ? friendlyProblemId(id) : id || "evidence";
}

function Citation({ c }: { c: AiCitation }) {
  const href = answerCiteHref(c.href);
  const text = citeLabel(c);
  return href
    ? <a className="ric-cite" href={href} title={text}>{text}</a>
    : <span className="ric-cite plain" title={text}>{text}</span>;
}

function footerText(a: AiAnswer): string {
  if (a.model) return `Grounded in this problem's evidence · ${a.model}`;
  if (!a.provider || a.provider === "none") return "Evidence only — no model answered";
  return `Grounded in this problem's evidence · ${a.provider}`;
}

export default function RcaAskAi({ correlationId }: { correlationId: string }) {
  const ent = useAIEntitlements();
  const [turns, setTurns] = useState<Turn[]>([]);
  const [busy, setBusy] = useState(false);
  const [steps, setSteps] = useState<ProgressStep[]>([]);
  const [draft, setDraft] = useState("");
  const convRef = useRef<string | null>(null);
  const seq = useRef(0);
  const logRef = useRef<HTMLDivElement | null>(null);

  // A different problem is a different conversation.
  useEffect(() => {
    convRef.current = null;
    setTurns([]);
    setSteps([]);
  }, [correlationId]);

  useEffect(() => {
    const el = logRef.current;
    if (el && typeof el.scrollTo === "function") el.scrollTo({ top: el.scrollHeight });
  }, [turns, steps]);

  const context = { correlation_id: correlationId };

  // One ask: streamed progress, the same answer as aiAsk; a cut stream falls
  // back ONCE to the plain JSON ask.
  const askOnce = async (q: string, conv: string | undefined): Promise<AiAnswer> => {
    setSteps([]);
    try {
      return await api.aiAskStream(q, context, conv, (ev) => setSteps((s) => applyEvent(s, ev)));
    } catch (e) {
      if (!(e instanceof StreamBrokenError)) throw e;
      setSteps([]);
      return api.aiAsk(q, context, conv);
    }
  };

  const ask = async (raw: string) => {
    const q = raw.trim().slice(0, MAX_QUESTION);
    if (!q || busy) return;
    const id = ++seq.current;
    setTurns((t) => [...t, { id, question: q }].slice(-MAX_TURNS));
    setDraft("");
    setBusy(true);
    try {
      let conv = convRef.current;
      // Follow-ups need a server conversation (ai.nlquery). Without it the ask
      // still works — each question is answered on its own.
      if (!conv && ent.has("ai.nlquery")) {
        try { conv = (await api.startIrisConversation()).id; } catch { conv = null; }
      }
      let ans: AiAnswer;
      try {
        ans = await askOnce(q, conv ?? undefined);
      } catch (e) {
        // A conversation the server no longer has: drop it and ask once without.
        if (!conv || httpFailure(e)?.status !== 404) throw e;
        convRef.current = null;
        ans = await askOnce(q, undefined);
      }
      convRef.current = ans.conversation_id ?? null;
      setTurns((t) => t.map((x) => (x.id === id ? { ...x, answer: ans } : x)));
    } catch (e) {
      const msg = operatorError(e, "Iris could not answer that just now.");
      setTurns((t) => t.map((x) => (x.id === id ? { ...x, error: msg } : x)));
    } finally {
      setBusy(false);
      setSteps([]);
    }
  };

  const rate = (turn: Turn, r: "up" | "down") => {
    if (turn.rated || !turn.answer) return;
    setTurns((t) => t.map((x) => (x.id === turn.id ? { ...x, rated: r } : x)));
    // Best effort: a rating never blocks the conversation.
    api.aiFeedback(r, turn.answer.intent, convRef.current ?? undefined, turn.answer.answer_id).catch(() => {});
  };

  const submit = (e: FormEvent) => { e.preventDefault(); void ask(draft); };

  if (!ent.has("ai.chat")) return null;

  const pid = friendlyProblemId(correlationId);
  return (
    <section className="ric" aria-label={`Ask Iris about ${pid}`} data-testid="rca-iris-chat">
      <header className="ric-head">
        <span className="ric-mark" aria-hidden="true"><Icon name="copilot" size={16} /></span>
        <div className="ric-title">
          <h3>Ask Iris</h3>
          <span className="ric-scope">About {pid}</span>
        </div>
      </header>

      <div className="ric-log" ref={logRef} role="log" aria-live="polite" aria-busy={busy}>
        {turns.length === 0 && (
          <p className="ric-hello">Ask anything about {pid}. Answers cite this problem&apos;s evidence.</p>
        )}
        {turns.map((t) => (
          <div key={t.id} className="ric-turn">
            <div className="ric-q">{t.question}</div>
            {t.error && <div className="ric-err" role="alert">{t.error}</div>}
            {t.answer && (
              <div className="ric-a">
                {/* Model text: escaped React text only (LLM02). */}
                <div className="ric-text">{t.answer.text || "No answer."}</div>
                {t.answer.problem && (t.answer.problem.recommended_owner || (t.answer.problem.missing_evidence?.length ?? 0) > 0) && (
                  <dl className="ric-facts">
                    {t.answer.problem.recommended_owner && (<><dt>Owner</dt><dd>{t.answer.problem.recommended_owner}</dd></>)}
                    {(t.answer.problem.missing_evidence?.length ?? 0) > 0 && (<><dt>Still missing</dt><dd>{t.answer.problem.missing_evidence.join(", ")}</dd></>)}
                  </dl>
                )}
                {(t.answer.citations?.length ?? 0) > 0 && (
                  <div className="ric-cites" aria-label="Evidence">
                    {t.answer.citations.slice(0, 12).map((c, i) => <Citation key={`${c.id}-${i}`} c={c} />)}
                  </div>
                )}
                {(t.answer.disclaimers?.length ?? 0) > 0 && (
                  <ul className="ric-disc">{t.answer.disclaimers.map((d, i) => <li key={i}>{d}</li>)}</ul>
                )}
                <div className="ric-foot">
                  <span className="ric-src">{footerText(t.answer)}</span>
                  <span className="ric-rate">
                    <button type="button" className={`ric-thumb${t.rated === "up" ? " on" : ""}`} aria-label="Helpful"
                      aria-pressed={t.rated === "up"} disabled={!!t.rated} onClick={() => rate(t, "up")}>
                      <span aria-hidden="true">👍</span>
                    </button>
                    <button type="button" className={`ric-thumb${t.rated === "down" ? " on" : ""}`} aria-label="Not helpful"
                      aria-pressed={t.rated === "down"} disabled={!!t.rated} onClick={() => rate(t, "down")}>
                      <span aria-hidden="true">👎</span>
                    </button>
                  </span>
                </div>
              </div>
            )}
            {!t.answer && !t.error && busy && t.id === seq.current && (
              <div className="ric-a pending">
                {steps.length > 0 ? <IrisProgress steps={steps} /> : <span className="ric-wait">Reading this problem&apos;s evidence…</span>}
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="ric-suggest" role="group" aria-label="Suggested questions">
        {RCA_SUGGESTED_QUESTIONS.map((s) => (
          <button key={s} type="button" className="ric-chip" disabled={busy} onClick={() => void ask(s)}>{s}</button>
        ))}
      </div>

      <form className="ric-form" onSubmit={submit}>
        <input value={draft} maxLength={MAX_QUESTION} onChange={(e) => setDraft(e.target.value)}
          aria-label={`Ask Iris about ${pid}`} placeholder="Ask a follow-up…" />
        <button type="submit" className="ric-send" disabled={busy || !draft.trim()}>{busy ? "Asking…" : "Ask"}</button>
      </form>
    </section>
  );
}
