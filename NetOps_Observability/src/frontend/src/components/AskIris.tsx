// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// AskIris — the 16 px `(i)` that replaced an on-screen explanation.
//
// Programme: docs/design/UI_WORDS_IRIS_EXPLAINS_2026-09-06.md (tracker 270).
// Owner direction: "remove the jargon and lots of words across the site. Remove
// so much of explanation, instead train the Iris AI to answer those questions."
//
// So a screen keeps the number and the action; the sentence that TAUGHT what the
// number means moves into `src/backend/ai/skills/explain/<topic>.md` and is
// reachable from exactly here. Clicking asks Iris the canned question for the
// topic; Iris answers from the authored file and cites it.
//
// WHY AN EVENT AND NOT A PROP DRILL. The assistant is a shell-level surface (the
// docked Iris drawer, components/OpsisDrawer.tsx → tabs/Opsis.tsx). Threading an
// "ask this" callback from the shell down through every KPI on every page would
// couple every page to the assistant's internals; a single named window event is
// the seam. It carries NO data of its own — just the topic id, which the server
// resolves against its own authored corpus — so nothing a page holds can leak
// through it and nothing on the wire is trusted (§3: the server re-resolves the
// topic; an unknown one is refused, never improvised).
//
// The event is also why this component touches NO context. It is dropped into
// dozens of cards that are unit tested standalone, often with the shell module
// mocked; a context read here would make an explanation affordance the reason an
// unrelated page test fails. Opening the drawer is the drawer's job.
//
// The component makes NO network call until it is clicked, and none itself even
// then: the drawer owns the ask.

import { type MouseEvent } from "react";
import Icon from "./Icon";

/** The window event AskIris raises. components/OpsisDrawer.tsx is the only listener. */
export const IRIS_ASK_EVENT = "iris:ask";

export type IrisAskDetail = {
  /** The authored topic id — the file name under ai/skills/explain/. */
  topic: string;
  /** What the operator's turn reads as in the drawer. */
  question: string;
};

/**
 * The question shown as the operator's turn. It is deliberately about the LABEL
 * on the screen, not the topic id: an operator reading their own chat history
 * should see a question they could have typed. The topic id travels beside it and
 * is what the server actually keys on, so the wording here can never change which
 * file answers.
 */
export function irisAskQuestion(label: string): string {
  return `What does "${label}" mean here?`;
}

/** Raises the ask. Exported so a page with its own Iris lane can reuse it. */
export function askIris(topic: string, label: string): void {
  window.dispatchEvent(
    new CustomEvent<IrisAskDetail>(IRIS_ASK_EVENT, {
      detail: { topic, question: irisAskQuestion(label) },
    }),
  );
}

export default function AskIris({ topic, label, className }: {
  /** Authored topic id, e.g. "kpi.confirmed-rca". */
  topic: string;
  /** The on-screen words this explains — becomes the accessible name. */
  label: string;
  className?: string;
}) {
  const open = (e: MouseEvent<HTMLButtonElement>) => {
    // KPI tiles and table rows are themselves clickable; explaining a number must
    // never also filter or navigate.
    e.preventDefault();
    e.stopPropagation();
    askIris(topic, label);
  };
  return (
    <button
      type="button"
      className={`ask-iris${className ? ` ${className}` : ""}`}
      data-topic={topic}
      onClick={open}
      aria-label={`Ask Iris about ${label}`}
      title={`Ask Iris about ${label}`}
    >
      <Icon name="info" size={16} />
    </button>
  );
}
