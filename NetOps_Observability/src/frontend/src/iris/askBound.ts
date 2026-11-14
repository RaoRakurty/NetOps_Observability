// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { api, StreamBrokenError, type AiAnswer, type IrisStreamEvent } from "../services/api";
import { httpFailure } from "../lib/errors";

// askBound.ts — the ONE way the product asks Iris a question (tracker 337
// N-E4: "one RCA Iris ask instead of two"). The Iris box, the RCA view's
// docked conversation and the investigation surface's lane all go through it,
// so every surface sends the same request shape and gets the same behaviour:
//
//   · progress streams while Iris works (N-E2); a stream a proxy cut short
//     falls back ONCE to the plain JSON ask;
//   · a conversation the server no longer has (404) is dropped and the
//     question is asked once without it — the next question starts anew;
//   · the context is whatever the caller passes (the screen's subject,
//     iris/viewContext.ts, and the page route, iris/pageRoute.ts, are merged
//     by the caller); the server re-validates all of it.

export interface AskBoundResult {
  answer: AiAnswer;
  /** The conversation the answer belongs to (null = none). */
  conversationId: string | null;
}

export async function askBound(
  question: string,
  context: Record<string, string> | undefined,
  conversationId: string | null | undefined,
  onEvent?: (e: IrisStreamEvent) => void,
): Promise<AskBoundResult> {
  const once = async (conv: string | undefined): Promise<AiAnswer> => {
    try {
      return await api.aiAskStream(question, context, conv, onEvent ?? (() => {}));
    } catch (e) {
      if (!(e instanceof StreamBrokenError)) throw e;
      return conv ? api.aiAsk(question, context, conv) : api.aiAsk(question, context);
    }
  };
  const conv = conversationId ?? undefined;
  try {
    const answer = await once(conv);
    return { answer, conversationId: answer.conversation_id ?? null };
  } catch (e) {
    if (!conv || httpFailure(e)?.status !== 404) throw e;
    const answer = await once(undefined);
    return { answer, conversationId: answer.conversation_id ?? null };
  }
}
