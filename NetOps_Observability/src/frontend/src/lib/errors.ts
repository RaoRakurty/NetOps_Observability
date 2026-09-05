// errors.ts — turn a thrown value into something a NOC operator can act on.
//
// WHY THIS EXISTS. `services/api.ts` throws `new Error(\`${status} ${statusText}: ${body}\`)`.
// Around 50 render sites did `setErr(e instanceof Error ? e.message : String(e))`,
// so what actually reached the screen was:
//
//     500 Internal Server Error: {"error":"clickhouse: dial tcp 172.18.0.9:9000: connect: connection refused"}
//
// That is a stack trace wearing a label. It tells an operator nothing they can
// do, and it leaks internal hostnames and component names into the product.
//
// WHAT THIS DOES. It keeps the useful half and drops the developer half:
//
//   - a message that ALREADY reads as a sentence is passed through untouched —
//     the backend's own operator-facing wording is better than anything we can
//     substitute, and throwing it away would be its own kind of dishonesty;
//   - the HTTP envelope is unwrapped: a server body carrying a plain sentence
//     becomes the message, a JSON/HTML/stack-shaped body does not;
//   - what is left maps to a short sentence about what happened, falling back
//     to the caller's own description of the failed action.
//
// It NEVER invents a cause. "Couldn't load X" is a statement about our read, not
// a claim about the network — the same honesty rule the empty states follow.

/** What each status class means to someone watching a network, not a server. */
function statusSentence(code: number): string | null {
  if (code === 401) return "Your session has expired — sign in again.";
  if (code === 403) return "You do not have access to this.";
  if (code === 404) return "That is not available.";
  if (code === 409) return "That conflicts with the current state — reload and try again.";
  if (code === 429) return "Too many requests just now — try again shortly.";
  if (code === 413) return "That is too large to accept.";
  if (code >= 500) return "The service did not answer.";
  if (code >= 400) return "That request was not accepted.";
  return null;
}

/**
 * Shapes that are code talking to code, never copy.
 *
 * These patterns are what the backend's own errors actually look like when they
 * escape: a Go wrap chain ("clickhouse: dial tcp 10.0.0.5:9000: connect:
 * connection refused"), a driver prefix ("pq: relation … does not exist"), a JS
 * runtime error, a JSON or HTML body. Two things make them unfit for the screen
 * and are called out separately below: they name INTERNAL COMPONENTS AND
 * ADDRESSES, and they say nothing the operator can act on.
 */
function looksLikeDeveloperText(s: string): boolean {
  if (!s) return true;
  if (s.length > 240) return true;
  if (/^[[{<]/.test(s)) return true;                       // JSON body or HTML
  if (/\b(TypeError|ReferenceError|SyntaxError|RangeError)\b/.test(s)) return true;
  if (/\bat \w+ \(.*:\d+:\d+\)/.test(s)) return true;      // a stack frame
  if (/\bundefined is not\b|\bis not a function\b|\bCannot read propert/.test(s)) return true;
  if (!/[a-z]/.test(s)) return true;                       // no prose at all

  // Internal addressing must never be shown — it is both meaningless to the
  // operator and an infrastructure disclosure.
  if (/\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b/.test(s)) return true;   // an IP (:port)
  if (/\b[a-z0-9-]+:\d{2,5}\b/.test(s)) return true;              // host:port

  // Runtime/driver vocabulary from the server's own stack.
  if (/\b(dial|goroutine|panic|EOF|i\/o timeout|no such host|connection refused|context deadline exceeded)\b/.test(s)) return true;
  if (/^(pq|sql|x509|rpc|grpc|http|net|os|json|yaml|exec)\s*:/i.test(s)) return true;

  // A wrap chain — Go errors nest with ": " and nothing written for a person does.
  if ((s.match(/: /g) ?? []).length >= 2) return true;

  return false;
}

function capitalize(s: string): string {
  return s.length ? s[0].toUpperCase() + s.slice(1) : s;
}

function ensureStop(s: string): string {
  return /[.!?…]$/.test(s) ? s : s + ".";
}

/** Pulls the human part out of an error body, if there is one. */
function fromBody(body: string): string | null {
  const raw = body.trim();
  if (!raw) return null;
  if (/^[[{]/.test(raw)) {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (parsed && typeof parsed === "object") {
        const rec = parsed as Record<string, unknown>;
        for (const key of ["error", "message", "detail", "reason"]) {
          const v = rec[key];
          if (typeof v === "string" && !looksLikeDeveloperText(v)) return v;
        }
      }
    } catch {
      /* not JSON after all — fall through */
    }
    return null;
  }
  return looksLikeDeveloperText(raw) ? null : raw;
}

/**
 * The operator-facing sentence for a thrown value.
 *
 * @param e         whatever was caught
 * @param fallback  what WE were trying to do, as a sentence — e.g.
 *                  "The audit log could not be loaded." Always supply one:
 *                  it is what the operator sees when the failure carries no
 *                  usable explanation, which is the common case.
 */
export function operatorError(e: unknown, fallback: string): string {
  let msg = e instanceof Error ? e.message : typeof e === "string" ? e : String(e ?? "");
  msg = msg.replace(/^Error:\s*/, "").trim();
  if (!msg) return fallback;

  // The api.ts envelope: "<status> <statusText>: <body>".
  const http = msg.match(/^(\d{3})\s+([^:]*):\s*([\s\S]*)$/);
  if (http) {
    const code = Number(http[1]);
    const body = fromBody(http[3]);
    if (body) return ensureStop(capitalize(body));
    return statusSentence(code) ?? fallback;
  }

  // A bare "<status>" or "<status>: <body>" (the download/export paths throw these).
  const bare = msg.match(/^(\d{3})(?::\s*([\s\S]*))?$/);
  if (bare) {
    const body = bare[2] ? fromBody(bare[2]) : null;
    if (body) return ensureStop(capitalize(body));
    return statusSentence(Number(bare[1])) ?? fallback;
  }

  if (looksLikeDeveloperText(msg)) return fallback;

  // Already a sentence — the server said something worth showing. Keep its
  // wording; only the shape is normalized.
  return ensureStop(capitalize(msg));
}

// ── the HTTP envelope, for callers that need the STATUS, not a sentence ──────
//
// Added for the licence upgrade card (components/licence/UpgradeCard.tsx). A
// 402 is not a failure to explain away — it is a structured refusal with a
// ceiling, a limit and the tier that lifts it, and the card renders all of
// that. To find one, a caller has to see the status code that `operatorError`
// deliberately swallows, so it is exposed here rather than re-implemented at
// each call site with a slightly different regex.
//
// This is purely additive: `operatorError` above is unchanged, and anything
// that does not care about the code keeps calling it.

/** The two halves of the api.ts throw envelope: "<status> <statusText>: <body>". */
export type HttpFailure = { status: number; body: string };

/**
 * The status and raw body of a thrown api.ts error, or null when the value is
 * not one. The body is returned EXACTLY as the server sent it — no unwrapping,
 * no prose test — because the caller is about to parse it as a contract, not
 * show it to anyone.
 */
export function httpFailure(e: unknown): HttpFailure | null {
  const msg = (e instanceof Error ? e.message : typeof e === "string" ? e : String(e ?? ""))
    .replace(/^Error:\s*/, "")
    .trim();
  if (!msg) return null;
  const envelope = msg.match(/^(\d{3})\s+([^:]*):\s*([\s\S]*)$/);
  if (envelope) return { status: Number(envelope[1]), body: envelope[3].trim() };
  const bare = msg.match(/^(\d{3})(?::\s*([\s\S]*))?$/);
  if (bare) return { status: Number(bare[1]), body: (bare[2] ?? "").trim() };
  return null;
}
