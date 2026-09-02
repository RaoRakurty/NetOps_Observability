// copyScan.ts — the machinery behind the UI-copy guard tests.
//
// Two guards use it:
//   - components/rca/vocabulary.test.ts — the engine word "Signals" must never
//     reach a screen (owner directive, docs/design/rca-evidence-summary.md §3);
//   - copyVoice.test.ts — the developer-speak denylist removed in the
//     2026-09-02 copy pass must not come back.
//
// Both need the same thing and it is subtle enough to be worth writing once:
// **only inspect what a person can actually read.** A scan over raw source
// fires on identifiers, API field names and code comments, which makes it
// noisy, then ignored, then deleted. So comments are blanked first (preserving
// character positions, and therefore line numbers) and only string literals and
// JSX text nodes are handed to the matcher.
//
// This is COPY tooling, not runtime code — it lives in lib/ rather than in one
// of the test files so both guards share one implementation.

/**
 * Blanks out line and block comments, preserving every character position (and
 * therefore line numbers) so hits report the true file:line. String literals
 * are tracked so a `//` inside a URL is not mistaken for a comment.
 */
export function stripComments(text: string): string {
  const out = text.split("");
  let i = 0;
  type Mode = "code" | "line" | "block" | "sq" | "dq" | "tpl";
  let mode: Mode = "code";
  while (i < text.length) {
    const c = text[i], n = text[i + 1];
    if (mode === "code") {
      if (c === "/" && n === "/") { mode = "line"; out[i] = out[i + 1] = " "; i += 2; continue; }
      if (c === "/" && n === "*") { mode = "block"; out[i] = out[i + 1] = " "; i += 2; continue; }
      if (c === "'") mode = "sq"; else if (c === '"') mode = "dq"; else if (c === "`") mode = "tpl";
      i++; continue;
    }
    if (mode === "line") {
      if (c === "\n") { mode = "code"; i++; continue; }
      out[i] = " "; i++; continue;
    }
    if (mode === "block") {
      if (c === "*" && n === "/") { mode = "code"; out[i] = out[i + 1] = " "; i += 2; continue; }
      if (c !== "\n") out[i] = " ";
      i++; continue;
    }
    // inside a string literal
    if (c === "\\") { i += 2; continue; }
    // A ' or " string CANNOT span a newline in JavaScript. Resetting at the line
    // break is therefore exact, and it is what keeps an apostrophe in JSX text
    // ("isn't enabled") from swallowing the rest of the file: without this the
    // scanner drifts into string mode and stops recognizing `//` comments, so
    // every later comment gets scanned as if it were copy. Template literals do
    // span lines, so `tpl` is deliberately not reset.
    if ((mode === "sq" || mode === "dq") && c === "\n") { mode = "code"; i++; continue; }
    if ((mode === "sq" && c === "'") || (mode === "dq" && c === '"') || (mode === "tpl" && c === "`")) mode = "code";
    i++;
  }
  return out.join("");
}

/** The parts of a line a user can actually read: string literals + JSX text. */
export function readableSpans(line: string): string[] {
  const spans: string[] = [];
  for (const m of line.matchAll(/"([^"]*)"|'([^']*)'|`([^`]*)`/g)) spans.push(m[1] ?? m[2] ?? m[3] ?? "");
  for (const m of line.matchAll(/>([^<>{}]+)</g)) spans.push(m[1]);
  return spans;
}
