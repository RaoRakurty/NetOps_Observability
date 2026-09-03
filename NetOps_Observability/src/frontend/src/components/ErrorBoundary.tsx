// ErrorBoundary.tsx — the shell's last line of defence against a white screen.
//
// WHY THIS EXISTS. React unmounts the whole tree when a render throws and
// nothing catches it: one bad field access in one route blanks the entire
// console, and the operator watching a network sees a white page with no
// wording, no route and nothing to report. That happened (a contract slip in
// Security → Detection Rules). A boundary turns that into a bounded, named,
// recoverable panel: the shell chrome (rail, top bar, drawers) keeps rendering
// and only the view inside the boundary is replaced.
//
// WHAT THE OPERATOR GETS (CLAUDE.md §10 — no silent failures, everything
// observable):
//   · WHAT failed, by its nav label — never "Something went wrong".
//   · Try again      — re-renders the same view in place (a transient read
//                      that threw once usually succeeds on the retry).
//   · Reload this page — the full reset, when the retry does not take.
//   · Copy report    — a REDACTED diagnostic they can paste to their platform
//                      team, readable on screen before they send it.
//
// WHAT NEVER REACHES THE SCREEN (§15 LLM06/§8 — sanitize, no leakage):
//   · the stack and the React component stack go to console.error ONLY;
//   · the operator-visible diagnostic is passed through redact(), which strips
//     anything token-, key-, credential-, address- or URL-shaped.
// Everything rendered is escaped React text — no dangerouslySetInnerHTML, ever
// (§15 LLM02): an error message can carry attacker-controlled text (a server
// echo, a URL fragment), so it is treated as data, never as markup.
//
// RECOVERY BY NAVIGATION. A boundary that has caught stays caught until it is
// told otherwise, so the shell passes `resetKey` = the active route: navigating
// away from a broken view clears the error without the operator doing anything.

import { Component, ErrorInfo, ReactNode } from "react";
import { BRAND } from "../brand";

/** What a custom fallback renderer is handed. All text here is already safe. */
export interface BoundaryFallback {
  /** The view's operator-facing name (the nav label). */
  label: string;
  /** The caught error. Render its message only via `diagnostic`. */
  error: Error;
  /** The redacted, stack-free report — safe to display and to copy. */
  diagnostic: string;
  /** Clear the error and re-render the children. */
  reset: () => void;
  /** Full page reload. */
  reload: () => void;
  /** Copy `diagnostic` to the clipboard. */
  copyReport: () => void;
  /** True once the report has been copied (resets with the boundary). */
  copied: boolean;
}

export interface ErrorBoundaryProps {
  children: ReactNode;
  /** What failed, in the operator's words — usually the nav leaf label. */
  label: string;
  /** Route recorded in the report. Defaults to the live location hash. */
  route?: string;
  /**
   * Change this to clear a caught error. The shell passes the active route, so
   * navigating away from a broken view recovers on its own.
   */
  resetKey?: string | number;
  /** Panel-shaped or otherwise bespoke fallback (FrontPage uses this). */
  fallback?: (f: BoundaryFallback) => ReactNode;
  /** Escape hatch for a future telemetry sink. Never receives redacted text. */
  onError?: (error: Error, componentStack: string) => void;
}

interface ErrorBoundaryState {
  error: Error | null;
  /** ISO timestamp of the catch — the "when" of the report. */
  at: string;
  copied: boolean;
  /** The resetKey this state was built for (see getDerivedStateFromProps). */
  seenKey: string;
}

const REDACTED = "[redacted]";

/**
 * Strips anything an error message must never carry off the operator's screen
 * or into a pasted report: credentials, keys, addresses and URLs.
 *
 * Deliberately over-broad. A redacted-but-useless report is a small cost; a
 * leaked session token in a support ticket is not. Order matters — the
 * structured shapes (JWT, `key=value`, URL) are consumed before the generic
 * "long opaque run" rule, which would otherwise eat their halves separately.
 */
export function redact(text: string): string {
  let s = typeof text === "string" ? text : String(text ?? "");
  // A JWT or any other dotted opaque triple.
  s = s.replace(/\b[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g, REDACTED);
  // Authorization headers echoed back in a message.
  s = s.replace(/\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]+/gi, `$1 ${REDACTED}`);
  // Secret-shaped assignments: token=…, api_key: "…", password=…
  s = s.replace(
    /\b(tokens?|secrets?|passwords?|passwd|pwd|api[_-]?keys?|apikey|access[_-]?key|authorization|auth|cookie|session[_-]?id|session|credentials?|private[_-]?key)\b(\s*[:=]\s*)("?)[^\s"',;)]+\3/gi,
    `$1$2${REDACTED}`,
  );
  // Any URL — it can carry a host, an id and a query string full of both.
  s = s.replace(/\b[a-z][a-z0-9+.-]*:\/\/\S+/gi, REDACTED);
  s = s.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, REDACTED);
  s = s.replace(/\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b/g, REDACTED);
  // IPv4, with an optional port or prefix length.
  s = s.replace(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?:\/\d{1,2})?\b/g, REDACTED);
  s = s.replace(/\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b/g, REDACTED);
  // Whatever is left that looks like a key rather than a word.
  s = s.replace(/\b[A-Za-z0-9+/=_-]{24,}\b/g, REDACTED);
  return s.replace(/\s+/g, " ").trim().slice(0, 300);
}

/** The five facts a report carries. No stack, by construction. */
export function diagnosticText(input: { label: string; route: string; at: string; error: Error }): string {
  const name = redact(input.error?.name || "Error");
  const message = redact(input.error?.message || "");
  return [
    `${BRAND} view report`,
    `view: ${redact(input.label)}`,
    `route: ${redact(input.route)}`,
    `time: ${input.at}`,
    `error: ${name}${message ? ` — ${message}` : ""}`,
  ].join("\n");
}

export default class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null, at: "", copied: false, seenKey: "" };

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { error, at: new Date().toISOString(), copied: false };
  }

  /**
   * Recovery-by-navigation: when the shell hands us a new route the previous
   * failure is no longer on screen, so the boundary clears itself. Runs before
   * every render, including the one right after a catch (the key is unchanged
   * there, so the error stands).
   */
  static getDerivedStateFromProps(
    props: ErrorBoundaryProps,
    state: ErrorBoundaryState,
  ): Partial<ErrorBoundaryState> | null {
    const key = String(props.resetKey ?? "");
    if (key !== state.seenKey) return { error: null, at: "", copied: false, seenKey: key };
    return null;
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    const componentStack = info?.componentStack ?? "";
    // Structured, and console-only: the stack is for whoever opens devtools or
    // reads a browser log, never for the panel (§8 sanitize, §10 observable).
    try {
      console.error("[ui] view render error", {
        view: this.props.label,
        route: this.props.route ?? this.hash(),
        name: error?.name,
        message: error?.message,
        componentStack,
        error,
      });
    } catch {
      /* a console that throws must not take the fallback down with it */
    }
    try {
      this.props.onError?.(error, componentStack);
    } catch {
      /* a reporting sink is never allowed to break the recovery path */
    }
  }

  private hash(): string {
    try {
      return location.hash || "#/";
    } catch {
      return "#/";
    }
  }

  private reset = (): void => {
    this.setState({ error: null, at: "", copied: false });
  };

  private reload = (): void => {
    try {
      location.reload();
    } catch {
      /* a sandboxed frame cannot reload; Try again is still available */
    }
  };

  private copyReport = (): void => {
    const text = this.diagnostic();
    if (!text) return;
    try {
      // Typed loosely on purpose: the Clipboard API is absent in insecure
      // contexts and in some embedded browsers, where the lib types still
      // claim it exists.
      const clip = (navigator as Navigator | undefined)?.clipboard as
        | { writeText?: (t: string) => Promise<void> }
        | undefined;
      if (typeof clip?.writeText === "function") {
        const done = clip.writeText(text);
        this.setState({ copied: true });
        // A denied clipboard permission rejects asynchronously — take the
        // confirmation back rather than claiming a copy that did not happen.
        if (done && typeof done.catch === "function") done.catch(() => this.setState({ copied: false }));
        return;
      }
    } catch {
      /* clipboard blocked — the report stays selectable on screen */
    }
    this.setState({ copied: false });
  };

  private diagnostic(): string {
    const error = this.state.error;
    if (!error) return "";
    return diagnosticText({
      label: this.props.label,
      route: this.props.route ?? this.hash(),
      at: this.state.at,
      error,
    });
  }

  render(): ReactNode {
    const { error, copied } = this.state;
    if (!error) return this.props.children;

    const diagnostic = this.diagnostic();
    if (this.props.fallback) {
      return this.props.fallback({
        label: this.props.label,
        error,
        diagnostic,
        reset: this.reset,
        reload: this.reload,
        copyReport: this.copyReport,
        copied,
      });
    }

    return (
      <section className="eb-panel" role="alert" aria-live="assertive">
        <h2 className="eb-title">{this.props.label} could not be displayed</h2>
        <p className="eb-body">
          Something in this view stopped working. The rest of the console is unaffected — the report
          below names what happened, with addresses and credentials removed.
        </p>
        <div className="eb-actions">
          <button type="button" className="btn" onClick={this.reset}>Try again</button>
          <button type="button" className="btn" onClick={this.reload}>Reload this page</button>
          <button type="button" className="btn" onClick={this.copyReport}>
            {copied ? "Report copied" : "Copy report"}
          </button>
        </div>
        <details className="eb-report">
          <summary>Report</summary>
          <pre className="eb-report-text">{diagnostic}</pre>
        </details>
      </section>
    );
  }
}
