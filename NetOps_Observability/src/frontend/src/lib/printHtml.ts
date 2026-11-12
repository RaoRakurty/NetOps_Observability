// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// printHtmlDocument opens the browser's print dialog ("Save as PDF") on a
// complete, self-contained HTML document WITHOUT opening another tab.
//
// Why: the server renders the canonical RCA document as HTML and, when the
// optional PDF sidecar is running, converts it to PDF. Customer bundles never
// carry the sidecar (licence audit D6), so the HTML is the document there —
// and opening it in a new tab left the operator on a bare page with no way to
// save it. Printing it in place goes straight to Save-as-PDF.
//
// How: a real-size, off-screen iframe (a 0×0 frame clips the print). It is
// SANDBOXED without allow-scripts: the document is server-rendered and escaped,
// but nothing inside it should ever execute with the app's origin.
// allow-same-origin lets the parent write the document and call print();
// allow-modals is what lets print() open the dialog in a sandboxed frame.
//
// Returns false when the frame could not be created (no document to print).
export function printHtmlDocument(html: string, host: Document = document): boolean {
  const iframe = host.createElement("iframe");
  iframe.setAttribute("aria-hidden", "true");
  iframe.setAttribute("tabindex", "-1");
  iframe.setAttribute("sandbox", "allow-same-origin allow-modals");
  iframe.style.cssText = "position:fixed;left:-10000px;top:0;width:820px;height:1160px;border:0;";
  host.body.appendChild(iframe);

  const cw = iframe.contentWindow;
  const doc = cw?.document;
  if (!cw || !doc) {
    iframe.remove();
    return false;
  }
  doc.open();
  doc.write(html);
  doc.close();

  // Print exactly once: the load event and the timer fallback can both fire,
  // and two print() calls mean two Save dialogs.
  let printed = false;
  const printOnce = (): void => {
    if (printed) return;
    printed = true;
    try {
      cw.focus();
      cw.print();
    } catch {
      // A browser that refuses print() from a frame leaves nothing to do here;
      // the caller already holds the document and the frame is cleaned up below.
    }
  };
  iframe.addEventListener("load", () => setTimeout(printOnce, 200));
  setTimeout(printOnce, 600);
  // print() blocks while the dialog is open in most browsers, so this timer
  // only runs after it closes; it is a ceiling, not a race with the dialog.
  setTimeout(() => iframe.remove(), 60_000);
  return true;
}
