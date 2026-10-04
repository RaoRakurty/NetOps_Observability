// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ConfigDiffView — a unified diff, coloured per line from its +/- prefix.
//
// Lifted unchanged from pages/config/DeviceConfigPanel.tsx (which re-exports it)
// so the Iris answer surface can show "exactly what changed" with the SAME view
// the device Configuration tab uses (tracker 337 N-E3) instead of a second diff
// renderer.
//
// SECURITY (§3 / §15 LLM02). Diff text is written by a device or carried in a
// change record — hostile input. Every line is an escaped React text node
// inside <pre>, coloured by CLASS; there is no HTML sink on this path.

import type { ConfigDiffResult } from "../services/api";
import { diffLines, fmtChurn } from "../pages/config/configModel";

/** The fields the view reads — a server diff, or one built from a change record. */
export type UnifiedDiff = Pick<ConfigDiffResult, "unified" | "added" | "removed" | "truncated">;

/** A unified diff, coloured per line from the +/- prefix. Text only. */
export function ConfigDiffView({ diff, title }: { diff: UnifiedDiff; title: string }) {
  const lines = diffLines(diff.unified);
  return (
    <div className="ccw-code">
      <div className="ccw-code-h">
        <span className="mono">{title}</span>
        <span className="mini-meta">{fmtChurn(diff.added, diff.removed)}</span>
      </div>
      {diff.truncated && (
        <p className="mini-meta cfg-note" role="status">
          Truncated by the server — only the start of the change.
          Open the full versions to read the rest.
        </p>
      )}
      {lines.length === 0 ? (
        <p className="fact-line" style={{ margin: 0 }}>The two versions are identical — the server returned an empty diff.</p>
      ) : (
        <pre className="ccw-pre cfg-diff" aria-label={title}>
          {lines.map((l, i) => (
            // Untrusted diff text — escaped React text node, coloured by CLASS.
            <div key={i} className={`cfg-diff-line cfg-diff-${l.kind}`}>{l.text}</div>
          ))}
        </pre>
      )}
    </div>
  );
}

export default ConfigDiffView;
