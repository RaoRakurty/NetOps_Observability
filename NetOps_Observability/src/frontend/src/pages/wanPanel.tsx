// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// wanPanel.tsx — the independent-read plumbing the WAN pages share (WAN
// circuits on Paths, and WAN settings under Administration → Discovery).

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { operatorError } from "../lib/errors";

// ── panel plumbing (the DataProtection convention) ──────────────────────────

export type Panel<T> = { data: T | null; error: string | null; loading: boolean; at: number };

/**
 * One independent read. Each section owns its failure as an operator sentence,
 * so one dead route never blanks a neighbouring section's evidence.
 */
export function usePanel<T>(read: () => Promise<T>, fallback: string): [Panel<T>, () => void] {
  const [state, setState] = useState<Panel<T>>({ data: null, error: null, loading: true, at: 0 });
  const readRef = useRef(read);
  readRef.current = read;
  const reload = useCallback(() => {
    setState((p) => ({ ...p, loading: true }));
    readRef.current()
      .then((data) => setState({ data, error: null, loading: false, at: Date.now() }))
      .catch((e: unknown) => setState({ data: null, error: operatorError(e, fallback), loading: false, at: Date.now() }));
  }, [fallback]);
  useEffect(() => { reload(); }, [reload]);
  return [state, reload];
}

export function PanelState({ panel, what, onRetry, children }: {
  panel: Panel<unknown>; what: string; onRetry: () => void; children: ReactNode;
}) {
  if (panel.error) {
    return (
      <div className="empty" role="alert">
        <span className="dp-bad-text">{panel.error}</span>{" "}
        <button type="button" className="bgp-more" onClick={onRetry}>Read it again</button>
      </div>
    );
  }
  if (panel.loading && panel.data == null) return <div className="empty">Reading {what}…</div>;
  return <>{children}</>;
}
