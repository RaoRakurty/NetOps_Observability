// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// useTicked — load once when the inputs change, then again on each tick of the
// page's refresh clock (lib/refreshTick). Replaces the old per-panel 30 s
// setInterval: a panel that is not mounted (another tab) asks for nothing, and
// nothing asks while the browser tab is hidden.
//
// A failed refresh keeps the last good answer on screen and reports the error
// beside it — "the API said nothing" and "the API did not answer" are not the
// same thing, and must not render the same way.

import { useEffect, useRef, useState } from "react";
import { usePageTick } from "../../lib/refreshTick";

export type Ticked<T> = { data: T | undefined; error: unknown; loading: boolean };

export function useTicked<T>(load: () => Promise<T>, deps: readonly unknown[], enabled = true): Ticked<T> {
  const tick = usePageTick();
  const [state, setState] = useState<Ticked<T>>({ data: undefined, error: null, loading: enabled });
  const loadRef = useRef(load);
  loadRef.current = load;
  // A new set of inputs is a new question: drop the old answer.
  const key = JSON.stringify(deps);
  const lastKey = useRef(key);
  useEffect(() => {
    if (!enabled) {
      setState({ data: undefined, error: null, loading: false });
      return;
    }
    let alive = true;
    const changed = lastKey.current !== key;
    lastKey.current = key;
    setState((s) => (changed ? { data: undefined, error: null, loading: true } : { ...s, loading: s.data === undefined }));
    loadRef.current().then(
      (data) => {
        if (alive) setState({ data, error: null, loading: false });
      },
      (error: unknown) => {
        if (alive) setState((s) => ({ data: s.data, error, loading: false }));
      },
    );
    return () => {
      alive = false;
    };
  }, [key, tick, enabled]);
  return state;
}
