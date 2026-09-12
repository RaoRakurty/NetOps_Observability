// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// useCloudScope — binds the Service View's global scope + range (scopeUrl.ts)
// to location.hash (Wave 2 #5). The URL is the single source of truth: every
// mutation writes the hash, and the hashchange listener folds it back into
// state — so back/forward, refresh, pasted links and the drawer's `inv` param
// (which shares the same query string) all stay coherent with zero extra sync.

import { useCallback, useEffect, useState } from "react";
import {
  CloudScopeState, ScopeDim, scopeFromHash, hashWithScope, emptyScope, isScopeActive,
} from "./scopeUrl";

export interface CloudScopeControl {
  scope: CloudScopeState;
  active: boolean;
  /** add one value to a dimension (no-op when already present). */
  add: (dim: ScopeDim, value: string) => void;
  /** remove one value (a chip's ×). */
  remove: (dim: ScopeDim, value: string) => void;
  /** drop every filter (keeps the range — clearing filters is not a time jump). */
  clearFilters: () => void;
  setRangeMinutes: (minutes: number) => void;
}

export function useCloudScope(): CloudScopeControl {
  const [scope, setScope] = useState<CloudScopeState>(() => scopeFromHash(location.hash));

  useEffect(() => {
    const apply = () => setScope(scopeFromHash(location.hash));
    window.addEventListener("hashchange", apply);
    return () => window.removeEventListener("hashchange", apply);
  }, []);

  // Write-through: state follows via the hashchange listener above.
  const write = useCallback((next: CloudScopeState) => {
    const h = hashWithScope(location.hash, next);
    if (h !== location.hash) location.hash = h;
    // Same-hash writes fire no hashchange — state is already in sync then.
  }, []);

  const add = useCallback((dim: ScopeDim, value: string) => {
    const v = value.trim();
    if (!v) return;
    const cur = scopeFromHash(location.hash);
    if (cur[dim].includes(v)) return;
    write({ ...cur, [dim]: [...cur[dim], v] });
  }, [write]);

  const remove = useCallback((dim: ScopeDim, value: string) => {
    const cur = scopeFromHash(location.hash);
    write({ ...cur, [dim]: cur[dim].filter((x) => x !== value) });
  }, [write]);

  const clearFilters = useCallback(() => {
    const cur = scopeFromHash(location.hash);
    write({ ...emptyScope(), rangeMinutes: cur.rangeMinutes });
  }, [write]);

  const setRangeMinutes = useCallback((minutes: number) => {
    write({ ...scopeFromHash(location.hash), rangeMinutes: minutes });
  }, [write]);

  return { scope, active: isScopeActive(scope), add, remove, clearFilters, setRangeMinutes };
}
