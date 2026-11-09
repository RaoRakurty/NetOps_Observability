// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// A controllable window.matchMedia for unit tests that depend on viewport
// width (e.g. components/topBarTier.ts). Understands `(max-width: Npx)` and
// `(min-width: Npx)`; anything else never matches. resize() updates every
// live MediaQueryList and fires `change` on the ones whose result flipped.

type Listener = (e: MediaQueryListEvent) => void;

export interface FakeViewport {
  resize(width: number): void;
  /** Live change listeners across every list handed out (0 after cleanup). */
  listenerCount(): number;
}

function evaluate(query: string, width: number): boolean {
  const max = query.match(/\(max-width:\s*(\d+(?:\.\d+)?)px\)/);
  if (max) return width <= Number(max[1]);
  const min = query.match(/\(min-width:\s*(\d+(?:\.\d+)?)px\)/);
  if (min) return width >= Number(min[1]);
  return false;
}

export function installViewport(initialWidth: number, opts: { legacy?: boolean } = {}): FakeViewport {
  let width = initialWidth;
  const lists: { mql: MediaQueryList; listeners: Set<Listener> }[] = [];

  window.matchMedia = ((query: string) => {
    const listeners = new Set<Listener>();
    const mql = {
      media: query,
      matches: evaluate(query, width),
      onchange: null,
      addListener: (l: Listener) => listeners.add(l),
      removeListener: (l: Listener) => listeners.delete(l),
      dispatchEvent: () => true,
    } as unknown as MediaQueryList & { matches: boolean };
    if (!opts.legacy) {
      Object.assign(mql, {
        addEventListener: (_t: string, l: Listener) => listeners.add(l),
        removeEventListener: (_t: string, l: Listener) => listeners.delete(l),
      });
    }
    lists.push({ mql, listeners });
    return mql;
  }) as typeof window.matchMedia;

  return {
    resize(next: number) {
      width = next;
      for (const { mql, listeners } of lists) {
        const m = evaluate(mql.media, width);
        if (m === mql.matches) continue;
        (mql as { matches: boolean }).matches = m;
        for (const l of [...listeners]) l({ matches: m, media: mql.media } as MediaQueryListEvent);
      }
    },
    listenerCount() {
      return lists.reduce((n, { listeners }) => n + listeners.size, 0);
    },
  };
}
