// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import "@testing-library/jest-dom";

// React 18 needs this flag to treat act() as the test-environment batching hook;
// without it every render logs "not configured to support act(...)" and the
// budget output drowns in warnings.
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// happy-dom does no layout, so every element reports clientHeight 0. A windowed
// list measuring a 0px viewport renders only its overscan — which would make a
// virtualized surface look far cheaper than it is in a browser, and would let a
// DE-virtualized regression hide. Report a realistic operator viewport instead,
// so the window sizes to roughly what a 1080p screen shows and the DOM-node
// budgets mean what they say.
const VIEWPORT_PX = 600;
Object.defineProperty(HTMLElement.prototype, "clientHeight", {
  configurable: true,
  get(): number {
    return VIEWPORT_PX;
  },
});
