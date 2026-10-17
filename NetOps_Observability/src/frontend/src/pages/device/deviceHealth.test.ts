// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { deviceHealth } from "./deviceHealth";

describe("deviceHealth — the one status every inventory surface renders", () => {
  it("follows the collectors' reachability, with alerts lowering up to degraded", () => {
    expect(deviceHealth({ reachability: "up" }, false)).toBe("up");
    expect(deviceHealth({ reachability: "up" }, true)).toBe("degraded");
    expect(deviceHealth({ reachability: "partial" }, false)).toBe("degraded");
    expect(deviceHealth({ reachability: "down" }, false)).toBe("down");
    expect(deviceHealth({ reachability: "down" }, true)).toBe("down");
  });

  it("never calls a device it has no recent poll for down", () => {
    expect(deviceHealth({ reachability: "unknown" }, false)).toBe("unknown");
    expect(deviceHealth({}, true)).toBe("unknown");
  });
});
