// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import { investigationsHint, modelsBanner, modelsOffNote } from "./aiModelsBanner";
import type { AIModelsState } from "../services/api";

const st = (state: AIModelsState["state"], models_on = false, investigations_on = false): AIModelsState => ({
  state, licensed: state !== "unlicensed", models_on, investigations_on,
});

describe("modelsBanner", () => {
  it("says nothing when models are on or the state is unknown", () => {
    expect(modelsBanner(st("on", true), true)).toBeNull();
    expect(modelsBanner(undefined, true)).toBeNull();
  });
  it("names the add-on when the licence lacks it, and says Iris still answers", () => {
    const b = modelsBanner(st("unlicensed"), true)!;
    expect(b.text).toMatch(/answering from your network data/);
    expect(b.text).toMatch(/Iris AI add-on/);
    expect(b.text).toMatch(/Enterprise includes it/);
  });
  it("tells a platform admin where the switch is, and anyone else who can turn it on", () => {
    expect(modelsBanner(st("off"), true)!.text).toMatch(/Administration → Features/);
    expect(modelsBanner(st("off"), false)!.text).toMatch(/platform administrator can turn them on/);
  });
});

describe("modelsOffNote", () => {
  it("gives the reason the server sent", () => {
    expect(modelsOffNote("not_licensed")).toMatch(/add-on/);
    expect(modelsOffNote("switched_off")).toMatch(/turned off on this installation/);
    expect(modelsOffNote("tenant_off")).toMatch(/this workspace/);
    expect(modelsOffNote(undefined)).toBe("Answered from your network data.");
  });
});

describe("investigationsHint", () => {
  it("walks the order: licence, models switch, investigations switch", () => {
    expect(investigationsHint(st("unlicensed"))).toMatch(/add-on/);
    expect(investigationsHint(st("off"))).toMatch(/Iris AI models/);
    expect(investigationsHint(st("on", true, false))).toMatch(/AI investigations/);
    expect(investigationsHint(st("on", true, true))).toBeNull();
    expect(investigationsHint(undefined)).toBeNull();
  });
});
