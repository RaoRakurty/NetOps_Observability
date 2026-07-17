import { describe, expect, it } from "vitest";
import { deleteView, hashWithSq, listViews, saveView, sqFromHash } from "./signalPage";

function memStorage(): Pick<Storage, "getItem" | "setItem"> & { data: Record<string, string> } {
  const data: Record<string, string> = {};
  return {
    data,
    getItem: (k: string) => (k in data ? data[k] : null),
    setItem: (k: string, v: string) => { data[k] = v; },
  };
}

describe("sq hash param", () => {
  it("round-trips the search term preserving other params", () => {
    const h = hashWithSq("#/monitoring/appobs?inv=abc", "gateway timeout");
    expect(sqFromHash(h)).toBe("gateway timeout");
    expect(h).toContain("inv=abc");
  });
  it("empty term removes the param and the dangling ?", () => {
    expect(hashWithSq("#/monitoring/appobs?sq=x", "")).toBe("#/monitoring/appobs");
    expect(sqFromHash("#/monitoring/appobs")).toBe("");
  });
});

describe("saved views", () => {
  it("saves, lists sorted, upserts by name, deletes", () => {
    const s = memStorage();
    saveView(s, "acme", "zeta", "?sq=a");
    saveView(s, "acme", "alpha", "?sq=b");
    expect(listViews(s, "acme").map((v) => v.name)).toEqual(["alpha", "zeta"]);
    saveView(s, "acme", "alpha", "?sq=NEW");
    expect(listViews(s, "acme").find((v) => v.name === "alpha")?.query).toBe("?sq=NEW");
    deleteView(s, "acme", "zeta");
    expect(listViews(s, "acme").map((v) => v.name)).toEqual(["alpha"]);
  });
  it("keys views by tenant scope — another scope sees nothing", () => {
    const s = memStorage();
    saveView(s, "acme", "mine", "?sq=x");
    expect(listViews(s, "globex")).toEqual([]);
    expect(listViews(s, "acme")).toHaveLength(1);
  });
  it("blank names are refused; corrupt storage yields empty, never throws", () => {
    const s = memStorage();
    saveView(s, "acme", "   ", "?sq=x");
    expect(listViews(s, "acme")).toEqual([]);
    s.data["netops_appobs_views"] = "{not json";
    expect(listViews(s, "acme")).toEqual([]);
  });
});
