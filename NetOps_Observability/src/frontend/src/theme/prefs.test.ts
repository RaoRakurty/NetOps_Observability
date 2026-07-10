// Binary appearance knob (2026-07-10): the 6-way Theme picker + Accent picker
// were retired for one Dark/Light knob (Dark = Indigo Causal), synced with the
// login pill through netops.theme. These tests pin the migration contract so
// a user upgrading with any legacy stored pref lands on a knob position and
// nobody is stranded on a preset that no longer has UI.

import { describe, it, expect, beforeEach } from "vitest";
import {
  appearanceOf,
  themeForAppearance,
  readAppearance,
  setAppearancePref,
  applyPrefs,
  Theme,
} from "./prefs";

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  document.documentElement.removeAttribute("data-chrome");
});

describe("appearance mapping", () => {
  it("maps every theme onto exactly one knob position", () => {
    const dark: Theme[] = ["indigo", "dark", "graphite", "oled"];
    const light: Theme[] = ["light", "white"];
    dark.forEach((t) => expect(appearanceOf(t)).toBe("dark"));
    light.forEach((t) => expect(appearanceOf(t)).toBe("light"));
  });

  it("Dark is the Indigo Causal identity, Light the light canvas", () => {
    expect(themeForAppearance("dark")).toBe("indigo");
    expect(themeForAppearance("light")).toBe("light");
  });
});

describe("legacy stored-theme migration", () => {
  it.each([
    ["dark", "indigo"],
    ["graphite", "indigo"],
    ["oled", "indigo"],
    ["white", "light"],
  ])("migrates a stored %s pref to %s once, in place", (legacy, target) => {
    localStorage.setItem("netops.theme", legacy);
    expect(readAppearance()).toBe(target === "light" ? "light" : "dark");
    expect(localStorage.getItem("netops.theme")).toBe(target);
  });

  it("keeps valid knob values untouched and defaults unknowns to dark", () => {
    localStorage.setItem("netops.theme", "light");
    expect(readAppearance()).toBe("light");
    expect(localStorage.getItem("netops.theme")).toBe("light");
    localStorage.setItem("netops.theme", "not-a-theme");
    expect(readAppearance()).toBe("dark");
  });
});

describe("setAppearancePref (login pill / topbar knob shared write path)", () => {
  it("persists the theme and applies it to <html> immediately", () => {
    setAppearancePref("light");
    expect(localStorage.getItem("netops.theme")).toBe("light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    setAppearancePref("dark");
    expect(localStorage.getItem("netops.theme")).toBe("indigo");
    expect(document.documentElement.getAttribute("data-theme")).toBe("indigo");
  });

  it("notifies usePrefs listeners so open UI re-renders", () => {
    let pinged = 0;
    const onPrefs = () => pinged++;
    window.addEventListener("netops-prefs", onPrefs);
    setAppearancePref("light");
    window.removeEventListener("netops-prefs", onPrefs);
    expect(pinged).toBe(1);
  });
});

describe("chrome follows the appearance knob (Accent picker retired)", () => {
  it("Light mode carries the glossy white chrome, Dark the navy glass", () => {
    localStorage.setItem("netops.theme", "light");
    applyPrefs();
    expect(document.documentElement.getAttribute("data-chrome")).toBe("white");
    setAppearancePref("dark");
    expect(document.documentElement.getAttribute("data-chrome")).toBe("navy");
    expect(localStorage.getItem("netops.chrome")).toBe("navy");
  });

  it("overrides any stored legacy chrome pick with the derived value", () => {
    localStorage.setItem("netops.theme", "indigo");
    localStorage.setItem("netops.chrome", "graphite");
    applyPrefs();
    expect(document.documentElement.getAttribute("data-chrome")).toBe("navy");
    expect(localStorage.getItem("netops.chrome")).toBe("navy");
  });
});
