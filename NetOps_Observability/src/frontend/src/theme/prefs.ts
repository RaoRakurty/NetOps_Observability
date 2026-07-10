import { useEffect, useState } from "react";

// prefs.ts — user-facing display preferences (theme + table density + chrome
// accent), persisted to localStorage and applied as data-attributes on <html>
// so the centralized CSS tokens swap with a single attribute (no per-component
// theming). See the [data-theme] / [data-density] / [data-chrome] blocks in
// styles.css.

export type Theme = "light" | "dark" | "oled" | "indigo" | "graphite" | "white";
// Curated Correlix themes shown in the picker (light/dark/oled stay available).
export const THEME_PRESETS: { id: Theme; label: string; swatch: string }[] = [
  { id: "indigo", label: "Indigo", swatch: "#8B7CFF" },
  { id: "graphite", label: "Graphite", swatch: "#9BB0C7" },
  { id: "white", label: "White", swatch: "#5B45F0" },
  { id: "dark", label: "Dark", swatch: "#0a0e1a" },
  { id: "light", label: "Light", swatch: "#f6f7fb" },
  { id: "oled", label: "OLED", swatch: "#000000" },
];
const THEME_IDS: Theme[] = THEME_PRESETS.map((t) => t.id);
export type Density = "comfortable" | "compact";
// Chrome = the accent hue of the glassy nav rail + topbar. The frosted-glass
// treatment is shared; only the hue/lightness shifts. "navy" is the bare :root
// tokens (default), so it needs no override block. `swatch` is the picker dot's
// base color. Three curated, professional options: Navy (default), a dark
// graphite, and a clean "White" (replaced the old grey "Mist").
export type Chrome = "navy" | "graphite" | "white";

export const CHROME_PRESETS: { id: Chrome; label: string; swatch: string }[] = [
  { id: "navy", label: "Navy", swatch: "#20283c" },
  { id: "graphite", label: "Graphite", swatch: "#23262d" },
  { id: "white", label: "White", swatch: "#ffffff" },
];

const THEME_KEY = "netops.theme";
const DENSITY_KEY = "netops.density";
const CHROME_KEY = "netops.chrome";

// The user-facing appearance model is BINARY (owner, 2026-07-10): one
// Dark/Light knob in the topbar + the login-page pill, both reading/writing
// netops.theme. Dark = the Indigo Causal signature identity; Light = the
// light canvas. The full Theme union + its CSS token blocks stay intact —
// this is a picker-surface simplification, not a token removal.
export type Appearance = "dark" | "light";
export const appearanceOf = (t: Theme): Appearance =>
  t === "light" || t === "white" ? "light" : "dark";
export const themeForAppearance = (a: Appearance): Theme =>
  a === "dark" ? "indigo" : "light";

function readTheme(): Theme {
  const v = localStorage.getItem(THEME_KEY) as Theme | null;
  if (!v || !THEME_IDS.includes(v)) return "indigo"; // Indigo Causal is the default identity
  // Binary-knob migration: a value saved by the retired 6-way picker
  // collapses onto the nearest knob position (dark/graphite/oled → indigo,
  // white → light) and is written back so the migration runs once.
  const migrated = themeForAppearance(appearanceOf(v));
  if (migrated !== v) localStorage.setItem(THEME_KEY, migrated);
  return migrated;
}

function readDensity(): Density {
  const v = localStorage.getItem(DENSITY_KEY);
  return v === "compact" ? "compact" : "comfortable";
}

function readChrome(): Chrome {
  // The Accent picker is retired (2026-07-10) — every install converges on
  // the default navy chrome. The preset CSS blocks remain for the future;
  // stored picks migrate so nobody is stranded on a preset with no UI.
  const v = localStorage.getItem(CHROME_KEY);
  if (v && v !== "navy") localStorage.setItem(CHROME_KEY, "navy");
  return "navy";
}

// readAppearance / setAppearancePref — the binary knob outside React (the
// pre-auth login page pins its own ramps and doesn't mount usePrefs). Writes
// go through the same key + <html> attribute + event as the hook setters, so
// login pill, topbar knob and ⌘K stay one preference.
export function readAppearance(): Appearance {
  return appearanceOf(readTheme());
}
export function setAppearancePref(a: Appearance) {
  const t = themeForAppearance(a);
  localStorage.setItem(THEME_KEY, t);
  document.documentElement.setAttribute("data-theme", t);
  window.dispatchEvent(new Event("netops-prefs"));
}

// applyPrefs reflects the stored prefs onto <html>. Called once at boot (before
// React renders, from main.tsx) so there's no flash of the wrong theme.
export function applyPrefs() {
  const root = document.documentElement;
  root.setAttribute("data-theme", readTheme());
  root.setAttribute("data-density", readDensity());
  root.setAttribute("data-chrome", readChrome());
}

// usePrefs is the React hook the UI controls bind to. Setters persist + apply
// immediately and notify other hook instances via a window event.
export function usePrefs() {
  const [theme, setThemeState] = useState<Theme>(readTheme);
  const [density, setDensityState] = useState<Density>(readDensity);
  const [chrome, setChromeState] = useState<Chrome>(readChrome);

  useEffect(() => {
    const sync = () => {
      setThemeState(readTheme());
      setDensityState(readDensity());
      setChromeState(readChrome());
    };
    window.addEventListener("netops-prefs", sync);
    return () => window.removeEventListener("netops-prefs", sync);
  }, []);

  const setTheme = (t: Theme) => {
    localStorage.setItem(THEME_KEY, t);
    document.documentElement.setAttribute("data-theme", t);
    setThemeState(t);
    window.dispatchEvent(new Event("netops-prefs"));
  };
  const setDensity = (d: Density) => {
    localStorage.setItem(DENSITY_KEY, d);
    document.documentElement.setAttribute("data-density", d);
    setDensityState(d);
    window.dispatchEvent(new Event("netops-prefs"));
  };
  const setChrome = (c: Chrome) => {
    localStorage.setItem(CHROME_KEY, c);
    document.documentElement.setAttribute("data-chrome", c);
    setChromeState(c);
    window.dispatchEvent(new Event("netops-prefs"));
  };

  // appearance is the binary view of theme the knob binds to.
  const appearance = appearanceOf(theme);
  const setAppearance = (a: Appearance) => setTheme(themeForAppearance(a));

  return { theme, setTheme, density, setDensity, chrome, setChrome, appearance, setAppearance };
}
