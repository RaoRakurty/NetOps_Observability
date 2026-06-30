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
// graphite, and a soft light-grey "Mist".
export type Chrome = "navy" | "graphite" | "mist";

export const CHROME_PRESETS: { id: Chrome; label: string; swatch: string }[] = [
  { id: "navy", label: "Navy", swatch: "#20283c" },
  { id: "graphite", label: "Graphite", swatch: "#23262d" },
  { id: "mist", label: "Mist", swatch: "#cbd5e1" },
];
const CHROME_IDS = CHROME_PRESETS.map((c) => c.id);

const THEME_KEY = "netops.theme";
const DENSITY_KEY = "netops.density";
const CHROME_KEY = "netops.chrome";

function readTheme(): Theme {
  const v = localStorage.getItem(THEME_KEY) as Theme | null;
  return v && THEME_IDS.includes(v) ? v : "indigo"; // Indigo Causal is the default identity
}

function readDensity(): Density {
  const v = localStorage.getItem(DENSITY_KEY);
  return v === "compact" ? "compact" : "comfortable";
}

function readChrome(): Chrome {
  const v = localStorage.getItem(CHROME_KEY) as Chrome | null;
  return v && CHROME_IDS.includes(v) ? v : "navy";
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

  return { theme, setTheme, density, setDensity, chrome, setChrome };
}
