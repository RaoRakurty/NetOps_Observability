import { useEffect, useState } from "react";

// prefs.ts — user-facing display preferences (theme + table density), persisted
// to localStorage and applied as data-attributes on <html> so the centralized
// CSS tokens swap with a single attribute (no per-component theming). See the
// [data-theme="dark"] / [data-density="compact"] blocks in styles.css.

export type Theme = "light" | "dark" | "oled";
export type Density = "comfortable" | "compact";
// Chrome = the accent hue of the always-dark, glassy nav rail + topbar (the app
// "chrome"). Independent of theme/density: a desaturated dark jewel-tone the user
// picks; the frosted-glass reflection treatment is shared, only the hue shifts so
// it stays cohesive ("shouldn't look too different"). Values live in CSS under
// :root[data-chrome="…"] (styles.css). "indigo" == the bare :root tokens, so it
// needs no override block. `swatch` is the glassy picker dot's base color.
// First step: three curated options (one neutral graphite, Datadog-like). More
// hues can be added later — just extend this list + the CSS override blocks.
export type Chrome = "graphite" | "indigo" | "violet";

export const CHROME_PRESETS: { id: Chrome; label: string; swatch: string }[] = [
  { id: "graphite", label: "Graphite", swatch: "#2e333f" },
  { id: "indigo", label: "Indigo", swatch: "#2a3450" },
  { id: "violet", label: "Violet", swatch: "#33294e" },
];
const CHROME_IDS = CHROME_PRESETS.map((c) => c.id);

const THEME_KEY = "netops.theme";
const DENSITY_KEY = "netops.density";
const CHROME_KEY = "netops.chrome";

function readTheme(): Theme {
  const v = localStorage.getItem(THEME_KEY);
  return v === "dark" || v === "oled" ? v : "light";
}

function readDensity(): Density {
  const v = localStorage.getItem(DENSITY_KEY);
  return v === "compact" ? "compact" : "comfortable";
}

function readChrome(): Chrome {
  const v = localStorage.getItem(CHROME_KEY) as Chrome | null;
  return v && CHROME_IDS.includes(v) ? v : "indigo";
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
