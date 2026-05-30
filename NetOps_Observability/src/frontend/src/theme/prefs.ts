import { useEffect, useState } from "react";

// prefs.ts — user-facing display preferences (theme + table density), persisted
// to localStorage and applied as data-attributes on <html> so the centralized
// CSS tokens swap with a single attribute (no per-component theming). See the
// [data-theme="dark"] / [data-density="compact"] blocks in styles.css.

export type Theme = "light" | "dark";
export type Density = "comfortable" | "compact";

const THEME_KEY = "netops.theme";
const DENSITY_KEY = "netops.density";

function readTheme(): Theme {
  const v = localStorage.getItem(THEME_KEY);
  return v === "dark" ? "dark" : "light";
}

function readDensity(): Density {
  const v = localStorage.getItem(DENSITY_KEY);
  return v === "compact" ? "compact" : "comfortable";
}

// applyPrefs reflects the stored prefs onto <html>. Called once at boot (before
// React renders, from main.tsx) so there's no flash of the wrong theme.
export function applyPrefs() {
  const root = document.documentElement;
  root.setAttribute("data-theme", readTheme());
  root.setAttribute("data-density", readDensity());
}

// usePrefs is the React hook the UI controls bind to. Setters persist + apply
// immediately and notify other hook instances via a window event.
export function usePrefs() {
  const [theme, setThemeState] = useState<Theme>(readTheme);
  const [density, setDensityState] = useState<Density>(readDensity);

  useEffect(() => {
    const sync = () => {
      setThemeState(readTheme());
      setDensityState(readDensity());
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

  return { theme, setTheme, density, setDensity };
}
