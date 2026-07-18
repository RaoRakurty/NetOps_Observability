import { usePrefs } from "../theme/prefs";

// AppearanceControls — the per-user display preferences in the account menu.
// Theme (Dark/Light) is chosen on the LOGIN screen and carries over (both
// surfaces read/write netops.theme); this menu is the one explicit in-app
// place to change it afterwards (owner 2026-07-18 — no topbar knob). The
// Accent picker is retired. Preferences persist per user via localStorage and
// apply instantly to <html> (see theme/prefs.ts). Shared by the account menus
// in both shells (IconRail in shell-v2, TopBar in v1).
export default function AppearanceControls() {
  const { appearance, setAppearance, density, setDensity } = usePrefs();
  return (
    <div className="appearance">
      <div className="pref-row">
        <span className="pref-label">Theme</span>
        <span className="pref-seg" role="group" aria-label="Theme">
          <button className={appearance === "dark" ? "on" : ""} aria-pressed={appearance === "dark"} onClick={() => setAppearance("dark")}>Dark</button>
          <button className={appearance === "light" ? "on" : ""} aria-pressed={appearance === "light"} onClick={() => setAppearance("light")}>Light</button>
        </span>
      </div>
      <div className="pref-row">
        <span className="pref-label">Density</span>
        <span className="pref-seg">
          <button className={density === "comfortable" ? "on" : ""} onClick={() => setDensity("comfortable")}>Cozy</button>
          <button className={density === "compact" ? "on" : ""} onClick={() => setDensity("compact")}>Compact</button>
        </span>
      </div>
    </div>
  );
}
