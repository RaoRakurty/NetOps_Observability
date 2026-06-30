import { usePrefs, THEME_PRESETS, CHROME_PRESETS } from "../theme/prefs";

// AppearanceControls — the per-user display preferences a signed-in user can
// pick: Theme (incl. OLED), Accent (the rail/topbar chrome hue), and table
// Density. Preferences persist per user via localStorage and apply instantly to
// <html> (see theme/prefs.ts). Shared by the account menus in both shells
// (IconRail in shell-v2, TopBar in v1) so the picker never drifts between them.
export default function AppearanceControls() {
  const { theme, setTheme, chrome, setChrome, density, setDensity } = usePrefs();
  return (
    <div className="appearance">
      <div className="pref-row">
        <span className="pref-label">Theme</span>
        <span className="pref-seg pref-seg-wrap">
          {THEME_PRESETS.map((t) => (
            <button
              key={t.id}
              className={theme === t.id ? "on" : ""}
              onClick={() => setTheme(t.id)}
              title={t.label}
              aria-pressed={theme === t.id}
            >
              <span className="pref-swatch" style={{ background: t.swatch }} aria-hidden="true" />
              {t.label}
            </button>
          ))}
        </span>
      </div>
      <div className="pref-row">
        <span className="pref-label">Accent</span>
        <span className="pref-seg pref-seg-wrap">
          {CHROME_PRESETS.map((c) => (
            <button
              key={c.id}
              className={chrome === c.id ? "on" : ""}
              onClick={() => setChrome(c.id)}
              title={c.label}
              aria-pressed={chrome === c.id}
            >
              <span className="pref-swatch" style={{ background: c.swatch }} aria-hidden="true" />
              {c.label}
            </button>
          ))}
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
