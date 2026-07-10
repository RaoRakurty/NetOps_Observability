import { usePrefs } from "../theme/prefs";

// AppearanceControls — the per-user display preferences left in the account
// menu. Theme is now a binary Dark/Light knob in the TOPBAR (synced with the
// login page through netops.theme) and the Accent picker is retired, so the
// menu keeps only table Density. Preferences persist per user via localStorage
// and apply instantly to <html> (see theme/prefs.ts). Shared by the account
// menus in both shells (IconRail in shell-v2, TopBar in v1).
export default function AppearanceControls() {
  const { density, setDensity } = usePrefs();
  return (
    <div className="appearance">
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
