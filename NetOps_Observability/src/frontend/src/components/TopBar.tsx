import { useEffect, useRef, useState } from "react";
import { AuthUser, Health } from "../services/api";
import { useShell, TIME_RANGES } from "../context/shell";

type Props = {
  health: Health | null;
  user: AuthUser;
  onLogout: () => void;
};

// Global top bar: brand · omni-search · time range · health · user menu.
// The search box and time picker drive every section through ShellContext.
export default function TopBar({ health, user, onLogout }: Props) {
  const { range, setRange, query, setQuery, navigate } = useShell();
  const [draft, setDraft] = useState(query);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => setDraft(query), [query]);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const ok = health?.status === "healthy";

  const submitSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setQuery(draft.trim() || "*");
    navigate("search/logs");
  };

  return (
    <header className="topbar">
      <div className="brand">
        <span className="brand-mark">◧</span>
        <span className="brand-name">NetOps</span>
      </div>

      <form className="omni" onSubmit={submitSearch}>
        <span className="omni-icon">🔍</span>
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Search logs, devices, alerts…   (Lucene query_string)"
          spellCheck={false}
        />
      </form>

      <div className="topbar-right">
        <select
          className="range-picker"
          value={range.minutes}
          onChange={(e) =>
            setRange(TIME_RANGES.find((r) => r.minutes === Number(e.target.value)) ?? range)
          }
          title="Global time range"
        >
          {TIME_RANGES.map((r) => (
            <option key={r.minutes} value={r.minutes}>
              {r.label}
            </option>
          ))}
        </select>

        <span className={`health${ok ? "" : " bad"}`} title={ok ? `v${health?.version}` : "Disconnected"}>
          <span className="dot" />
          {ok ? "Healthy" : "Disconnected"}
        </span>

        <div className="user-menu" ref={menuRef}>
          <button className="user-btn" onClick={() => setMenuOpen((o) => !o)}>
            <span className="avatar">{user.username.slice(0, 1).toUpperCase()}</span>
            <span className="user-name">{user.username}</span>
            <span style={{ opacity: 0.6, fontSize: 10 }}>▾</span>
          </button>
          {menuOpen && (
            <div className="menu-pop">
              <div className="menu-head">
                {user.username}
                <span style={{ color: "var(--muted)" }}> · {user.role}</span>
              </div>
              <button onClick={() => { setMenuOpen(false); navigate("settings"); }}>Settings</button>
              <button onClick={onLogout}>Sign out</button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
