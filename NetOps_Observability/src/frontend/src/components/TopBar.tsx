import { useEffect, useRef, useState } from "react";
import { AuthUser, Health, api, GlobalResult, GlobalResultKind } from "../services/api";
import { useShell, TIME_RANGES } from "../context/shell";
import Icon from "./Icon";

type Props = {
  health: Health | null;
  user: AuthUser;
  onLogout: () => void;
};

const KIND_ICON: Record<GlobalResultKind, string> = {
  device: "datasets",
  alert: "alerts",
  saved: "dashboards",
  logs: "search",
};
const KIND_LABEL: Record<GlobalResultKind, string> = {
  device: "Device",
  alert: "Alert",
  saved: "Saved",
  logs: "Logs",
};

// Global top bar: brand · omni-search · time range · health · user menu.
// The search box and time picker drive every section through ShellContext.
// The omni-search shows a live results dropdown (devices, alerts, saved
// objects) backed by /api/search/global, plus a raw log-search handoff —
// so it behaves like Splunk/Datadog's global search, not just a log query.
export default function TopBar({ health, user, onLogout }: Props) {
  const { range, setRange, query, setQuery, navigate } = useShell();
  const [draft, setDraft] = useState(query);
  const [menuOpen, setMenuOpen] = useState(false);
  const [results, setResults] = useState<GlobalResult[]>([]);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const omniRef = useRef<HTMLFormElement | null>(null);

  useEffect(() => setDraft(query), [query]);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
      if (omniRef.current && !omniRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  // Debounced live search against the global resolver.
  useEffect(() => {
    const q = draft.trim();
    if (q.length < 2) {
      setResults([]);
      return;
    }
    let cancelled = false;
    const t = setTimeout(() => {
      api
        .globalSearch(q)
        .then((r) => {
          if (cancelled) return;
          setResults(r.results);
          setActive(-1); // nothing preselected: Enter runs the log search
          setOpen(true);
        })
        .catch(() => {
          if (!cancelled) setResults([]);
        });
    }, 180);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [draft]);

  const ok = health?.status === "healthy";

  const runLogSearch = () => {
    setQuery(draft.trim() || "*");
    navigate("search/logs");
    setOpen(false);
  };

  const choose = (g: GlobalResult) => {
    if (g.kind === "logs") {
      runLogSearch();
      return;
    }
    navigate(g.route);
    setOpen(false);
  };

  const submitSearch = (e: React.FormEvent) => {
    e.preventDefault();
    // Enter runs the log search by default; only jump to a result the user
    // has explicitly highlighted with the arrow keys.
    if (open && active >= 0 && results[active]) {
      choose(results[active]);
    } else {
      runLogSearch();
    }
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!open || results.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => (a + 1) % results.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => (a <= 0 ? results.length - 1 : a - 1));
    } else if (e.key === "Escape") {
      setOpen(false);
    }
  };

  return (
    <header className="topbar">
      <div className="brand">
        <span className="brand-mark"><Icon name="logo" size={20} /></span>
        <span className="brand-name">NetOps</span>
      </div>

      <form className="omni" onSubmit={submitSearch} ref={omniRef}>
        <span className="omni-icon"><Icon name="search" size={15} /></span>
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onFocus={() => results.length && setOpen(true)}
          onKeyDown={onKeyDown}
          placeholder="Search logs, devices, alerts, saved…"
          spellCheck={false}
        />
        {open && results.length > 0 && (
          <div className="omni-pop">
            {results.map((g, i) => (
              <button
                type="button"
                key={`${g.kind}:${g.id}:${i}`}
                className={`omni-item${i === active ? " active" : ""}`}
                onMouseEnter={() => setActive(i)}
                onClick={() => choose(g)}
              >
                <span className={`omni-kind k-${g.kind}`}>
                  <Icon name={KIND_ICON[g.kind]} size={13} />
                </span>
                <span className="omni-text">
                  <span className="omni-title">{g.title}</span>
                  {g.sub && <span className="omni-sub">{g.sub}</span>}
                </span>
                <span className="omni-tag">{KIND_LABEL[g.kind]}</span>
              </button>
            ))}
          </div>
        )}
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
