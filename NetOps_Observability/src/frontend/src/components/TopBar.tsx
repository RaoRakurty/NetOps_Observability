import { useEffect, useRef, useState } from "react";
import { AuthUser, Health, api, GlobalResult, GlobalResultKind, Tenant, getActingTenant, setActingTenant } from "../services/api";
import { useShell } from "../context/shell";
import { usePrefs, CHROME_PRESETS } from "../theme/prefs";
import { allRanges, addCustomPreset, rangeFromMinutes } from "../theme/timeprefs";
import Icon from "./Icon";

type Props = {
  health: Health | null;
  user: AuthUser;
  onLogout: () => void;
  // Open the self-service change-password modal. Undefined for federated accounts
  // (they change it at the IdP), which hides the menu item.
  onChangePassword?: () => void;
  // Shell v2 relocates the account/user menu into the left rail's utility
  // cluster, so the top-right copy is suppressed to avoid duplication.
  hideUserMenu?: boolean;
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
// so it behaves like Splunk's global search, not just a log query.
export default function TopBar({ health, user, onLogout, onChangePassword, hideUserMenu }: Props) {
  const { range, setRange, query, setQuery, navigate } = useShell();
  const { theme, setTheme, density, setDensity, chrome, setChrome } = usePrefs();
  // "*" is the match-all sentinel for the query; don't surface it literally in
  // the search box (it reads as a stray asterisk). Empty submit re-applies "*".
  const [draft, setDraft] = useState(query === "*" ? "" : query);
  const [menuOpen, setMenuOpen] = useState(false);
  const [results, setResults] = useState<GlobalResult[]>([]);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [ranges, setRanges] = useState(() => allRanges());
  const [tenantOpen, setTenantOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const omniRef = useRef<HTMLFormElement | null>(null);
  const tenantRef = useRef<HTMLDivElement | null>(null);

  // Tenant switcher ("view as tenant"): platform owner only. Lets the SaaS
  // operator scope the WHOLE app to one tenant (or the global/infra namespace).
  // The choice is stamped on every API call (X-Acting-Tenant) — see api.ts.
  const platformOwner = !!user.platform_admin;
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const acting = getActingTenant();
  useEffect(() => {
    if (!platformOwner) return;
    let alive = true;
    api.listTenants().then((ts) => alive && setTenants(ts)).catch(() => {});
    return () => { alive = false; };
  }, [platformOwner]);
  // Changing scope re-scopes every view at once; a full reload is the simplest
  // correct way to refetch all mounted data against the new tenant.
  const onScope = (v: string) => { setActingTenant(v); window.location.reload(); };

  useEffect(() => setDraft(query === "*" ? "" : query), [query]);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
      if (omniRef.current && !omniRef.current.contains(e.target as Node)) setOpen(false);
      if (tenantRef.current && !tenantRef.current.contains(e.target as Node)) setTenantOpen(false);
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
    navigate("explore/logs");
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
        <kbd className="omni-kbd" title="Command palette">⌘K</kbd>
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
        {platformOwner && (() => {
          const label = !acting ? "All tenants" : acting === "global" ? "Global" : (tenants.find((t) => t.id === acting)?.name ?? acting);
          const choose = (v: string) => { setTenantOpen(false); onScope(v); };
          const Item = ({ v, name, sub }: { v: string; name: string; sub?: string }) => {
            const on = (acting || "all") === v;
            return (
              <button type="button" className={`tsw-item${on ? " on" : ""}`} onClick={() => choose(v)}>
                <Icon name={v === "all" ? "datasets" : v === "global" ? "server" : "infrastructure"} size={14} />
                <span className="tsw-item-text"><span className="tsw-item-name">{name}</span>{sub && <span className="tsw-item-sub">{sub}</span>}</span>
                {on && <Icon name="check" size={14} />}
              </button>
            );
          };
          return (
            <div className="tenant-switch2" ref={tenantRef}>
              <button
                type="button"
                className={`tsw-btn${acting ? " scoped" : ""}`}
                onClick={() => setTenantOpen((o) => !o)}
                aria-haspopup="listbox"
                aria-expanded={tenantOpen}
                title="Choose which tenant you're viewing"
              >
                <Icon name={acting ? "infrastructure" : "datasets"} size={14} />
                <span className="tsw-label"><span className="tsw-cap">Viewing</span>{label}</span>
                <span className="tsw-caret">▾</span>
              </button>
              {tenantOpen && (
                <div className="tsw-pop" role="listbox">
                  <div className="tsw-group">Scope</div>
                  <Item v="all" name="All tenants" sub="Everything, merged" />
                  <Item v="global" name="Global" sub="Platform / infra only" />
                  {tenants.filter((t) => t.id !== "global").length > 0 && <div className="tsw-group">Tenants</div>}
                  {tenants.filter((t) => t.id !== "global").map((t) => <Item key={t.id} v={t.id} name={t.name} />)}
                </div>
              )}
            </div>
          );
        })()}
        <select
          className="range-picker"
          value={range.minutes}
          onChange={(e) => {
            if (e.target.value === "__add") {
              const raw = window.prompt("New time-range preset — enter minutes (e.g. 30, 720, 4320):");
              const mins = raw ? parseInt(raw, 10) : NaN;
              if (mins && mins > 0) {
                setRanges(addCustomPreset(mins));
                setRange(rangeFromMinutes(mins));
              }
              return;
            }
            setRange(rangeFromMinutes(Number(e.target.value)));
          }}
          title="Time range (remembered per section)"
        >
          {/* If the current range isn't in the preset list (a one-off), show it. */}
          {!ranges.some((r) => r.minutes === range.minutes) && (
            <option value={range.minutes}>{range.label}</option>
          )}
          {ranges.map((r) => (
            <option key={r.minutes} value={r.minutes}>
              {r.label}
            </option>
          ))}
          <option value="__add">＋ Add preset…</option>
        </select>

        <span className={`health${ok ? "" : " bad"}`} title={ok ? `v${health?.version}` : "Disconnected"}>
          <span className="dot" />
          {ok ? "Healthy" : "Disconnected"}
        </span>

        {!hideUserMenu && (
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
              <div className="pref-row">
                <span className="pref-label">Theme</span>
                <span className="pref-seg">
                  <button className={theme === "light" ? "on" : ""} onClick={() => setTheme("light")}>Light</button>
                  <button className={theme === "dark" ? "on" : ""} onClick={() => setTheme("dark")}>Dark</button>
                  <button className={theme === "oled" ? "on" : ""} onClick={() => setTheme("oled")}>OLED</button>
                </span>
              </div>
              <div className="pref-row">
                <span className="pref-label">Accent</span>
                <span className="chrome-seg">
                  {CHROME_PRESETS.map((c) => (
                    <button
                      key={c.id}
                      className={`chrome-dot${chrome === c.id ? " on" : ""}`}
                      style={{ ["--dot" as any]: c.swatch }}
                      title={c.label}
                      aria-label={`${c.label} accent`}
                      aria-pressed={chrome === c.id}
                      onClick={() => setChrome(c.id)}
                    />
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
              <button onClick={() => { setMenuOpen(false); navigate("admin/settings"); }}>Settings</button>
              {onChangePassword && (
                <button onClick={() => { setMenuOpen(false); onChangePassword(); }}>Change password</button>
              )}
              <button onClick={onLogout}>Sign out</button>
            </div>
          )}
        </div>
        )}
      </div>
    </header>
  );
}
