import { useEffect, useMemo, useRef, useState } from "react";
import { AuthUser, Health } from "../services/api";
import { omniSearch, groupHits, OmniHit, OmniKind, OMNI_KIND_ICON, OMNI_KIND_TAG, OMNI_KIND_LABEL } from "../lib/omniSearch";
import { useShell } from "../context/shell";
import { allRanges, addCustomPreset, rangeFromMinutes } from "../theme/timeprefs";
import CorrelixLogo from "./brand/CorrelixLogo";
import Icon from "./Icon";
import ScopeSelector from "./ScopeSelector";
import AppearanceControls from "./AppearanceControls";
import ScopeBadge from "./ScopeBadge";

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

// A dropdown row: a typed unified-search hit, or the raw log-search handoff.
type TopHit = { kind: OmniKind | "logs"; id: string; label: string; sublabel?: string; href: string };

const hitIcon = (k: TopHit["kind"]): string => (k === "logs" ? "search" : OMNI_KIND_ICON[k]);
const hitTag = (k: TopHit["kind"]): string => (k === "logs" ? "Logs" : OMNI_KIND_TAG[k]);

// Global top bar: brand · omni-search · time range · health · user menu.
// The search box and time picker drive every section through ShellContext.
// The omni-search shows a live, kind-grouped results dropdown (devices ·
// resources · services · accounts · cases · alerts · saved) backed by the
// tenant-scoped unified search (lib/omniSearch), plus a raw log-search
// handoff — a true global search, not just a log query. Each row navigates
// to the entity's permanent URL.
export default function TopBar({ health, user, onLogout, onChangePassword, hideUserMenu }: Props) {
  const { range, setRange, query, setQuery, navigate, setHelpOpen } = useShell();
  // "*" is the match-all sentinel for the query; don't surface it literally in
  // the search box (it reads as a stray asterisk). Empty submit re-applies "*".
  const [draft, setDraft] = useState(query === "*" ? "" : query);
  const [menuOpen, setMenuOpen] = useState(false);
  const [results, setResults] = useState<OmniHit[]>([]);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [ranges, setRanges] = useState(() => allRanges());
  const menuRef = useRef<HTMLDivElement | null>(null);
  const omniRef = useRef<HTMLFormElement | null>(null);

  useEffect(() => setDraft(query === "*" ? "" : query), [query]);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
      if (omniRef.current && !omniRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  // Debounced live search against the unified (tenant-scoped) resolver.
  useEffect(() => {
    const q = draft.trim();
    if (q.length < 2) {
      setResults([]);
      return;
    }
    let cancelled = false;
    const t = setTimeout(() => {
      omniSearch(q)
        .then((hits) => {
          if (cancelled) return;
          setResults(hits);
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

  // Flat display rows in group order: each group's first row carries the
  // header label; a raw log-search handoff row closes the list.
  const rows = useMemo<{ hit: TopHit; header?: string }[]>(() => {
    const out: { hit: TopHit; header?: string }[] = [];
    for (const group of groupHits(results)) {
      group.hits.forEach((h, i) => out.push({ hit: h, header: i === 0 ? OMNI_KIND_LABEL[group.kind] : undefined }));
    }
    if (draft.trim().length >= 2) {
      out.push({ hit: { kind: "logs", id: "logs", label: `Search logs for "${draft.trim()}"`, sublabel: "OpenSearch", href: "" } });
    }
    return out;
  }, [results, draft]);

  const ok = health?.status === "healthy";

  const runLogSearch = () => {
    setQuery(draft.trim() || "*");
    navigate("logs/logs");
    setOpen(false);
  };

  const choose = (h: TopHit) => {
    if (h.kind === "logs") {
      runLogSearch();
      return;
    }
    navigate(h.href);
    setOpen(false);
  };

  const submitSearch = (e: React.FormEvent) => {
    e.preventDefault();
    // Enter runs the log search by default; only jump to a result the user
    // has explicitly highlighted with the arrow keys.
    if (open && active >= 0 && rows[active]) {
      choose(rows[active].hit);
    } else {
      runLogSearch();
    }
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!open || rows.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => (a + 1) % rows.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => (a <= 0 ? rows.length - 1 : a - 1));
    } else if (e.key === "Escape") {
      setOpen(false);
    }
  };

  // Close the account menu on Escape and return focus to its trigger.
  const onMenuKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      setMenuOpen(false);
      (menuRef.current?.querySelector(".user-btn") as HTMLElement | null)?.focus();
    }
  };

  return (
    <header className="topbar">
      {/* Brand wordmark (owner 2026-07-19): CORRELIX with the O as the
          signature eye — inline SVG mark (brand/CorrelixLogo), same Space
          Grotesk face as the login wordmark, no raster assets. Anchors the
          product identity top-left on every page. */}
      <CorrelixLogo />
      <div className="topbar-right">
        <form className="omni omni-compact" onSubmit={submitSearch} ref={omniRef}>
          <span className="omni-icon" aria-hidden="true"><Icon name="search" size={14} /></span>
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onFocus={() => rows.length > 0 && setOpen(true)}
            onKeyDown={onKeyDown}
            placeholder="Search…"
            spellCheck={false}
            role="combobox"
            aria-label="Search devices, resources, and logs"
            aria-expanded={open && rows.length > 0}
            aria-controls="omni-results"
            aria-autocomplete="list"
            aria-activedescendant={open && active >= 0 ? `omni-opt-${active}` : undefined}
          />
          <kbd className="omni-kbd" title="Command palette" aria-hidden="true">⌘K</kbd>
          {open && rows.length > 0 && (
            <div className="omni-pop" id="omni-results" role="listbox" aria-label="Search results">
              {rows.map(({ hit: g, header }, i) => (
                <div key={`${g.kind}:${g.id}:${i}`}>
                  {header && <div className="omni-group" role="presentation">{header}</div>}
                  <button
                    type="button"
                    id={`omni-opt-${i}`}
                    role="option"
                    aria-selected={i === active}
                    tabIndex={-1}
                    className={`omni-item${i === active ? " active" : ""}`}
                    onMouseEnter={() => setActive(i)}
                    onClick={() => choose(g)}
                  >
                    <span className={`omni-kind k-${g.kind}`}>
                      <Icon name={hitIcon(g.kind)} size={13} />
                    </span>
                    <span className="omni-text">
                      <span className="omni-title">{g.label}</span>
                      {g.sublabel && <span className="omni-sub">{g.sublabel}</span>}
                    </span>
                    <span className="omni-tag">{hitTag(g.kind)}</span>
                  </button>
                </div>
              ))}
            </div>
          )}
        </form>
        <ScopeSelector />
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
          aria-label="Time range"
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

        {/* Time display (Local/UTC) moved to Settings → a per-TENANT persisted
            preference (owner 2026-07-17): every user of the tenant reads the
            same zone; storage stays UTC (lib/time.ts still renders it). */}

        {/* Appearance knob removed from the topbar (owner 2026-07-18): theme is
            chosen on the login screen and carries over (shared netops.theme
            pref); an explicit Theme control lives in the account menu's
            Appearance settings (AppearanceControls). */}

        <button
          className="help-btn"
          type="button"
          onClick={() => setHelpOpen(true)}
          title="Documentation"
          aria-label="Open documentation"
        >
          <Icon name="help" size={16} />
        </button>

        <span className={`health${ok ? "" : " bad"}`} role="status" title={ok ? `v${health?.version}` : "Disconnected"}>
          <span className="dot" aria-hidden="true" />
          {ok ? "Healthy" : "Disconnected"}
        </span>

        {!hideUserMenu && (
        <div className="user-menu" ref={menuRef} onKeyDown={onMenuKeyDown}>
          <button className="user-btn" onClick={() => setMenuOpen((o) => !o)} aria-haspopup="menu" aria-expanded={menuOpen}>
            <span className="avatar" aria-hidden="true">{user.username.slice(0, 1).toUpperCase()}</span>
            <span className="user-name">{user.username}</span>
            <span style={{ opacity: 0.6, fontSize: 10 }} aria-hidden="true">▾</span>
          </button>
          {menuOpen && (
            <div className="menu-pop">
              <div className="menu-head">
                {user.username}
                <span style={{ color: "var(--muted)" }}> · {user.role}</span>
                <ScopeBadge user={user} />
              </div>
              <AppearanceControls />
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
