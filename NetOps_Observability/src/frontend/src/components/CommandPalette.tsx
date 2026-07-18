import { useEffect, useMemo, useRef, useState } from "react";
import { api, GlobalResult } from "../services/api";
import { useShell } from "../context/shell";
import { usePrefs } from "../theme/prefs";
import { navDestinations, NavSection } from "../nav";
import Icon from "./Icon";

// CommandPalette — a ⌘K / Ctrl-K overlay that turns the omni-search into a
// keyboard-first command bar (Linear/VS Code style). It unifies three
// kinds of entries:
//   · navigation — jump to any nav destination (built from nav.tsx)
//   · actions    — toggle theme/density, open Copilot
//   · search     — live device/alert/saved results (debounced /api/search/global)
// Arrow keys move, Enter runs the highlighted row, Esc closes.

type Cmd = {
  id: string;
  kind: "nav" | "action" | "device" | "alert" | "saved" | "logs";
  title: string;
  sub?: string;
  run: () => void;
};

const KIND_ICON: Record<Cmd["kind"], string> = {
  nav: "overview",
  action: "settings",
  device: "datasets",
  alert: "alerts",
  saved: "dashboards",
  logs: "search",
};
const KIND_LABEL: Record<Cmd["kind"], string> = {
  nav: "Go to",
  action: "Action",
  device: "Device",
  alert: "Alert",
  saved: "Saved",
  logs: "Logs",
};

export default function CommandPalette({ nav }: { nav: NavSection[] }) {
  const { navigate, setQuery, setCopilotOpen } = useShell();
  const { density, setDensity } = usePrefs();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const [results, setResults] = useState<GlobalResult[]>([]);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Global hotkey: ⌘K / Ctrl-K toggles the palette.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        setOpen((o) => !o);
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Reset + focus when opened.
  useEffect(() => {
    if (open) {
      setQ("");
      setActive(0);
      setResults([]);
      // focus after paint
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  // Debounced global search for the search-kind rows.
  useEffect(() => {
    if (!open) return;
    const term = q.trim();
    if (term.length < 2) {
      setResults([]);
      return;
    }
    let cancelled = false;
    const t = setTimeout(() => {
      api
        .globalSearch(term)
        .then((r) => !cancelled && setResults(r.results.filter((x) => x.kind !== "logs")))
        .catch(() => !cancelled && setResults([]));
    }, 180);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [q, open]);

  const go = (route: string) => {
    navigate(route);
    setOpen(false);
  };

  // The static command set (nav destinations + actions), rebuilt only when the
  // prefs change (labels reflect the next state).
  const staticCmds = useMemo<Cmd[]>(() => {
    const navCmds: Cmd[] = navDestinations(nav).map((d) => ({
      id: `nav:${d.route}`,
      kind: "nav",
      title: d.label,
      sub: d.section,
      run: () => (d.action === "copilot" ? (setCopilotOpen(true), setOpen(false)) : go(d.route)),
    }));
    // Theme command removed (owner 2026-07-18): theme is set on the login
    // screen or in the account menu's Appearance settings only.
    const actions: Cmd[] = [
      {
        id: "act:density",
        kind: "action",
        title: `Switch to ${density === "compact" ? "cozy" : "compact"} density`,
        sub: "Appearance",
        run: () => setDensity(density === "compact" ? "comfortable" : "compact"),
      },
      {
        id: "act:copilot",
        kind: "action",
        title: "Open Copilot",
        sub: "Assistant",
        run: () => {
          setCopilotOpen(true);
          setOpen(false);
        },
      },
    ];
    return [...navCmds, ...actions];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [density, nav]);

  // Combine: filtered static commands + live search results.
  const cmds = useMemo<Cmd[]>(() => {
    const term = q.trim().toLowerCase();
    const filteredStatic = term
      ? staticCmds.filter((c) => c.title.toLowerCase().includes(term) || (c.sub ?? "").toLowerCase().includes(term))
      : staticCmds;
    const searchCmds: Cmd[] = results.map((r, i) => ({
      id: `s:${r.kind}:${r.id}:${i}`,
      kind: r.kind as Cmd["kind"],
      title: r.title,
      sub: r.sub,
      run: () => go(r.route),
    }));
    // Always offer a raw log-search handoff when there's a query.
    const logsCmd: Cmd[] = term
      ? [
          {
            id: "logs:raw",
            kind: "logs",
            title: `Search logs for "${q.trim()}"`,
            sub: "OpenSearch",
            run: () => {
              setQuery(q.trim());
              go("explore/logs");
            },
          },
        ]
      : [];
    return [...filteredStatic, ...searchCmds, ...logsCmd];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, staticCmds, results]);

  useEffect(() => {
    setActive((a) => Math.min(a, Math.max(0, cmds.length - 1)));
  }, [cmds.length]);

  if (!open) return null;

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => (cmds.length ? (a + 1) % cmds.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => (cmds.length ? (a <= 0 ? cmds.length - 1 : a - 1) : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      cmds[active]?.run();
    } else if (e.key === "Escape") {
      setOpen(false);
    }
  };

  return (
    <div className="cmdk-backdrop" onMouseDown={() => setOpen(false)}>
      <div className="cmdk" onMouseDown={(e) => e.stopPropagation()}>
        <div className="cmdk-input">
          <Icon name="search" size={16} />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Jump to a section, run an action, or search…"
            spellCheck={false}
          />
          <kbd className="cmdk-kbd">esc</kbd>
        </div>
        <div className="cmdk-list">
          {cmds.length === 0 && <div className="cmdk-empty">No matches.</div>}
          {cmds.map((c, i) => (
            <button
              key={c.id}
              className={`cmdk-item${i === active ? " active" : ""}`}
              onMouseEnter={() => setActive(i)}
              onClick={() => c.run()}
            >
              <span className={`cmdk-kind k-${c.kind}`}>
                <Icon name={KIND_ICON[c.kind]} size={13} />
              </span>
              <span className="cmdk-text">
                <span className="cmdk-title">{c.title}</span>
                {c.sub && <span className="cmdk-sub">{c.sub}</span>}
              </span>
              <span className="cmdk-tag">{KIND_LABEL[c.kind]}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
