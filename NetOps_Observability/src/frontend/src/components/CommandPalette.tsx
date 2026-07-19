import { useEffect, useMemo, useRef, useState } from "react";
import { useShell } from "../context/shell";
import { usePrefs } from "../theme/prefs";
import { navDestinations, NavSection } from "../nav";
import { omniSearch, groupHits, OmniHit, OmniKind, OMNI_KIND_ICON, OMNI_KIND_TAG, OMNI_KIND_LABEL } from "../lib/omniSearch";
import Icon from "./Icon";

// CommandPalette — a ⌘K / Ctrl-K overlay that turns the omni-search into a
// keyboard-first command bar (Linear/VS Code style). It unifies three
// kinds of entries:
//   · navigation — jump to any nav destination (built from nav.tsx)
//   · actions    — toggle density, open Copilot
//   · search     — live, tenant-scoped results from the unified search
//     (devices · resources · services · accounts · cases · alerts · saved),
//     grouped by kind, each row deep-linking to its permanent URL
// Arrow keys move, Enter runs the highlighted row, Esc closes.

type CmdKind = "nav" | "action" | "logs" | OmniKind;

type Cmd = {
  id: string;
  kind: CmdKind;
  title: string;
  sub?: string;
  /** group header rendered above this row (first row of each group only). */
  header?: string;
  run: () => void;
};

const BASE_ICON: Record<string, string> = { nav: "overview", action: "settings", logs: "search" };
const BASE_LABEL: Record<string, string> = { nav: "Go to", action: "Action", logs: "Logs" };

const kindIcon = (k: CmdKind): string => BASE_ICON[k] ?? OMNI_KIND_ICON[k as OmniKind] ?? "search";
const kindTag = (k: CmdKind): string => BASE_LABEL[k] ?? OMNI_KIND_TAG[k as OmniKind] ?? k;

export default function CommandPalette({ nav }: { nav: NavSection[] }) {
  const { navigate, setQuery, setCopilotOpen } = useShell();
  const { density, setDensity } = usePrefs();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const [results, setResults] = useState<OmniHit[]>([]);
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

  // Debounced unified search for the result rows.
  useEffect(() => {
    if (!open) return;
    const term = q.trim();
    if (term.length < 2) {
      setResults([]);
      return;
    }
    let cancelled = false;
    const t = setTimeout(() => {
      omniSearch(term)
        .then((hits) => !cancelled && setResults(hits))
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

  // Combine: filtered static commands + grouped live search results.
  const cmds = useMemo<Cmd[]>(() => {
    const term = q.trim().toLowerCase();
    const filteredStatic = term
      ? staticCmds.filter((c) => c.title.toLowerCase().includes(term) || (c.sub ?? "").toLowerCase().includes(term))
      : staticCmds;
    // Group by kind (devices · resources · services · accounts · cases ·
    // alerts · saved); the first row of each group carries the header.
    const searchCmds: Cmd[] = [];
    for (const group of groupHits(results)) {
      group.hits.forEach((h, i) => {
        searchCmds.push({
          id: `s:${h.kind}:${h.id}:${i}`,
          kind: h.kind,
          title: h.label,
          sub: h.sublabel,
          header: i === 0 ? OMNI_KIND_LABEL[group.kind] : undefined,
          run: () => go(h.href),
        });
      });
    }
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
              go("logs/logs");
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
            <div key={c.id}>
              {c.header && <div className="cmdk-group">{c.header}</div>}
              <button
                className={`cmdk-item${i === active ? " active" : ""}`}
                onMouseEnter={() => setActive(i)}
                onClick={() => c.run()}
              >
                <span className={`cmdk-kind k-${c.kind}`}>
                  <Icon name={kindIcon(c.kind)} size={13} />
                </span>
                <span className="cmdk-text">
                  <span className="cmdk-title">{c.title}</span>
                  {c.sub && <span className="cmdk-sub">{c.sub}</span>}
                </span>
                <span className="cmdk-tag">{kindTag(c.kind)}</span>
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
