// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useCallback, useEffect, useState } from "react";
import { api, SavedObject } from "../services/api";
import { PANELS, PANEL_CATEGORIES } from "./panels";
import { Modal } from "../components/ui";
import { fmtDateTime } from "../lib/time";
import { operatorError } from "../lib/errors";
// Saved dashboards — the customer dashboard BUILDER (the surface the panel
// registry was designed for: panels.tsx's PANEL_CATEGORIES is the "Add panel"
// picker). A dashboard is a named, ordered list of {type, span} cells rendered
// through the registry, persisted server-side as a saved object of type
// "dashboard" (tenant-scoped, RLS-backed — the backend supports the type
// already; no backend change).
//
// Layout model matches My Dashboard: a 12-column grid where span ∈
// {3,4,6,8,12} is the only layout unit — reorder + resize covers composition
// without a drag-layout dependency. Unknown panel types in a stored body are
// PRESERVED (forward compatibility) but skipped at render with a visible note,
// never silently dropped.

type Cell = { type: string; span: number };
type BoardBody = { v: 1; cells: Cell[] };

const SPANS: number[] = [3, 4, 6, 8, 12];
const MAX_CELLS = 40;

function parseBody(raw: unknown): BoardBody {
  const body = raw as Partial<BoardBody> | null;
  const cells: Cell[] = [];
  if (body && Array.isArray(body.cells)) {
    for (const c of body.cells.slice(0, MAX_CELLS)) {
      if (c && typeof c.type === "string") {
        cells.push({ type: c.type, span: SPANS.includes(c.span) ? c.span : 4 });
      }
    }
  }
  return { v: 1, cells };
}

function PanelPicker({ onPick, onClose }: { onPick: (type: string) => void; onClose: () => void }) {
  return (
    <Modal title="Add panel" onClose={onClose}>
      <div style={{ display: "grid", gap: 14, maxHeight: "60vh", overflowY: "auto" }}>
        {PANEL_CATEGORIES.map((cat) => (
          <div key={cat.category}>
            <div className="dashb-cat">{cat.category}</div>
            <div className="dashb-pick-grid">
              {cat.types.filter((t) => PANELS[t]).map((t) => (
                <button key={t} type="button" className="dashb-pick" onClick={() => onPick(t)}>
                  <strong>{PANELS[t].title}</strong>
                  <span className="dashb-pick-span">{PANELS[t].defaultSpan} col</span>
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Modal>
  );
}

function BoardEditor({ board, onBack, onSaved }: {
  board: SavedObject | null; // null = new dashboard
  onBack: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(board?.name ?? "");
  const [cells, setCells] = useState<Cell[]>(() => parseBody(board?.body).cells);
  const [editing, setEditing] = useState(board === null); // a new board starts in edit mode
  const [picking, setPicking] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);

  const mutate = (fn: (prev: Cell[]) => Cell[]) => {
    setCells(fn);
    setDirty(true);
  };
  const move = (i: number, dir: -1 | 1) =>
    mutate((prev) => {
      const j = i + dir;
      if (j < 0 || j >= prev.length) return prev;
      const next = prev.slice();
      [next[i], next[j]] = [next[j], next[i]];
      return next;
    });
  const resize = (i: number, span: number) =>
    mutate((prev) => prev.map((c, k) => (k === i ? { ...c, span } : c)));
  const remove = (i: number) => mutate((prev) => prev.filter((_, k) => k !== i));
  const add = (type: string) => {
    setPicking(false);
    mutate((prev) => (prev.length >= MAX_CELLS ? prev : [...prev, { type, span: PANELS[type]?.defaultSpan ?? 4 }]));
  };

  const save = async () => {
    const trimmed = name.trim();
    if (!trimmed) {
      setErr("Give the dashboard a name.");
      return;
    }
    setSaving(true);
    setErr(null);
    try {
      const body: BoardBody = { v: 1, cells };
      if (board) await api.updateSaved(board.id, trimmed, body);
      else await api.createSaved("dashboard", trimmed, body);
      setDirty(false);
      onSaved();
    } catch (e) {
      setErr(operatorError(e, "The dashboard could not be loaded."));
    } finally {
      setSaving(false);
    }
  };

  const unknown = cells.filter((c) => !PANELS[c.type]).length;

  return (
    <div className="mydash">
      <div className="mydash-head">
        <div>
          <div className="mydash-eyebrow">Saved dashboard</div>
          {editing ? (
            <input
              className="ccw-input dashb-name"
              value={name}
              onChange={(e) => { setName(e.target.value); setDirty(true); }}
              placeholder="Name this dashboard"
              maxLength={80}
              aria-label="Dashboard name"
            />
          ) : (
            <h1 className="mydash-title">{name || "Untitled"}</h1>
          )}
        </div>
        <div className="mydash-head-meta" style={{ display: "inline-flex", gap: 8 }}>
          {editing && <button className="btn btn-sm" onClick={() => setPicking(true)}>+ Add panel</button>}
          {editing ? (
            <button className="btn btn-sm btn-primary" onClick={() => void save()} disabled={saving}>
              {saving ? "Saving…" : "Save"}
            </button>
          ) : (
            <button className="btn btn-sm" onClick={() => setEditing(true)}>Edit</button>
          )}
          <button className="btn btn-sm" onClick={onBack}>
            {dirty && editing ? "Back (discard changes)" : "Back"}
          </button>
        </div>
      </div>

      {err && <div role="alert" style={{ color: "var(--bad)", marginBottom: 10 }}>{err}</div>}
      {unknown > 0 && (
        <div className="ccw-hint" style={{ marginBottom: 10 }}>
          {unknown} panel{unknown === 1 ? "" : "s"} in this dashboard {unknown === 1 ? "is" : "are"} from a newer
          version and can't render here — {unknown === 1 ? "it is" : "they are"} kept in the saved layout untouched.
        </div>
      )}

      {cells.length === 0 ? (
        <div className="card empty-state">
          <div className="empty-state-icon">📊</div>
          <h2 style={{ textTransform: "none", color: "var(--fg)", fontSize: 18 }}>An empty canvas</h2>
          <p style={{ color: "var(--muted)", maxWidth: 480, margin: "8px auto 0" }}>
            Add panels — KPI tiles, gauges, top-N bars, traffic and flow charts — and arrange them into your own view.
          </p>
          <p style={{ marginTop: 12 }}>
            <button className="btn btn-primary" onClick={() => setPicking(true)}>+ Add your first panel</button>
          </p>
        </div>
      ) : (
        <div className="ov-grid mydash-grid">
          {cells.map((cell, i) => {
            const def = PANELS[cell.type];
            if (!def) return null; // preserved in the body; disclosed above
            return (
              <div className={`panel col-${cell.span}`} key={`${cell.type}-${i}`}>
                <div className="panel-tools">
                  <h3>{def.title}</h3>
                  {editing && (
                    <div className="panel-tools-btns dashb-cell-tools">
                      <select
                        className="dashb-span"
                        value={cell.span}
                        onChange={(e) => resize(i, Number(e.target.value))}
                        title="Panel width (of 12 columns)"
                        aria-label={`${def.title} width`}
                      >
                        {SPANS.map((s) => <option key={s} value={s}>{s} col</option>)}
                      </select>
                      <button onClick={() => move(i, -1)} disabled={i === 0} title="Move earlier" aria-label="Move panel earlier">←</button>
                      <button onClick={() => move(i, 1)} disabled={i === cells.length - 1} title="Move later" aria-label="Move panel later">→</button>
                      <button onClick={() => remove(i)} title="Remove panel" aria-label="Remove panel">✕</button>
                    </div>
                  )}
                </div>
                {def.render()}
              </div>
            );
          })}
        </div>
      )}

      {picking && <PanelPicker onPick={add} onClose={() => setPicking(false)} />}
    </div>
  );
}

export default function SavedDashboards() {
  const [boards, setBoards] = useState<SavedObject[] | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [open, setOpen] = useState<SavedObject | null>(null);
  const [creating, setCreating] = useState(false);
  const [nonce, setNonce] = useState(0);

  const load = useCallback(async () => {
    try {
      const list = await api.listSaved("dashboard");
      setBoards(list ?? []);
      setLoadErr(null);
    } catch (e) {
      setLoadErr(operatorError(e, "The dashboard could not be loaded."));
    }
  }, []);
  useEffect(() => { void load(); }, [load, nonce]);

  const remove = async (b: SavedObject) => {
    if (!window.confirm(`Delete dashboard "${b.name}"?`)) return;
    try {
      await api.deleteSaved(b.id);
      setNonce((n) => n + 1);
    } catch (e) {
      setLoadErr(operatorError(e, "The dashboard could not be loaded."));
    }
  };

  if (creating || open) {
    return (
      <BoardEditor
        board={open}
        onBack={() => { setOpen(null); setCreating(false); }}
        onSaved={() => { setOpen(null); setCreating(false); setNonce((n) => n + 1); }}
      />
    );
  }

  return (
    <div className="card">
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <h2 style={{ margin: 0 }}>Your dashboards</h2>
        <span style={{ color: "var(--muted)", fontSize: 12 }}>
          composed from live panels · saved to your tenant
        </span>
        <button className="btn btn-sm btn-primary" style={{ marginLeft: "auto" }} onClick={() => setCreating(true)}>
          + New dashboard
        </button>
      </div>
      {loadErr && (
        <div role="alert" style={{ color: "var(--bad)", marginTop: 10 }}>
          Saved dashboards could not be loaded: {loadErr}
        </div>
      )}
      {!loadErr && boards !== null && boards.length === 0 && (
        <p style={{ color: "var(--muted)", marginTop: 10 }}>
          No custom dashboards yet — build one from the same live panels the curated boards use.
        </p>
      )}
      {!loadErr && boards !== null && boards.length > 0 && (
        <div className="dashb-list">
          {boards.map((b) => {
            const count = parseBody(b.body).cells.length;
            return (
              <div key={b.id} className="dashb-row">
                <button type="button" className="dashb-open" onClick={() => setOpen(b)} title="Open dashboard">
                  <strong>{b.name}</strong>
                  <span className="dashb-meta">
                    {count} panel{count === 1 ? "" : "s"} · updated {fmtDateTime(b.updated_at)}
                  </span>
                </button>
                <button className="btn btn-sm" onClick={() => void remove(b)} aria-label={`Delete ${b.name}`}>
                  Delete
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
