// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// My dashboards — the tenant's own dashboards (Overview → My dashboards). Moved
// from the builder that sat at the bottom of Analytics → Dashboard List, and
// given what it lacked:
//   * an address per dashboard (#/overview/dashboards/<id>): bookmark, share,
//     or set as a landing;
//   * "Make a copy of the default" and a "Network telemetry" template, so a
//     dashboard rarely starts empty;
//   * the Overview's RCA panels in the picker (verdicts, next step, impact,
//     health by site), sharing one read per tick;
//   * honest errors: a save that failed says it failed to save, a delete says
//     it failed to delete, and another tenant's id reads "not found".
// A dashboard is a saved object of type "dashboard", scoped to the tenant by the
// server (row-level security; another tenant's id answers 404).

import { useCallback, useEffect, useState } from "react";
import { api, type SavedObject } from "../../services/api";
import { Modal } from "../../components/ui";
import { fmtDateTime } from "../../lib/time";
import { httpFailure, operatorError } from "../../lib/errors";
import { useShell } from "../../context/shell";
import Icon from "../../components/Icon";
import { BOARD_CATEGORIES, BOARD_PANELS } from "./panelRegistry";
import { OverviewDataProvider } from "./useOverviewData";
import { Liveness } from "./boardParts";
import { Safe } from "./rcaPanels";
import DashboardPicker from "./DashboardPicker";
import { MAX_CELLS, SPANS, TEMPLATES, dashHref, dashRoute, parseBody, type BoardBody, type Cell, type DashRoute, type TemplateId } from "./dashboardModel";


function PanelPicker({ onPick, onClose }: { onPick: (type: string) => void; onClose: () => void }) {
  return (
    <Modal title="Add panel" onClose={onClose}>
      <div style={{ display: "grid", gap: 14, maxHeight: "60vh", overflowY: "auto" }}>
        {BOARD_CATEGORIES.map((cat) => (
          <div key={cat.category}>
            <div className="dashb-cat">{cat.category}</div>
            <div className="dashb-pick-grid">
              {cat.types.filter((t) => BOARD_PANELS[t]).map((t) => (
                <button key={t} type="button" className="dashb-pick" onClick={() => onPick(t)}>
                  <strong>{BOARD_PANELS[t].title}</strong>
                  <span className="dashb-pick-span">{BOARD_PANELS[t].defaultSpan} col</span>
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Modal>
  );
}

function CellView({ cell, editing, index, count, onResize, onMove, onRemove }: {
  cell: Cell; editing: boolean; index: number; count: number;
  onResize: (span: number) => void; onMove: (dir: -1 | 1) => void; onRemove: () => void;
}) {
  const { navigate } = useShell();
  const def = BOARD_PANELS[cell.type];
  if (!def) return null; // kept in the saved body; disclosed above the grid
  const tools = editing && (
    <div className="panel-tools-btns dashb-cell-tools">
      <select className="dashb-span" value={cell.span} onChange={(e) => onResize(Number(e.target.value))}
        title="Panel width (of 12 columns)" aria-label={`${def.title} width`}>
        {SPANS.map((s) => <option key={s} value={s}>{s} col</option>)}
      </select>
      <button onClick={() => onMove(-1)} disabled={index === 0} title="Move earlier" aria-label={`Move ${def.title} earlier`}>←</button>
      <button onClick={() => onMove(1)} disabled={index === count - 1} title="Move later" aria-label={`Move ${def.title} later`}>→</button>
      <button onClick={onRemove} title="Remove panel" aria-label={`Remove ${def.title}`}>✕</button>
    </div>
  );
  // An RCA panel draws its own title; in edit mode a slim bar names it and holds the tools.
  if (def.selfTitled) {
    return (
      <div className={`col-${cell.span} dashb-self`}>
        {editing && <div className="panel-tools dashb-self-tools"><h3>{def.title}</h3>{tools}</div>}
        <Safe>{def.render()}</Safe>
      </div>
    );
  }
  return (
    <div className={`panel col-${cell.span}`}>
      <div className="panel-tools">
        <h3>
          {def.drill && !editing ? (
            <button type="button" className="panel-title-link" onClick={() => navigate(def.drill!)}
              title="Open detail view" aria-label={`${def.title} — open detail view`}>
              {def.title}
              <Icon name="arrow-up-right" size={13} className="panel-drill-icon" />
            </button>
          ) : def.title}
        </h3>
        {tools}
      </div>
      <Safe>{def.render()}</Safe>
    </div>
  );
}

export function BoardEditor({ board, template }: { board: SavedObject | null; template?: TemplateId }) {
  const fresh = board === null;
  const [name, setName] = useState(board?.name ?? (template ? TEMPLATES[template].name : ""));
  const [cells, setCells] = useState<Cell[]>(() => (board ? parseBody(board.body).cells : template ? TEMPLATES[template].cells.slice() : []));
  const [editing, setEditing] = useState(fresh);
  const [picking, setPicking] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(fresh && !!template);

  const mutate = (fn: (prev: Cell[]) => Cell[]) => { setCells(fn); setDirty(true); };
  const move = (i: number, dir: -1 | 1) => mutate((prev) => {
    const j = i + dir;
    if (j < 0 || j >= prev.length) return prev;
    const next = prev.slice();
    [next[i], next[j]] = [next[j], next[i]];
    return next;
  });
  const add = (type: string) => {
    setPicking(false);
    mutate((prev) => (prev.length >= MAX_CELLS ? prev : [...prev, { type, span: BOARD_PANELS[type]?.defaultSpan ?? 4 }]));
  };

  const save = async () => {
    const trimmed = name.trim();
    if (!trimmed) { setErr("Give the dashboard a name."); return; }
    setSaving(true);
    setErr(null);
    try {
      const body: BoardBody = { v: 1, cells };
      if (board) {
        await api.updateSaved(board.id, trimmed, body);
        setDirty(false);
        setEditing(false);
      } else {
        const created = await api.createSaved("dashboard", trimmed, body);
        setDirty(false);
        location.hash = dashHref({ kind: "open", id: created.id });
      }
    } catch (e) {
      setErr(operatorError(e, "The dashboard could not be saved."));
    } finally {
      setSaving(false);
    }
  };

  const unknown = cells.filter((c) => !BOARD_PANELS[c.type]).length;

  return (
    <div className="overview-page fp mydash" data-testid="dashboard-board">
      <div className="mydash-head">
        <div>
          <div className="mydash-eyebrow">My dashboards</div>
          {editing ? (
            <input className="ccw-input dashb-name" value={name} maxLength={80} aria-label="Dashboard name"
              onChange={(e) => { setName(e.target.value); setDirty(true); }} placeholder="Name this dashboard" />
          ) : (
            <h1 className="mydash-title">{name || "Untitled"}</h1>
          )}
        </div>
        <div className="ov-head-right">
          {!editing && board && <DashboardPicker current={board.id} />}
          {editing && <button className="btn btn-sm" onClick={() => setPicking(true)}>+ Add panel</button>}
          {editing ? (
            <button className="btn btn-sm btn-primary" onClick={() => void save()} disabled={saving}>{saving ? "Saving…" : "Save"}</button>
          ) : (
            <button className="btn btn-sm" onClick={() => setEditing(true)}>Edit</button>
          )}
          <a className="btn btn-sm" href={dashHref({ kind: "list" })}>{dirty && editing ? "Back (discard changes)" : "All dashboards"}</a>
          {!editing && <Liveness />}
        </div>
      </div>

      {err && <div role="alert" className="ov-err">{err}</div>}
      {unknown > 0 && (
        <div className="ccw-hint ov-note">
          {unknown} panel{unknown === 1 ? "" : "s"} in this dashboard {unknown === 1 ? "is" : "are"} from a newer
          version and can't render here — {unknown === 1 ? "it is" : "they are"} kept in the saved layout untouched.
        </div>
      )}

      {cells.length === 0 ? (
        <div className="card empty-state">
          <h2 className="ov-empty-h">An empty dashboard</h2>
          <p className="ov-empty-p">Add panels — problems and RCA, alerts, traffic, interfaces, routing — and arrange them into your own view.</p>
          <p><button className="btn btn-primary" onClick={() => { setEditing(true); setPicking(true); }}>+ Add your first panel</button></p>
        </div>
      ) : (
        <OverviewDataProvider>
          <div className="ov-grid mydash-grid">
            {cells.map((cell, i) => (
              <CellView key={`${cell.type}-${i}`} cell={cell} editing={editing} index={i} count={cells.length}
                onResize={(span) => mutate((prev) => prev.map((c, k) => (k === i ? { ...c, span } : c)))}
                onMove={(dir) => move(i, dir)}
                onRemove={() => mutate((prev) => prev.filter((_, k) => k !== i))} />
            ))}
          </div>
        </OverviewDataProvider>
      )}

      {picking && <PanelPicker onPick={add} onClose={() => setPicking(false)} />}
    </div>
  );
}

/** A dashboard opened by its address. Another tenant's id, or one that was
 *  deleted, reads "not found" — the server answers both with 404. */
function OpenBoard({ id }: { id: string }) {
  const [state, setState] = useState<{ board?: SavedObject; missing?: boolean; err?: string }>({});
  useEffect(() => {
    let alive = true;
    Promise.resolve().then(() => api.getSaved(id))
      .then((b) => { if (alive) setState({ board: b }); })
      .catch((e: unknown) => {
        if (!alive) return;
        setState(httpFailure(e)?.status === 404 ? { missing: true } : { err: operatorError(e, "The dashboard could not be loaded.") });
      });
    return () => { alive = false; };
  }, [id]);
  if (state.board) return <BoardEditor board={state.board} />;
  if (state.missing || state.err) {
    return (
      <div className="overview-page card" data-testid="dashboard-missing">
        <h2 className="ov-empty-h">{state.missing ? "This dashboard does not exist" : "The dashboard could not be loaded"}</h2>
        <p className="ov-empty-p">{state.missing
          ? "It was deleted, or it belongs to another tenant."
          : state.err}</p>
        <p><a className="btn btn-sm" href={dashHref({ kind: "list" })}>All dashboards</a> <a className="btn btn-sm" href="#/overview/operations">Overview</a></p>
      </div>
    );
  }
  return <div className="overview-page card" aria-busy="true">Loading the dashboard…</div>;
}

function DashboardList() {
  const [boards, setBoards] = useState<SavedObject[] | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [actErr, setActErr] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const list = await api.listSaved("dashboard");
      setBoards(list ?? []);
      setLoadErr(null);
    } catch (e) {
      setLoadErr(operatorError(e, "Your dashboards could not be loaded."));
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const remove = async (b: SavedObject) => {
    setConfirming(null);
    try {
      await api.deleteSaved(b.id);
      setActErr(null);
      void load();
    } catch (e) {
      setActErr(operatorError(e, `"${b.name}" could not be deleted.`));
    }
  };

  const start = (r: DashRoute) => { location.hash = dashHref(r); };
  return (
    <div className="overview-page" data-testid="dashboard-list">
      <div className="mydash-head">
        <div>
          <h1 className="mydash-title">My dashboards</h1>
          <div className="ov-sub">Your own views from Overview's live panels, shared with your tenant.</div>
        </div>
      </div>
      <div className="ov-starts">
        <button type="button" className="ov-start" onClick={() => start({ kind: "new", template: "default" })}>
          <strong>Make a copy of the default</strong><span>{TEMPLATES.default.blurb}</span>
        </button>
        <button type="button" className="ov-start" onClick={() => start({ kind: "new", template: "telemetry" })}>
          <strong>Start from Network telemetry</strong><span>{TEMPLATES.telemetry.blurb}</span>
        </button>
        <button type="button" className="ov-start" onClick={() => start({ kind: "new" })}>
          <strong>Start empty</strong><span>Pick every panel yourself.</span>
        </button>
      </div>

      {loadErr && <div role="alert" className="ov-err">{loadErr}</div>}
      {actErr && <div role="alert" className="ov-err">{actErr}</div>}
      {!loadErr && boards !== null && boards.length === 0 && (
        <p className="ov-empty-p">No dashboards yet. Start from one of the three above.</p>
      )}
      {!loadErr && boards !== null && boards.length > 0 && (
        <div className="dashb-list">
          {boards.map((b) => {
            const count = parseBody(b.body).cells.length;
            return (
              <div key={b.id} className="dashb-row">
                <a className="dashb-open" href={dashHref({ kind: "open", id: b.id })}>
                  <strong>{b.name}</strong>
                  <span className="dashb-meta">{count} panel{count === 1 ? "" : "s"} · updated {fmtDateTime(b.updated_at)}</span>
                </a>
                {confirming === b.id ? (
                  <>
                    <button className="btn btn-sm btn-danger" onClick={() => void remove(b)}>Delete "{b.name}"</button>
                    <button className="btn btn-sm" onClick={() => setConfirming(null)}>Keep</button>
                  </>
                ) : (
                  <button className="btn btn-sm" onClick={() => setConfirming(b.id)} aria-label={`Delete ${b.name}`}>Delete</button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function MyDashboards() {
  const [route, setRoute] = useState<DashRoute>(() => dashRoute(location.hash));
  useEffect(() => {
    const on = () => setRoute(dashRoute(location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  if (route.kind === "open") return <OpenBoard key={route.id} id={route.id} />;
  if (route.kind === "new") return <BoardEditor key={`new-${route.template ?? ""}`} board={null} template={route.template} />;
  return <DashboardList />;
}
