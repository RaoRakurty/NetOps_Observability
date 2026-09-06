import { useEffect, useState } from "react";
import "./Security.css";
import { api, SecFindingQuery, SecSavedView } from "../../services/api";
import { Group } from "../../components/board/panels";
import { operatorError } from "../../lib/errors";
import AskIris from "../../components/AskIris";
// Saved views — named filter sets over the Exposures workbench. A view stores a
// FILTER, never rows: applying one re-queries under the caller's own token, so
// a view can never widen what its owner may see (§3a) and can never carry
// another tenant's data with it.

/** One-line human summary of a saved view's filters. */
export function describeFilters(f: SecFindingQuery | undefined): string {
  if (!f) return "no filters — every current finding";
  const parts: string[] = [];
  if (f.severity) parts.push(`severity ${f.severity}`);
  if (f.status) parts.push(`verdict ${f.status}`);
  if (f.seam) parts.push(`seam ${f.seam}`);
  if (f.framework) parts.push(`standard ${f.framework}`);
  if (f.device) parts.push(`device ${f.device}`);
  if (f.q) parts.push(`search "${f.q}"`);
  if (f.since || f.until) parts.push(`window ${f.since ?? "…"} → ${f.until ?? "now"}`);
  parts.push(f.current === false ? "full history" : "current verdicts");
  return parts.join(" · ");
}

export default function SavedViews() {
  const [views, setViews] = useState<SecSavedView[]>([]);
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");
  const [current, setCurrent] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const load = () => {
    let alive = true;
    api.securityViews()
      .then((v) => { if (alive) { setViews(Array.isArray(v) ? v : []); setErr(null); } })
      .catch((e: unknown) => { if (alive) setErr(operatorError(e, "Saved views could not be loaded.")); })
      .finally(() => { if (alive) setLoaded(true); });
    return () => { alive = false; };
  };
  useEffect(load, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed || busy) return;
    const filters: SecFindingQuery = { current };
    if (severity) filters.severity = severity;
    if (status) filters.status = status;
    if (q.trim()) filters.q = q.trim();
    setBusy(true);
    try {
      const created = await api.securityViewCreate(trimmed, filters);
      setViews((v) => [...v.filter((x) => x.id !== created.id), created]);
      setName(""); setSeverity(""); setStatus(""); setQ(""); setCurrent(true);
      setErr(null);
    } catch (ex) {
      setErr((ex as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (v: SecSavedView) => {
    setBusy(true);
    try {
      await api.securityViewDelete(v.id);
      setViews((list) => list.filter((x) => x.id !== v.id));
      setErr(null);
    } catch (ex) {
      setErr((ex as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="sec dm-board">
      <Group title="Saved views" hue="#14b8a6">
        <form className="sec-toolbar" onSubmit={create}>
          <label className="sr-only" htmlFor="sv-name">View name</label>
          <input id="sv-name" className="sec-input" placeholder="View name" value={name}
            onChange={(e) => setName(e.target.value)} style={{ width: 200 }} />
          <label className="sr-only" htmlFor="sv-sev">Severity</label>
          <select id="sv-sev" className="sec-input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">Any severity</option>
            {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <label className="sr-only" htmlFor="sv-status">Verdict</label>
          <select id="sv-status" className="sec-input" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Any verdict</option>
            {["fail", "warn", "pass"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <label className="sr-only" htmlFor="sv-q">Search text</label>
          <input id="sv-q" className="sec-input" placeholder="Search text" value={q}
            onChange={(e) => setQ(e.target.value)} style={{ width: 180 }} />
          <label style={{ display: "inline-flex", gap: 6, alignItems: "center", fontSize: 12.5 }}>
            <input type="checkbox" checked={current} onChange={(e) => setCurrent(e.target.checked)} />
            Current verdicts only
          </label>
          <button className="btn accent" type="submit" disabled={!name.trim() || busy}>Save view</button>
        </form>

        {err && <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>}

        {!loaded ? (
          <div className="empty" role="status">Loading…</div>
        ) : views.length === 0 ? (
          <div className="empty">
            No saved view yet.
            <AskIris topic="views.saved-view" label="a saved view" />
          </div>
        ) : (
          <table className="ds-table" aria-label="Saved views">
            <thead>
              <tr><th scope="col">Name</th><th scope="col">Filters</th><th scope="col">Actions</th></tr>
            </thead>
            <tbody>
              {views.map((v) => (
                <tr key={v.id}>
                  <th scope="row" style={{ textAlign: "left", fontWeight: 500 }}>{v.name}</th>
                  <td className="sec-line">{describeFilters(v.filters)}</td>
                  <td style={{ display: "flex", gap: 6 }}>
                    <a className="btn" href={`#/security/exposures?view=${encodeURIComponent(v.id)}`}>Open</a>
                    <button className="btn" type="button" disabled={busy} onClick={() => { void remove(v); }}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Group>
    </div>
  );
}
