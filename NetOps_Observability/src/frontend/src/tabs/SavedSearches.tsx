// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { fmtDateTime } from "../lib/time";
import { useEffect, useState } from "react";
import { api, SavedObject } from "../services/api";
import { useShell } from "../context/shell";
import { PageHeader, OutlinedButton } from "../components/kit";

// Saved searches — the list side of the Search → save → reopen loop.
// Opening one applies its query to the global omni-search and jumps to
// the Search view (which reads the shell query).

export default function SavedSearches() {
  const { setQuery, navigate } = useShell();
  const [items, setItems] = useState<SavedObject[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      setItems(await api.listSaved("saved_search"));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const open = (o: SavedObject) => {
    setQuery(o.body?.query ?? "*");
    navigate("explore/logs");
  };

  const remove = async (o: SavedObject) => {
    if (!window.confirm(`Delete saved search "${o.name}"?`)) return;
    try {
      await api.deleteSaved(o.id);
      setItems((prev) => prev.filter((x) => x.id !== o.id));
    } catch (e) {
      window.alert(`Delete failed: ${(e as Error).message}`);
    }
  };

  return (
    <div className="card">
      <PageHeader icon="bookmark" title="Saved searches" count={loading ? undefined : items.length} />
      {error && <p style={{ color: "var(--bad)" }}>{error}</p>}
      {loading ? (
        <div className="empty">Loading…</div>
      ) : items.length === 0 ? (
        <div className="empty">
          No saved searches yet. Run a query under <strong>Explore → Logs</strong> and click ★ Save.
        </div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Query</th>
              <th style={{ width: 110 }}>Signal</th>
              <th style={{ width: 170 }}>Updated</th>
              <th style={{ width: 140 }}></th>
            </tr>
          </thead>
          <tbody>
            {items.map((o) => (
              <tr key={o.id}>
                <td><span className="kit-host-name">{o.name}</span></td>
                <td className="kit-mono">{o.body?.query ?? "*"}</td>
                <td className="kit-muted">{o.body?.signal || "all"}</td>
                <td className="kit-muted kit-mono">{fmtDateTime(o.updated_at)}</td>
                <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                  <span style={{ display: "inline-flex", gap: 6 }}>
                    <OutlinedButton icon="close" label={`Delete ${o.name}`} onClick={() => remove(o)} />
                    <OutlinedButton chevron onClick={() => open(o)}>Open</OutlinedButton>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
