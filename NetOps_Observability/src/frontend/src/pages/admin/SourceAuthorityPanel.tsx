// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// SourceAuthorityPanel — Administration → Iris → Network Context, "Which source
// Iris believes" (tracker 337 N-F6).
//
// When several sources report the same device and disagree, Iris uses the
// highest source in this order, says which one it used and what the others
// said. A workspace administrator may reorder it for their own workspace; the
// platform default stays as it is.
//
// §3a: every call is the caller's own workspace (from the token); the panel
// never sends a tenant. Labels come from the server and render as text.

import { useCallback, useEffect, useState } from "react";
import { api, SourceAuthorityClass, SourceAuthorityView } from "../../services/api";
import { operatorError } from "../../lib/errors";

export default function SourceAuthorityPanel() {
  const [view, setView] = useState<SourceAuthorityView | null>(null);
  const [order, setOrder] = useState<SourceAuthorityClass[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const show = (v: SourceAuthorityView) => {
    setView(v);
    setOrder(v.order);
    setError(null);
  };

  const load = useCallback(async () => {
    try {
      show(await api.sourceAuthority());
    } catch (e) {
      setError(operatorError(e, "The source order could not be loaded."));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const move = (i: number, by: number) => {
    const next = [...order];
    const [item] = next.splice(i, 1);
    next.splice(i + by, 0, item);
    setOrder(next);
    setNotice(null);
  };

  const run = async (what: () => Promise<SourceAuthorityView>, done: string) => {
    setBusy(true);
    setNotice(null);
    try {
      show(await what());
      setNotice(done);
    } catch (e) {
      setError(operatorError(e, "The source order could not be saved."));
    } finally {
      setBusy(false);
    }
  };

  const key = (o: SourceAuthorityClass[]) => o.map((c) => c.class).join(",");
  const changed = view !== null && key(order) !== key(view.order);
  const editable = view?.editable === true;

  return (
    <div className="card disc-card nctx" style={{ marginBottom: 16 }} data-testid="source-authority">
      <div className="disc-head">
        <div>
          <h2 className="disc-title">Which source Iris believes</h2>
          <p className="disc-desc">
            When sources report different values for the same device, Iris uses the highest source in this list, says
            which one it used and what the others reported.
          </p>
        </div>
      </div>
      {error && (
        <div className="disc-refusal" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <p className="disc-text" role="status">
          {notice}
        </p>
      )}
      {view && (
        <>
          <ol className="disc-steps" aria-label="Source order">
            {order.map((c, i) => (
              <li className="disc-step" key={c.class}>
                <span className="disc-step-num" aria-hidden>
                  {i + 1}
                </span>
                <div className="disc-step-body">
                  <div className="nctx-actions">
                    <span className="disc-text">{c.label}</span>
                    {editable && (
                      <>
                        <button
                          className="btn"
                          disabled={busy || i === 0}
                          aria-label={`Move ${c.label} up`}
                          onClick={() => move(i, -1)}
                        >
                          Up
                        </button>
                        <button
                          className="btn"
                          disabled={busy || i === order.length - 1}
                          aria-label={`Move ${c.label} down`}
                          onClick={() => move(i, 1)}
                        >
                          Down
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </li>
            ))}
          </ol>
          {editable ? (
            <div className="nctx-actions">
              <button
                className="btn"
                disabled={busy || !changed}
                onClick={() =>
                  void run(() => api.sourceAuthoritySave(order.map((c) => c.class)), "Saved. Iris uses this order from its next answer.")
                }
              >
                Save order
              </button>
              <button
                className="btn"
                disabled={busy || !view.customized}
                onClick={() => void run(() => api.sourceAuthorityReset(), "Back to the platform default order.")}
              >
                Use the platform default
              </button>
            </div>
          ) : (
            <p className="disc-text">This deployment uses the platform default order. Changing it needs the Postgres platform store.</p>
          )}
          <p className="disc-text">
            {view.customized ? `This workspace uses its own order${view.updated_by ? `, last set by ${view.updated_by}` : ""}.` : "This workspace uses the platform default order."}
          </p>
        </>
      )}
    </div>
  );
}
