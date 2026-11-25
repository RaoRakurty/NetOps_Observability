// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// CorsOrigins — Platform → Configuration → Cross-origin access (tracker 439).
//
// The web addresses of a customer's own apps that may send data to Correlix
// from a browser — what the real-user tag needs. It used to be the
// installation-file value CORS_ALLOWED_ORIGINS, and customers never edit that
// file. A list saved here wins over it and is in use at once (no restart);
// "Use the installation value" returns to it.
//
// GATE. /api/platform/cors-origins is requirePlatformAdmin (platform-global,
// CLAUDE.md §3a rule 3); the page lives in the provider-only Platform section
// and a 403 renders as "denied", never as a failure.

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type CorsOriginsView } from "../../services/api";
import { httpFailure, operatorError } from "../../lib/errors";
import { fmtDateTime } from "../../lib/time";
import { parseLines, problems, sourceLine, textFor } from "./corsOriginsModel";

import { PageHeader } from "../../components/kit";
type Load =
  | { kind: "loading" }
  | { kind: "denied" }
  | { kind: "error"; message: string }
  | { kind: "ready"; data: CorsOriginsView };

const toneColor = { good: "var(--good)", bad: "var(--bad)" } as const;

export default function CorsOrigins() {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "good" | "bad"; text: string } | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await api.corsOrigins();
      setLoad({ kind: "ready", data });
      setText(textFor(data));
    } catch (e) {
      if (httpFailure(e)?.status === 403) setLoad({ kind: "denied" });
      else setLoad({ kind: "error", message: operatorError(e, "The cross-origin settings could not be read.") });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const data = load.kind === "ready" ? load.data : null;
  const lines = useMemo(() => parseLines(text), [text]);
  const bad = useMemo(() => problems(lines, data?.max_origins ?? 50), [lines, data]);
  const dirty = data ? lines.join("\n") !== data.origins.join("\n") : false;

  if (load.kind === "loading") return <div className="empty">Loading…</div>;
  if (load.kind === "denied") return <div className="empty">Only the platform administrator can change cross-origin access.</div>;
  if (load.kind === "error") return <div className="empty" role="alert">{load.message}</div>;
  const v = load.data;

  const apply = async (fn: () => Promise<CorsOriginsView>, ok: string) => {
    setBusy(true);
    setMessage(null);
    try {
      const next = await fn();
      setLoad({ kind: "ready", data: next });
      setText(textFor(next));
      setMessage({ tone: "good", text: ok });
    } catch (e) {
      setMessage({ tone: "bad", text: operatorError(e, "Not saved. The list in use did not change.") });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="cors-origins-page" style={{ fontSize: 14, maxWidth: 1000 }}><PageHeader icon="globe" title="Cross-origin access" />
      <p style={{ margin: "0 0 12px" }}>
        The web addresses of your own apps that may send data to Correlix from a browser. The real-user tag needs each app
        listed here; browsers block the data from any other address.
      </p>

      {v.env_dropped.length > 0 && (
        <div className="cc-panel" role="alert" data-testid="env-dropped" style={{ padding: "10px 12px", marginBottom: 12, borderColor: "var(--warn)" }}>
          These entries in the installation file are not web addresses Correlix can allow, so they do nothing:{" "}
          {v.env_dropped.join("; ")}.
        </div>
      )}

      <section className="cc-panel" style={{ padding: "12px 14px" }}>
        <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>Allowed addresses</h3>
        <div className="fact-line" data-testid="cors-source" style={{ marginBottom: 8 }}>
          {sourceLine(v)}
        </div>
        <label htmlFor="cors-origins" style={{ display: "block", marginBottom: 4 }}>
          One address per line, like https://shop.example.com (add a port only if the app uses one)
        </label>
        <textarea
          id="cors-origins"
          data-testid="cors-origins-input"
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setMessage(null);
          }}
          rows={Math.min(12, Math.max(4, lines.length + 1))}
          spellCheck={false}
          style={{ fontSize: 14, fontFamily: "var(--font-mono, monospace)", width: "100%", maxWidth: 620, padding: "6px 8px" }}
        />
        {bad.length > 0 && (
          <ul role="alert" data-testid="cors-problems" style={{ color: "var(--bad)", margin: "6px 0", paddingLeft: 18 }}>
            {bad.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        )}
        <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap", marginTop: 8 }}>
          <button
            className="btn"
            style={{ fontSize: 14 }}
            disabled={busy || !dirty || bad.length > 0}
            onClick={() => void apply(() => api.saveCorsOrigins(lines), "Saved. In use now.")}
          >
            {busy ? "Saving…" : "Save"}
          </button>
          {v.source !== "env" && (
            <button
              className="btn-ghost"
              style={{ fontSize: 14 }}
              disabled={busy}
              onClick={() => void apply(() => api.resetCorsOrigins(), "The installation value is in use again.")}
            >
              Use the installation value{v.env_origins.length === 0 ? " (none)" : ` (${v.env_origins.length})`}
            </button>
          )}
          {message && (
            <span role={message.tone === "bad" ? "alert" : "status"} style={{ color: toneColor[message.tone] }}>
              {message.text}
            </span>
          )}
        </div>
        <p className="fact-line" style={{ margin: "10px 0 0" }}>
          Use https. Wildcards, paths and plain http (except localhost) are refused. At most {v.max_origins} addresses.
        </p>
        {v.updated_by && v.updated_at && (
          <div className="fact-line" style={{ marginTop: 6 }}>
            Last changed by {v.updated_by} on {fmtDateTime(v.updated_at)}.
          </div>
        )}
      </section>
    </div>
  );
}
