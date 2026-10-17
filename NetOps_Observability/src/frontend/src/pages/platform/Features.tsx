// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Features — Platform → Configuration → Features (tracker 348; owner
// 2026-10-05: every feature switchable from the GUI, customers never edit
// .env, env = install defaults only).
//
// GATE. /api/platform/features and /api/platform/restart are
// requirePlatformAdmin: the switches are platform-global, so the page lives in
// the provider-only Platform section (docs/design/ADMIN_IA_2026-09-05.md §1).
//
// HONESTY RULES:
//   · A switch that applies after a restart shows what is RUNNING and what
//     will run after the restart until the restart happens — never a value
//     that is not running.
//   · A switch that reaches into the network (device logins, packet capture,
//     write actions) asks for confirmation before it turns on.
//   · After a restart the page re-reads the server and shows the result it
//     reads, not the result it expected.

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type PlatformFeature, type PlatformFeatures } from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { httpFailure, operatorError } from "../../lib/errors";
import { Modal } from "../../components/ui";
import { groupFeatures, applyLabel, sourceLine, pendingLine, switchValue } from "./featuresModel";

type Load =
  | { kind: "loading" }
  | { kind: "denied" }
  | { kind: "error"; message: string }
  | { kind: "ready"; data: PlatformFeatures };

type Restart = { kind: "idle" } | { kind: "restarting"; since: number } | { kind: "done" } | { kind: "failed"; message: string };

const RESTART_POLL_MS = 3000;
const RESTART_GIVE_UP_MS = 180_000;

export default function Features() {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [busy, setBusy] = useState<string | null>(null);
  const [rowError, setRowError] = useState<{ env: string; message: string } | null>(null);
  const [confirm, setConfirm] = useState<PlatformFeature | null>(null);
  const [restart, setRestart] = useState<Restart>({ kind: "idle" });

  const refresh = useCallback(async () => {
    try {
      const data = await api.platformFeatures();
      setLoad({ kind: "ready", data });
      return data;
    } catch (e) {
      const f = httpFailure(e);
      if (f?.status === 403) setLoad({ kind: "denied" });
      else setLoad({ kind: "error", message: operatorError(e, "Feature settings could not be read.") });
      return null;
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // While restarting: poll until the server answers with nothing pending.
  useEffect(() => {
    if (restart.kind !== "restarting") return;
    const id = setInterval(async () => {
      if (Date.now() - restart.since > RESTART_GIVE_UP_MS) {
        setRestart({ kind: "failed", message: "Correlix has not come back after three minutes. Check Stack Health." });
        return;
      }
      try {
        const data = await api.platformFeatures();
        setLoad({ kind: "ready", data });
        setRestart(data.restart_pending ? { kind: "failed", message: "Correlix restarted, but some settings are still waiting. Restart again or check Stack Health." } : { kind: "done" });
      } catch {
        /* still restarting */
      }
    }, RESTART_POLL_MS);
    return () => clearInterval(id);
  }, [restart]);

  const save = useCallback(
    async (f: PlatformFeature, value: boolean, acknowledged: boolean) => {
      setBusy(f.env);
      setRowError(null);
      try {
        await api.setPlatformFeature(f.env, value, acknowledged ? f.env : undefined);
        await refresh();
      } catch (e) {
        setRowError({ env: f.env, message: operatorError(e, "The change was not saved.") });
      } finally {
        setBusy(null);
      }
    },
    [refresh],
  );

  const onToggle = (f: PlatformFeature) => {
    const next = !switchValue(f);
    if (next && f.risky) {
      setConfirm(f);
      return;
    }
    void save(f, next, false);
  };

  const groups = useMemo(() => (load.kind === "ready" ? groupFeatures(load.data.features) : []), [load]);

  if (load.kind === "loading") return <div className="empty">Loading…</div>;
  if (load.kind === "denied") return <div className="empty">Only the platform administrator can change features.</div>;
  if (load.kind === "error") return <div className="empty" role="alert">{load.message}</div>;
  const { data } = load;

  return (
    <div className="features-page" style={{ fontSize: 14, maxWidth: 1100 }}>
      <h2 style={{ margin: "0 0 4px" }}>Features</h2>
      <ol className="fact-line" style={{ margin: "0 0 16px", paddingLeft: 20, lineHeight: 1.7 }}>
        <li>Turn a feature on or off below. It is saved at once.</li>
        <li>Most features apply at once. Some apply after a restart — they say so.</li>
        <li>When a restart is needed, use the button at the top.</li>
      </ol>

      {data.store_load_error && (
        <div className="cc-panel" role="alert" style={{ padding: "10px 12px", marginBottom: 12, borderColor: "var(--bad)" }}>
          {data.store_load_error}
        </div>
      )}

      {(data.restart_pending || restart.kind !== "idle") && (
        <div className="cc-panel" data-testid="restart-banner" style={{ padding: "12px 14px", marginBottom: 16, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
          {restart.kind === "restarting" ? (
            <span>Restarting Correlix… this page will update when it is back.</span>
          ) : restart.kind === "done" ? (
            <span>Correlix restarted. The new settings are running.</span>
          ) : restart.kind === "failed" ? (
            <span role="alert">{restart.message}</span>
          ) : data.can_restart ? (
            <>
              <span>Some changes apply after a restart. Pages reconnect when Correlix is back, usually within a minute or two.</span>
              <button
                className="btn"
                onClick={async () => {
                  try {
                    await api.restartPlatform();
                    setRestart({ kind: "restarting", since: Date.now() });
                  } catch (e) {
                    setRestart({ kind: "failed", message: operatorError(e, "The restart was not requested.") });
                  }
                }}
              >
                Restart now
              </button>
            </>
          ) : (
            <span>Some changes apply after a restart. Restart the Correlix service from the host to apply them.</span>
          )}
        </div>
      )}

      {groups.map((g) => (
        <section key={g.name} className="cc-panel" style={{ padding: "12px 14px", marginBottom: 14 }}>
          <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>{g.name}</h3>
          <div role="list">
            {g.features.map((f) => {
              const pending = pendingLine(f);
              return (
                <div
                  key={f.env}
                  role="listitem"
                  data-testid={`feature-${f.env}`}
                  style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) auto", gap: 12, padding: "10px 0", borderTop: "1px solid var(--border)" }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 600 }}>
                      {f.label}
                      {f.risky && <span className="chip chip-warn" style={{ marginLeft: 8, fontSize: 12.5 }}>Asks to confirm</span>}
                    </div>
                    <div>{f.help}</div>
                    <div className="fact-line" style={{ marginTop: 2 }}>
                      {applyLabel(f)} · {sourceLine(f, fmtDateTime)}
                    </div>
                    {pending && <div style={{ marginTop: 2, color: "var(--warn)" }}>{pending}</div>}
                    {rowError?.env === f.env && <div role="alert" style={{ marginTop: 2, color: "var(--bad)" }}>{rowError.message}</div>}
                  </div>
                  <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: busy ? "wait" : "pointer" }}>
                    <span>{switchValue(f) ? "On" : "Off"}</span>
                    <input
                      type="checkbox"
                      role="switch"
                      aria-label={f.label}
                      checked={switchValue(f)}
                      disabled={busy !== null || restart.kind === "restarting"}
                      onChange={() => onToggle(f)}
                      style={{ width: 20, height: 20 }}
                    />
                  </label>
                </div>
              );
            })}
          </div>
        </section>
      ))}

      {confirm && (
        <Modal title={`Turn on ${confirm.label}?`} onClose={() => setConfirm(null)}>
          <p style={{ fontSize: 14 }}>{confirm.help}</p>
          <p style={{ fontSize: 14 }}>
            This feature reaches into your network or out of Correlix. Turn it on only if your security policy allows it.
          </p>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <button className="btn-ghost" onClick={() => setConfirm(null)}>Cancel</button>
            <button
              className="btn"
              onClick={() => {
                const f = confirm;
                setConfirm(null);
                void save(f, true, true);
              }}
            >
              Turn on
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}
