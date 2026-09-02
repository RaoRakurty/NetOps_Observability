// DeviceConfigPanel — the "Configuration" tab of the device detail page.
//
// What it gives an operator, in one place: the current drift verdict (four
// honest states, "unknown" when nothing was ever captured), when the last
// capture landed, which version is the golden baseline, a one-click backup,
// the version history, and — per row — the captured text, a unified diff
// against the previous version or against golden, and promotion to golden.
//
// SECURITY (§3 zero trust / §15 LLM02-adjacent). Configuration text is written
// by the DEVICE. It is redacted server-side, but this component still treats it
// as hostile input: every byte of config text and every diff line is rendered
// as an escaped React text node inside <pre>. There is no innerHTML, no
// dangerouslySetInnerHTML and no markup parsing anywhere on this path.
//
// FEATURE FLAG. The backend family is dormant unless FEATURE_CONFIG_BACKUP is
// set. A 404/501 is therefore a PRODUCT state — "not enabled on this
// deployment" — rendered as a calm card, never as an error toast.
//
// PERMISSIONS. Reads need infrastructure:read. Backup and golden need
// infrastructure:write; the client gate is a courtesy only — a server 403 is
// caught and shown inline, because the client is never the authority.

import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  type ConfigDiffResult,
  type ConfigStatus,
  type ConfigText,
  type ConfigVersion,
  type Device,
} from "../../services/api";
import { useWorkspace } from "../../context/workspace";
import { fmtDateTime } from "../../lib/time";
import {
  BACKUP_BUSY_MESSAGE,
  DRIFT_LABEL,
  DRIFT_HELP,
  FEATURE_OFF_HINT,
  FEATURE_OFF_MESSAGE,
  NO_PERMISSION_MESSAGE,
  actionErrorMessage,
  classifyError,
  diffLines,
  driftOf,
  driftTone,
  fmtBytes,
  fmtChurn,
  shortSha,
  statusBadge,
} from "./configModel";

type Notice = { tone: "good" | "bad"; text: string };
type DiffView = { diff: ConfigDiffResult; title: string };

// ── read-only, escaped text blocks ──────────────────────────────────────────

/** One captured configuration, rendered as escaped text with a copy button. */
export function ConfigTextView({ doc }: { doc: ConfigText }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    try {
      void navigator.clipboard?.writeText(doc.text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard unavailable — the text is selectable regardless */
    }
  };
  return (
    <div className="ccw-code">
      <div className="ccw-code-h">
        <span className="mono" title={doc.sha}>
          {shortSha(doc.sha)} · {fmtDateTime(doc.captured_at)} · {fmtBytes(doc.size_bytes)}
          {doc.golden ? " · golden" : ""}
        </span>
        <button type="button" className="btn" onClick={copy} aria-label={`Copy configuration ${shortSha(doc.sha)}`}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      {/* Untrusted device text — escaped React text node, never an HTML sink. */}
      <pre className="ccw-pre" aria-label={`Configuration ${shortSha(doc.sha)}`}><code>{doc.text}</code></pre>
    </div>
  );
}

/** A unified diff, coloured per line from the +/- prefix. Text only. */
export function ConfigDiffView({ diff, title }: { diff: ConfigDiffResult; title: string }) {
  const lines = diffLines(diff.unified);
  return (
    <div className="ccw-code">
      <div className="ccw-code-h">
        <span className="mono">{title}</span>
        <span className="mini-meta">{fmtChurn(diff.added, diff.removed)}</span>
      </div>
      {diff.truncated && (
        <p className="mini-meta cfg-note" role="status">
          This diff was truncated by the server — it shows the beginning of the change only.
          Open the full versions to read the rest.
        </p>
      )}
      {lines.length === 0 ? (
        <p className="mini-meta cfg-note">The two versions are identical — the server returned an empty diff.</p>
      ) : (
        <pre className="ccw-pre cfg-diff" aria-label={title}>
          {lines.map((l, i) => (
            // Untrusted diff text — escaped React text node, coloured by CLASS.
            <div key={i} className={`cfg-diff-line cfg-diff-${l.kind}`}>{l.text}</div>
          ))}
        </pre>
      )}
    </div>
  );
}

// ── the panel ───────────────────────────────────────────────────────────────

export default function DeviceConfigPanel({ device }: { device: Device }) {
  const ws = useWorkspace();
  const [status, setStatus] = useState<ConfigStatus | null>(null);
  const [versions, setVersions] = useState<ConfigVersion[]>([]);
  const [goldenSha, setGoldenSha] = useState<string | null>(null);
  const [off, setOff] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [canWrite, setCanWrite] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [text, setText] = useState<ConfigText | null>(null);
  const [diff, setDiff] = useState<DiffView | null>(null);
  const [confirmSha, setConfirmSha] = useState<string | null>(null);
  const alive = useRef(true);
  const timer = useRef<number | undefined>(undefined);

  const load = useCallback(async () => {
    try {
      const [st, page] = await Promise.all([api.configStatus(device.id), api.configVersions(device.id)]);
      if (!alive.current) return;
      setStatus(st);
      setVersions(Array.isArray(page.items) ? page.items : []);
      setGoldenSha(page.golden_sha ?? null);
      setOff(false);
      setErr(null);
    } catch (e) {
      if (!alive.current) return;
      if (classifyError(e) === "off") {
        setOff(true);
        setErr(null);
      } else {
        setErr(String((e as Error).message ?? e));
      }
    } finally {
      if (alive.current) setLoaded(true);
    }
  }, [device.id]);

  useEffect(() => {
    alive.current = true;
    void load();
    api.permissions()
      .then((p) => { if (alive.current) setCanWrite((p.permissions?.infrastructure ?? 0) >= 2); })
      .catch(() => { if (alive.current) setCanWrite(false); });
    return () => {
      alive.current = false;
      if (timer.current !== undefined) window.clearTimeout(timer.current);
    };
  }, [load]);

  // Opening a version / diff: prefer the docked Inspector when the shell offers
  // one, and ALWAYS keep an inline copy so the content is never hidden.
  const showText = (doc: ConfigText) => {
    setText(doc);
    setDiff(null);
    if (ws.enabled) {
      ws.openInspector(<ConfigTextView doc={doc} />, {
        title: `Configuration ${shortSha(doc.sha)}`,
        subtitle: device.name || device.id,
      });
    }
  };

  const openVersion = async (v: ConfigVersion) => {
    setNotice(null);
    try {
      const doc = await api.configVersion(device.id, v.sha);
      if (alive.current) showText(doc);
    } catch (e) {
      if (alive.current) setNotice({ tone: "bad", text: actionErrorMessage(e) });
    }
  };

  const openDiff = async (from: string, to: string, title: string) => {
    setNotice(null);
    try {
      const d = await api.configDiff(device.id, from, to);
      if (!alive.current) return;
      setText(null);
      setDiff({ diff: d, title });
      if (ws.enabled) ws.openInspector(<ConfigDiffView diff={d} title={title} />, { title, subtitle: device.name || device.id });
    } catch (e) {
      if (alive.current) setNotice({ tone: "bad", text: actionErrorMessage(e) });
    }
  };

  const backup = async () => {
    setBusy(true);
    setNotice(null);
    try {
      const job = await api.configBackup(device.id);
      if (!alive.current) return;
      setNotice({
        tone: "good",
        text: `Backup queued — job ${job.job_id} (${job.status}). The capture appears in the version history once it lands.`,
      });
      timer.current = window.setTimeout(() => { void load(); }, 4000);
    } catch (e) {
      if (!alive.current) return;
      const kind = classifyError(e);
      setNotice({ tone: "bad", text: kind === "busy" ? BACKUP_BUSY_MESSAGE : actionErrorMessage(e) });
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  const promoteGolden = async (sha: string) => {
    setBusy(true);
    setNotice(null);
    try {
      const r = await api.configSetGolden(device.id, sha);
      if (!alive.current) return;
      setGoldenSha(r.golden_sha);
      setConfirmSha(null);
      setNotice({ tone: "good", text: `Golden baseline set to ${shortSha(r.golden_sha)}. Drift is now measured against this version.` });
      await load();
    } catch (e) {
      if (!alive.current) return;
      setNotice({ tone: "bad", text: actionErrorMessage(e) });
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  if (off) {
    return (
      <section className="cfg-panel" aria-label="Configuration">
        <h3 className="cfg-h">Configuration</h3>
        <div className="empty" role="status">
          {FEATURE_OFF_MESSAGE}. {FEATURE_OFF_HINT}
        </div>
      </section>
    );
  }

  if (err) {
    return (
      <section className="cfg-panel" aria-label="Configuration">
        <h3 className="cfg-h">Configuration</h3>
        <div className="empty cfg-bad" role="alert">{err}</div>
      </section>
    );
  }

  if (!loaded) {
    return (
      <section className="cfg-panel" aria-label="Configuration">
        <h3 className="cfg-h">Configuration</h3>
        <div className="empty" role="status">Loading configuration history…</div>
      </section>
    );
  }

  const badge = statusBadge(status);

  return (
    <section className="cfg-panel" aria-label="Configuration">
      <h3 className="cfg-h">Configuration</h3>

      <div className="cfg-summary">
        <span className={`badge ${badge.tone}`} title={badge.help}>{badge.label}</span>
        <span className="mini-meta">
          Last capture {status?.last_capture_at ? fmtDateTime(status.last_capture_at) : "never"}
        </span>
        <span className="mini-meta">
          {goldenSha
            ? <>Golden baseline <span className="mono" title={goldenSha}>★ {shortSha(goldenSha)}</span></>
            : "No golden baseline set — drift cannot be measured yet."}
        </span>
        {status?.next_scheduled_at && (
          <span className="mini-meta">Next scheduled {fmtDateTime(status.next_scheduled_at)}</span>
        )}
        <button
          type="button"
          className="btn"
          onClick={() => { void backup(); }}
          disabled={busy || canWrite === false}
          aria-label={`Back up the configuration of ${device.name || device.id} now`}
        >
          {busy ? "Working…" : "Back up now"}
        </button>
      </div>

      {status?.last_error && (
        <p className="mini-meta cfg-note" role="status">Last capture error: {status.last_error}</p>
      )}
      {canWrite === false && (
        <p className="mini-meta cfg-note" role="status">{NO_PERMISSION_MESSAGE}</p>
      )}
      <p className={`mini-meta cfg-note${notice?.tone === "bad" ? " cfg-bad" : ""}`} role="status" aria-live="polite">
        {notice?.text ?? ""}
      </p>

      {versions.length === 0 ? (
        <div className="empty">
          No configuration has been captured from this device yet. An empty history means nothing was
          collected — not that the configuration is unchanged.
        </div>
      ) : (
        <div className="ds-table-wrap">
          <table className="ds-table" aria-label={`Configuration versions for ${device.name || device.id}`}>
            <thead>
              <tr>
                <th scope="col">Version</th>
                <th scope="col">Captured</th>
                <th scope="col">Size</th>
                <th scope="col">Status</th>
                <th scope="col">Drift</th>
                <th scope="col">Changes</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {versions.map((v, i) => {
                const short = shortSha(v.sha);
                const d = driftOf(v.drift);
                const prev = versions[i + 1];
                const isGolden = v.golden || v.sha === goldenSha;
                return (
                  <tr key={v.sha}>
                    <th scope="row" className="mono cfg-sha" title={v.sha}>
                      {isGolden && <span title="Golden baseline" aria-label="Golden baseline">★ </span>}
                      {short}
                    </th>
                    <td>{fmtDateTime(v.captured_at)}</td>
                    <td>{fmtBytes(v.size_bytes)}</td>
                    <td>
                      {v.status === "ok"
                        ? <span className="badge good">ok</span>
                        : <span className="badge bad" title={v.error || "The capture failed."}>failed</span>}
                    </td>
                    <td><span className={`badge ${driftTone(d)}`} title={DRIFT_HELP[d]}>{DRIFT_LABEL[d]}</span></td>
                    <td className="mono">{fmtChurn(v.added, v.removed)}</td>
                    <td>
                      <div className="cfg-actions">
                        <button
                          type="button" className="btn" aria-label={`View version ${short}`}
                          onClick={() => { void openVersion(v); }}
                        >
                          View
                        </button>
                        {prev && (
                          <button
                            type="button" className="btn"
                            aria-label={`Compare version ${short} with the previous version`}
                            onClick={() => { void openDiff(prev.sha, v.sha, `${shortSha(prev.sha)} → ${short}`); }}
                          >
                            Diff previous
                          </button>
                        )}
                        {goldenSha && goldenSha !== v.sha && (
                          <button
                            type="button" className="btn"
                            aria-label={`Compare version ${short} with the golden baseline`}
                            onClick={() => { void openDiff(goldenSha, v.sha, `golden ${shortSha(goldenSha)} → ${short}`); }}
                          >
                            Diff golden
                          </button>
                        )}
                        {!isGolden && v.status === "ok" && canWrite !== false && (
                          confirmSha === v.sha ? (
                            <>
                              <button
                                type="button" className="btn accent" disabled={busy}
                                aria-label={`Confirm version ${short} as the golden baseline`}
                                onClick={() => { void promoteGolden(v.sha); }}
                              >
                                Confirm
                              </button>
                              <button
                                type="button" className="btn"
                                aria-label={`Cancel setting version ${short} as the golden baseline`}
                                onClick={() => setConfirmSha(null)}
                              >
                                Cancel
                              </button>
                            </>
                          ) : (
                            <button
                              type="button" className="btn"
                              aria-label={`Set version ${short} as the golden baseline`}
                              onClick={() => setConfirmSha(v.sha)}
                            >
                              Set golden
                            </button>
                          )
                        )}
                      </div>
                      {confirmSha === v.sha && (
                        <p className="mini-meta cfg-note" role="status">
                          Promoting {short} makes it the baseline every future capture is measured against.
                        </p>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Inline fallback: when the shell has no docked Inspector the content is
          rendered here instead, so an opened version/diff is never hidden. */}
      {!ws.enabled && diff && <div className="cfg-detail"><ConfigDiffView diff={diff.diff} title={diff.title} /></div>}
      {!ws.enabled && text && <div className="cfg-detail"><ConfigTextView doc={text} /></div>}
    </section>
  );
}
