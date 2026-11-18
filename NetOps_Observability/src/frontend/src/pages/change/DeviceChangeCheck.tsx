// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DeviceChangeCheck — the "Change" tab of the device detail page (Iris change
// assistance, 2026-11-18): take a baseline of the device before a change, and
// compare a fresh read with it afterwards — what came back, what did not,
// which counts changed.
//
// SAFETY. Both actions run read-only show commands through the server's closed
// state battery. Nothing on the device changes; the panel says so. Taking and
// comparing need infrastructure write access (a live device read) — the server
// is the authority, so a 403 is shown inline, never pre-empted.
//
// HONESTY. Every result line is an OBSERVED statement the server built from
// parsed output; a section that could not be read is shown as "Cannot compare",
// never as a loss. A 409 means the device could not be read at all, and its
// reason is shown verbatim. Everything device-authored is an escaped text node.

import { useCallback, useEffect, useState } from "react";
import { api, type Device, type DeviceBaselineDiff, type DeviceBaselineSummary } from "../../services/api";
import { fmtDateTime } from "../../lib/time";

export const NO_PERMISSION = "Taking or comparing a baseline needs infrastructure write access.";
export const NOT_AVAILABLE = "Change baselines are not available here.";
export const NO_BASELINE = "No baseline yet. Take one before the change.";
export const MAX_LABEL = 80;

type Notice = { tone: "good" | "bad"; text: string };

/** The server's own reason from a thrown request error ("409 Conflict: {…}"). */
export function serverReason(e: unknown): { status: number; reason: string } {
  const m = String((e as Error | undefined)?.message ?? e ?? "");
  const status = Number(/^(\d{3})\b/.exec(m)?.[1] ?? 0);
  const body = m.replace(/^\d{3}[^:]*:\s*/, "");
  try {
    const j = JSON.parse(body) as { error?: unknown };
    if (typeof j.error === "string" && j.error.trim() !== "") return { status, reason: j.error };
  } catch {
    /* not JSON: fall through to the raw text */
  }
  return { status, reason: body || "The request failed." };
}

function actionError(e: unknown): string {
  const { status, reason } = serverReason(e);
  if (status === 403) return NO_PERMISSION;
  if (status === 503) return NOT_AVAILABLE;
  if (status === 404) return NO_BASELINE;
  return reason;
}

/** Tone of one result line: a loss or a drop is bad, an unread section muted. */
export function lineTone(line: string): "bad" | "muted" | "" {
  if (line.startsWith("Cannot compare")) return "muted";
  if (/software version/i.test(line)) return ""; // expected after an upgrade
  if (/did not come back|is not in the current read|before the change and is .+ now\.$/i.test(line)) return "bad";
  return "";
}

export default function DeviceChangeCheck({ device }: { device: Device }) {
  const [items, setItems] = useState<DeviceBaselineSummary[] | null>(null);
  const [off, setOff] = useState(false);
  const [label, setLabel] = useState("");
  const [pick, setPick] = useState("");
  const [busy, setBusy] = useState<"" | "take" | "compare">("");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [diff, setDiff] = useState<DeviceBaselineDiff | null>(null);
  const name = device.name || device.id;

  const load = useCallback(async () => {
    try {
      const res = await api.deviceBaselines(device.id);
      setItems(res.items ?? []);
      setOff(false);
    } catch (e) {
      const { status, reason } = serverReason(e);
      if (status === 503 || status === 404) setOff(true);
      else setNotice({ tone: "bad", text: reason });
      setItems([]);
    }
  }, [device.id]);

  useEffect(() => { void load(); }, [load]);

  const take = async () => {
    setBusy("take");
    setNotice(null);
    try {
      const b = await api.deviceBaselineTake(device.id, label.trim());
      setNotice({ tone: "good", text: `Baseline taken at ${fmtDateTime(new Date(b.taken_at).getTime())}.` });
      setLabel("");
      setPick("");
      await load();
    } catch (e) {
      setNotice({ tone: "bad", text: actionError(e) });
    } finally {
      setBusy("");
    }
  };

  const compare = async () => {
    setBusy("compare");
    setNotice(null);
    setDiff(null);
    try {
      setDiff(await api.deviceBaselineCompare(device.id, pick || undefined));
    } catch (e) {
      setNotice({ tone: "bad", text: actionError(e) });
    } finally {
      setBusy("");
    }
  };

  if (off) {
    return (
      <section className="cfg-panel" aria-label="Change check">
        <h3 className="cfg-h">Change check</h3>
        <p className="mini-meta cfg-note">{NOT_AVAILABLE}</p>
      </section>
    );
  }

  const hasBaseline = (items?.length ?? 0) > 0;
  return (
    <section className="cfg-panel chg-panel" aria-label="Change check">
      <h3 className="cfg-h">Change check</h3>
      <p className="mini-meta cfg-note">Read-only show commands only. Nothing on the device changes.</p>

      <ol className="chg-steps">
        <li className="chg-step">
          <span className="chg-step-h">1. Before the change</span>
          <div className="chg-row">
            <label className="chg-field">
              <span>Change ticket (optional)</span>
              <input type="text" value={label} maxLength={MAX_LABEL} placeholder="CHG-1042"
                onChange={(e) => setLabel(e.target.value)} disabled={busy !== ""} />
            </label>
            <button type="button" className="btn accent" data-testid="baseline-take"
              onClick={() => { void take(); }} disabled={busy !== ""} aria-label={`Take a baseline of ${name}`}>
              {busy === "take" ? "Reading…" : "Take baseline"}
            </button>
          </div>
        </li>
        <li className="chg-step">
          <span className="chg-step-h">2. After the change</span>
          <div className="chg-row">
            {hasBaseline && (
              <label className="chg-field">
                <span>Baseline</span>
                <select value={pick} onChange={(e) => setPick(e.target.value)} disabled={busy !== ""}>
                  {items!.map((b, i) => (
                    <option key={b.id} value={i === 0 ? "" : b.id}>
                      {fmtDateTime(new Date(b.taken_at).getTime())}{b.label ? ` · ${b.label}` : ""}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <button type="button" className="btn" data-testid="baseline-compare"
              onClick={() => { void compare(); }} disabled={busy !== "" || !hasBaseline}
              aria-label={`Compare ${name} with its baseline`}>
              {busy === "compare" ? "Reading…" : "Compare with baseline"}
            </button>
          </div>
        </li>
      </ol>

      <p className={`chg-status${notice?.tone === "bad" ? " cfg-bad" : ""}`} role="status" aria-live="polite">
        {notice?.text ?? ""}
      </p>

      {diff && (
        <div className="chg-result" data-testid="baseline-diff">
          <h4 className="cfg-h">Result</h4>
          <ul className="chg-lines">
            {diff.lines.map((l, i) => {
              const tone = lineTone(l);
              return <li key={i} className={tone ? `chg-line chg-${tone}` : "chg-line"}>{l}</li>;
            })}
          </ul>
        </div>
      )}

      <h4 className="cfg-h">Baselines</h4>
      {items !== null && !hasBaseline && <p className="mini-meta chg-empty">No baseline taken yet.</p>}
      {hasBaseline && (
        <table className="chg-table">
          <thead>
            <tr><th>Taken</th><th>Ticket</th><th>By</th><th>Interfaces</th><th>Neighbors</th></tr>
          </thead>
          <tbody>
            {items!.map((b) => (
              <tr key={b.id}>
                <td>{fmtDateTime(new Date(b.taken_at).getTime())}</td>
                <td>{b.label || "—"}</td>
                <td>{b.taken_by}</td>
                <td>{b.interfaces}</td>
                <td>{b.neighbors}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
