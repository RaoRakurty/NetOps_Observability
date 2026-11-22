// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// WanSettings — Administration → Discovery → WAN circuits: the measurement
// policy (anchors, ISP next-hops, the WAN-router name hint, whether ports
// facing a WAN router are offered). Moved off Investigate › Paths on
// 2026-11-22 (owner: settings do not belong on an investigation page); the
// WAN circuits tab links here.

import { useEffect, useRef, useState } from "react";
import { api, WanMeasurementPolicy } from "../services/api";
import { Section } from "./bgp/Section";
import { operatorError } from "../lib/errors";
import AskIris from "../components/AskIris";
import { PanelState, usePanel, type Panel } from "./wanPanel";
import {
  MAX_NEXT_HOPS,
  blankNextHopRow,
  formFromPolicy,
  isDirty,
  policyPatch,
  validateForm,
  type NextHopRow,
  type PolicyForm,
} from "./wanCircuits.model";

const mono = { fontFamily: "var(--font-mono, monospace)" } as const;

// ── 4 · the measurement policy (GET / PUT /api/wan/policy) ──────────────────

function PolicySection({ panel, onRetry, canEdit, onSaved }: {
  panel: Panel<WanMeasurementPolicy>;
  onRetry: () => void;
  canEdit: boolean | null;
  onSaved: () => void;
}) {
  const stored = panel.data;
  const [form, setForm] = useState<PolicyForm | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "good" | "bad"; text: string } | null>(null);

  // The form is seeded from the read ONCE per read. A failed save must leave the
  // operator's text exactly where they left it, so nothing re-seeds on error.
  const seededAt = useRef(0);
  useEffect(() => {
    if (stored && panel.at !== seededAt.current) {
      seededAt.current = panel.at;
      setForm(formFromPolicy(stored));
    }
  }, [stored, panel.at]);

  const problems = form ? validateForm(form) : [];
  const dirty = form ? isDirty(form, stored) : false;
  const editable = canEdit !== false;

  const patch = (over: Partial<PolicyForm>) => setForm((f) => (f ? { ...f, ...over } : f));
  const setRow = (id: string, over: Partial<NextHopRow>) =>
    patch({ nextHops: (form?.nextHops ?? []).map((r) => (r.id === id ? { ...r, ...over } : r)) });

  const save = async () => {
    if (!form) return;
    setBusy(true);
    setMsg(null);
    try {
      await api.setWanPolicy(policyPatch(form));
      setMsg({ tone: "good", text: "Measurement policy saved. The paths and endpoints above were derived again from it." });
      onSaved();
    } catch (e: unknown) {
      setMsg({ tone: "bad", text: operatorError(e, "The measurement policy was not accepted.") });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section
      id="wan-policy" title="Measurement policy" updatedAt={panel.at || null}
      note={<>the only thing stored here<AskIris topic="wan.policy" label="Measurement policy" /></>}
    >
      <PanelState panel={panel} what="the measurement policy" onRetry={onRetry}>
        {form && (
          <div className="dp-form">
            <p className="wan-line">Saving re-derives everything above.</p>

            <label className="dp-field">
              <span>WAN device name pattern</span>
              <input
                className="dp-input mono" style={mono}
                aria-label="WAN device name pattern"
                value={form.pattern} disabled={busy || !editable}
                onChange={(ev) => patch({ pattern: ev.target.value })}
              />
              <span className="wan-line">A device whose name matches is a WAN device.</span>
            </label>

            <label className="dp-check">
              <input
                type="checkbox" checked={form.includeConnected} disabled={busy || !editable}
                onChange={(ev) => patch({ includeConnected: ev.target.checked })}
              />
              Also measure interfaces directly connected to a WAN device
            </label>

            <label className="dp-field">
              <span>Reachability anchors</span>
              <input
                className="dp-input mono" style={mono}
                aria-label="Reachability anchors"
                value={form.anchorsText} disabled={busy || !editable}
                onChange={(ev) => patch({ anchorsText: ev.target.value })}
              />
              <span className="wan-line">The fallback target, comma separated.</span>
            </label>
            {/* The `(i)` sits OUTSIDE the label: a <label> may not carry
                interactive content other than its own control. */}
            <AskIris topic="wan.anchor" label="Reachability anchors" />

            <fieldset className="dp-fieldset" disabled={busy || !editable}>
              <legend>ISP next-hop overrides</legend>
              <p className="wan-line">
                One per device, or per interface with <code style={mono}>device/interface</code>. Up to {MAX_NEXT_HOPS}.
                <AskIris topic="wan.next-hop" label="ISP next-hop" />
              </p>
              <table className="dp-tbl">
                <thead>
                  <tr>
                    <th>Device, or device/interface</th>
                    <th>ISP next-hop</th>
                    <th aria-label="Row actions" />
                  </tr>
                </thead>
                <tbody>
                  {form.nextHops.length === 0 ? (
                    <tr className="dp-row-na">
                      <td colSpan={3}>
                        No ISP next-hop has been declared, so every interface without a
                        neighbor on the wire measures to an anchor.
                      </td>
                    </tr>
                  ) : form.nextHops.map((r, i) => (
                    <tr key={r.id}>
                      <td>
                        <input
                          className="dp-input mono" style={mono}
                          aria-label={`Device or device and interface, override ${i + 1}`}
                          value={r.key} onChange={(ev) => setRow(r.id, { key: ev.target.value })}
                        />
                      </td>
                      <td>
                        <input
                          className="dp-input mono" style={mono}
                          aria-label={`ISP next-hop address, override ${i + 1}`}
                          value={r.target} onChange={(ev) => setRow(r.id, { target: ev.target.value })}
                        />
                      </td>
                      <td>
                        <button
                          type="button" className="btn"
                          aria-label={`Remove override ${i + 1}`}
                          onClick={() => patch({ nextHops: form.nextHops.filter((x) => x.id !== r.id) })}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="dp-actions" style={{ justifyContent: "flex-start" }}>
                <button
                  type="button" className="btn"
                  onClick={() => patch({ nextHops: [...form.nextHops, blankNextHopRow()] })}
                >
                  Add an override
                </button>
              </div>
            </fieldset>

            {problems.length > 0 && (
              <ul className="dp-sub" role="alert" style={{ margin: 0, paddingLeft: 18 }}>
                {problems.map((p) => <li key={p} className="dp-bad-text">{p}</li>)}
              </ul>
            )}

            {msg && <p className={`dp-msg dp-${msg.tone}`} role="status">{msg.text}</p>}

            <p className="wan-line">
              {stored?.updated_by
                ? `Last changed by ${stored.updated_by}${stored.updated_at ? ` on ${new Date(stored.updated_at).toLocaleString()}` : ""}.`
                : "Nobody has changed this policy. These are the defaults."}
            </p>

            {editable ? (
              <div className="dp-actions">
                <button
                  type="button" className="btn"
                  disabled={busy || !dirty}
                  onClick={() => setForm(formFromPolicy(stored))}
                >
                  Undo my changes
                </button>
                <button
                  type="button" className="btn accent"
                  disabled={busy || !dirty || problems.length > 0}
                  onClick={save}
                >
                  {busy ? "Saving…" : "Save policy"}
                </button>
              </div>
            ) : (
              <p className="wan-line">
                Changing the policy needs write access.
                <AskIris topic="wan.policy-readonly" label="Read-only policy" />
              </p>
            )}
          </div>
        )}
      </PanelState>
    </Section>
  );
}

/** The WAN settings section: reads the policy and the caller's write access. */
export default function WanSettings() {
  const [policy, reloadPolicy] = usePanel(
    () => api.wanPolicy(), "The measurement policy could not be read.");
  // Write access to infrastructure is what the PUT needs. Without it the editor
  // explains itself rather than offering a button that 403s.
  const [canEdit, setCanEdit] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    api.permissions()
      .then((p) => { if (live) setCanEdit((p.permissions?.infrastructure ?? 0) >= 2); })
      .catch(() => { if (live) setCanEdit(false); });
    return () => { live = false; };
  }, []);
  return (
    <div className="paths-page" data-testid="wan-settings">
      <PolicySection panel={policy} onRetry={reloadPolicy} canEdit={canEdit} onSaved={reloadPolicy} />
    </div>
  );
}
