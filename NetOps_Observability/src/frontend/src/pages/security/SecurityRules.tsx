// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useMemo, useState } from "react";
import "./Security.css";
import { api, SecRule } from "../../services/api";
import DataTable, { Column } from "../../components/DataTable";
import { Group } from "../../components/board/panels";
import { fidelityTone, mitreList, rulesPutPayload } from "./model";
import { operatorError } from "../../lib/errors";
import AskIris from "../../components/AskIris";
// WORD SWEEP (2026-09-06, tracker 270): what fidelity means, and what disabling
// a rule costs, are ai/skills/explain/rules.*.md behind the `(i)`.
//
// Rules — the detection / hardening rule inventory, with enable-disable.
//
// The client sends ONLY `{rule_id, enabled}` for the rules that actually
// changed (rulesPutPayload). Family, fidelity, MITRE tags and seam-awareness
// are server-owned facts: echoing them back would let a client assert
// properties it does not own, so they are never in the request body. The PUT is
// admin-gated and audited server-side; a 403 surfaces as an honest message
// rather than a silently reverted toggle.

export default function SecurityRules() {
  const [rules, setRules] = useState<SecRule[]>([]);
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const load = () => {
    let alive = true;
    api.securityRules()
      .then((r) => { if (alive) { setRules(Array.isArray(r) ? r : []); setPending({}); setErr(null); } })
      .catch((e: unknown) => { if (alive) setErr(operatorError(e, "Security rules could not be loaded.")); })
      .finally(() => { if (alive) setLoaded(true); });
    return () => { alive = false; };
  };
  useEffect(load, []);

  const payload = useMemo(() => rulesPutPayload(rules, pending), [rules, pending]);

  const save = async () => {
    if (payload.length === 0) return;
    setBusy(true); setNote(null);
    try {
      const updated = await api.securityRulesUpdate(payload);
      setRules(Array.isArray(updated) ? updated : rules);
      setPending({});
      setNote(`${payload.length} rule${payload.length === 1 ? "" : "s"} updated.`);
      setErr(null);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const enabledOf = (r: SecRule): boolean =>
    Object.prototype.hasOwnProperty.call(pending, r.rule_id) ? pending[r.rule_id] : r.enabled;

  const columns = useMemo<Column<SecRule>[]>(() => [
    {
      key: "enabled", header: "Enabled", width: 90, sortable: true,
      sortValue: (r) => (enabledOf(r) ? 1 : 0), text: (r) => (enabledOf(r) ? "enabled" : "disabled"),
      render: (r) => (
        <label style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          <input
            type="checkbox"
            checked={enabledOf(r)}
            aria-label={`Enable ${r.rule_id}`}
            onChange={(e) => setPending((p) => ({ ...p, [r.rule_id]: e.target.checked }))}
          />
        </label>
      ),
    },
    { key: "rule", header: "Rule", sortable: true, text: (r) => r.rule_id, render: (r) => <span className="sec-mono">{r.rule_id}</span> },
    { key: "family", header: "Family", width: 150, sortable: true, text: (r) => r.family, render: (r) => r.family || "—" },
    {
      key: "fidelity", width: 110, sortable: true, text: (r) => r.fidelity,
      // The definition ("the author's confidence in a match, not the severity of
      // what it finds") is ai/skills/explain/rules.fidelity.md — the `(i)` in the
      // header is where it used to be a paragraph under the table.
      header: <>Fidelity<AskIris topic="rules.fidelity" label="Fidelity" /></>,
      render: (r) => (r.fidelity
        ? <span className={`badge ${fidelityTone(r.fidelity)}`}>{r.fidelity}</span>
        : <span className="sec-unassessed">unrated</span>),
    },
    {
      key: "seam", header: "Seam-aware", width: 110, sortable: true,
      sortValue: (r) => (r.seam_aware ? 1 : 0), text: (r) => (r.seam_aware ? "yes" : "no"),
      render: (r) => (r.seam_aware ? <span className="badge good">seam-aware</span> : <span className="sec-unassessed">no</span>),
    },
    {
      // The wire value is normalized (mitreList) rather than read directly: the
      // field is typed string[] but arrives from an external boundary, and a
      // scalar "T1071" once took this page down entirely. Rendering degrades to
      // "—" instead of throwing.
      key: "mitre", header: "Technique", width: 180, sortable: false,
      text: (r) => mitreList(r).join(" "),
      render: (r) => {
        const techniques = mitreList(r);
        return techniques.length > 0
          ? <span className="sec-chips">{techniques.map((m) => <span key={m} className="sec-chip">{m}</span>)}</span>
          : <span className="sec-unassessed">—</span>;
      },
    },
  ], [pending, rules]);

  return (
    <div className="sec dm-board">
      <Group title="Detection rules" hue="#0ea5e9">
        <div className="sec-toolbar">
          <button className="btn accent" type="button" disabled={payload.length === 0 || busy} onClick={() => { void save(); }}>
            {busy ? "Saving…" : payload.length === 0 ? "No changes" : `Save ${payload.length} change${payload.length === 1 ? "" : "s"}`}
          </button>
          <button className="btn" type="button" disabled={payload.length === 0 || busy} onClick={() => setPending({})}>
            Discard changes
          </button>
          <span className="sec-line" role="status" aria-live="polite">
            {err ? "" : note ?? `${rules.filter((r) => enabledOf(r)).length} of ${rules.length} rules enabled`}
          </span>
        </div>

        {err && <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>}

        {!loaded ? (
          <div className="empty" role="status">Loading…</div>
        ) : rules.length === 0 ? (
          <div className="empty">
            No rules are registered.
            <AskIris topic="rules.disabled" label="a disabled rule" />
          </div>
        ) : (
          <DataTable
            rows={rules}
            columns={columns}
            rowKey={(r) => r.rule_id}
            height={520}
            ariaLabel="Detection rules"
          />
        )}
        <p className="mini-meta" style={{ margin: 0 }}>
          Disabling a rule silences its evidence everywhere.
          <AskIris topic="rules.disabled" label="disabling a rule" />
        </p>
      </Group>
    </div>
  );
}
