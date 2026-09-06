// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// AppIdCoverage.tsx — the two Settings cards over the App-ID engine:
//
//   AppIdCoverageCard   GET /api/appid/status   — what the engine can see, and
//                       in which order it trusts it. Read-only; the ORDER is
//                       edited one card up, in Attribution Precedence.
//   AppIdOverridesCard  GET/POST /api/appid/catalog, DELETE /api/appid/catalog/{id}
//                       — this tenant's operator overrides: the highest-
//                       precedence layer of that same order.
//
// House rules followed here:
//   · a count of -1 is UNKNOWN, never zero — see appIdCoverage.readCount. This
//     card exists to say what the engine can see, so a store that did not answer
//     has to say so rather than quietly reading as "this tenant declared none".
//   · the tenant is stamped from the caller's token server-side; the form has no
//     tenant field and the body carries none.
//   · a refused write shows the server's own reason (operatorError), never a
//     silent no-op.
//   · there is NO per-entry history on these rows: the platform audit log
//     records the create/delete request, and the copy says exactly that.

import { useEffect, useState } from "react";
import { api } from "../../services/api";
import type { AppCatalogEntry, AppIdStatus } from "../../services/api";
import { operatorError } from "../../lib/errors";
import { fmtDateTime } from "../../lib/time";
import {
  EMPTY_OVERRIDE_DRAFT, MATCH_KINDS, MATCH_KIND_LABELS, NO_FEEDS_NOTE,
  attributionHints, coverageScopeNote, deleteOverridePrompt, overrideInput,
  precedenceOrigin, precedenceRows, readCount, sortOverrides, unavailableReason,
  validateOverride,
} from "./appIdCoverage";
import type { OverrideDraft } from "./appIdCoverage";

// One coverage number plus what it is. An unknown reading renders as the word,
// dimmed — the reason sits once under the whole block, not on every cell.
function CoverageStat({ label, n, hint }: { label: string; n: number; hint: string }) {
  const r = readCount(n);
  return (
    <div style={{ minWidth: 132 }}>
      <div style={{ fontSize: 20, color: r.known ? "var(--fg)" : "var(--fg-subtle)" }}
        title={hint}>{r.text}</div>
      <div className="ao-muted" style={{ fontSize: 12 }}>{label}</div>
    </div>
  );
}

export function AppIdCoverageCard() {
  const [status, setStatus] = useState<AppIdStatus | null>(null);
  const [busy, setBusy] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    api.appIdStatus()
      .then((s) => { if (live) setStatus(s); })
      .catch((e) => { if (live) setErr(operatorError(e, "The identification coverage could not be read.")); })
      .finally(() => { if (live) setBusy(false); });
    return () => { live = false; };
  }, []);

  const unknownWhy = status ? unavailableReason(status) : null;
  const rows = status ? precedenceRows(status.attribution_precedence ?? []) : [];

  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Identification Coverage{" "}
        <span className="ao-panel-meta">
          {status ? precedenceOrigin(status.precedence_is_default) : "reading"} · read-only
        </span>
      </div>
      <p className="ao-set-d">
        What the engine can draw on when it names the application behind a flow, and the order it
        trusts those sources in. The order itself is set in Attribution Precedence above; this card
        reports it alongside how much each layer actually holds.
        {err && <span style={{ color: "var(--crit)" }}> · {err}</span>}
      </p>

      {busy ? (
        <div className="ao-muted" style={{ fontSize: 12 }}>Loading…</div>
      ) : !status ? null : (
        <>
          <ol style={{ listStyle: "none", margin: "0 0 12px", padding: 0, display: "flex", flexDirection: "column", gap: 4 }}>
            {rows.map((r) => (
              <li key={r.cls} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13,
                padding: "4px 8px", background: "var(--panel-2, rgba(127,127,127,0.06))", borderRadius: 6 }}>
                <span className="ao-muted" style={{ width: 16, textAlign: "right" }}>{r.rank}.</span>
                <span style={{ flex: 1 }}>{r.label}</span>
                {r.isOperator && (
                  <span className="ao-muted" style={{ fontSize: 12 }}>your overrides, below</span>
                )}
              </li>
            ))}
          </ol>

          <div style={{ display: "flex", flexWrap: "wrap", gap: 18, marginBottom: 8 }}>
            <CoverageStat label="Vendor prefixes" n={status.catalog_prefixes}
              hint="IPv4 prefixes loaded from the managed vendor feeds — public data, the same for every tenant" />
            <CoverageStat label="Vendor domains" n={status.catalog_domains}
              hint="domain suffixes loaded from the managed vendor feeds — public data, the same for every tenant" />
            <CoverageStat label="Firewall attributions" n={status.ngfw_attributions}
              hint={attributionHints(status).ngfw} />
            <CoverageStat label="Cloud attributions" n={status.cloud_attributions}
              hint={attributionHints(status).cloud} />
          </div>
          <p className="ao-muted" style={{ fontSize: 12, margin: "0 0 12px" }}>
            {coverageScopeNote(status)}
          </p>

          <div style={{ display: "flex", flexWrap: "wrap", gap: 18 }}>
            <CoverageStat label="Your overrides" n={status.tenant_overrides}
              hint="operator overrides this tenant has declared — prefix and domain rows combined" />
            <CoverageStat label="…as prefixes" n={status.tenant_override_pfx}
              hint="how many of this tenant's overrides match on an IP prefix" />
            <CoverageStat label="…as domains" n={status.tenant_override_dom}
              hint="how many of this tenant's overrides match on a domain suffix" />
          </div>

          {unknownWhy && (
            <p style={{ color: "var(--warn)", fontSize: 12.5, margin: "8px 0 0" }}>{unknownWhy}</p>
          )}
          {!status.feeds_configured && (
            <p className="ao-muted" style={{ fontSize: 12.5, margin: "8px 0 0" }}>{NO_FEEDS_NOTE}</p>
          )}
        </>
      )}
    </div>
  );
}

// ── the override editor ─────────────────────────────────────────────────────

export function AppIdOverridesCard() {
  const [entries, setEntries] = useState<AppCatalogEntry[] | null>(null);
  const [draft, setDraft] = useState<OverrideDraft>(EMPTY_OVERRIDE_DRAFT);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(true);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [formErr, setFormErr] = useState("");
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    setErr(null);
    api.appIdOverrides()
      .then((r) => { if (live) setEntries(r.entries ?? []); })
      .catch((e) => { if (live) { setEntries([]); setErr(operatorError(e, "The override list could not be read.")); } })
      .finally(() => { if (live) setBusy(false); });
    return () => { live = false; };
  }, [nonce]);

  const set = (k: keyof OverrideDraft) => (e: { target: { value: string } }) =>
    setDraft((p) => ({ ...p, [k]: e.target.value }));

  const create = async () => {
    const invalid = validateOverride(draft);
    setFormErr(invalid);
    if (invalid) return;
    setSaving(true);
    try {
      await api.createAppIdOverride(overrideInput(draft));
      setDraft(EMPTY_OVERRIDE_DRAFT);
      setOpen(false);
      setNonce((n) => n + 1);
    } catch (e) {
      setFormErr(operatorError(e, "The override was not saved."));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (e: AppCatalogEntry) => {
    if (!window.confirm(deleteOverridePrompt(e))) return;
    setErr(null);
    try {
      await api.deleteAppIdOverride(e.catalog_id);
      setNonce((n) => n + 1);
    } catch (x) {
      setErr(operatorError(x, "The override was not removed."));
    }
  };

  const rows = sortOverrides(entries ?? []);
  const kindHint = MATCH_KINDS.find((k) => k.value === draft.match_kind)?.hint ?? "";

  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Identification Overrides{" "}
        <span className="ao-panel-meta">operator-curated · outranks every other source</span>
        <span style={{ marginLeft: "auto" }}>
          <button className="ao-btn ao-btn--primary"
            onClick={() => { setFormErr(""); setOpen((o) => !o); }}>
            {open ? "Cancel" : "New override"}
          </button>
        </span>
      </div>
      <p className="ao-set-d">
        Names this tenant declares for itself — an address range, a domain, an AS or a port that the
        vendor feeds get wrong or have never heard of. These sit at the top of the order above, so an
        entry here wins outright. Rows belong to this tenant: they are stamped from your sign-in, and
        no other tenant can read or remove them. Creating and removing an override is recorded in the
        platform audit log; the row itself carries no separate history.
        {err && <span style={{ color: "var(--crit)" }}> · {err}</span>}
      </p>

      {open && (
        <div style={{ display: "grid", gap: 8, margin: "0 0 12px", padding: 10,
          background: "var(--panel-2, rgba(127,127,127,0.06))", borderRadius: 6 }}>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <select className="app-select" aria-label="Match on" value={draft.match_kind}
              disabled={saving} onChange={set("match_kind")}>
              {MATCH_KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
            </select>
            <input className="app-input" style={{ flex: "1 1 200px" }} maxLength={256}
              aria-label="Match value" placeholder={kindHint} value={draft.match_value}
              disabled={saving} onChange={set("match_value")} />
            <input className="app-input" style={{ flex: "1 1 160px" }} maxLength={128}
              aria-label="Application name" placeholder="the name to report, e.g. Microsoft 365"
              value={draft.app_label} disabled={saving} onChange={set("app_label")} />
            <input className="app-input" style={{ width: 120 }} maxLength={8}
              aria-label="Confidence" placeholder="confidence 0–1"
              value={draft.confidence} disabled={saving} onChange={set("confidence")} />
          </div>
          {formErr && <div style={{ color: "var(--crit)", fontSize: 12.5 }}>{formErr}</div>}
          <div style={{ display: "flex", gap: 8 }}>
            <button className="ao-btn ao-btn--primary" disabled={saving} onClick={() => void create()}>
              {saving ? "Saving…" : "Add override"}
            </button>
            <span className="ao-muted" style={{ fontSize: 12, alignSelf: "center" }}>
              Leave confidence empty to take the engine&apos;s own default.
            </span>
          </div>
        </div>
      )}

      {busy ? (
        <div className="ao-muted" style={{ fontSize: 12 }}>Loading…</div>
      ) : rows.length === 0 ? (
        <div className="ao-muted" style={{ fontSize: 12 }}>
          This tenant has declared no overrides — identification falls to the sources listed above.
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="ao-kv" style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ textAlign: "left", color: "var(--fg-muted)" }}>
                <th style={{ padding: "4px 8px" }}>Matches on</th>
                <th style={{ padding: "4px 8px" }}>Value</th>
                <th style={{ padding: "4px 8px" }}>Reported as</th>
                <th style={{ padding: "4px 8px" }}>Confidence</th>
                <th style={{ padding: "4px 8px" }}>Added</th>
                <th style={{ padding: "4px 8px" }}></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.catalog_id}>
                  <td style={{ padding: "4px 8px" }}>{MATCH_KIND_LABELS[e.match_kind] ?? e.match_kind}</td>
                  <td style={{ padding: "4px 8px" }} className="ao-mono">{e.match_value}</td>
                  <td style={{ padding: "4px 8px" }}>{e.app_label}</td>
                  <td style={{ padding: "4px 8px" }}>{e.confidence}</td>
                  <td style={{ padding: "4px 8px", whiteSpace: "nowrap" }}>{fmtDateTime(e.created_at)}</td>
                  <td style={{ padding: "4px 8px" }}>
                    <button className="ao-rowaction" aria-label={`Remove the override for ${e.match_value}`}
                      onClick={() => void remove(e)}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
