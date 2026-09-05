// Registries.tsx — the two operator-authored registries that had no screen:
//
//   /api/services      the SERVICE CATALOG (+ versioned selectors, + bindings)
//   /api/applications  the APPLICATION REGISTRY
//
// THE AUDIT VERDICT THIS SURFACE IMPLEMENTS: expose both and cross-link them; do
// NOT unify. Migration 0015_app_identity.sql adds services.application_id as a
// nullable thin-parent link, but internal/servicecat never selects or writes that
// column and Service carries no such field — the parent link is not wired through
// the store or the API. So the page states, in the operator's words, that the two
// are separate lists today and that a service cannot yet be attached to an
// application. Nothing here invents that link.
//
// Honesty rules:
//   · the catalog needs a relational store; a deployment without one answers 501
//     with its own reason, which is rendered — never a silent empty list;
//   · a service whose latest selector has no usable predicate attributes NOTHING,
//     and the editor says that before and after the save;
//   · DELETE is an ARCHIVE on both registries and every confirm says so;
//   · another tenant's row is simply not there — a cross-tenant id reads as
//     not-found, so this surface only ever shows the caller's own registries.
//
// DELIBERATELY NOT SURFACED: the selector backfill
// (POST /api/services/{id}/selectors/{version}/backfill, svc_backfill.go). Its
// contract is not a button: it demands infrastructure:ADMIN (a strictly higher
// gate than the write permission everything else here needs), REQUIRED from/to
// RFC3339 params bounded by SVC_BACKFILL_MAX_DAYS, and it answers 202 for an
// asynchronous job or 409 when the two process-wide slots are taken — with no
// progress endpoint to follow it. It also reclassifies history, which is an
// intentional, separately audited act. A one-click control could not honour any
// of that, and services/api.ts carries no helper for it, so it is left out
// rather than shipped as a control that lies about what it does.

import { useEffect, useState } from "react";
import type { CSSProperties } from "react";
import { api } from "../../services/api";
import type {
  ApplicationRow, CatalogServiceBinding, CatalogServiceRow, CatalogServiceSelector,
} from "../../services/api";
import { operatorError } from "../../lib/errors";
import { fmtDateTime } from "../../lib/time";
import { EmptyState, EvidenceDrawer } from "./badges";
import { CRITICALITY_ORDER, CRITICALITY_META } from "./catalog";
import { CriticalityBadge } from "./ServiceCatalog";
import {
  BINDING_KINDS, BINDING_KIND_LABELS, EMPTY_SELECTOR_DRAFT, NO_SELECTOR_CONSEQUENCE,
  archivePrompt, describeSpec, ignoredSpecKeys, isStoreUnavailable, latestSelector,
  nextSelectorVersion, parseSelectorDraft, specAttributes, validateBinding,
  validateRegistryName,
} from "./registries";
import type { SelectorDraft } from "./registries";

const TH: CSSProperties = { padding: "4px 8px" };
const HEAD: CSSProperties = { textAlign: "left", color: "var(--fg-muted)" };
const TABLE: CSSProperties = { width: "100%", fontSize: 12, borderCollapse: "collapse" };

// ── what drives what ────────────────────────────────────────────────────────

function RegistryGuide({ onOpenCloudCatalog }: { onOpenCloudCatalog: () => void }) {
  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Which registry drives what{" "}
        <span className="ao-panel-meta">three separate lists · none of them the same thing</span>
      </div>
      <ul style={{ margin: "0 0 8px", paddingLeft: 18, fontSize: 12.5, display: "grid", gap: 6 }}>
        <li>
          <strong>Service catalog</strong> (below) — an operable unit of traffic. Its selector is what
          makes per-service flow totals add up: without a usable one the service is carried with
          nothing attributed to it. Explore &rarr; Flows &rarr; <strong>Services</strong> reads those
          totals, and shows a service with no usable selector as not measured rather than as idle.
        </li>
        <li>
          <strong>Application registry</strong> (below) — the business application and the team
          accountable for it. It names ownership; it does not group traffic.
        </li>
        <li>
          <strong>Cloud business services</strong> — the cloud-side registry behind resource
          assignment and the criticality-aware impact view.{" "}
          <button className="ao-rowaction" onClick={onOpenCloudCatalog}>Open the Catalog view</button>
        </li>
      </ul>
      <p className="ao-muted" style={{ fontSize: 12.5, margin: 0 }}>
        The service catalog and the application registry are separate lists today: a service cannot
        be attached to an application in the product, so treat the shared names as a convention you
        keep, not a link the platform enforces.
      </p>
    </div>
  );
}

// ── service selectors + bindings (the per-service drawer) ───────────────────

function SelectorSection({ service }: { service: CatalogServiceRow }) {
  const [sels, setSels] = useState<CatalogServiceSelector[] | null>(null);
  const [draft, setDraft] = useState<SelectorDraft>(EMPTY_SELECTOR_DRAFT);
  const [err, setErr] = useState("");
  const [saving, setSaving] = useState(false);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    api.catalogServiceSelectors(service.service_id)
      .then((r) => { if (live) setSels(r ?? []); })
      .catch((e) => { if (live) { setSels([]); setErr(operatorError(e, "The grouping rules could not be read.")); } });
    return () => { live = false; };
  }, [service.service_id, nonce]);

  const parsed = parseSelectorDraft(draft);
  const willAttribute = specAttributes(parsed.spec);

  const save = async () => {
    if (parsed.error) { setErr(parsed.error); return; }
    setSaving(true); setErr("");
    try {
      await api.addCatalogServiceSelector(service.service_id, parsed.spec);
      setDraft(EMPTY_SELECTOR_DRAFT);
      setNonce((n) => n + 1);
    } catch (e) {
      setErr(operatorError(e, "The grouping rule was not saved."));
    } finally {
      setSaving(false);
    }
  };

  const rows = sels ?? [];
  const latest = latestSelector(rows);
  const set = (k: keyof SelectorDraft) => (e: { target: { value: string } }) =>
    setDraft((p) => ({ ...p, [k]: e.target.value }));

  return (
    <section>
      <div className="ao-panel-h" style={{ padding: 0 }}>Grouping rule{" "}
        <span className="ao-panel-meta">versioned · a save adds version {nextSelectorVersion(rows)}, it never edits one</span>
      </div>
      <p className="ao-set-d">
        Which traffic belongs to this service. The engine acts on destination ports, destination
        prefixes and protocol numbers; the newest version is the one in force, and earlier versions
        stay on the record so past attribution keeps its meaning.
      </p>
      {latest && !specAttributes(latest.spec) && (
        <p style={{ color: "var(--warn)", fontSize: 12.5, margin: "0 0 8px" }}>{NO_SELECTOR_CONSEQUENCE}</p>
      )}
      {latest && ignoredSpecKeys(latest.spec).length > 0 && (
        <p className="ao-muted" style={{ fontSize: 12.5, margin: "0 0 8px" }}>
          Version {latest.version} also carries {ignoredSpecKeys(latest.spec).join(", ")}, which the
          engine does not act on.
        </p>
      )}
      {sels === null ? (
        <div className="ao-muted" style={{ fontSize: 12 }}>Loading…</div>
      ) : rows.length === 0 ? (
        <div className="ao-muted" style={{ fontSize: 12.5, marginBottom: 8 }}>{NO_SELECTOR_CONSEQUENCE}</div>
      ) : (
        <table className="ao-kv" style={{ ...TABLE, marginBottom: 8 }}>
          <thead>
            <tr style={HEAD}>
              <th style={TH}>Version</th><th style={TH}>Matches</th>
              <th style={TH}>Attributes</th><th style={TH}>In force from</th><th style={TH}>Author</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.version}>
                <td style={TH}>{s.version}{latest && s.version === latest.version ? " · in force" : ""}</td>
                <td style={TH} className="ao-mono">{describeSpec(s.spec) || "—"}</td>
                <td style={TH}>{specAttributes(s.spec) ? "yes" : "nothing"}</td>
                <td style={{ ...TH, whiteSpace: "nowrap" }}>{fmtDateTime(s.effective_from)}</td>
                <td style={TH}>{s.created_by || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div style={{ display: "grid", gap: 8, padding: 10, borderRadius: 6,
        background: "var(--panel-2, rgba(127,127,127,0.06))" }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input className="app-input" style={{ flex: "1 1 150px" }} aria-label="Destination ports"
            placeholder="ports, e.g. 443 8443" value={draft.ports} disabled={saving} onChange={set("ports")} />
          <input className="app-input" style={{ flex: "1 1 180px" }} aria-label="Destination prefixes"
            placeholder="destinations, e.g. 10.0.0.0/8" value={draft.prefixes} disabled={saving} onChange={set("prefixes")} />
          <input className="app-input" style={{ flex: "1 1 130px" }} aria-label="Protocol numbers"
            placeholder="protocols, e.g. 6" value={draft.protocols} disabled={saving} onChange={set("protocols")} />
        </div>
        <div style={{ fontSize: 12.5, color: parsed.error ? "var(--crit)" : "var(--fg-muted)" }}>
          {parsed.error || (willAttribute
            ? `Version ${nextSelectorVersion(rows)} would attribute ${describeSpec(parsed.spec)}.`
            : NO_SELECTOR_CONSEQUENCE)}
        </div>
        {err && <div style={{ color: "var(--crit)", fontSize: 12.5 }}>{err}</div>}
        <div>
          <button className="ao-btn ao-btn--primary" disabled={saving || Boolean(parsed.error) || !willAttribute}
            onClick={() => void save()}>
            {saving ? "Saving…" : `Save version ${nextSelectorVersion(rows)}`}
          </button>
        </div>
      </div>
    </section>
  );
}

function BindingSection({ service }: { service: CatalogServiceRow }) {
  const [rows, setRows] = useState<CatalogServiceBinding[] | null>(null);
  const [kind, setKind] = useState<string>(BINDING_KINDS[0].value);
  const [ref, setRef] = useState("");
  const [err, setErr] = useState("");
  const [saving, setSaving] = useState(false);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    api.catalogServiceBindings(service.service_id)
      .then((r) => { if (live) setRows(r ?? []); })
      .catch((e) => { if (live) { setRows([]); setErr(operatorError(e, "The attachments could not be read.")); } });
    return () => { live = false; };
  }, [service.service_id, nonce]);

  const add = async () => {
    const invalid = validateBinding(kind, ref);
    if (invalid) { setErr(invalid); return; }
    setSaving(true); setErr("");
    try {
      await api.addCatalogServiceBinding(service.service_id, kind, ref.trim());
      setRef("");
      setNonce((n) => n + 1);
    } catch (e) {
      setErr(operatorError(e, "The attachment was not saved."));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (b: CatalogServiceBinding) => {
    setErr("");
    try {
      await api.deleteCatalogServiceBinding(service.service_id, b.binding_id);
      setNonce((n) => n + 1);
    } catch (e) {
      setErr(operatorError(e, "The attachment was not removed."));
    }
  };

  return (
    <section style={{ marginTop: 16 }}>
      <div className="ao-panel-h" style={{ padding: 0 }}>Attachments{" "}
        <span className="ao-panel-meta">probes, paths and seams this service is measured through</span>
      </div>
      <p className="ao-set-d">
        What this service is watched by. An attachment is a reference, not a measurement: removing one
        stops the association, it never deletes the probe or the path it names.
      </p>
      {rows === null ? (
        <div className="ao-muted" style={{ fontSize: 12 }}>Loading…</div>
      ) : rows.length === 0 ? (
        <div className="ao-muted" style={{ fontSize: 12.5, marginBottom: 8 }}>
          Nothing is attached to this service yet.
        </div>
      ) : (
        <table className="ao-kv" style={{ ...TABLE, marginBottom: 8 }}>
          <thead>
            <tr style={HEAD}><th style={TH}>Kind</th><th style={TH}>Reference</th><th style={TH}>Added</th><th style={TH}></th></tr>
          </thead>
          <tbody>
            {rows.map((b) => (
              <tr key={b.binding_id}>
                <td style={TH}>{BINDING_KIND_LABELS[b.kind] ?? b.kind}</td>
                <td style={TH} className="ao-mono">{b.ref}</td>
                <td style={{ ...TH, whiteSpace: "nowrap" }}>{fmtDateTime(b.created_at)}</td>
                <td style={TH}>
                  <button className="ao-rowaction" aria-label={`Remove the attachment ${b.ref}`}
                    onClick={() => void remove(b)}>Remove</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <select className="app-select" aria-label="Attachment kind" value={kind} disabled={saving}
          onChange={(e) => setKind(e.target.value)}>
          {BINDING_KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
        </select>
        <input className="app-input" style={{ flex: "1 1 200px" }} maxLength={256} aria-label="Attachment reference"
          placeholder={BINDING_KINDS.find((k) => k.value === kind)?.hint ?? ""}
          value={ref} disabled={saving} onChange={(e) => setRef(e.target.value)} />
        <button className="ao-btn" disabled={saving || !ref.trim()} onClick={() => void add()}>Attach</button>
      </div>
      {err && <div style={{ color: "var(--crit)", fontSize: 12.5, marginTop: 6 }}>{err}</div>}
    </section>
  );
}

// ── the service catalog panel ───────────────────────────────────────────────

type ServiceDraft = { name: string; criticality: string; description: string };
const EMPTY_SERVICE: ServiceDraft = { name: "", criticality: "normal", description: "" };

function ServiceRegistryPanel({ onOpen }: { onOpen: (s: CatalogServiceRow) => void }) {
  const [rows, setRows] = useState<CatalogServiceRow[] | null>(null);
  const [archived, setArchived] = useState(false);
  const [unavailable, setUnavailable] = useState("");
  const [err, setErr] = useState("");
  const [draft, setDraft] = useState<ServiceDraft>(EMPTY_SERVICE);
  const [open, setOpen] = useState(false);
  const [formErr, setFormErr] = useState("");
  const [saving, setSaving] = useState(false);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    setUnavailable(""); setErr("");
    api.catalogServices(archived)
      .then((r) => { if (live) setRows(r ?? []); })
      .catch((e) => {
        if (!live) return;
        setRows([]);
        const sentence = operatorError(e, "The service catalog could not be read.");
        if (isStoreUnavailable(e)) setUnavailable(sentence); else setErr(sentence);
      });
    return () => { live = false; };
  }, [archived, nonce]);

  const create = async () => {
    const invalid = validateRegistryName(draft.name, "service");
    setFormErr(invalid);
    if (invalid) return;
    setSaving(true);
    try {
      await api.createCatalogService({
        name: draft.name.trim(), criticality: draft.criticality, description: draft.description.trim(),
      });
      setDraft(EMPTY_SERVICE); setOpen(false); setNonce((n) => n + 1);
    } catch (e) {
      setFormErr(operatorError(e, "The service was not created."));
    } finally {
      setSaving(false);
    }
  };

  const archive = async (s: CatalogServiceRow) => {
    if (!window.confirm(archivePrompt("service", s.name))) return;
    setErr("");
    try {
      await api.archiveCatalogService(s.service_id);
      setNonce((n) => n + 1);
    } catch (e) {
      setErr(operatorError(e, "The service was not archived."));
    }
  };

  const set = (k: keyof ServiceDraft) => (e: { target: { value: string } }) =>
    setDraft((p) => ({ ...p, [k]: e.target.value }));
  const list = rows ?? [];

  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Service catalog{" "}
        <span className="ao-panel-meta">operator-authored · a selector here is what attributes traffic</span>
        <span style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          <label style={{ fontSize: 12 }} className="ao-muted">
            <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} />{" "}
            Include archived
          </label>
          <button className="ao-btn ao-btn--primary" disabled={Boolean(unavailable)}
            onClick={() => { setFormErr(""); setOpen((o) => !o); }}>
            {open ? "Cancel" : "New service"}
          </button>
        </span>
      </div>

      {unavailable ? (
        <EmptyState title="The service catalog is not available on this deployment" hint={unavailable} />
      ) : (
        <>
          {err && <div style={{ color: "var(--crit)", fontSize: 12.5, marginBottom: 8 }}>{err}</div>}
          {open && (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 10,
              padding: 10, borderRadius: 6, background: "var(--panel-2, rgba(127,127,127,0.06))" }}>
              <input className="app-input" style={{ flex: "1 1 180px" }} maxLength={120} aria-label="Service name"
                placeholder="service name, e.g. payments" value={draft.name} disabled={saving} onChange={set("name")} />
              <select className="app-select" aria-label="Service criticality" value={draft.criticality}
                disabled={saving} onChange={set("criticality")}>
                {CRITICALITY_ORDER.map((c) => <option key={c} value={c}>{CRITICALITY_META[c].label}</option>)}
              </select>
              <input className="app-input" style={{ flex: "1 1 220px" }} maxLength={512} aria-label="Service description"
                placeholder="what this service is, for the next operator" value={draft.description}
                disabled={saving} onChange={set("description")} />
              <button className="ao-btn ao-btn--primary" disabled={saving} onClick={() => void create()}>
                {saving ? "Saving…" : "Create service"}
              </button>
              {formErr && <div style={{ color: "var(--crit)", fontSize: 12.5, flexBasis: "100%" }}>{formErr}</div>}
            </div>
          )}
          {rows === null ? (
            <div className="ao-muted" style={{ fontSize: 12 }}>Loading…</div>
          ) : list.length === 0 ? (
            <EmptyState title="No services defined yet"
              hint="a service groups the traffic your team operates as one unit; its grouping rule is what makes per-service flow totals add up" />
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table className="ao-kv" style={TABLE}>
                <thead>
                  <tr style={HEAD}>
                    <th style={TH}>Service</th><th style={TH}>Criticality</th><th style={TH}>Description</th>
                    <th style={TH}>State</th><th style={TH}>Defined</th><th style={TH}></th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((s) => (
                    <tr key={s.service_id}>
                      <td style={TH}><strong>{s.name}</strong></td>
                      <td style={TH}><CriticalityBadge value={s.criticality} /></td>
                      <td style={TH}>{s.description || <span className="ao-muted">—</span>}</td>
                      <td style={TH}>{s.archived_at
                        ? <span className="ao-muted">archived {fmtDateTime(s.archived_at)}</span>
                        : "active"}</td>
                      <td style={{ ...TH, whiteSpace: "nowrap" }}>{fmtDateTime(s.created_at)}</td>
                      <td style={TH}>
                        <span className="ao-cta-btns">
                          <button className="ao-rowaction" aria-label={`Open ${s.name}`}
                            onClick={() => onOpen(s)}>Grouping &amp; attachments</button>
                          {!s.archived_at && (
                            <button className="ao-rowaction" aria-label={`Archive ${s.name}`}
                              onClick={() => void archive(s)}>Archive</button>
                          )}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── the application registry panel ──────────────────────────────────────────

type AppDraft = { name: string; owner_team: string; criticality: string; description: string };
const EMPTY_APP: AppDraft = { name: "", owner_team: "", criticality: "normal", description: "" };

function ApplicationRegistryPanel() {
  const [rows, setRows] = useState<ApplicationRow[] | null>(null);
  const [archived, setArchived] = useState(false);
  const [err, setErr] = useState("");
  const [draft, setDraft] = useState<AppDraft>(EMPTY_APP);
  const [open, setOpen] = useState(false);
  const [formErr, setFormErr] = useState("");
  const [saving, setSaving] = useState(false);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    setErr("");
    api.applications(archived)
      .then((r) => { if (live) setRows(r ?? []); })
      .catch((e) => { if (live) { setRows([]); setErr(operatorError(e, "The application registry could not be read.")); } });
    return () => { live = false; };
  }, [archived, nonce]);

  const create = async () => {
    const invalid = validateRegistryName(draft.name, "application");
    setFormErr(invalid);
    if (invalid) return;
    setSaving(true);
    try {
      await api.createApplication({
        name: draft.name.trim(), owner_team: draft.owner_team.trim(),
        criticality: draft.criticality, description: draft.description.trim(),
      });
      setDraft(EMPTY_APP); setOpen(false); setNonce((n) => n + 1);
    } catch (e) {
      setFormErr(operatorError(e, "The application was not created."));
    } finally {
      setSaving(false);
    }
  };

  const archive = async (a: ApplicationRow) => {
    if (!window.confirm(archivePrompt("application", a.name))) return;
    setErr("");
    try {
      await api.archiveApplication(a.application_id);
      setNonce((n) => n + 1);
    } catch (e) {
      setErr(operatorError(e, "The application was not archived."));
    }
  };

  const set = (k: keyof AppDraft) => (e: { target: { value: string } }) =>
    setDraft((p) => ({ ...p, [k]: e.target.value }));
  const list = rows ?? [];

  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Application registry{" "}
        <span className="ao-panel-meta">operator-authored · names the application and who owns it</span>
        <span style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          <label style={{ fontSize: 12 }} className="ao-muted">
            <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} />{" "}
            Include archived
          </label>
          <button className="ao-btn ao-btn--primary" onClick={() => { setFormErr(""); setOpen((o) => !o); }}>
            {open ? "Cancel" : "New application"}
          </button>
        </span>
      </div>
      <p className="ao-set-d">
        The applications this tenant runs, and the team answerable for each. This list does not group
        traffic and it is not joined to the service catalog above — the two are kept separately today.
        {err && <span style={{ color: "var(--crit)" }}> · {err}</span>}
      </p>

      {open && (
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 10,
          padding: 10, borderRadius: 6, background: "var(--panel-2, rgba(127,127,127,0.06))" }}>
          <input className="app-input" style={{ flex: "1 1 170px" }} maxLength={120} aria-label="Application name"
            placeholder="application name, e.g. billing" value={draft.name} disabled={saving} onChange={set("name")} />
          <input className="app-input" style={{ flex: "1 1 150px" }} maxLength={120} aria-label="Owner team"
            placeholder="owning team, e.g. payments-sre" value={draft.owner_team} disabled={saving} onChange={set("owner_team")} />
          <select className="app-select" aria-label="Application criticality" value={draft.criticality}
            disabled={saving} onChange={set("criticality")}>
            {CRITICALITY_ORDER.map((c) => <option key={c} value={c}>{CRITICALITY_META[c].label}</option>)}
          </select>
          <input className="app-input" style={{ flex: "1 1 200px" }} maxLength={512} aria-label="Application description"
            placeholder="what this application is, for the next operator" value={draft.description}
            disabled={saving} onChange={set("description")} />
          <button className="ao-btn ao-btn--primary" disabled={saving} onClick={() => void create()}>
            {saving ? "Saving…" : "Create application"}
          </button>
          {formErr && <div style={{ color: "var(--crit)", fontSize: 12.5, flexBasis: "100%" }}>{formErr}</div>}
        </div>
      )}

      {rows === null ? (
        <div className="ao-muted" style={{ fontSize: 12 }}>Loading…</div>
      ) : list.length === 0 ? (
        <EmptyState title="No applications registered yet"
          hint="register the applications your teams own so ownership has a name here rather than living in a spreadsheet" />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="ao-kv" style={TABLE}>
            <thead>
              <tr style={HEAD}>
                <th style={TH}>Application</th><th style={TH}>Owning team</th><th style={TH}>Criticality</th>
                <th style={TH}>Description</th><th style={TH}>State</th><th style={TH}>Registered</th><th style={TH}></th>
              </tr>
            </thead>
            <tbody>
              {list.map((a) => (
                <tr key={a.application_id}>
                  <td style={TH}><strong>{a.name}</strong></td>
                  <td style={TH}>{a.owner_team || <span className="ao-muted">—</span>}</td>
                  <td style={TH}><CriticalityBadge value={a.criticality} /></td>
                  <td style={TH}>{a.description || <span className="ao-muted">—</span>}</td>
                  <td style={TH}>{a.archived_at
                    ? <span className="ao-muted">archived {fmtDateTime(a.archived_at)}</span>
                    : "active"}</td>
                  <td style={{ ...TH, whiteSpace: "nowrap" }}>{fmtDateTime(a.created_at)}</td>
                  <td style={TH}>
                    {!a.archived_at && (
                      <button className="ao-rowaction" aria-label={`Archive ${a.name}`}
                        onClick={() => void archive(a)}>Archive</button>
                    )}
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

// ── the sub-tab ─────────────────────────────────────────────────────────────

export default function Registries({ onOpenCloudCatalog }: { onOpenCloudCatalog: () => void }) {
  const [sel, setSel] = useState<CatalogServiceRow | null>(null);
  return (
    <div className="ao-stack">
      <RegistryGuide onOpenCloudCatalog={onOpenCloudCatalog} />
      <ServiceRegistryPanel onOpen={setSel} />
      <ApplicationRegistryPanel />
      {sel && (
        <EvidenceDrawer title={`Service · ${sel.name}`}
          subtitle={<span className="ao-muted">grouping rule and attachments</span>}
          onClose={() => setSel(null)}>
          <SelectorSection service={sel} />
          <BindingSection service={sel} />
        </EvidenceDrawer>
      )}
    </div>
  );
}
