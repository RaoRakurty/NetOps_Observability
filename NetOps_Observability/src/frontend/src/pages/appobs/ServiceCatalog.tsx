// Service catalog (Wave 3 #8 / product-review rev #12) — the operator-authored
// registry over /api/cloud/business-services, finally with a UI: list, create,
// edit, delete. Criticality and owner entered here light up the Services join
// and the Overview degraded strip ("2 degraded, 1 business-critical").
//
// House rules: tenant-scoped server-side (the token owns the rows); a deployment
// without the database backend gets the exact reason (501), never a silent
// failure; deleting a service reverts its resource mappings to inference and the
// confirm says so.

import { useEffect, useState } from "react";
import { api } from "../../services/api";
import type { BusinessServiceRow, BusinessServiceInput, ResourceMappingRow } from "../../services/api";
import { Chip } from "../../components/noc";
import DataTable from "../../components/DataTable";
import { EmptyState, EvidenceDrawer } from "./badges";
import { assignErrorMessage } from "./assign";
import { CRITICALITY_META, CRITICALITY_ORDER, criticalityRank, mappingCounts, safeRunbookUrl, validateServiceForm } from "./catalog";
import { fmtDateTime } from "../../lib/time";

export function CriticalityBadge({ value }: { value: string }) {
  const meta = CRITICALITY_META[value];
  if (!meta) return <span className="ao-muted">—</span>;
  return <Chip label={meta.label} tone={meta.tone} />;
}

type FormState = { id: string; name: string; description: string; criticality: string; owner: string; runbook: string };
const EMPTY_FORM: FormState = { id: "", name: "", description: "", criticality: "normal", owner: "", runbook: "" };

function CatalogForm({ initial, busy, error, onSubmit, onClose }: {
  initial: FormState; busy: boolean; error: string;
  onSubmit: (f: FormState) => void; onClose: () => void;
}) {
  const [f, setF] = useState<FormState>(initial);
  const [localErr, setLocalErr] = useState("");
  const editing = f.id !== "";
  const set = (k: keyof FormState) => (e: { target: { value: string } }) =>
    setF((p) => ({ ...p, [k]: e.target.value }));
  const submit = () => {
    const v = validateServiceForm(f);
    setLocalErr(v);
    if (!v) onSubmit(f);
  };
  return (
    <EvidenceDrawer
      title={editing ? `Edit service · ${initial.name}` : "New service"}
      subtitle={<span className="ao-muted">the catalog drives criticality-aware impact on the Overview</span>}
      onClose={onClose}
    >
      <div className="ao-stack" style={{ gap: 12 }}>
        <label className="ccw-field">
          <span className="ccw-label">Service name <span className="ccw-req" aria-hidden="true">*</span></span>
          <input className="ccw-input" type="text" value={f.name} maxLength={128}
            placeholder="e.g. payments" aria-required="true" onChange={set("name")} />
        </label>
        <label className="ccw-field">
          <span className="ccw-label">Criticality</span>
          <select className="app-select" aria-label="Criticality" value={f.criticality} onChange={set("criticality")}>
            {CRITICALITY_ORDER.map((c) => (
              <option key={c} value={c}>{CRITICALITY_META[c].label}</option>
            ))}
          </select>
        </label>
        <label className="ccw-field">
          <span className="ccw-label">Owner</span>
          <input className="ccw-input" type="text" value={f.owner} maxLength={128}
            placeholder="team or person accountable, e.g. payments-sre" onChange={set("owner")} />
        </label>
        <label className="ccw-field">
          <span className="ccw-label">Runbook URL</span>
          <input className="ccw-input" type="url" value={f.runbook} maxLength={512}
            placeholder="https:// link to this service's operational runbook" onChange={set("runbook")} />
        </label>
        <label className="ccw-field">
          <span className="ccw-label">Description</span>
          <input className="ccw-input" type="text" value={f.description} maxLength={512}
            placeholder="what this service is, for the next operator" onChange={set("description")} />
        </label>
        <p className="ccw-hint"><span className="ccw-req" aria-hidden="true">*</span> required field</p>
        {(localErr || error) && (
          <div style={{ color: "var(--crit)", fontSize: 12.5 }}>{localErr || error}</div>
        )}
        <div className="ao-cta-btns">
          <button className="ao-btn ao-btn--primary" onClick={submit} disabled={busy}>
            {busy ? "Saving…" : editing ? "Save changes" : "Create service"}
          </button>
          <button className="ao-btn" onClick={onClose} disabled={busy}>Cancel</button>
        </div>
      </div>
    </EvidenceDrawer>
  );
}

export default function ServiceCatalog() {
  const [services, setServices] = useState<BusinessServiceRow[] | null>(null);
  const [mappings, setMappings] = useState<ResourceMappingRow[]>([]);
  const [loadErr, setLoadErr] = useState("");
  const [form, setForm] = useState<FormState | null>(null);
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState("");
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    setLoadErr("");
    Promise.all([
      api.cloudBusinessServices(),
      // counts are enrichment — a mapping-read failure must not blank the catalog.
      api.cloudResourceMappings().catch(() => ({ resource_mappings: [] as ResourceMappingRow[], count: 0 })),
    ]).then(
      ([s, m]) => { if (live) { setServices(s.business_services ?? []); setMappings(m.resource_mappings ?? []); } },
      (e) => { if (live) { setServices([]); setLoadErr(assignErrorMessage(e)); } },
    );
    return () => { live = false; };
  }, [nonce]);

  const save = async (f: FormState) => {
    setBusy(true);
    setFormErr("");
    const body: BusinessServiceInput = {
      name: f.name.trim(), description: f.description.trim(),
      criticality: f.criticality, owner: f.owner.trim(), runbook_url: f.runbook.trim(),
    };
    try {
      if (f.id) await api.cloudUpdateBusinessService(f.id, body);
      else await api.cloudCreateBusinessService(body);
      setForm(null);
      setNonce((n) => n + 1);
    } catch (e) {
      setFormErr(assignErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (s: BusinessServiceRow, mapped: number) => {
    const extra = mapped
      ? ` ${mapped.toLocaleString()} mapped resource${mapped === 1 ? "" : "s"} revert to automatic inference.`
      : "";
    if (!window.confirm(`Delete the service "${s.name}"?${extra}`)) return;
    try {
      await api.cloudDeleteBusinessService(s.business_service_id);
      setNonce((n) => n + 1);
    } catch (e) {
      setLoadErr(assignErrorMessage(e));
    }
  };

  if (services === null) {
    return <div className="ao-panel"><div className="ao-muted">loading the service catalog…</div></div>;
  }
  if (loadErr && services.length === 0) {
    return <div className="ao-panel"><EmptyState title="The service catalog is unavailable" hint={loadErr} /></div>;
  }

  const counts = mappingCounts(mappings);
  const rows = [...services];

  return (
    <div className="ao-stack">
      <div className="ao-panel">
        <div className="ao-panel-h">Service catalog
          <span className="ao-panel-meta">operator-authored · criticality and owner drive the Overview impact view</span>
          <span style={{ marginLeft: "auto" }}>
            <button className="ao-btn ao-btn--primary" onClick={() => { setFormErr(""); setForm(EMPTY_FORM); }}>
              New service
            </button>
          </span>
        </div>
        {loadErr && <div style={{ color: "var(--crit)", fontSize: 12.5, marginBottom: 8 }}>{loadErr}</div>}
        {rows.length === 0 ? (
          <EmptyState title="No services in the catalog yet"
            hint="name the services your teams run — assignments from the Resources tab and the impact view build on them"
            action={<button className="ao-btn ao-btn--primary" onClick={() => { setFormErr(""); setForm(EMPTY_FORM); }}>Create the first service</button>} />
        ) : (
          <DataTable<BusinessServiceRow> rows={rows} rowKey={(s) => s.business_service_id}
            height={Math.min(520, 56 + rows.length * 34)} ariaLabel="Service catalog"
            initialSort={{ key: "crit", dir: "asc" }}
            columns={[
              { key: "name", header: "Service", width: 200, sortable: true, text: (s) => s.name,
                render: (s) => <strong>{s.name}</strong> },
              { key: "crit", header: "Criticality", width: 175,
                sortValue: (s) => criticalityRank(s.criticality),
                render: (s) => <CriticalityBadge value={s.criticality} /> },
              { key: "owner", header: "Owner", width: 160, sortValue: (s) => s.owner,
                render: (s) => s.owner || <span className="ao-muted">—</span> },
              { key: "runbook", header: "Runbook", width: 80, align: "center",
                sortValue: (s) => (safeRunbookUrl(s.runbook_url) ? 0 : 1),
                render: (s) => {
                  const href = safeRunbookUrl(s.runbook_url);
                  return href
                    ? <a className="ao-console-link" href={href} target="_blank" rel="noopener noreferrer"
                        title={href} onClick={(e) => e.stopPropagation()}>open ↗</a>
                    : <span className="ao-muted">—</span>;
                } },
              { key: "desc", header: "Description", width: 280, sortValue: (s) => s.description,
                render: (s) => s.description
                  ? <span className="ao-why" title={s.description}>{s.description}</span>
                  : <span className="ao-muted">—</span> },
              { key: "mapped", header: "Resources", width: 90, align: "right",
                sortValue: (s) => counts.get(s.business_service_id) ?? 0,
                render: (s) => (counts.get(s.business_service_id) ?? 0).toLocaleString() },
              { key: "updated", header: "Updated", width: 150,
                sortValue: (s) => s.updated_at, render: (s) => fmtDateTime(s.updated_at) },
              { key: "act", header: "", width: 150, render: (s) => (
                <span className="ao-cta-btns">
                  <button className="ao-rowaction" onClick={(e) => {
                    e.stopPropagation();
                    setFormErr("");
                    setForm({ id: s.business_service_id, name: s.name, description: s.description, criticality: s.criticality || "normal", owner: s.owner, runbook: s.runbook_url || "" });
                  }}>Edit</button>
                  <button className="ao-rowaction" onClick={(e) => {
                    e.stopPropagation();
                    void remove(s, counts.get(s.business_service_id) ?? 0);
                  }}>Delete</button>
                </span>
              ) },
            ]} />
        )}
      </div>
      {form && (
        <CatalogForm initial={form} busy={busy} error={formErr}
          onSubmit={save} onClose={() => setForm(null)} />
      )}
    </div>
  );
}
