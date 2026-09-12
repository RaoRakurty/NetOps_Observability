// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// App Observability — Assign-to-service drawer (2026-07 review, imp #5).
//
// The in-product close of the attribution loop: pick an existing business
// service or type a new name, and the selected resources get an operator-
// authoritative manual mapping (PUT /api/cloud/resource-mappings — confirmed,
// source=Operator, wins over tag/graph inference via the backend overlay).
// Until now this API had zero UI consumers and the untagged queue dead-ended
// at "go tag it in the provider console".
//
// Honesty rules as everywhere: a deployment without the database backend gets
// the exact reason (501 → "needs the platform database backend"), never a
// silent failure; the resources list refreshes from the server after a write
// (invalidateCloudInventory) so the page shows the stored truth, not an
// optimistic guess.

import { useEffect, useState } from "react";
import { api, BusinessServiceRow } from "../../services/api";
import { EmptyState, EvidenceDrawer } from "./badges";
import { buildAssignRequest, assignErrorMessage, ASSIGN_MAX_RESOURCES } from "./assign";
import { invalidateCloudInventory } from "./api";

export default function AssignServiceDrawer({ resourceIds, onClose, onAssigned }: {
  /** The resources to bind (bulk selection or a single row's id). */
  resourceIds: string[];
  onClose: () => void;
  /** Called after a successful write — the caller reloads its live data. */
  onAssigned: (assigned: number, serviceLabel: string) => void;
}) {
  const [services, setServices] = useState<BusinessServiceRow[] | null>(null);
  const [svcError, setSvcError] = useState<string>("");
  const [picked, setPicked] = useState<string>("");   // business_service_id, "" = free text
  const [newName, setNewName] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    let live = true;
    api.cloudBusinessServices().then(
      (r) => { if (live) setServices(r.business_services ?? []); },
      (e) => {
        if (!live) return;
        // A 501 (file backend) still allows nothing — say so instead of an
        // empty picker that looks broken.
        setServices([]);
        setSvcError(assignErrorMessage(e));
      },
    );
    return () => { live = false; };
  }, []);

  const submit = async () => {
    setError("");
    const req = buildAssignRequest(resourceIds, picked
      ? { businessServiceId: picked }
      : { serviceName: newName });
    if (!req.ok) { setError(req.error); return; }
    setBusy(true);
    try {
      const r = await api.cloudAssignResources(req.body);
      invalidateCloudInventory(); // the next read must see the stored truth
      const label = picked
        ? (services ?? []).find((s) => s.business_service_id === picked)?.name ?? "service"
        : newName.trim();
      onAssigned(r.assigned, label);
    } catch (e) {
      setError(assignErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const n = resourceIds.length;
  return (
    <EvidenceDrawer
      title={`Assign to service · ${n.toLocaleString()} resource${n === 1 ? "" : "s"}`}
      subtitle={<span className="ao-muted">operator assignment — confirmed, wins over tag / graph inference</span>}
      onClose={onClose}
    >
      {svcError ? (
        <EmptyState title="Service assignment is unavailable" hint={svcError} />
      ) : (
        <>
          <div className="ao-ev-h">Existing service</div>
          {services === null ? (
            <div className="ao-muted">loading services…</div>
          ) : services.length === 0 ? (
            <div className="ao-muted">no named services yet — create one below</div>
          ) : (
            <select
              className="ao-select"
              aria-label="Existing service"
              value={picked}
              onChange={(e) => { setPicked(e.target.value); if (e.target.value) setNewName(""); }}
            >
              <option value="">— pick a service —</option>
              {services.map((s) => (
                <option key={s.business_service_id} value={s.business_service_id}>
                  {s.name}{s.criticality ? ` · ${s.criticality}` : ""}
                </option>
              ))}
            </select>
          )}

          <div className="ao-ev-h">Or a new service name</div>
          <input
            className="ao-select"
            type="text"
            aria-label="New service name"
            placeholder="e.g. payments"
            maxLength={128}
            value={newName}
            onChange={(e) => { setNewName(e.target.value); if (e.target.value) setPicked(""); }}
            disabled={!!picked}
          />

          {n > ASSIGN_MAX_RESOURCES && (
            <div className="ao-muted" style={{ marginTop: 8 }}>
              at most {ASSIGN_MAX_RESOURCES.toLocaleString()} resources per assignment — narrow the selection
            </div>
          )}
          {error && <div style={{ color: "var(--crit)", marginTop: 8, fontSize: 12.5 }}>{error}</div>}

          <div className="ao-cta-btns" style={{ marginTop: 14 }}>
            <button className="ao-btn ao-btn--primary" onClick={submit}
              disabled={busy || svcError !== "" || (!picked && !newName.trim())}>
              {busy ? "Assigning…" : "Assign"}
            </button>
            <button className="ao-btn" onClick={onClose} disabled={busy}>Cancel</button>
          </div>
        </>
      )}
    </EvidenceDrawer>
  );
}
