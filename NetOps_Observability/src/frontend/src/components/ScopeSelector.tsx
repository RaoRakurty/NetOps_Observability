// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useMemo, useRef, useState } from "react";
import { api, ScopeDetail, getActiveScope, setActiveScope } from "../services/api";
import Icon from "./Icon";
import { PROVIDER_TENANT } from "../lib/tenantOwner";

/** The cross-tenant view's name (tracker 365: it was "All organizations"). */
export const ALL_TENANTS_LABEL = "All tenants";

// ScopeSelector — the Global top-bar Org | Region | Tenant context control.
//
// It lists the scopes the signed-in principal may act in (from /api/scopes,
// which is bindings-derived and server-enforced). Choosing one narrows the whole
// app to that tenant (the selection rides on every API call as X-Acting-Tenant;
// the backend only ever narrows to a bound scope, never widens). The platform
// owner additionally gets an "All tenants" (cross-tenant) option.
//
// Tracker 365: "Provider" (the Global tenant, id "global") is an ordinary
// entry and NARROWS to the platform's own data. It used to mean cross-tenant,
// so an operator who picked Provider saw every tenant's integrations
// unlabelled and deleted another tenant's. "All tenants" (no scope) is now the
// only cross view, and the pages it opens label every row with its tenant.
//
// This is also the landing control: a single-tenant user sees a static chip; a
// multi-scope user lands in their last-used scope (persisted) and switches here.
export default function ScopeSelector() {
  const [scopes, setScopes] = useState<ScopeDetail[]>([]);
  const [allTenants, setAllTenants] = useState(false);
  const [active, setActive] = useState<string>(getActiveScope());
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    api.myScopes().then((r) => {
      setScopes(r.scopes);
      setAllTenants(r.all_tenants);
      // Validate the persisted scope is still reachable; if not, fall back —
      // and ANNOUNCE the fallback so TenantGate re-locks in-tab (it listens on
      // netops:scope; silently clearing localStorage would leave an already-
      // unlocked gate open on the merged view).
      const cur = getActiveScope();
      if (cur && !r.scopes.some((s) => s.tenant_id === cur)) {
        setActiveScope("");
        setActive("");
        window.dispatchEvent(new CustomEvent("netops:scope", { detail: "" }));
      }
    }).catch(() => { /* not fatal — selector just stays empty */ });
  }, []);

  // Follow scope changes made elsewhere in the shell — TenantGate's pick
  // dispatches netops:scope (same-tab, no reload), other tabs arrive via
  // storage. Without this the label freezes on "All tenants" while every
  // page renders one tenant's data. Same pattern as TenantGate's sync effect.
  useEffect(() => {
    const sync = () => setActive(getActiveScope());
    window.addEventListener("storage", sync);
    window.addEventListener("netops:scope", sync as EventListener);
    return () => {
      window.removeEventListener("storage", sync);
      window.removeEventListener("netops:scope", sync as EventListener);
    };
  }, []);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  // Group tenants under their org for the menu.
  const byOrg = useMemo(() => {
    const m = new Map<string, { name: string; tenants: ScopeDetail[] }>();
    for (const s of scopes) {
      if (!m.has(s.org_id)) m.set(s.org_id, { name: s.org_name, tenants: [] });
      m.get(s.org_id)!.tenants.push(s);
    }
    return [...m.entries()].sort((a, b) => a[1].name.localeCompare(b[1].name));
  }, [scopes]);

  const current = scopes.find((s) => s.tenant_id === active);
  // The platform owner DOES get this control (owner 2026-07-21, reversing the
  // earlier "no view-as-tenant" stance). Telemetry sections are now gated behind
  // TenantGate — an admin must open one tenant at a time — so the top bar has to
  // show which door is open and offer a one-click switch. Without it the only
  // way back out of a tenant would be clearing local storage.
  // "All tenants" here means the ESTATE view (tenant list, platform config,
  // and the inventory pages that label each row by tenant), not a merged
  // telemetry dump: picking it re-locks the telemetry sections.
  const switchable = scopes.length > 1 || allTenants;

  const pick = (tenantId: string) => {
    setActiveScope(tenantId);
    setActive(tenantId);
    setOpen(false);
    // Re-fetch the whole app under the new scope. A hard reload is the simplest
    // correct way to re-scope every section + websocket at once.
    window.location.reload();
  };

  const label = active && current
    ? `${current.org_name} · ${current.tenant_name}`
    : allTenants ? ALL_TENANTS_LABEL : current ? current.tenant_name : (scopes[0]?.tenant_name ?? "—");
  const region = current?.region || (allTenants ? "all" : scopes[0]?.region);

  if (!switchable) {
    // Single fixed scope: show it as a non-interactive context chip.
    return (
      <span className="scope-chip" title="Your organization and tenant">
        <Icon name="infrastructure" size={13} />
        <span className="scope-chip-text">{label}</span>
        {region && region !== "all" && <span className="scope-region">{region}</span>}
      </span>
    );
  }

  return (
    <div
      className="scope-sel"
      ref={ref}
      onKeyDown={(e) => {
        if (e.key === "Escape" && open) {
          setOpen(false);
          (ref.current?.querySelector(".scope-btn") as HTMLElement | null)?.focus();
        }
      }}
    >
      <button
        className="scope-btn"
        onClick={() => setOpen((o) => !o)}
        title="Switch organization / tenant"
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <Icon name="infrastructure" size={13} />
        <span className="scope-btn-text">{label}</span>
        {region && region !== "all" && <span className="scope-region">{region}</span>}
        <span style={{ opacity: 0.6, fontSize: 10 }} aria-hidden="true">▾</span>
      </button>
      {open && (
        <div className="scope-pop">
          {allTenants && (
            <button className={`scope-opt${!active ? " on" : ""}`} aria-current={!active ? "true" : undefined} onClick={() => pick("")}>
              <span className="scope-opt-title">{ALL_TENANTS_LABEL}</span>
              <span className="scope-opt-sub">Every tenant, each row labelled with its tenant</span>
            </button>
          )}
          {byOrg.map(([orgId, og]) => (
            <div key={orgId} className="scope-group">
              <div className="scope-group-head">{og.name}</div>
              {og.tenants.map((t) => (
                <button key={t.tenant_id} className={`scope-opt${active === t.tenant_id ? " on" : ""}`} aria-current={active === t.tenant_id ? "true" : undefined} onClick={() => pick(t.tenant_id)}>
                  <span className="scope-opt-title">{t.tenant_name}</span>
                  <span className="scope-opt-sub">
                    {t.tenant_id === PROVIDER_TENANT ? "Your own (platform) data only" : t.region}
                  </span>
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
