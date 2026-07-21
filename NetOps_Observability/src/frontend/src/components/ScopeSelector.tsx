import { useEffect, useMemo, useRef, useState } from "react";
import { api, ScopeDetail, getActiveScope, setActiveScope } from "../services/api";
import Icon from "./Icon";

// ScopeSelector — the Global top-bar Org | Region | Tenant context control.
//
// It lists the scopes the signed-in principal may act in (from /api/scopes,
// which is bindings-derived and server-enforced). Choosing one narrows the whole
// app to that tenant (the selection rides on every API call as X-Acting-Tenant;
// the backend only ever narrows to a bound scope, never widens). The platform
// owner additionally gets an "All organizations" (cross-tenant) option.
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
      // Validate the persisted scope is still reachable; if not, fall back.
      const cur = getActiveScope();
      if (cur && !r.scopes.some((s) => s.tenant_id === cur)) {
        setActiveScope("");
        setActive("");
      }
    }).catch(() => { /* not fatal — selector just stays empty */ });
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
  // "All organizations" here means the ESTATE view (tenant list, platform
  // config), not a merged telemetry dump: picking it re-locks the data sections.
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
    : allTenants ? "All organizations" : current ? current.tenant_name : (scopes[0]?.tenant_name ?? "—");
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
              <span className="scope-opt-title">All organizations</span>
              <span className="scope-opt-sub">Estate view — tenant data stays locked</span>
            </button>
          )}
          {byOrg.map(([orgId, og]) => (
            <div key={orgId} className="scope-group">
              <div className="scope-group-head">{og.name}</div>
              {og.tenants.map((t) => (
                <button key={t.tenant_id} className={`scope-opt${active === t.tenant_id ? " on" : ""}`} aria-current={active === t.tenant_id ? "true" : undefined} onClick={() => pick(t.tenant_id)}>
                  <span className="scope-opt-title">{t.tenant_name}</span>
                  <span className="scope-opt-sub">{t.region}</span>
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
