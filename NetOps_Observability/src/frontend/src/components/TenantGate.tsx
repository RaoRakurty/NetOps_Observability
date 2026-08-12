import { useEffect, useMemo, useState } from "react";
import { api, ScopeDetail, getActiveScope, setActiveScope } from "../services/api";
import Icon from "./Icon";

// TenantGate — the per-tenant entry gate for the platform (cross-tenant) admin.
//
// WHY THIS EXISTS (owner decision 2026-07-21). A platform admin may reach every
// tenant, and the API happily answers cross-tenant — so telemetry pages used to
// render EVERY tenant's rows in one list. Technically isolated (each row is
// tenant-stamped and the storage layer enforces it), but operationally useless:
// ten retailers' interface metrics and logs interleaved in a single table is
// noise, and worse, it invites reading one tenant's incident with another
// tenant's data in view.
//
// The rule we adopt instead: **cross-tenant reach is not cross-tenant display.**
// A platform admin holds the keys to every door but still opens ONE door at a
// time. Telemetry sections stay locked until an Org → Tenant is chosen; the
// choice rides on X-Acting-Tenant, so from that moment every page, query and
// export in the app is that tenant's and only that tenant's.
//
// Scope of the gate:
//   • non-cross-tenant principals  → never gated (they are already one tenant)
//   • platform admin WITH a scope  → not gated (door open, badge shows which)
//   • platform admin, no scope, telemetry section → gate
//   • platform sections (the estate itself: Administration, Iris) → never gated,
//     that is where you manage tenants and pick which one to open.
//
// Deliberately NOT an "All tenants" escape hatch on telemetry: an aggregate view
// is a real feature, but it must be a purpose-built cross-tenant rollup (counts
// and health per tenant), not a merged row dump. Merging is what we are fixing.

/** Sections that describe the PLATFORM or the tenant estate, not one tenant's
 *  telemetry. Everything not listed here is treated as tenant data and gated —
 *  a new section is gated by default, which is the safe direction. The 2026-08
 *  redesign sections (overview · operations · investigate · infrastructure ·
 *  explore · security · analytics) are ALL tenant data and deliberately absent
 *  from this allowlist. */
const PLATFORM_SECTIONS = new Set(["admin", "copilot"]);

export function isTenantScopedSection(sectionId: string): boolean {
  return !PLATFORM_SECTIONS.has(sectionId);
}

const RECENT_KEY = "netops.recentTenants";
const RECENT_MAX = 4;

function readRecent(): string[] {
  try {
    const raw = JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
    return Array.isArray(raw) ? raw.filter((x) => typeof x === "string").slice(0, RECENT_MAX) : [];
  } catch {
    return [];
  }
}

export function rememberTenant(tenantId: string) {
  if (!tenantId) return;
  try {
    const next = [tenantId, ...readRecent().filter((t) => t !== tenantId)].slice(0, RECENT_MAX);
    localStorage.setItem(RECENT_KEY, JSON.stringify(next));
  } catch {
    /* storage disabled — recents are a convenience, never a requirement */
  }
}

type Props = {
  /** Active nav section id — decides whether this view holds tenant data. */
  sectionId: string;
  /** Human label for the section, used in the gate copy. */
  sectionLabel: string;
  children: React.ReactNode;
};

export default function TenantGate({ sectionId, sectionLabel, children }: Props) {
  const [scopes, setScopes] = useState<ScopeDetail[] | null>(null);
  const [crossTenant, setCrossTenant] = useState(false);
  const [active, setActive] = useState<string>(getActiveScope());
  const [q, setQ] = useState("");

  useEffect(() => {
    let dead = false;
    api
      .myScopes()
      .then((r) => {
        if (dead) return;
        setScopes(r.scopes);
        setCrossTenant(!!r.all_tenants);
      })
      // Fail OPEN on a scopes error: the gate is an organising device, not a
      // security control (the server enforces isolation regardless). Blocking
      // the whole app because one metadata call failed would be worse.
      .catch(() => !dead && setScopes([]));
    return () => {
      dead = true;
    };
  }, []);

  // Keep in step with the top-bar selector, which writes the same key.
  useEffect(() => {
    const sync = () => setActive(getActiveScope());
    window.addEventListener("storage", sync);
    window.addEventListener("netops:scope", sync as EventListener);
    return () => {
      window.removeEventListener("storage", sync);
      window.removeEventListener("netops:scope", sync as EventListener);
    };
  }, []);

  const byOrg = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const m = new Map<string, { name: string; tenants: ScopeDetail[] }>();
    for (const s of scopes ?? []) {
      if (needle && !`${s.tenant_name} ${s.org_name}`.toLowerCase().includes(needle)) continue;
      if (!m.has(s.org_id)) m.set(s.org_id, { name: s.org_name, tenants: [] });
      m.get(s.org_id)!.tenants.push(s);
    }
    return [...m.entries()]
      .map(([id, v]) => ({ id, ...v, tenants: v.tenants.sort((a, b) => a.tenant_name.localeCompare(b.tenant_name)) }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [scopes, q]);

  const recent = useMemo(() => {
    const ids = readRecent();
    return ids.map((id) => (scopes ?? []).find((s) => s.tenant_id === id)).filter(Boolean) as ScopeDetail[];
  }, [scopes]);

  const open = (s: ScopeDetail) => {
    setActiveScope(s.tenant_id);
    rememberTenant(s.tenant_id);
    setActive(s.tenant_id);
    // Tell the rest of the shell (top-bar selector, badges) without a reload.
    window.dispatchEvent(new CustomEvent("netops:scope", { detail: s.tenant_id }));
  };

  // Still resolving scopes — render nothing rather than flashing the gate at a
  // single-tenant user who should never see it.
  if (scopes === null) return null;
  if (!crossTenant || active || !isTenantScopedSection(sectionId)) return <>{children}</>;

  return (
    <div className="tenant-gate" role="region" aria-label={`Select a tenant to view ${sectionLabel}`}>
      <div className="tg-card">
        <div className="tg-lock" aria-hidden="true">
          <Icon name="lock" size={20} />
        </div>
        <h2 className="tg-title">Choose a tenant to open {sectionLabel}</h2>
        <p className="tg-sub">
          You have platform-wide access, so this page could show every tenant at once — but merged
          telemetry is unreadable and easy to misread. Pick one tenant and the whole app follows it
          until you switch.
        </p>

        {recent.length > 0 && !q && (
          <div className="tg-recent">
            <div className="tg-label">Recent</div>
            <div className="tg-chips">
              {recent.map((s) => (
                <button key={s.tenant_id} className="tg-chip" type="button" onClick={() => open(s)}>
                  <span className="tg-chip-t">{s.tenant_name}</span>
                  <span className="tg-chip-o">{s.org_name}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="tg-search">
          <Icon name="search" size={14} />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter organizations and tenants…"
            aria-label="Filter organizations and tenants"
            spellCheck={false}
            autoFocus
          />
        </div>

        <div className="tg-orgs">
          {byOrg.map((org) => (
            <div className="tg-org" key={org.id}>
              <div className="tg-org-head">
                <Icon name="directory" size={13} />
                <span>{org.name}</span>
                <span className="tg-count">{org.tenants.length}</span>
              </div>
              <div className="tg-tenants">
                {org.tenants.map((s) => (
                  <button key={s.tenant_id} className="tg-tenant" type="button" onClick={() => open(s)}>
                    <span className="tg-tenant-name">{s.tenant_name}</span>
                    <span className="tg-tenant-meta">{s.region}</span>
                    <span className="tg-open" aria-hidden="true">
                      <Icon name="chevron-right" size={14} />
                    </span>
                  </button>
                ))}
              </div>
            </div>
          ))}
          {byOrg.length === 0 && <div className="tg-empty">No organization or tenant matches “{q}”.</div>}
        </div>
      </div>
    </div>
  );
}
