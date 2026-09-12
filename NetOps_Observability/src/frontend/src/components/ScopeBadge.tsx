// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useState } from "react";
import { api, AuthUser } from "../services/api";

// ScopeBadge — states plainly WHO the signed-in principal is acting as: the
// platform operator (Global, reaches every tenant) or a member of exactly one
// tenant. Shown in the Administration header + the account menus so scope is
// never ambiguous. Names resolve via /api/scopes (display names — raw opaque
// t_/org_ ids are never surfaced, per the customer-facing-language rule).
export default function ScopeBadge({ user }: { user: AuthUser }) {
  const [tenantName, setTenantName] = useState<string | null>(null);

  useEffect(() => {
    if (user.platform_admin) return;
    let dead = false;
    api
      .myScopes()
      .then((r) => {
        if (dead) return;
        const own = r.scopes.find((s) => s.tenant_id === user.tenant_id) ?? r.scopes[0];
        setTenantName(own?.tenant_name ?? null);
      })
      .catch(() => {
        /* name lookup is cosmetic — the badge still states the scope kind */
      });
    return () => {
      dead = true;
    };
  }, [user.platform_admin, user.tenant_id]);

  if (user.platform_admin) {
    return (
      <span className="scope-badge scope-badge-global" title="Cross-tenant platform operator — sees and configures every tenant">
        Platform administrator · Global
      </span>
    );
  }
  return (
    <span className="scope-badge" title="Everything you see and configure is scoped to your tenant">
      {tenantName ? `Tenant · ${tenantName}` : "Tenant member"}
    </span>
  );
}
