// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useState } from "react";
import { api, getActiveScope } from "../services/api";
import { isAllTenantsView, tenantNames, type TenantNames } from "../lib/tenantOwner";

// useTenantView — what an inventory page needs to label rows by tenant
// (tracker 365): the caller's tenant names, the selected scope, and whether
// this is the "All tenants" view (cross-tenant, no scope selected), where a
// Tenant column is shown and changes to another tenant's row name that tenant.
export type TenantView = {
  names: TenantNames;
  activeScope: string;
  allTenants: boolean;
};

export function useTenantView(): TenantView {
  const [names, setNames] = useState<TenantNames>({});
  const [cross, setCross] = useState(false);
  const [activeScope, setActiveScope] = useState<string>(getActiveScope());

  useEffect(() => {
    let dead = false;
    api
      .myScopes()
      .then((r) => {
        if (dead) return;
        setNames(tenantNames(r.scopes));
        setCross(!!r.all_tenants);
      })
      // Not fatal: without names the column shows ids, and without the cross
      // flag it is hidden — the server still scopes every row.
      .catch(() => undefined);
    return () => {
      dead = true;
    };
  }, []);

  useEffect(() => {
    const sync = () => setActiveScope(getActiveScope());
    window.addEventListener("storage", sync);
    window.addEventListener("netops:scope", sync as EventListener);
    return () => {
      window.removeEventListener("storage", sync);
      window.removeEventListener("netops:scope", sync as EventListener);
    };
  }, []);

  return { names, activeScope, allTenants: isAllTenantsView(cross, activeScope) };
}
