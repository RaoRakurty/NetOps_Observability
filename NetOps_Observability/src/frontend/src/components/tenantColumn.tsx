// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import type { Column } from "./DataTable";
import { tenantLabel, type TenantNames } from "../lib/tenantOwner";

// tenantColumn — the "Tenant" column of the All-tenants view (tracker 365).
// A row with no tenant is the Provider's. Sortable and searchable by name, so
// "show me RETAIL's rows" is one keystroke in the table filter.
export function tenantColumn<T>(tenantOf: (row: T) => string | undefined, names: TenantNames): Column<T> {
  return {
    key: "tenant",
    header: "Tenant",
    width: "11%",
    sortable: true,
    text: (row) => tenantLabel(tenantOf(row), names),
    sortValue: (row) => tenantLabel(tenantOf(row), names).toLowerCase(),
    render: (row) => {
      const label = tenantLabel(tenantOf(row), names);
      return (
        <span className="tenant-cell" title={`Owned by ${label}`} style={{ fontSize: 14 }}>
          {label}
        </span>
      );
    },
  };
}
