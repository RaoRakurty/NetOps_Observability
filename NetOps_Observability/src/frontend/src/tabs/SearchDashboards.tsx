// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// OpenSearch Dashboards embed — power-user view for ad-hoc search,
// SIEM-style workflows, and index management.
export default function SearchDashboardsTab() {
  return (
    <div className="iframe-wrap">
      <iframe title="OpenSearch Dashboards" src="/search/" />
    </div>
  );
}
