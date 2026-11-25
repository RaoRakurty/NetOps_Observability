// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// OpenSearch Dashboards embed — power-user view for ad-hoc search,
// SIEM-style workflows, and index management.
import { PageHeader } from "../components/kit";

export default function SearchDashboardsTab() {
  return (
    <div className="iframe-wrap">
      <PageHeader icon="search" title="Search Dashboards" />
      <iframe title="OpenSearch Dashboards" src="/search/" />
    </div>
  );
}
