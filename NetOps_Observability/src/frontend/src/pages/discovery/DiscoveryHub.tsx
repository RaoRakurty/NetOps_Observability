// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DiscoveryHub — Administration → Discovery: everything that makes devices
// and their data appear, in the order an operator sets it up (owner,
// 2026-10-18: merge Collection Coverage, SNMP Profiles, Telemetry Coverage,
// Subnet discovery — now "Network Scan" — and Sensors into one place).
//
//   1. SNMP Profiles      — the credentials scans and pollers use
//   2. Network Scan       — find devices on address ranges
//   3. Sensors            — which collectors run (platform administrator only)
//   4. Collection Coverage — what each device is being collected for
//   5. Telemetry Coverage — what the parsers recognize
//
// Each section is the page it replaces, unchanged, mounted only while open.
// Deep links: #/admin/discovery/<section>; the old leaves' routes are aliases
// to these (nav.tsx LEGACY_ROUTE_ALIAS). A bare #/admin/discovery opens
// Network Scan, so a bookmark of the old Subnet Discovery leaf keeps its
// meaning.
//
// TENANT ISOLATION (UI half). Sensors and its switches are platform-global
// (requireCrossTenant / requirePlatformAdmin): for anyone else the section is
// neither rendered nor fetched. The server gates are unchanged and remain the
// real boundary.

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "../../hooks/useAuth";
import AdminPageHeader from "../../components/admin/AdminPageHeader";
import AdminSection from "../../components/admin/AdminSection";
import ErrorBoundary from "../../components/ErrorBoundary";
import SnmpProfileManager from "../../tabs/SnmpProfileManager";
import SubnetDiscovery from "../SubnetDiscovery";
import Collectors from "../../tabs/Collectors";
import DataSources from "../DataSources";
import TelemetryCoverage from "../telemetry/TelemetryCoverage";

export type DiscoverySection = { id: string; title: string; summary: string; platformOnly?: boolean };

export const DISCOVERY_SECTIONS: DiscoverySection[] = [
  { id: "snmp", title: "SNMP Profiles", summary: "Credentials for scans and polling" },
  { id: "scan", title: "Network Scan", summary: "Find devices on address ranges" },
  { id: "sensors", title: "Sensors", summary: "Which collectors run", platformOnly: true },
  { id: "coverage", title: "Collection Coverage", summary: "What each device is collected for" },
  { id: "telemetry", title: "Telemetry Coverage", summary: "What the parsers recognize" },
];

/** Sections this viewer may see, in setup order. */
export function visibleSections(platformAdmin: boolean): DiscoverySection[] {
  return DISCOVERY_SECTIONS.filter((s) => platformAdmin || !s.platformOnly);
}

/** The section a route opens: #/admin/discovery/<id>; bare → Network Scan. */
export function sectionFromHash(hash: string, platformAdmin: boolean): string {
  const seg = hash.replace(/^#\/?/, "").split("?")[0].split("/")[2] ?? "";
  return visibleSections(platformAdmin).some((s) => s.id === seg) ? seg : "scan";
}

function render(id: string) {
  switch (id) {
    case "snmp": return <SnmpProfileManager />;
    case "scan": return <SubnetDiscovery />;
    case "sensors": return <Collectors />;
    case "coverage": return <DataSources />;
    case "telemetry": return <TelemetryCoverage />;
  }
  return null;
}

export default function DiscoveryHub() {
  const { user } = useAuth();
  const platform = !!user?.platform_admin;
  const [open, setOpen] = useState<Set<string>>(() => new Set([sectionFromHash(window.location.hash, platform)]));

  // Navigation FOCUSES one section: the route's target replaces what is open.
  // Re-read when the address changes (a flyout sub-item, an old link's
  // redirect landing after the first render) and when sign-in resolves (a
  // Sensors link read before /api/auth/me answered would otherwise fall back
  // to Network Scan for the platform administrator and never recover).
  useEffect(() => {
    const read = () => {
      const target = sectionFromHash(window.location.hash, platform);
      setOpen((prev) => (prev.size === 1 && prev.has(target) ? prev : new Set([target])));
    };
    read();
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, [platform]);

  const toggle = useCallback((id: string) => {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  return (
    <div className="adm discovery-hub">
      <AdminPageHeader title="Discovery" topic="admin.discovery" />
      {visibleSections(platform).map((s, i) => (
        <AdminSection key={s.id} id={s.id} title={`${i + 1}. ${s.title}`} summary={s.summary} open={open.has(s.id)} onToggle={toggle}>
          {/* One section failing must not blank the other four. */}
          <ErrorBoundary label={s.title} route={`#/admin/discovery/${s.id}`} resetKey={s.id}>
            {render(s.id)}
          </ErrorBoundary>
        </AdminSection>
      ))}
    </div>
  );
}
