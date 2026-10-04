// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// SubnetDiscovery — Administration → Data sources → Subnet Discovery
// (#/admin/discovery), beside Telemetry Coverage. It replaced the Subnet
// Discovery tab of the old Infrastructure → "Discovery & NMS" composite (NMS
// Integrations is its own Infrastructure leaf now) and the duplicate card on
// the Sensors page: there is exactly ONE subnet-discovery screen.
//
// Audience gate: the discovery config is platform plumbing — the card
// (SubnetDiscoveryCard) renders only for the platform principal, and the server
// enforces the same boundary on /api/discovery/config regardless. Tenant users
// get an honest explanation, not a broken form.

import { useAuth } from "../hooks/useAuth";
import SubnetDiscoveryCard from "./SubnetDiscoveryCard";

export default function SubnetDiscovery() {
  // Honor the resolved-auth pattern (App.tsx gates the shell on `loading` the
  // same way): user is transiently null while /api/auth/me is in flight, and
  // deciding the audience from that null flashes the tenant copy at the
  // platform operator. Wait for auth to RESOLVE before picking whose page this is.
  const { user, loading: authLoading } = useAuth();
  if (authLoading) {
    return <div style={{ padding: 40, color: "var(--muted)" }}>Loading…</div>;
  }
  if (user?.platform_admin) return <SubnetDiscoveryCard />;
  return (
    // Honest tenant state: discovery is real, it just isn't THEIR control.
    <div className="card" style={{ maxWidth: 760 }}>
      <h3 style={{ marginTop: 0 }}>Subnet discovery</h3>
      <p style={{ color: "var(--muted)", fontSize: 14 }}>
        Your platform operator runs subnet discovery. Devices it finds appear in{" "}
        <a href="#/infrastructure/devices">Devices</a>. The SNMP credentials it uses are in{" "}
        <a href="#/admin/snmp">SNMP Profiles</a>.
      </p>
    </div>
  );
}
