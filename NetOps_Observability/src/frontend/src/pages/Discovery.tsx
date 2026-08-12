// Discovery — Infrastructure → Discovery & NMS (2026-08 nav redesign, owner
// tree). One entry for "how do devices get INTO the inventory": subnet
// discovery (the platform-operated SNMP sweep) and the NMS vendor-controller
// integrations (#95). Tab lives in the route's third segment:
//
//   #/infrastructure/discovery            → Subnet Discovery (default)
//   #/infrastructure/discovery/discovery  → same, explicit
//   #/infrastructure/discovery/nms        → NMS Integrations
//
// Gates carried verbatim: the discovery config is platform plumbing — the card
// (tabs/Collectors.tsx DiscoveryCard, reused, not forked) renders only for the
// platform principal, and the backend enforces the same boundary on
// /api/discovery/config regardless. Tenant users get an honest explanation,
// not a broken form. NMS Integrations keeps its own FEATURE_NMS_INTEGRATIONS
// dormant-by-default behaviour inside the page, exactly as before.

import { Suspense, lazy, useEffect, useState } from "react";
import { Segmented } from "../components/ui";
import { useAuth } from "../hooks/useAuth";

// Route-level chunks stay small: both panes lazy-load (same rule as nav.tsx).
const NmsIntegrations = lazy(() => import("./NmsIntegrations"));
const DiscoveryCard = lazy(() => import("../tabs/Collectors").then((m) => ({ default: m.DiscoveryCard })));

type Tab = "discovery" | "nms";

function tabFromHash(): Tab {
  const seg = location.hash.replace(/^#\/?/, "").split("?")[0].split("/")[2];
  return seg === "nms" ? "nms" : "discovery";
}

export default function Discovery() {
  const { user } = useAuth();
  const platform = !!user?.platform_admin;
  const [tab, setTab] = useState<Tab>(tabFromHash);
  // Re-read on hashchange so flyout sub-item clicks switch tabs while mounted.
  useEffect(() => {
    const on = () => setTab(tabFromHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const go = (t: Tab) => {
    const next = `#/infrastructure/discovery/${t}`;
    if (location.hash.split("?")[0] !== next) window.history.replaceState(null, "", next);
    setTab(t);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <Segmented
        value={tab}
        ariaLabel="Discovery view"
        options={[
          { value: "discovery", label: "Subnet Discovery" },
          { value: "nms", label: "NMS Integrations" },
        ]}
        onChange={go}
      />
      <Suspense fallback={<div style={{ padding: 40, color: "var(--muted)" }}>Loading…</div>}>
        {tab === "nms" ? (
          <NmsIntegrations />
        ) : platform ? (
          <DiscoveryCard />
        ) : (
          // Honest tenant state: discovery is real, it just isn't THEIR control.
          <div className="card" style={{ maxWidth: 760 }}>
            <h3 style={{ marginTop: 0 }}>Subnet discovery</h3>
            <p style={{ color: "var(--muted)" }}>
              Subnet discovery is operated at the platform level: the platform operator scopes which
              management subnets the SNMP prober may sweep, and discovered devices appear in your{" "}
              <a href="#/infrastructure/devices">Devices</a> inventory automatically. There is nothing
              to configure here for a tenant account — if devices you expect are missing, ask your
              platform operator to widen the discovery scope, or add per-device credentials under{" "}
              <a href="#/admin/snmp">SNMP Profiles</a>.
            </p>
          </div>
        )}
      </Suspense>
    </div>
  );
}
