import { useState } from "react";
import SnmpCredentials from "./SnmpCredentials";
import SnmpProfiles from "./SnmpProfiles";
import SnmpConfigGenerator from "./SnmpConfigGenerator";

// SnmpProfileManager — one roof for SNMP Credentials & Profiles (previously two
// separate Infrastructure leaves). An internal segmented control switches between
// the credential vault (per-device community / v3 USM secrets) and the vendor
// OID/metric profile library, so operators manage both in one place.
type Pane = "credentials" | "profiles" | "generate";

const PANES: { id: Pane; label: string; hint: string }[] = [
  { id: "credentials", label: "Credentials", hint: "Per-device community / SNMPv3 USM secrets" },
  { id: "profiles", label: "Profiles", hint: "Vendor OID & metric library" },
  { id: "generate", label: "Generate Config", hint: "One-click device config + auto-provisioned profile" },
];

export default function SnmpProfileManager() {
  const [pane, setPane] = useState<Pane>("credentials");
  const active = PANES.find((p) => p.id === pane)!;
  return (
    <>
      <div className="card" style={{ paddingTop: 12, paddingBottom: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <h2 style={{ margin: 0, fontSize: 16 }}>SNMP Profile Manager</h2>
          <div className="seg" style={{ display: "inline-flex", gap: 4, background: "var(--hover)", borderRadius: 8, padding: 3 }}>
            {PANES.map((p) => (
              <button
                key={p.id}
                onClick={() => setPane(p.id)}
                className={pane === p.id ? "btn accent" : "btn"}
                style={{ border: "none", background: pane === p.id ? undefined : "transparent" }}
              >
                {p.label}
              </button>
            ))}
          </div>
          <span style={{ color: "var(--muted)", fontSize: 12 }}>{active.hint}</span>
        </div>
      </div>
      {pane === "credentials" ? <SnmpCredentials /> : pane === "profiles" ? <SnmpProfiles /> : <SnmpConfigGenerator />}
    </>
  );
}
