import { useState } from "react";
import { api, SnmpGenResult } from "../services/api";
import { capitalize } from "../lib/text";

// SnmpConfigGenerator — onboarding automation UI. Pick a vendor + version;
// Correlix generates the credentials, provisions the matching profile, and
// returns the ready-to-paste device CLI block. The operator pastes one block on
// the device and the credential sentinel verifies it live within ~2 minutes.

const VENDORS = [
  "cisco", "juniper", "arista", "fortinet", "paloalto", "f5",
  "checkpoint", "mikrotik", "huawei", "extreme", "ubiquiti",
];

export default function SnmpConfigGenerator() {
  const [vendor, setVendor] = useState("cisco");
  const [version, setVersion] = useState<"v3" | "v2c">("v3");
  const [subnet, setSubnet] = useState("");
  const [mask, setMask] = useState("");
  const [res, setRes] = useState<SnmpGenResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const generate = async () => {
    setBusy(true); setErr(null); setRes(null); setCopied(false);
    try {
      const r = await api.generateSnmpConfig({
        vendor, version,
        ...(vendor === "fortinet" && subnet ? { mgmt_subnet: subnet, mask } : {}),
      });
      setRes(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const copy = () => {
    if (res) { navigator.clipboard?.writeText(res.device_config); setCopied(true); setTimeout(() => setCopied(false), 1500); }
  };

  return (
    <div className="card" style={{ padding: 16 }}>
      <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 0 }}>
        Generate ready-to-paste SNMP config for a device. Correlix creates the credentials,
        provisions the matching profile, and shows you the exact CLI block — paste it on the
        device and monitoring is verified live within about two minutes.
      </p>

      <div style={{ display: "flex", gap: 12, alignItems: "flex-end", flexWrap: "wrap", marginBottom: 12 }}>
        <label style={{ display: "flex", flexDirection: "column", fontSize: 12, gap: 4 }}>
          Vendor
          <select value={vendor} onChange={(e) => setVendor(e.target.value)}>
            {VENDORS.map((v) => <option key={v} value={v}>{capitalize(v)}</option>)}
          </select>
        </label>
        <label style={{ display: "flex", flexDirection: "column", fontSize: 12, gap: 4 }}>
          Version
          <select value={version} onChange={(e) => setVersion(e.target.value as "v3" | "v2c")}>
            <option value="v3">SNMPv3 (auth + encryption — recommended)</option>
            <option value="v2c">SNMPv2c (community)</option>
          </select>
        </label>
        {vendor === "fortinet" && version === "v2c" && (
          <>
            <label style={{ display: "flex", flexDirection: "column", fontSize: 12, gap: 4 }}>
              Mgmt subnet
              <input value={subnet} onChange={(e) => setSubnet(e.target.value)} placeholder="0.0.0.0" style={{ width: 120 }} />
            </label>
            <label style={{ display: "flex", flexDirection: "column", fontSize: 12, gap: 4 }}>
              Mask
              <input value={mask} onChange={(e) => setMask(e.target.value)} placeholder="0.0.0.0" style={{ width: 120 }} />
            </label>
          </>
        )}
        <button className="btn accent" onClick={generate} disabled={busy}>{busy ? "Generating…" : "Generate"}</button>
      </div>

      {err && <div style={{ color: "var(--crit,#e5484d)", fontSize: 12 }}>{err}</div>}

      {res && (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
            <div style={{ fontSize: 12, color: "var(--muted)" }}>
              Paste on the {capitalize(res.vendor)} device{" "}
              {res.templated ? "" : "(generic guidance — adapt to your CLI)"}
              {res.profile_id && <> · profile <code>{res.profile_id}</code> provisioned</>}
            </div>
            <button className="btn" onClick={copy}>{copied ? "Copied ✓" : "Copy"}</button>
          </div>
          <pre style={{ background: "var(--surface-2)", color: "var(--fg)", border: "1px solid var(--border)", borderRadius: 6, padding: 12, overflowX: "auto", fontSize: 12, whiteSpace: "pre" }}>
            {res.device_config}
          </pre>
          <div style={{ fontSize: 11, color: "var(--warn,#f5a623)", marginTop: 6 }}>
            ⚠ These credentials are shown once — the profile stores them but can never display them again. Copy them now.
            The credential sentinel will confirm the device answers within ~2 minutes.
          </div>
        </div>
      )}
    </div>
  );
}
