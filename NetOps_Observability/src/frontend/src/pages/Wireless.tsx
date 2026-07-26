import { useEffect, useMemo, useState } from "react";
import { api, WirelessAP, WirelessController, WirelessWLAN } from "../services/api";
import { Skeleton, Stat, StatStrip } from "../components/ui";

// Wireless (#128 Phase 7) — the wireless canonical inventory: controllers
// (logical clusters + physical members), APs with radios and their LAN uplink
// (the rank-1 wireless↔LAN join), and WLAN profiles with their SSIDs.
// Read-only: the inventory is written by vendor connectors (Catalyst 9800
// today); an empty state explains exactly how to light it up rather than
// showing a blank page. Wired + wireless are ONE LAN domain (owner ruling) —
// this page is the wireless VIEW of it, not a separate world.

function fmtSeen(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function RadioChips({ ap }: { ap: WirelessAP }) {
  if (!ap.radios?.length) return <span className="muted">no radios reported</span>;
  return (
    <span className="wifi-radios">
      {ap.radios.map((r) => (
        <span
          key={r.slot}
          className={`chip ${r.oper_state === "down" ? "chip-crit" : r.oper_state === "up" ? "chip-ok" : ""}`}
          title={`slot ${r.slot}${r.band ? ` · ${r.band}` : ""} · admin ${r.admin_state || "unknown"} · oper ${r.oper_state || "unknown"}`}
        >
          r{r.slot}{r.band ? ` ${r.band}` : ""}{r.oper_state === "down" ? " ↓" : ""}
        </span>
      ))}
    </span>
  );
}

export default function Wireless() {
  const [controllers, setControllers] = useState<WirelessController[] | null>(null);
  const [aps, setAPs] = useState<WirelessAP[] | null>(null);
  const [wlans, setWLANs] = useState<WirelessWLAN[] | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    let alive = true;
    Promise.all([api.wirelessControllers(), api.wirelessAPs(), api.wirelessWLANs()])
      .then(([cs, as_, ws]) => {
        if (!alive) return;
        setControllers(cs ?? []);
        setAPs(as_ ?? []);
        setWLANs(ws ?? []);
      })
      .catch((e) => { if (alive) setErr(String(e?.message || e)); });
    return () => { alive = false; };
  }, []);

  const loading = controllers === null || aps === null || wlans === null;
  const stats = useMemo(() => {
    const total = aps?.length ?? 0;
    const stale = aps?.filter((a) => a.stale).length ?? 0;
    const radioDown = aps?.filter((a) => a.radios?.some((r) => r.oper_state === "down")).length ?? 0;
    return { total, stale, radioDown };
  }, [aps]);

  if (err) {
    return <div className="page-pad"><div className="card error-card" role="alert">Wireless inventory unavailable: {err}</div></div>;
  }
  if (loading) {
    return (
      <div className="page-pad">
        <Skeleton w="40%" /><br /><Skeleton /><br /><Skeleton /><br /><Skeleton w="70%" />
      </div>
    );
  }

  const empty = !controllers!.length && !aps!.length && !wlans!.length;
  return (
    <div className="page-pad wireless-page">
      <StatStrip>
        <Stat label="Controllers" value={String(controllers!.length)} />
        <Stat label="Access points" value={String(stats.total)} />
        <Stat label="APs with a radio down" value={String(stats.radioDown)} tone={stats.radioDown ? "bad" : ""} />
        <Stat label="Stale (not seen last poll)" value={String(stats.stale)} tone={stats.stale ? "warn" : ""} />
      </StatStrip>

      {empty && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>No wireless inventory yet</h3>
          <p className="muted">
            The wireless view fills from a vendor controller connector. Add a
            <b> Cisco Catalyst 9800</b> integration under <a href="#/infrastructure/nms">NMS Integrations</a>
            {" "}(RESTCONF read-only credentials) and the controllers, APs, radios and
            WLANs discovered there will appear here — along with AP join / radio
            state evidence in Correlations.
          </p>
        </div>
      )}

      {!!controllers!.length && (
        <section style={{ marginTop: 16 }}>
          <h3>Controllers</h3>
          <table className="data-table">
            <thead>
              <tr><th>Name</th><th>Vendor</th><th>Cluster</th><th>Members</th><th>Visibility</th><th>Last seen</th></tr>
            </thead>
            <tbody>
              {controllers!.map((c) => (
                <tr key={c.controller_id} className={c.stale ? "row-stale" : ""}>
                  <td>{c.name || c.controller_id}</td>
                  <td>{c.vendor}</td>
                  <td>{c.cluster_role}{c.kind === "gateway" ? " (gateway)" : ""}</td>
                  <td>{c.members?.length ?? 0}</td>
                  <td>{c.visibility || "partial"}</td>
                  <td>{fmtSeen(c.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {!!aps!.length && (
        <section style={{ marginTop: 16 }}>
          <h3>Access points</h3>
          <table className="data-table">
            <thead>
              <tr><th>Name</th><th>Model</th><th>Serial</th><th>Radios</th><th>LAN uplink</th><th>Mgmt address</th><th>Forwarding</th><th>Last seen</th></tr>
            </thead>
            <tbody>
              {aps!.map((ap) => (
                <tr key={ap.ap_id} className={ap.stale ? "row-stale" : ""}>
                  <td>{ap.name || ap.ap_id}</td>
                  <td>{ap.model || "—"}</td>
                  <td>{ap.serial || "—"}</td>
                  <td><RadioChips ap={ap} /></td>
                  <td title="The AP's switch port — the wireless↔LAN join and the second witness a confirmed wireless verdict needs">
                    {ap.uplink_switch_ref ? `${ap.uplink_switch_ref}:${ap.uplink_port_ref}` : <span className="muted">unknown</span>}
                  </td>
                  <td>{ap.mgmt_address || "—"}</td>
                  <td>{ap.forwarding_mode || "unknown"}</td>
                  <td>{fmtSeen(ap.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {!!wlans!.length && (
        <section style={{ marginTop: 16 }}>
          <h3>WLANs</h3>
          <table className="data-table">
            <thead>
              <tr><th>Profile</th><th>SSID</th><th>Security</th><th>Auth</th><th>Forwarding</th><th>Enabled</th></tr>
            </thead>
            <tbody>
              {wlans!.map((w) => (
                <tr key={w.wlan_id} className={w.stale ? "row-stale" : ""}>
                  <td>{w.profile_name}</td>
                  <td>{w.ssid_name || "—"}</td>
                  <td>{w.security_mode || "unknown"}</td>
                  <td>{w.auth_method || "unknown"}</td>
                  <td>{w.forwarding_mode || "unknown"}</td>
                  <td>{w.enabled ? "yes" : "no"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
