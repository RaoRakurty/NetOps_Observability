import { useEffect, useMemo, useState } from "react";
import { api, WirelessAP, WirelessBSSID, WirelessController, WirelessWLAN } from "../services/api";
import { Skeleton, Stat, StatStrip } from "../components/ui";
import AskIris from "../components/AskIris";

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

/**
 * The broadcast identities beneath the APs. One row per BSSID, grouped by the
 * AP that carries it, with the WLAN it serves and the radio it sits on.
 *
 * Honesty: a BSSID read that FAILED is not an AP that broadcasts nothing, and
 * an AP the connector reported no BSSID for is not an AP with no SSIDs on air —
 * both say which they are. `stale` means the connector has not re-observed the
 * BSSID inside its freshness window, so the row is history, not a live claim.
 */
function BssidTable({ aps, byAP, read, failed }: {
  aps: WirelessAP[];
  byAP: Map<string, WirelessBSSID[]>;
  read: boolean;
  failed: boolean;
}) {
  if (failed || !read) {
    return (
      <p className="cc-empty" style={{ marginTop: 8 }}>
        The BSSIDs were not read.
        <AskIris topic="wifi.bssid-unread" label="BSSIDs not read" />
      </p>
    );
  }
  const rows = aps.flatMap((ap) => (byAP.get(ap.ap_id) ?? []).map((b) => ({ ap, b })));
  if (rows.length === 0) {
    return (
      <p className="cc-empty" style={{ marginTop: 8 }}>
        The controller reported no BSSID here.
        <AskIris topic="wifi.bssid-none" label="No BSSID reported" />
      </p>
    );
  }
  return (
    <>
      <h4 style={{ margin: "12px 0 4px" }}>BSSIDs</h4>
      <table className="data-table">
        <thead>
          <tr><th>BSSID</th><th>Access point</th><th>WLAN</th><th>Radio</th><th>First seen</th><th>Last seen</th></tr>
        </thead>
        <tbody>
          {rows.map(({ ap, b }) => (
            <tr key={`${ap.ap_id}-${b.bssid}`} className={b.stale ? "row-stale" : ""}>
              <td className="mono">{b.bssid}</td>
              <td>{ap.name || ap.ap_id}</td>
              <td>{b.wlan_ref || "not reported"}</td>
              <td>{b.radio_ref || "not reported"}</td>
              <td>{fmtSeen(b.first_seen)}</td>
              <td>{fmtSeen(b.last_seen)}{b.stale ? " (stale)" : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export default function Wireless() {
  const [controllers, setControllers] = useState<WirelessController[] | null>(null);
  const [aps, setAPs] = useState<WirelessAP[] | null>(null);
  const [wlans, setWLANs] = useState<WirelessWLAN[] | null>(null);
  // BSSIDs are read separately and are allowed to FAIL without taking the page
  // with them: they are the detail beneath an AP, not the inventory itself.
  // `null` here means "not read", which the sub-table states rather than
  // rendering as "this AP broadcasts nothing".
  const [bssids, setBSSIDs] = useState<WirelessBSSID[] | null>(null);
  const [bssidErr, setBSSIDErr] = useState(false);
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
    api.wirelessBSSIDs()
      .then((bs) => { if (alive) setBSSIDs(bs ?? []); })
      .catch(() => { if (alive) { setBSSIDs(null); setBSSIDErr(true); } });
    return () => { alive = false; };
  }, []);

  // BSSIDs grouped under the AP that broadcasts them.
  const bssidsByAP = useMemo(() => {
    const m = new Map<string, WirelessBSSID[]>();
    for (const b of bssids ?? []) {
      const key = b.ap_ref || "";
      if (!key) continue;
      const list = m.get(key);
      if (list) list.push(b);
      else m.set(key, [b]);
    }
    for (const list of m.values()) list.sort((a, b) => a.bssid.localeCompare(b.bssid));
    return m;
  }, [bssids]);

  const loading = controllers === null || aps === null || wlans === null;
  const stats = useMemo(() => {
    const total = aps?.length ?? 0;
    const stale = aps?.filter((a) => a.stale).length ?? 0;
    const radioDown = aps?.filter((a) => a.radios?.some((r) => r.oper_state === "down")).length ?? 0;
    return { total, stale, radioDown };
  }, [aps]);

  if (err) {
    return <div className="page-pad"><div className="card error-card" role="alert">The wireless inventory could not be read: {err}</div></div>;
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
        <Stat label="Radio down" value={String(stats.radioDown)} tone={stats.radioDown ? "bad" : ""} />
        <Stat label="Stale" value={String(stats.stale)} tone={stats.stale ? "warn" : ""} />
      </StatStrip>

      {empty && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>No wireless inventory<AskIris topic="wifi.inventory-empty" label="No wireless inventory" /></h3>
          <p className="cc-empty">
            Add a controller connector under <a href="#/infrastructure/discovery/nms">NMS integrations</a>.
          </p>
        </div>
      )}

      {!!controllers!.length && (
        <section style={{ marginTop: 16 }}>
          <h3>Controllers</h3>
          <table className="data-table">
            <thead>
              <tr><th>Name</th><th>Vendor</th><th>Cluster</th><th>Members</th><th>Visibility</th>
                <th>Last seen<AskIris topic="wifi.stale" label="Last seen" /></th></tr>
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
              <tr><th>Name</th><th>Model</th><th>Serial</th><th>Radios</th>
                <th>Uplink<AskIris topic="wifi.uplink" label="Uplink" /></th>
                <th>Address</th><th>Forwarding</th><th>Last seen</th></tr>
            </thead>
            <tbody>
              {aps!.map((ap) => (
                <tr key={ap.ap_id} className={ap.stale ? "row-stale" : ""}>
                  <td>{ap.name || ap.ap_id}</td>
                  <td>{ap.model || "—"}</td>
                  <td>{ap.serial || "—"}</td>
                  <td><RadioChips ap={ap} /></td>
                  <td title="The access point's switch port">
                    {ap.uplink_switch_ref ? `${ap.uplink_switch_ref}:${ap.uplink_port_ref}` : <span className="muted">unknown</span>}
                  </td>
                  <td>{ap.mgmt_address || "—"}</td>
                  <td>{ap.forwarding_mode || "not reported"}</td>
                  <td>{fmtSeen(ap.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <BssidTable aps={aps!} byAP={bssidsByAP} read={bssids !== null} failed={bssidErr} />
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
                  <td>{w.security_mode || "not reported"}</td>
                  <td>{w.auth_method || "not reported"}</td>
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
