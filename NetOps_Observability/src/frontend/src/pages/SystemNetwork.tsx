import { useEffect, useState } from "react";
import { api, SystemNetworkConfig, SystemNetworkStatus } from "../services/api";
import Icon from "../components/Icon";

// SystemNetworkCard — Correlix system settings for DNS and NTP, rendered as a box
// inside Administration → Settings (platform-owner only).
//   • DNS servers: the resolvers Correlix uses to resolve outbound URLs.
//   • NTP servers: the time sources Correlix tracks its clock against; Test
//     reports the measured clock offset per server.
// Styled to match the other Settings cards (card shell, icon header, .btn / .btn-
// accent buttons, --muted labels, inherited theme font).

const toList = (s: string): string[] => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
const fromList = (a?: string[]): string => (a ?? []).join("\n");

const taStyle: React.CSSProperties = {
  background: "var(--surface-2)",
  border: "1px solid var(--border, var(--panel-border))",
  borderRadius: 8,
  color: "var(--fg)",
  font: "inherit",
  fontSize: 13,
  padding: "8px 10px",
  resize: "vertical",
  width: "100%",
};
const labelStyle: React.CSSProperties = { fontSize: 12, fontWeight: 600, color: "var(--muted)" };
const hintStyle: React.CSSProperties = { fontSize: 11.5, color: "var(--muted)" };

export default function SystemNetworkCard() {
  const [cfg, setCfg] = useState<SystemNetworkConfig | null>(null);
  const [dns, setDns] = useState("");
  const [search, setSearch] = useState("");
  const [ntp, setNtp] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [status, setStatus] = useState<SystemNetworkStatus | null>(null);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    api.systemNetwork()
      .then((c) => { setCfg(c); setDns(fromList(c.dns_servers)); setSearch(fromList(c.search_domains)); setNtp(fromList(c.ntp_servers)); })
      .catch((e) => setMsg({ kind: "err", text: (e as Error).message }));
  }, []);

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const saved = await api.setSystemNetwork({ dns_servers: toList(dns), search_domains: toList(search), ntp_servers: toList(ntp) });
      setCfg(saved);
      setDns(fromList(saved.dns_servers)); setSearch(fromList(saved.search_domains)); setNtp(fromList(saved.ntp_servers));
      setMsg({ kind: "ok", text: "Saved · DNS resolution now uses these servers" });
    } catch (e) { setMsg({ kind: "err", text: (e as Error).message }); } finally { setBusy(false); }
  };

  const test = async () => {
    setTesting(true); setStatus(null); setMsg(null);
    try { setStatus(await api.testSystemNetwork()); }
    catch (e) { setMsg({ kind: "err", text: (e as Error).message }); } finally { setTesting(false); }
  };

  const fmtOffset = (ms?: number) => (ms === undefined ? "—" : `${ms >= 0 ? "+" : ""}${ms.toFixed(0)} ms`);

  return (
    <div className="card">
      {/* Header row — matches DefaultLandingCard / Log export limits. */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
        <div style={{ width: 34, height: 34, borderRadius: 8, background: "var(--surface-2)", display: "grid", placeItems: "center" }}>
          <Icon name="stack" size={20} />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700 }}>System · DNS &amp; NTP</div>
          <div style={{ fontSize: 12, color: "var(--muted)" }}>
            The DNS resolvers Correlix uses for outbound URLs, and the NTP servers it tracks its clock against.
            {msg && <span style={{ color: msg.kind === "ok" ? "var(--ok)" : "var(--crit)" }}> · {msg.text}</span>}
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gap: 14 }}>
        <div style={{ display: "grid", gap: 5 }}>
          <span style={labelStyle}>DNS servers <span style={{ fontWeight: 400 }}>(one per line — IP addresses)</span></span>
          <textarea rows={2} value={dns} onChange={(e) => setDns(e.target.value)} placeholder={"1.1.1.1\n8.8.8.8"} style={taStyle} />
          <span style={hintStyle}>Correlix resolves integration, webhook, and provider URLs through these.</span>
        </div>

        <div style={{ display: "grid", gap: 5 }}>
          <span style={labelStyle}>Search domains <span style={{ fontWeight: 400 }}>(optional)</span></span>
          <textarea rows={1} value={search} onChange={(e) => setSearch(e.target.value)} placeholder={"corp.example.com"} style={taStyle} />
        </div>

        <div style={{ display: "grid", gap: 5 }}>
          <span style={labelStyle}>NTP servers <span style={{ fontWeight: 400 }}>(one per line — host or IP)</span></span>
          <textarea rows={2} value={ntp} onChange={(e) => setNtp(e.target.value)} placeholder={"pool.ntp.org\ntime.cloudflare.com"} style={taStyle} />
          <span style={hintStyle}>Correlix measures its clock offset against these — accurate time keeps correlation and timestamps honest.</span>
        </div>

        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <button className="btn-accent" onClick={save} disabled={busy}>{busy ? "Saving…" : "Save"}</button>
          <button className="btn" onClick={test} disabled={testing}>{testing ? "Testing…" : "Test connectivity"}</button>
          {cfg?.updated_at && <span style={hintStyle}>Last updated {new Date(cfg.updated_at).toLocaleString()}{cfg.updated_by ? ` by ${cfg.updated_by}` : ""}</span>}
        </div>
      </div>

      {status && (
        <div style={{ marginTop: 16, display: "grid", gap: 12, borderTop: "1px solid var(--border, var(--panel-border))", paddingTop: 14 }}>
          <div style={{ fontSize: 13 }}>
            <span style={labelStyle}>DNS resolution</span><br />
            Resolving <b>{status.dns.test_host}</b> via {status.dns.servers.length ? status.dns.servers.join(", ") : "system resolver"}:{" "}
            {status.dns.ok
              ? <span style={{ color: "var(--ok)" }}>OK — {status.dns.resolved?.slice(0, 4).join(", ")}</span>
              : <span style={{ color: "var(--crit)" }}>failed{status.dns.error ? ` — ${status.dns.error}` : ""}</span>}
          </div>
          <div style={{ fontSize: 13 }}>
            <span style={labelStyle}>NTP clock sync</span>
            {status.ntp.results.length === 0 ? (
              <div style={hintStyle}>No NTP servers configured.</div>
            ) : (
              <table style={{ width: "100%", marginTop: 6, borderCollapse: "collapse", fontSize: 12.5 }}>
                <thead>
                  <tr style={{ color: "var(--muted)", textAlign: "left" }}>
                    <th style={{ fontWeight: 600, padding: "2px 6px" }}>Server</th>
                    <th style={{ fontWeight: 600, padding: "2px 6px", textAlign: "center" }}>Reachable</th>
                    <th style={{ fontWeight: 600, padding: "2px 6px", textAlign: "center" }}>Stratum</th>
                    <th style={{ fontWeight: 600, padding: "2px 6px", textAlign: "right" }}>Offset</th>
                    <th style={{ fontWeight: 600, padding: "2px 6px", textAlign: "right" }}>RTT</th>
                  </tr>
                </thead>
                <tbody>
                  {status.ntp.results.map((r) => (
                    <tr key={r.server} style={{ borderTop: "1px solid var(--border, var(--panel-border))" }}>
                      <td style={{ padding: "3px 6px", fontFamily: "var(--font-mono, monospace)" }}>{r.server}</td>
                      <td style={{ padding: "3px 6px", textAlign: "center", color: r.reachable ? "var(--ok)" : "var(--crit)" }}>{r.reachable ? "yes" : "no"}</td>
                      <td style={{ padding: "3px 6px", textAlign: "center" }}>{r.stratum || "—"}</td>
                      <td style={{ padding: "3px 6px", textAlign: "right", color: Math.abs(r.offset_ms ?? 0) > 1000 ? "var(--warn)" : undefined }}>{r.reachable ? fmtOffset(r.offset_ms) : (r.error || "—")}</td>
                      <td style={{ padding: "3px 6px", textAlign: "right" }}>{r.reachable ? `${(r.rtt_ms ?? 0).toFixed(0)} ms` : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {status.ntp.ok && <div style={{ ...hintStyle, marginTop: 4 }}>Best clock offset: {fmtOffset(status.ntp.offset_ms)} (positive = Correlix ahead of the time source).</div>}
          </div>
        </div>
      )}
    </div>
  );
}
