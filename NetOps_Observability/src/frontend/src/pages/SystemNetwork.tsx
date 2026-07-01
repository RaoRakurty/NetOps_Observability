import { useEffect, useState } from "react";
import { api, SystemNetworkConfig, SystemNetworkStatus } from "../services/api";

// SystemNetwork — Correlix system settings for DNS and NTP.
//   • DNS servers: the resolvers Correlix uses to resolve outbound URLs
//     (integrations, webhooks, providers).
//   • NTP servers: the time sources Correlix tracks its clock against; the Test
//     action reports the measured clock offset per server.
// Platform‑admin only (the backend enforces it independently). Fields are simple
// newline/comma lists; Save validates server‑side (DNS must be IPs).

const toList = (s: string): string[] =>
  s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
const fromList = (a?: string[]): string => (a ?? []).join("\n");

export default function SystemNetwork() {
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
      const saved = await api.setSystemNetwork({
        dns_servers: toList(dns), search_domains: toList(search), ntp_servers: toList(ntp),
      });
      setCfg(saved);
      setDns(fromList(saved.dns_servers)); setSearch(fromList(saved.search_domains)); setNtp(fromList(saved.ntp_servers));
      setMsg({ kind: "ok", text: "Saved. DNS resolution now uses these servers." });
    } catch (e) {
      setMsg({ kind: "err", text: (e as Error).message });
    } finally { setBusy(false); }
  };

  const test = async () => {
    setTesting(true); setStatus(null); setMsg(null);
    try {
      setStatus(await api.testSystemNetwork());
    } catch (e) {
      setMsg({ kind: "err", text: (e as Error).message });
    } finally { setTesting(false); }
  };

  const fmtOffset = (ms?: number) => (ms === undefined ? "—" : `${ms >= 0 ? "+" : ""}${ms.toFixed(0)} ms`);

  return (
    <div className="card" style={{ maxWidth: 820 }}>
      <h2 style={{ marginTop: 0 }}>System — DNS &amp; NTP</h2>
      <p className="mini-meta" style={{ marginTop: -6, marginBottom: 16 }}>
        The DNS resolvers Correlix uses to resolve outbound URLs, and the NTP servers it
        tracks its clock against. These are platform‑wide system settings.
      </p>

      {msg && (
        <div style={{ marginBottom: 14, color: msg.kind === "ok" ? "var(--good)" : "var(--bad)", fontSize: 13 }}>{msg.text}</div>
      )}

      <div style={{ display: "grid", gap: 18 }}>
        <label className="op-field" style={{ display: "grid", gap: 6 }}>
          <span style={{ fontWeight: 600 }}>DNS servers <span className="mini-meta">(one per line — IP addresses)</span></span>
          <textarea rows={3} value={dns} onChange={(e) => setDns(e.target.value)}
            placeholder={"1.1.1.1\n8.8.8.8"} style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 13 }} />
          <span className="mini-meta">Correlix resolves integration, webhook, and provider URLs through these.</span>
        </label>

        <label className="op-field" style={{ display: "grid", gap: 6 }}>
          <span style={{ fontWeight: 600 }}>Search domains <span className="mini-meta">(optional)</span></span>
          <textarea rows={2} value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder={"corp.example.com"} style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 13 }} />
        </label>

        <label className="op-field" style={{ display: "grid", gap: 6 }}>
          <span style={{ fontWeight: 600 }}>NTP servers <span className="mini-meta">(one per line — host or IP)</span></span>
          <textarea rows={3} value={ntp} onChange={(e) => setNtp(e.target.value)}
            placeholder={"pool.ntp.org\ntime.cloudflare.com"} style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 13 }} />
          <span className="mini-meta">Correlix measures its clock offset against these — accurate time keeps correlation and timestamps honest.</span>
        </label>

        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <button className="dash-btn accent" onClick={save} disabled={busy}>{busy ? "Saving…" : "Save"}</button>
          <button className="dash-btn" onClick={test} disabled={testing}>{testing ? "Testing…" : "Test connectivity"}</button>
          {cfg?.updated_at && <span className="mini-meta">Last updated {new Date(cfg.updated_at).toLocaleString()}{cfg.updated_by ? ` by ${cfg.updated_by}` : ""}</span>}
        </div>
      </div>

      {status && (
        <div style={{ marginTop: 20, display: "grid", gap: 14 }}>
          {/* DNS test */}
          <div>
            <div className="op-sec-h" style={{ marginBottom: 4 }}>DNS resolution</div>
            <div style={{ fontSize: 13 }}>
              Resolving <b>{status.dns.test_host}</b> via {status.dns.servers.length ? status.dns.servers.join(", ") : "system resolver"}:{" "}
              {status.dns.ok
                ? <span style={{ color: "var(--good)" }}>OK — {status.dns.resolved?.slice(0, 4).join(", ")}</span>
                : <span style={{ color: "var(--bad)" }}>failed{status.dns.error ? ` — ${status.dns.error}` : ""}</span>}
            </div>
          </div>
          {/* NTP test */}
          <div>
            <div className="op-sec-h" style={{ marginBottom: 4 }}>NTP clock sync</div>
            {status.ntp.results.length === 0 ? (
              <div className="mini-meta">No NTP servers configured.</div>
            ) : (
              <table className="dt" style={{ fontSize: 13, width: "100%" }}>
                <thead><tr><th style={{ textAlign: "left" }}>Server</th><th>Reachable</th><th>Stratum</th><th>Offset</th><th>RTT</th></tr></thead>
                <tbody>
                  {status.ntp.results.map((r) => (
                    <tr key={r.server}>
                      <td style={{ fontFamily: "var(--font-mono, monospace)" }}>{r.server}</td>
                      <td style={{ textAlign: "center", color: r.reachable ? "var(--good)" : "var(--bad)" }}>{r.reachable ? "yes" : "no"}</td>
                      <td style={{ textAlign: "center" }}>{r.stratum || "—"}</td>
                      <td style={{ textAlign: "right", color: Math.abs(r.offset_ms ?? 0) > 1000 ? "var(--warn)" : undefined }}>{r.reachable ? fmtOffset(r.offset_ms) : (r.error || "—")}</td>
                      <td style={{ textAlign: "right" }}>{r.reachable ? `${(r.rtt_ms ?? 0).toFixed(0)} ms` : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {status.ntp.ok && <div className="mini-meta" style={{ marginTop: 4 }}>Best clock offset: {fmtOffset(status.ntp.offset_ms)} (positive = Correlix ahead of the time source).</div>}
          </div>
        </div>
      )}
    </div>
  );
}
