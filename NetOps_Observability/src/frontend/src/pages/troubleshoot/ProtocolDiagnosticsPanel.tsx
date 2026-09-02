// ProtocolDiagnosticsPanel — the "Protocol diagnostics" section of the
// Troubleshooting page (item 7; backend internal/protocoldiag).
//
// What it gives an operator, in one place: pick a routing protocol (BGP / OSPF /
// IS-IS) and one of that protocol's five most common issues; COLLECT the curated
// read-only `show` bundle from one of their own devices; or, when this
// deployment has no command runner wired, PASTE the output by hand; ANALYZE it
// against the version-pinned failure signatures; and hand a colleague or the
// vendor's TAC the redacted bundle.
//
// HONESTY (the whole point of the feature).
//  · A 503 from collect is a PRODUCT state, not an error: "collection is not
//    wired on this deployment yet — paste the output below". A capture is never
//    fabricated to fill the screen.
//  · A device the caller cannot see is a 404 and says only that it is not
//    visible — the server never reveals another tenant's ids, and neither does
//    this panel.
//  · When no signature fires, the panel says so in the server's own words and
//    still offers the raw output for TAC. A verdict is never invented.
//  · The collected output is shown AS CAPTURED; the redaction pass runs on the
//    TAC export, which is why the bundle is labelled "redacted" and the capture
//    on screen is not.
//
// SECURITY (§3 zero trust / §15 untrusted output). Every command output,
// verdict, cause, remediation and evidence line is DEVICE-authored text. It is
// rendered as an escaped React text node inside a <pre> — there is no innerHTML,
// no dangerouslySetInnerHTML and no markup parsing anywhere in this file.
//
// PERMISSIONS. The catalog and analyze need infrastructure:read; collect needs
// infrastructure:write. The client gate on the Collect button is a courtesy —
// a server 403 is caught and rendered inline, because the client is never the
// authority.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  type Device,
  type ProtocolDiagAnalysis,
  type ProtocolDiagCatalog,
  type ProtocolDiagCollection,
  type ProtocolDiagIssue,
} from "../../services/api";
import {
  MAX_OUTPUT_CHARS,
  NO_ANALYSIS_FOR_TAC_MESSAGE,
  PROTOCOL_TABS,
  VENDORS_COVERED,
  buildAnalyzeRequest,
  buildCollectRequest,
  confidenceLabel,
  confidenceTone,
  platformOf,
  protocolDiagErrorMessage,
  protocolLabel,
  tacFileName,
} from "./protocolDiagModel";

type Notice = { tone: "good" | "bad"; text: string };

/** The RCA list deep-links by verdict tier and by correlation id only — it has
 *  no device filter — so "Correlate" is an honest plain link to the list. */
const RCA_HREF = "#/investigate/rca";

export default function ProtocolDiagnosticsPanel() {
  const [catalog, setCatalog] = useState<ProtocolDiagCatalog | null>(null);
  const [catalogErr, setCatalogErr] = useState<string | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [canWrite, setCanWrite] = useState<boolean | null>(null);

  const [protocol, setProtocol] = useState<string>(PROTOCOL_TABS[0].id);
  const [issueId, setIssueId] = useState<string>("");
  const [deviceId, setDeviceId] = useState<string>("");
  const [target, setTarget] = useState({ interface: "", peer: "", prefix: "", vrf: "" });

  // Output per command spec id — collected, pasted, or a mix of the two.
  const [outputs, setOutputs] = useState<Record<string, string>>({});
  const [collection, setCollection] = useState<ProtocolDiagCollection | null>(null);
  const [analysis, setAnalysis] = useState<ProtocolDiagAnalysis | null>(null);

  const [collecting, setCollecting] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);

  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);

  const device = useMemo(() => devices.find((d) => d.id === deviceId) ?? null, [devices, deviceId]);
  const platform = platformOf(device);

  // Inventory + the permission courtesy gate. A failure here is not fatal: the
  // paste-and-analyze path works with no device at all.
  useEffect(() => {
    api.devices()
      .then((rows) => { if (alive.current) setDevices(Array.isArray(rows) ? rows : []); })
      .catch(() => { if (alive.current) setDevices([]); });
    api.permissions()
      .then((p) => { if (alive.current) setCanWrite((p.permissions?.infrastructure ?? 0) >= 2); })
      .catch(() => { if (alive.current) setCanWrite(false); });
  }, []);

  // The catalog renders in ONE dialect per response, so it is refetched when the
  // selected device changes — the commands on screen are then the ones that
  // device actually understands.
  useEffect(() => {
    let on = true;
    api.protocolDiagCatalog(platform || undefined)
      .then((c) => { if (on) { setCatalog(c); setCatalogErr(null); } })
      .catch((e) => { if (on) { setCatalog(null); setCatalogErr(protocolDiagErrorMessage(e)); } });
    return () => { on = false; };
  }, [platform]);

  const issues: ProtocolDiagIssue[] = useMemo(
    () => catalog?.issues?.[protocol] ?? [],
    [catalog, protocol],
  );
  const issue = useMemo(() => issues.find((i) => i.id === issueId) ?? null, [issues, issueId]);

  /** Switching protocol or issue drops the previous evidence — a capture from
   *  one issue must never be read under another issue's signatures. */
  const resetEvidence = useCallback(() => {
    setOutputs({});
    setCollection(null);
    setAnalysis(null);
    setNotice(null);
  }, []);

  const pickProtocol = (p: string) => {
    if (p === protocol) return;
    setProtocol(p);
    setIssueId("");
    resetEvidence();
  };

  const pickIssue = (id: string) => {
    if (id === issueId) return;
    setIssueId(id);
    resetEvidence();
  };

  // ── actions ───────────────────────────────────────────────────────────────

  const collect = async () => {
    setNotice(null);
    const built = buildCollectRequest(deviceId, issueId, target);
    if (!built.ok) {
      setNotice({ tone: "bad", text: built.reason });
      return;
    }
    setCollecting(true);
    try {
      const col = await api.protocolDiagCollect(built.request);
      if (!alive.current) return;
      setCollection(col);
      setAnalysis(null);
      const next: Record<string, string> = {};
      for (const c of col.commands ?? []) next[c.spec_id] = c.output ?? "";
      setOutputs(next);
      setNotice({
        tone: "good",
        text: `Captured ${(col.commands ?? []).length} command(s) from ${col.hostname || col.device_id} in the ${col.rendered_vendor} dialect.`,
      });
    } catch (e) {
      if (alive.current) setNotice({ tone: "bad", text: protocolDiagErrorMessage(e) });
    } finally {
      if (alive.current) setCollecting(false);
    }
  };

  const analyze = async () => {
    setNotice(null);
    const built = buildAnalyzeRequest(issue, { hostname: device?.name ?? "", platform }, outputs);
    if (!built.ok) {
      setNotice({ tone: "bad", text: built.reason });
      return;
    }
    setAnalyzing(true);
    try {
      const res = await api.protocolDiagAnalyze(built.request);
      if (alive.current) setAnalysis(res);
    } catch (e) {
      if (alive.current) { setAnalysis(null); setNotice({ tone: "bad", text: protocolDiagErrorMessage(e) }); }
    } finally {
      if (alive.current) setAnalyzing(false);
    }
  };

  /** The TAC bundle is the SERVER's redacted export (analysis.tac_export) — the
   *  browser only names the file and hands it to the download sink. */
  const sendToTac = () => {
    if (!analysis || !analysis.tac_export) {
      setNotice({ tone: "bad", text: NO_ANALYSIS_FOR_TAC_MESSAGE });
      return;
    }
    const name = tacFileName(analysis.issue_id, device?.name ?? collection?.hostname ?? "");
    const url = URL.createObjectURL(new Blob([analysis.tac_export], { type: "text/plain;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setNotice({ tone: "good", text: `TAC bundle (redacted) downloaded as ${name}.` });
  };

  // ── render ────────────────────────────────────────────────────────────────

  const collectBlocked = collecting || canWrite === false || deviceId === "" || issueId === "";

  return (
    <section className="cfg-panel pd-panel" aria-label="Protocol diagnostics">
      <h3 className="cfg-h">Protocol diagnostics</h3>
      <p className="mini-meta cfg-note">
        Pick the protocol and the issue you are chasing, then capture the curated read-only{" "}
        <code>show</code> bundle from the device — or paste the output you already have. The analysis
        runs hand-authored failure signatures over that text and says plainly what fired, or that
        nothing did. Ruleset {catalog?.ruleset_version ?? "—"} · commands rendered for{" "}
        {catalog?.vendor_display ?? "Cisco IOS-XE"} · vendors covered: {VENDORS_COVERED.join(" · ")}.
      </p>

      {/* Protocol switch as a toggle-button group (not ARIA tabs: no tabpanel /
          roving-focus wiring here, and plain buttons are fully keyboard operable) */}
      <div className="seg-mini pd-tabs" role="group" aria-label="Protocol">
        {PROTOCOL_TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            aria-pressed={protocol === t.id}
            className={protocol === t.id ? "on" : ""}
            onClick={() => pickProtocol(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {catalogErr ? (
        <div className="empty cfg-bad" role="alert">{catalogErr}</div>
      ) : issues.length === 0 ? (
        <div className="empty" role="status">Loading the {protocolLabel(protocol)} issue matrix…</div>
      ) : (
        <fieldset className="pd-issues">
          <legend className="mini-meta">{protocolLabel(protocol)} — pick the issue that matches your symptoms</legend>
          {issues.map((is) => (
            <label className={`pd-issue${issueId === is.id ? " on" : ""}`} key={is.id}>
              <input
                type="radio"
                name="pd-issue"
                value={is.id}
                checked={issueId === is.id}
                onChange={() => pickIssue(is.id)}
              />
              <span className="pd-issue-body">
                <span className="pd-issue-title">{is.title}</span>
                <span className="mini-meta">{is.description}</span>
                <span className="mini-meta pd-issue-id">{is.id}</span>
                <span className="pd-cmds">
                  {is.commands.map((c) => (
                    <span className="pd-cmd" key={c.spec_id}>
                      <code>{c.command}</code>
                      <span className="mini-meta">{c.purpose}</span>
                    </span>
                  ))}
                </span>
              </span>
            </label>
          ))}
        </fieldset>
      )}

      {/* ── device + optional target ─────────────────────────────────────── */}
      <div className="pcap-form pd-form">
        <label className="pcap-field">
          <span>Device</span>
          <select value={deviceId} onChange={(e) => { setDeviceId(e.target.value); resetEvidence(); }}>
            <option value="">Choose a device… (optional — you can paste output instead)</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>{d.name || d.id}{d.address ? ` — ${d.address}` : ""}</option>
            ))}
          </select>
          <span className="mini-meta">
            {device ? `Dialect: ${platform || "unknown platform"}` : "Only devices in your own inventory are listed."}
          </span>
        </label>
        <label className="pcap-field">
          <span>Interface (optional)</span>
          <input type="text" value={target.interface} maxLength={256}
            onChange={(e) => setTarget((t) => ({ ...t, interface: e.target.value }))} />
        </label>
        <label className="pcap-field">
          <span>Peer (optional)</span>
          <input type="text" value={target.peer} maxLength={256}
            onChange={(e) => setTarget((t) => ({ ...t, peer: e.target.value }))} />
        </label>
        <label className="pcap-field">
          <span>Prefix (optional)</span>
          <input type="text" value={target.prefix} maxLength={256}
            onChange={(e) => setTarget((t) => ({ ...t, prefix: e.target.value }))} />
        </label>
        <label className="pcap-field">
          <span>VRF (optional)</span>
          <input type="text" value={target.vrf} maxLength={256}
            onChange={(e) => setTarget((t) => ({ ...t, vrf: e.target.value }))} />
        </label>
        <div className="pcap-actions">
          <button type="button" className="btn accent" onClick={() => { void collect(); }} disabled={collectBlocked}
            aria-label="Collect the read-only command bundle from the device">
            {collecting ? "Collecting…" : "Collect"}
          </button>
          <button type="button" className="btn" onClick={() => { void analyze(); }} disabled={analyzing || !issue}
            aria-label="Analyze the collected or pasted output">
            {analyzing ? "Analyzing…" : "Analyze"}
          </button>
          <button type="button" className="btn" onClick={sendToTac} aria-label="Download the redacted TAC bundle">
            Send to TAC
          </button>
          <a className="btn" href={RCA_HREF} title="Open the RCA candidate list (it is not filtered by device)">
            Correlate
          </a>
        </div>
      </div>

      {canWrite === false && (
        <p className="mini-meta cfg-bad cfg-note">
          Collecting from a device needs infrastructure write access — you can still paste output and analyze it.
        </p>
      )}

      {notice && (
        <p className={`mini-meta cfg-note${notice.tone === "bad" ? " cfg-bad" : ""}`} role="status" aria-live="polite">
          {notice.text}
        </p>
      )}

      {/* ── captured output + the paste fallback ─────────────────────────── */}
      {issue && (
        <div className="pd-outputs">
          <h4 className="cfg-h">Command output</h4>
          <p className="mini-meta cfg-note">
            {collection
              ? `Captured ${collection.collected_at} from ${collection.hostname || collection.device_id}, shown as captured — the redaction pass runs on the TAC bundle.`
              : "Paste each command's output from your own session. Anything you leave empty is simply not analyzed."}
          </p>
          {issue.commands.map((c) => {
            const captured = (collection?.commands ?? []).find((cc) => cc.spec_id === c.spec_id);
            const text = outputs[c.spec_id] ?? "";
            return (
              <div className="pd-output" key={c.spec_id}>
                <div className="pd-output-head">
                  <code>{captured?.command ?? c.command}</code>
                  <span className="mini-meta">{c.purpose}</span>
                </div>
                {captured?.error ? (
                  <p className="mini-meta cfg-bad cfg-note">Command error: {captured.error}</p>
                ) : null}
                {captured && text !== "" ? (
                  <pre className="pd-pre">{text}</pre>
                ) : (
                  <textarea
                    className="pd-paste"
                    rows={5}
                    value={text}
                    maxLength={MAX_OUTPUT_CHARS}
                    placeholder={`Paste the output of \`${c.command}\` here`}
                    aria-label={`Paste output for ${c.command}`}
                    onChange={(e) => setOutputs((o) => ({ ...o, [c.spec_id]: e.target.value }))}
                  />
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ── analysis ─────────────────────────────────────────────────────── */}
      <div className="pd-analysis" role="status" aria-live="polite" aria-label="Analysis result">
        {analysis && (
          analysis.matched ? (
            <>
              <h4 className="cfg-h">
                {analysis.findings.length} signature(s) matched — {analysis.issue_title}
              </h4>
              {analysis.findings.map((f) => (
                <div className="pd-finding" key={f.signature_id}>
                  <div className="pd-finding-head">
                    <strong>{f.verdict}</strong>
                    <span className={`badge pd-conf-${confidenceTone(f.confidence)}`}>
                      {confidenceLabel(f.confidence)} confidence
                    </span>
                    <span className="mini-meta">{f.signature_id}</span>
                  </div>
                  <p className="mini-meta cfg-note"><strong>Likely cause:</strong> {f.cause}</p>
                  <p className="mini-meta cfg-note"><strong>Remediation:</strong> {f.remediation}</p>
                  {f.evidence.line && (
                    <p className="mini-meta cfg-note">
                      <strong>Evidence:</strong> <code>{f.evidence.line}</code> from <code>{f.evidence.command}</code>
                    </p>
                  )}
                </div>
              ))}
              <p className="mini-meta cfg-note">Scored using rule set {analysis.ruleset_version}.</p>
            </>
          ) : (
            <>
              <h4 className="cfg-h">No signature matched</h4>
              <p className="mini-meta cfg-note">{analysis.unmatched}</p>
              <p className="mini-meta cfg-note">
                That is the honest answer, not a failure: the raw output above is attached to the TAC
                bundle so a human can read it. Scored using rule set {analysis.ruleset_version}.
              </p>
            </>
          )
        )}
      </div>
    </section>
  );
}
