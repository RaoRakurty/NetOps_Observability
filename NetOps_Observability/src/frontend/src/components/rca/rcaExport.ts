import { CorrTimeline, Seam } from "../../services/api";
import {
  signatureNocTitle, PLANE_NOC_TITLE, entityLabel, kindLabel, isRoutingKind,
  modalityLabel, MODALITY_ORDER, mentionsInternal, ownerLabel,
} from "./labels";

// rcaExport — generates an elegant, light-themed, print-ready RCA report and
// opens it for the browser's "Save as PDF". No PDF dependency: a self-contained
// HTML document + print CSS. The product name appears only in the report's
// header/footer metadata (allowed in exports), never in the operator narrative.
//
// Derived from the same CorrTimeline + labels helpers the on-screen Operator View
// uses, with the canonical demo-ready wording, so the PDF reads like the page.

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

interface Report {
  title: string; verdict: string; confidence: string; state: string; observed: string;
  device: string; peer: string; scopeType: string;
  summary: string; decision: string;
  whySuspected: string; whyNotConfirmed: string; toConfirm: string;
  impact: string; impactWhy: string;
  routingContext: string; localization: string;
  evidence: { plane: string; detail: string; status: string }[];
  actions: string[];
}

function buildReport(timeline: CorrTimeline, owner: string, steps: string[]): Report {
  const confirmed = timeline.verdict_tier === "confirmed";

  // display-plane counts (routing kinds read as routing/link, like Operator View)
  const att: Record<string, number> = {};
  for (const s of timeline.signals) {
    if (s.kind.endsWith("_clear") || !s.attached) continue;
    const p = isRoutingKind(s.kind) ? "control_plane" : s.modality_class;
    att[p] = (att[p] ?? 0) + 1;
  }
  const dominant = Object.entries(att).sort((a, b) => b[1] - a[1])[0]?.[0] ?? "control_plane";
  const hasDevice = (att["device_telemetry"] ?? 0) > 0;
  const hasRouting = (att["control_plane"] ?? 0) > 0;
  const attachedCount = timeline.signals.filter((s) => s.attached && !s.kind.endsWith("_clear")).length;

  // routing context (device + peer)
  let device = "", peer = "", routeKind = "";
  for (const s of timeline.signals) {
    if (!s.attached || s.kind.endsWith("_clear") || !isRoutingKind(s.kind)) continue;
    device = s.entity_id; routeKind = s.kind;
    try { const a = JSON.parse((s as { attrs?: string }).attrs || "{}"); peer = a.peer || a.neighbor || ""; } catch { /* */ }
    const ci = s.entity_id.indexOf(":");
    if (ci > 0) { device = s.entity_id.slice(0, ci); if (!peer) peer = s.entity_id.slice(ci + 1); }
    if (mentionsInternal(device)) { device = ""; peer = ""; }
    break;
  }
  device = device ? entityLabel(device) : "";

  // title (with device/routing evidence-mix refinement)
  let title = timeline.top_hypothesis !== "undetermined"
    ? signatureNocTitle(timeline.top_hypothesis)
    : (PLANE_NOC_TITLE[dominant] ?? "Possible network issue");
  if (!confirmed && hasDevice && hasRouting && /routing|network/i.test(title) && !/wan|provider|boundary/i.test(title)) {
    title = "Possible device/routing issue";
  }

  const confidence = confirmed ? "High" : attachedCount >= 2 ? "Medium" : "Low";
  const w = (timeline.window_start || "").replace("T", " ").slice(0, 19);

  const summary = confirmed
    ? `${title.replace(/^Possible /, "")} — independent evidence confirms a real network issue.`
    : (hasRouting && device)
      ? `A ${kindLabel(routeKind)} was observed on ${device}${peer ? ` with peer ${peer}` : ""}. Customer impact is not confirmed yet.`
      : `Evidence changed but does not yet confirm a real network issue.`;

  const whySuspected = (hasDevice && hasRouting)
    ? "Device health and routing/link evidence were observed on the same device area."
    : hasRouting ? "A routing/link change was observed on the affected routing adjacency."
      : "The available evidence matches this issue type.";
  const whyNotConfirmed = attachedCount <= 1
    ? "This issue currently rests on a single observed signal. Independent evidence is needed before confirming customer impact."
    : "The supporting signals are related, but independent evidence is needed before confirming customer impact.";
  const toConfirm = hasDevice
    ? "Add peer-side BGP/routing state, traffic-flow loss, downstream service impact, or an active check from an independent vantage."
    : "Add peer-side BGP/routing state, interface errors or drops, traffic-flow loss, downstream service impact, or an active check from an independent vantage.";

  const confirmMenu = ["peer-side routing", "device health", "traffic-flow loss", "downstream impact", "or an independent active check"]
    .filter((o) => !(hasDevice && o === "device health"));
  const decision = confirmed
    ? `ESCALATE — confirmed; route to ${owner ? ownerLabel(owner) : "the network team"}.`
    : `HOLD — suspected only. Confirm with ${confirmMenu.join(", ")}.`;

  const notTied: string[] = [];
  if (!hasDevice) notTied.push("device-health");
  if ((att["passive_flow"] ?? 0) === 0) notTied.push("traffic-flow");
  if ((att["active_probe"] ?? 0) === 0) notTied.push("active-check");
  if (!hasRouting || attachedCount <= 1) notTied.push("peer-side");
  const impactWhy = notTied.length ? `${notTied.join(", ")} evidence ${notTied.length > 1 ? "are" : "is"} not tied to this issue.` : "";

  // evidence rows (per plane)
  const PLANE_DESC: Record<string, string> = {
    device_telemetry: "interface errors, link counters, CPU, memory",
    control_plane: "BGP, link up/down, syslog, traps",
    passive_flow: "traffic loss, volume drop, traffic shift",
    active_probe: "ping, HTTP, STAMP, path checks",
  };
  const evidence = MODALITY_ORDER.map((p) => {
    const n = att[p] ?? 0;
    return {
      plane: modalityLabel(p), detail: PLANE_DESC[p] ?? "",
      status: n > 0 ? (p === dominant ? "Main evidence · used" : "Used") : "Not observed",
    };
  });

  const actions = steps.length ? steps.slice(0, 6) : [
    "Check peer-side BGP/routing state for the affected adjacency.",
    "Review device CPU/memory and control-plane load around the event window.",
    "Run an independent active path check from another vantage.",
    "Hold ticketing/escalation until independent impact evidence appears.",
  ];

  return {
    title, verdict: confirmed ? "CONFIRMED" : "NOT CONFIRMED", confidence, state: timeline.verdict_tier === "confirmed" ? "Open" : "Open",
    observed: w ? `${w} UTC` : "—", device, peer, scopeType: device && peer ? "Routing adjacency" : "",
    summary, decision, whySuspected, whyNotConfirmed, toConfirm,
    impact: confirmed ? "Confirmed customer-impacting issue" : "No confirmed customer impact", impactWhy,
    routingContext: device ? `${device} → ${kindLabel(routeKind) === "BGP state change" ? "BGP neighbor changed" : "routing change"} → ${peer || "peer"}` : "",
    localization: device ? `Evidence localizes to: ${device}` : "",
    evidence, actions,
  };
}

function reportHtml(r: Report, objId: string): string {
  const block = (label: string, body: string) =>
    `<section><h2>${esc(label)}</h2>${body}</section>`;
  const line = (k: string, v: string) => v ? `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>` : "";
  const verdictColor = r.verdict === "CONFIRMED" ? "#b91c1c" : "#b45309";
  const confirmed = r.verdict === "CONFIRMED";
  const now = new Date().toISOString().replace("T", " ").slice(0, 19);

  // print-safe SVG of the routing context (the live graph can't be serialized).
  const [dDev, dEdge, dPeer] = r.routingContext ? r.routingContext.split(" → ") : ["", "", ""];
  const diagram = r.device ? `<svg viewBox="0 0 600 92" width="100%" style="max-width:560px;display:block;margin:6px auto" role="img" aria-label="routing context">
    <defs><marker id="ar" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#b45309"/></marker></defs>
    <rect x="8" y="28" width="172" height="40" rx="9" fill="#eff6ff" stroke="#3b82f6" stroke-width="1.5"/>
    <text x="94" y="53" text-anchor="middle" font-size="14" font-weight="700" fill="#1e3a8a">${esc(dDev || r.device)}</text>
    <text x="300" y="40" text-anchor="middle" font-size="11.5" font-weight="600" fill="#b45309">${esc(dEdge || "routing change")}</text>
    <line x1="182" y1="50" x2="416" y2="50" stroke="#b45309" stroke-width="2" stroke-dasharray="6 4" marker-end="url(#ar)"/>
    <rect x="420" y="28" width="172" height="40" rx="9" fill="#f8fafc" stroke="#94a3b8" stroke-width="1.5"/>
    <text x="506" y="53" text-anchor="middle" font-size="12.5" font-family="ui-monospace,monospace" fill="#334155">${esc(dPeer || r.peer || "peer")}</text>
  </svg>` : "";

  // visual confidence ladder (chips), mirroring the on-screen rungs.
  const rung = (label: string, on: boolean, tone: string, locked: boolean) =>
    `<span style="font-size:12px;font-weight:700;padding:4px 13px;border-radius:18px;${on ? `background:${tone};color:#fff;border:1px solid ${tone}` : `color:#94a3b8;border:1px solid #cbd5e1`}">${locked ? "&#128274; " : on ? "&#10003; " : ""}${label}</span>`;
  const conn = `<span style="width:24px;height:2px;background:#cbd5e1"></span>`;
  const ladder = `<div style="display:flex;align-items:center;gap:0;flex-wrap:wrap">${rung("Observed", true, "#16a34a", false)}${conn}${rung("Suspected", true, "#b45309", false)}${conn}${rung("Confirmed", confirmed, "#b91c1c", !confirmed)}</div>`;

  return `<!doctype html><html><head><meta charset="utf-8"><title>RCA Report — ${esc(r.title)}</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  * { box-sizing: border-box; }
  body { font: 13px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1f2933; margin: 0; }
  .doc { max-width: 720px; margin: 0 auto; padding: 8px 0 32px; }
  header.rpt { display:flex; justify-content:space-between; align-items:flex-start; border-bottom: 2px solid #1f2933; padding-bottom: 10px; margin-bottom: 18px; }
  header.rpt .brand { font-weight: 800; letter-spacing: .5px; font-size: 13px; color:#334155; }
  header.rpt .doctype { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color:#64748b; }
  h1 { font-size: 21px; margin: 0 0 6px; }
  .badges { font-size: 12px; font-weight: 700; color: ${verdictColor}; margin-bottom: 12px; }
  section { margin: 14px 0; }
  h2 { font-size: 11px; text-transform: uppercase; letter-spacing: .8px; color:#64748b; margin: 0 0 5px; border-bottom:1px solid #e2e8f0; padding-bottom:3px; }
  .kv { display:flex; gap:10px; padding:1px 0; }
  .kv .k { color:#64748b; min-width: 130px; }
  .kv .v { color:#1f2933; font-weight:600; }
  p.body { margin: 4px 0; font-size: 14px; }
  .decision { background:#fff7ed; border:1px solid #fed7aa; border-left:3px solid ${verdictColor}; border-radius:6px; padding:9px 12px; font-weight:600; }
  .reason b { color:#b45309; }
  table { width:100%; border-collapse: collapse; font-size:12px; }
  th, td { text-align:left; padding:5px 8px; border-bottom:1px solid #e2e8f0; }
  th { color:#64748b; font-weight:700; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
  ol { margin:4px 0; padding-left: 20px; }
  ol li { margin: 3px 0; }
  footer.rpt { margin-top: 24px; border-top:1px solid #e2e8f0; padding-top:8px; font-size:10.5px; color:#94a3b8; display:flex; justify-content:space-between; }
  .toolbar { position: sticky; top: 0; z-index: 10; display:flex; gap:8px; justify-content:flex-end; padding:10px 14px; background:#f1f5f9; border-bottom:1px solid #e2e8f0; }
  .toolbar button { font:600 13px/1 inherit; padding:8px 16px; border-radius:6px; cursor:pointer; border:1px solid #cbd5e1; background:#fff; color:#1f2933; }
  .toolbar button.primary { background:#2563eb; color:#fff; border-color:#2563eb; }
  @media print { .no-print { display:none !important; } body { background:#fff; } }
</style></head><body>
  <div class="toolbar no-print">
    <button class="primary" onclick="window.print()">⤓ Save as PDF</button>
    <button onclick="window.close()">Close</button>
  </div>
  <div class="doc">
  <header class="rpt"><span class="brand">CORRELIX</span><span class="doctype">Root Cause Analysis Report</span></header>
  <h1>${esc(r.title)}</h1>
  <div class="badges">${esc(r.verdict)} · Confidence: ${esc(r.confidence)} · State: ${esc(r.state)} · Observed: ${esc(r.observed)}</div>

  ${block("Affected", line("Device", r.device) + line("Peer", r.peer) + line("Scope type", r.scopeType))}
  ${block("Decision", `<div class="decision">${esc(r.decision)}</div>`)}
  ${block("Summary", `<p class="body">${esc(r.summary)}</p>`)}
  ${block("Assessment", `<div class="reason">
    <p class="body"><b>Why suspected:</b> ${esc(r.whySuspected)}</p>
    <p class="body"><b>Why not confirmed:</b> ${esc(r.whyNotConfirmed)}</p>
    <p class="body"><b>To confirm:</b> ${esc(r.toConfirm)}</p></div>`)}
  ${block("Confidence", ladder)}
  ${block("Impact &amp; blast radius", line("Impact", r.impact) + (r.impactWhy ? `<p class="body" style="color:#64748b">Why: ${esc(r.impactWhy)}</p>` : ""))}
  ${r.routingContext ? block("Routing context", `${diagram}<div class="kv" style="justify-content:center"><span class="v">${esc(r.localization)}</span></div>`) : ""}
  ${block("Evidence", `<table><thead><tr><th>Evidence type</th><th>Covers</th><th>Status</th></tr></thead><tbody>${
    r.evidence.map((e) => `<tr><td>${esc(e.plane)}</td><td>${esc(e.detail)}</td><td>${esc(e.status)}</td></tr>`).join("")
  }</tbody></table>`)}
  ${block("Recommended next actions", `<ol>${r.actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ol>`)}

  <footer class="rpt"><span>Generated ${esc(now)} UTC · Correlix RCA</span><span>Object ${esc(objId.slice(0, 8))} · Confidential</span></footer>
</div>
<script>
  function rcaPrint(){try{window.focus();window.print();}catch(e){}}
  // wait for full layout (SVG/fonts) before printing so nothing is cut off.
  if (document.readyState === 'complete') setTimeout(rcaPrint, 400);
  else window.addEventListener('load', function(){ setTimeout(rcaPrint, 400); });
</script>
</body></html>`;
}

// exportRcaPdf renders the print-ready report and triggers the browser print
// dialog (→ Save as PDF). The report HTML self-prints via an inline script (most
// reliable for document.write content). Prefers a new tab (preview UX); falls back
// to a hidden same-origin iframe when pop-ups are blocked. Always returns true —
// one of the two paths runs. (No `noopener`: it would null the window handle.)
export function exportRcaPdf(timeline: CorrTimeline, _seams: Record<string, Seam>, owner: string, steps: string[], objId: string): boolean {
  const r = buildReport(timeline, owner, steps);
  const html = reportHtml(r, objId);

  const win = window.open("", "_blank", "width=900,height=1000");
  if (win) {
    win.document.open();
    win.document.write(html);
    win.document.close();
    return true;
  }

  // Pop-up blocked → print via a hidden iframe (no pop-up, same origin).
  const iframe = document.createElement("iframe");
  iframe.setAttribute("aria-hidden", "true");
  iframe.style.cssText = "position:fixed;right:0;bottom:0;width:0;height:0;border:0;visibility:hidden;";
  document.body.appendChild(iframe);
  const doc = iframe.contentWindow?.document;
  if (!doc) { iframe.remove(); return false; }
  doc.open();
  doc.write(html); // the inline script auto-prints the iframe's document
  doc.close();
  setTimeout(() => iframe.remove(), 60000); // clean up after the dialog is done
  return true;
}
