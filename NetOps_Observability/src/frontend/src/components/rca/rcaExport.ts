import type { RcaCase, RcaPill, KV, Tone } from "./rcaCase";

// rcaExport — generates an elegant, light-themed, print-ready RCA report and
// opens it for the browser's "Save as PDF". No PDF dependency: a self-contained
// HTML document + print CSS.
//
// SINGLE SOURCE OF TRUTH: the report is rendered from the SAME `RcaCase` the
// on-screen workspace renders (see rcaCase.ts / RcaWorkspace.tsx), so the PDF
// always matches the page and includes every section — summary, impact, causal
// topology, evidence matrix, confidence ladder, hypothesis ranking, ticket, and
// next actions. The product name appears only in the report header/footer
// metadata (allowed in exports), never in the operator narrative.

const esc = (s: string) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

// tone → print colour (matches the on-screen .rca-ws palette)
const TONE: Record<Tone, { fg: string; bg: string; bd: string }> = {
  green: { fg: "#0f9f4f", bg: "#eafaf1", bd: "#bfeccf" },
  orange: { fg: "#d66a00", bg: "#fff4e8", bd: "#ffd3a9" },
  blue: { fg: "#2563eb", bg: "#eef4ff", bd: "#c9dbff" },
  red: { fg: "#d92d20", bg: "#fff0ee", bd: "#ffd0cc" },
  gray: { fg: "#667085", bg: "#eef1f6", bd: "#d8dee8" },
  purple: { fg: "#6d5dfc", bg: "#f3f1ff", bd: "#ddd7ff" },
};
const NODE: Record<string, { fg: string; bg: string; bd: string }> = {
  good: { fg: "#087c3d", bg: "#effcf4", bd: "#1aaf5d" },
  warn: { fg: "#c45a00", bg: "#fff7ed", bd: "#f59e0b" },
  bad: { fg: "#c5221a", bg: "#fff1f1", bd: "#ef4444" },
  info: { fg: "#2563eb", bg: "#eff6ff", bd: "#3b82f6" },
};
const EDGE: Record<string, string> = { good: "#22c55e", warn: "#f59e0b", bad: "#ef4444" };

const pill = (p: RcaPill) => {
  const t = TONE[p.tone] ?? TONE.gray;
  return `<span style="font-size:11px;font-weight:800;padding:3px 8px;border-radius:7px;background:${t.bg};color:${t.fg};border:1px solid ${t.bd};white-space:nowrap">${esc(p.text)}</span>`;
};
const kvRows = (rows: KV[]) => rows.map((r) =>
  `<div class="kv"><span class="k">${esc(r.k)}</span><span class="v"${r.mono ? ' style="font-family:ui-monospace,monospace"' : ""}>${esc(r.v)}</span></div>`).join("");
const block = (label: string, body: string) => body ? `<section><h2>${esc(label)}</h2>${body}</section>` : "";

// Causal-topology SVG — a horizontal node chain (1..N), print-safe (the live
// React-Flow canvas can't be serialized). Mirrors the workspace's node colours.
function topoSvg(topo: RcaCase["topology"]): string {
  if (!topo || topo.nodes.length === 0) return "";
  const nodes = topo.nodes, edges = topo.edges;
  const NW = 150, GAP = 64, PADX = 8, NY = 34, NH = 46;
  const width = PADX * 2 + nodes.length * NW + (nodes.length - 1) * GAP;
  const cx = (i: number) => PADX + i * (NW + GAP);
  let parts = "";
  // edges first (under nodes)
  for (let i = 0; i < nodes.length - 1; i++) {
    const e = edges[i]; const col = EDGE[e?.state ?? "good"] ?? "#cad5e5";
    const x1 = cx(i) + NW, x2 = cx(i + 1), midY = NY + NH / 2;
    const dash = e?.state === "good" ? "" : ' stroke-dasharray="6 4"';
    parts += `<line x1="${x1}" y1="${midY}" x2="${x2}" y2="${midY}" stroke="${col}" stroke-width="${e?.state === "good" ? 2 : 3}"${dash}/>`;
    if (e?.label) {
      const lx = (x1 + x2) / 2, ly = (e.side === 1 ? midY + 22 : midY - 12);
      parts += `<text x="${lx}" y="${ly}" text-anchor="middle" font-size="10.5" font-weight="700" fill="${col}">${esc(e.label)}</text>`;
    }
  }
  // nodes
  nodes.forEach((nd, i) => {
    const c = NODE[nd.kind] ?? NODE.info; const x = cx(i);
    parts += `<rect x="${x}" y="${NY}" width="${NW}" height="${NH}" rx="10" fill="${c.bg}" stroke="${c.bd}" stroke-width="1.6"/>`;
    parts += `<text x="${x + NW / 2}" y="${NY + 19}" text-anchor="middle" font-size="12.5" font-weight="800" fill="${c.fg}">${esc(nd.name)}</text>`;
    parts += `<text x="${x + NW / 2}" y="${NY + 35}" text-anchor="middle" font-size="10" fill="#697386">${esc(nd.meta)}</text>`;
    if (nd.tag) {
      const t = TONE[nd.tag.tone] ?? TONE.gray;
      parts += `<text x="${x + NW / 2}" y="${NY + NH + 14}" text-anchor="middle" font-size="9.5" font-weight="800" fill="${t.fg}">${esc(nd.tag.text)}</text>`;
    }
  });
  return `<svg viewBox="0 0 ${width} ${NY + NH + 24}" width="100%" style="max-width:${Math.min(width, 680)}px;display:block;margin:4px auto" role="img" aria-label="Causal topology">${parts}</svg>`;
}

function reportHtml(d: RcaCase, objId: string): string {
  const now = new Date().toISOString().replace("T", " ").slice(0, 19);

  const why = d.why.map((w) => {
    const t = TONE[w.tone] ?? TONE.orange;
    return `<p class="body"><b style="color:${t.fg}">${esc(w.label)}:</b> ${esc(w.text)}</p>`;
  }).join("");

  const ladder = `<div style="display:flex;align-items:center;gap:0;flex-wrap:wrap">${
    d.ladder.map((s, i) => {
      const tone = s.state === "done" ? "#16a34a" : s.state === "active" ? "#d66a00" : "#94a3b8";
      const on = s.state !== "next";
      const chip = `<span style="font-size:11.5px;font-weight:700;padding:4px 12px;border-radius:18px;${on ? `background:${tone};color:#fff;border:1px solid ${tone}` : "color:#94a3b8;border:1px solid #cbd5e1"}">${esc(s.label)}</span>`;
      const conn = i < d.ladder.length - 1 ? `<span style="width:20px;height:2px;background:#cbd5e1"></span>` : "";
      return chip + conn;
    }).join("")
  }</div>`;

  const evidence = `<table><thead><tr><th>Evidence type</th><th>Covers</th><th>Finding</th><th>Status</th></tr></thead><tbody>${
    d.evidence.map((e) => `<tr><td>${esc(e.title)}</td><td style="color:#64748b">${esc(e.desc)}</td><td>${esc(e.finding)}</td><td>${pill(e.pill)}</td></tr>`).join("")
  }</tbody></table>`;

  const hypotheses = d.hypotheses.length ? `<table><thead><tr><th>Rank</th><th>Hypothesis</th><th>Confidence</th><th>Reason</th></tr></thead><tbody>${
    d.hypotheses.map((h) => `<tr><td style="font-family:ui-monospace,monospace;font-weight:800">${esc(h.rank)}</td><td><b>${esc(h.hypo)}</b><div style="color:#697386;font-size:11px">${esc(h.sub)}</div></td><td>${pill(h.conf)}</td><td>${esc(h.reason)}</td></tr>`).join("")
  }</tbody></table>` : "";

  const ticket = `<div class="decision" style="${d.ticket.callout.tone === "red" ? "border-left-color:#b91c1c" : d.ticket.callout.tone === "confirmed" ? "border-left-color:#0f9f4f;background:#f2fbf6;border-color:#b9e5c7" : ""}"><b>${esc(d.ticket.callout.strong)}</b> ${esc(d.ticket.callout.text)}</div>${kvRows(d.ticket.rows)}`;

  const actions = `<ol>${d.nextActions.map((a) => `<li><b>${esc(a.badge)}</b> — ${esc(a.text)}</li>`).join("")}</ol>`;

  return `<!doctype html><html><head><meta charset="utf-8"><title>RCA Report — ${esc(d.title)}</title>
<style>
  @page { size: A4; margin: 16mm 14mm; }
  * { box-sizing: border-box; }
  body { font: 13px/1.5 Inter, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #172033; margin: 0; }
  .doc { max-width: 740px; margin: 0 auto; padding: 8px 0 32px; }
  header.rpt { display:flex; justify-content:space-between; align-items:flex-start; border-bottom: 2px solid #172033; padding-bottom: 10px; margin-bottom: 16px; }
  header.rpt .brand { font-weight: 800; letter-spacing: .5px; font-size: 13px; color:#334155; }
  header.rpt .doctype { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color:#64748b; }
  h1 { font-size: 21px; margin: 0 0 8px; }
  .badges { display:flex; gap:6px; flex-wrap:wrap; align-items:center; margin-bottom: 8px; }
  .meta { font-size:11.5px; color:#64748b; margin-bottom: 12px; }
  .meta b { color:#172033; font-family:ui-monospace,monospace; }
  section { margin: 13px 0; }
  h2 { font-size: 11px; text-transform: uppercase; letter-spacing: .7px; color:#64748b; margin: 0 0 6px; border-bottom:1px solid #e2e8f0; padding-bottom:3px; }
  .kv { display:flex; gap:10px; padding:1px 0; }
  .kv .k { color:#64748b; min-width: 150px; }
  .kv .v { color:#172033; font-weight:600; }
  p.body { margin: 3px 0; }
  .decision { background:#fff7ed; border:1px solid #fed7aa; border-left:3px solid #d66a00; border-radius:6px; padding:9px 12px; margin-bottom:6px; }
  table { width:100%; border-collapse: collapse; font-size:12px; }
  th, td { text-align:left; padding:5px 8px; border-bottom:1px solid #e2e8f0; vertical-align:top; }
  th { color:#64748b; font-weight:700; font-size:10.5px; text-transform:uppercase; letter-spacing:.5px; background:#f8fafc; }
  ol { margin:4px 0; padding-left: 20px; } ol li { margin: 3px 0; }
  ol li b { color:#1d55d7; font-size:11px; }
  footer.rpt { margin-top: 22px; border-top:1px solid #e2e8f0; padding-top:8px; font-size:10.5px; color:#94a3b8; display:flex; justify-content:space-between; }
  .toolbar { position: sticky; top: 0; z-index: 10; display:flex; gap:8px; justify-content:flex-end; padding:10px 14px; background:#f1f5f9; border-bottom:1px solid #e2e8f0; }
  .toolbar button { font:600 13px/1 inherit; padding:8px 16px; border-radius:6px; cursor:pointer; border:1px solid #cbd5e1; background:#fff; color:#172033; }
  .toolbar button.primary { background:#4f46e5; color:#fff; border-color:#4f46e5; }
  @media print { .no-print { display:none !important; } body { background:#fff; } section { break-inside: avoid; page-break-inside: avoid; } svg { max-width:100%; } table { break-inside:auto; } }
</style></head><body>
  <div class="toolbar no-print">
    <button id="rca-save" class="primary">⤓ Save as PDF</button>
    <button id="rca-close">Close</button>
  </div>
  <div class="doc">
  <header class="rpt"><span class="brand">CORRELIX</span><span class="doctype">Root Cause Analysis Report</span></header>
  <h1>${esc(d.title)}</h1>
  <div class="badges">${d.pills.map(pill).join("")}</div>
  <div class="meta">Observed at: <b>${esc(d.observedAt)}</b> &middot; RCA ID: <b>${esc(d.rcaId)}</b></div>

  ${d.decision.text ? block("Decision", `<div class="decision"${d.decision.tone === "confirmed" ? ' style="border-left-color:#0f9f4f;background:#f2fbf6;border-color:#b9e5c7"' : ""}>${esc(d.decision.text)}</div>`) : ""}
  ${block("Case", kvRows(d.aside))}
  ${block("Executive summary", `<p class="body">${esc(d.summary)}</p>${why}`)}
  ${block("Impact &amp; blast radius", kvRows(d.impact))}
  ${block("Causal topology", topoSvg(d.topology))}
  ${block("Evidence matrix", evidence)}
  ${block("Confidence ladder", ladder)}
  ${block("Hypothesis ranking", hypotheses)}
  ${block("Ticket &amp; escalation", ticket)}
  ${block("Next actions", actions)}

  <footer class="rpt"><span>Generated ${esc(now)} UTC &middot; Correlix RCA</span><span>Object ${esc(objId.slice(0, 8))} &middot; Confidential</span></footer>
</div>
</body></html>`;
  // NB: no inline <script>/onclick — the app CSP (script-src 'self') blocks inline
  // script in the popup. The parent wires the buttons + print via the DOM API below.
}

// exportRcaPdf renders the print-ready report from the RcaCase and opens it for
// "Save as PDF". Prefers a new tab (preview + working toolbar); falls back to a
// real-size off-screen iframe when pop-ups are blocked. Always returns true.
export function exportRcaPdf(data: RcaCase, objId: string): boolean {
  const html = reportHtml(data, objId);

  const win = window.open("", "_blank", "width=920,height=1040");
  if (win) {
    win.document.open();
    win.document.write(html);
    win.document.close();
    const wire = () => {
      try {
        const dd = win.document;
        dd.getElementById("rca-save")?.addEventListener("click", () => { win.focus(); win.print(); });
        dd.getElementById("rca-close")?.addEventListener("click", () => win.close());
      } catch { /* same-origin — fine */ }
    };
    wire();
    win.addEventListener("load", wire);
    win.focus();
    return true;
  }

  // Pop-up blocked → real-size off-screen iframe (a 0×0 iframe clips the print).
  const iframe = document.createElement("iframe");
  iframe.setAttribute("aria-hidden", "true");
  iframe.style.cssText = "position:fixed;left:-10000px;top:0;width:820px;height:1160px;border:0;";
  document.body.appendChild(iframe);
  const cw = iframe.contentWindow;
  const doc = cw?.document;
  if (!cw || !doc) { iframe.remove(); return false; }
  doc.open();
  doc.write(html);
  doc.close();
  const printIframe = () => { try { cw.focus(); cw.print(); } catch { /* ignore */ } };
  iframe.addEventListener("load", () => setTimeout(printIframe, 400));
  setTimeout(printIframe, 700);
  setTimeout(() => iframe.remove(), 60000);
  return true;
}
