// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// rumSetup.model.ts — what the real-user setup page hands to the customer's
// engineer: the tag, and copy-paste rules that inject it once at a shared layer
// (load balancer, reverse proxy, CDN edge, tag manager) instead of editing
// hundreds of apps. Correlix never applies any of this itself: it does not
// write to customer systems. Pure: no React, no IO.

import type { DemRumSourcesResponse } from "../../services/api";

/** Shown in place of a key the viewer has not generated on this page. */
export const KEY_PLACEHOLDER = "YOUR-INGEST-KEY";

/** The appliance origin a browser must reach ("https://correlix.example.com"). */
export function applianceOrigin(href: string): string {
  try {
    return new URL(href).origin;
  } catch {
    return "";
  }
}

/** A key or origin as it may appear inside the tag: nothing that could close an
 *  attribute or a string in any of the rule syntaxes below. */
function safe(v: string): string {
  return v.replace(/[^A-Za-z0-9._:/~+=-]/g, "");
}

/**
 * The tag. No data-app: each page is labelled by its own host name, which is
 * what lets ONE tag serve every app behind a shared proxy. Single-quoted
 * attributes, so the same text drops into the double-quoted strings most proxy
 * configurations use.
 */
export function snippetTag(origin: string, key: string): string {
  const o = safe(origin);
  const k = safe(key) || KEY_PLACEHOLDER;
  return `<script src='${o}/correlix-rum.js' data-endpoint='${o}' data-key='${k}' defer></script>`;
}

export type InjectionRule = {
  id: string;
  /** The product, as the customer's team knows it. */
  label: string;
  /** One plain sentence: where this goes. */
  where: string;
  code: string;
};

/** Copy-paste starting points, one per common shared layer. Each inserts the
 *  tag before </head> on HTML responses only. */
export function injectionRules(origin: string, key: string): InjectionRule[] {
  const tag = snippetTag(origin, key);
  const o = safe(origin);
  const k = safe(key) || KEY_PLACEHOLDER;
  return [
    {
      id: "nginx",
      label: "NGINX",
      where: "In the server or location block that proxies your apps.",
      code: [
        "# Upstream responses must be uncompressed for sub_filter to see </head>.",
        'proxy_set_header Accept-Encoding "";',
        "sub_filter_types text/html;",
        "sub_filter_once on;",
        `sub_filter '</head>' "${tag}</head>";`,
      ].join("\n"),
    },
    {
      id: "f5",
      label: "F5 BIG-IP (iRule)",
      where: "Attach to the virtual server, which also needs a stream profile.",
      code: [
        "when HTTP_REQUEST {",
        "  HTTP::header remove Accept-Encoding",
        "  STREAM::disable",
        "}",
        "when HTTP_RESPONSE {",
        '  if { [HTTP::header value Content-Type] contains "text/html" } {',
        `    STREAM::expression {@</head>@${tag}</head>@}`,
        "    STREAM::enable",
        "  }",
        "}",
      ].join("\n"),
    },
    {
      id: "netscaler",
      label: "Citrix NetScaler (rewrite policy)",
      where: "Bind to the load-balancing virtual server, response side.",
      code: [
        `add rewrite action rw_act_correlix_rum insert_before_all "HTTP.RES.BODY(500000).SET_TEXT_MODE(IGNORECASE)" "\\"${tag}\\"" -search "text(\\"</head>\\")"`,
        'add rewrite policy rw_pol_correlix_rum "HTTP.RES.HEADER(\\"Content-Type\\").CONTAINS(\\"text/html\\")" rw_act_correlix_rum',
        "bind lb vserver YOUR-VSERVER -policyName rw_pol_correlix_rum -priority 100 -gotoPriorityExpression END -type RESPONSE",
      ].join("\n"),
    },
    {
      id: "envoy",
      label: "Envoy / Istio (Lua filter)",
      where: "Add to the HTTP filter chain of the gateway in front of your apps.",
      code: [
        "- name: envoy.filters.http.lua",
        "  typed_config:",
        '    "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua',
        "    default_source_code:",
        "      inline_string: |",
        '        function envoy_on_request(h) h:headers():remove("accept-encoding") end',
        "        function envoy_on_response(h)",
        '          local ct = h:headers():get("content-type") or ""',
        '          if not string.find(ct, "text/html", 1, true) then return end',
        "          local body = h:body()",
        "          if body == nil then return end",
        `          local tag = "${tag}"`,
        '          local out, n = string.gsub(body:getBytes(0, body:length()), "</head>", tag .. "</head>", 1)',
        '          if n > 0 then body:setBytes(out); h:headers():remove("content-length") end',
        "        end",
      ].join("\n"),
    },
    {
      id: "cloudflare",
      label: "Cloudflare (Worker)",
      where: "Deploy as a Worker on the routes that serve your apps.",
      code: [
        `const TAG = "${tag}";`,
        "export default {",
        "  async fetch(request) {",
        "    const res = await fetch(request);",
        '    if (!(res.headers.get("content-type") || "").includes("text/html")) return res;',
        '    return new HTMLRewriter().on("head", { element(e) { e.append(TAG, { html: true }); } }).transform(res);',
        "  },",
        "};",
      ].join("\n"),
    },
    {
      id: "akamai",
      label: "Akamai (EdgeWorker)",
      where: "Add as an EdgeWorker on the property that serves your apps.",
      code: [
        "import { HtmlRewritingStream } from 'html-rewriter';",
        "import { httpRequest } from 'http-request';",
        "import { createResponse } from 'create-response';",
        `const TAG = "${tag}";`,
        "export async function responseProvider(request) {",
        "  const response = await httpRequest(`${request.scheme}://${request.host}${request.url}`);",
        "  const rewriter = new HtmlRewritingStream();",
        "  rewriter.onElement('head', (el) => el.append(TAG));",
        "  return createResponse(response.status, response.getHeaders(), response.body.pipeThrough(rewriter));",
        "}",
      ].join("\n"),
    },
    {
      id: "gtm",
      label: "Google Tag Manager",
      where: "A Custom HTML tag, fired on All Pages, in the container your apps share.",
      code: [
        `<script>window.CorrelixRUM = { endpoint: "${o}", key: "${k}" };</script>`,
        `<script src="${o}/correlix-rum.js" defer></script>`,
      ].join("\n"),
    },
  ];
}

/** The Content-Security-Policy additions an app with a strict policy needs. */
export function cspLines(origin: string): string[] {
  const o = safe(origin);
  return [`script-src ${o}`, `connect-src ${o}`];
}

/** One sentence for the "Is it working?" step. */
export function sourcesSummary(r: DemRumSourcesResponse | null): string {
  if (!r) return "";
  if (r.status === "unavailable") return "The real-user store could not be read just now, so this cannot say whether data is arriving.";
  if (r.restricted) return "This tenant's real-user data is hidden from you.";
  if (r.sources.length === 0) return "No app has sent real-user data in the last 7 days.";
  const parts = [`${r.reporting} ${r.reporting === 1 ? "app is" : "apps are"} sending real-user data`];
  if (r.quiet > 0) parts.push(`${r.quiet} went quiet (nothing in the last 24 hours)`);
  return parts.join("; ") + (r.truncated ? ". Showing the first 500." : ".");
}

/** How an app was labelled, in plain words. */
export function labelledBy(src: string): string {
  if (src === "attribute") return "Named on the page";
  if (src === "hostname") return "Named by its web address";
  return "Not stated";
}
