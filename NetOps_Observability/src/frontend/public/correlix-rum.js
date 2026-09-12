// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

/*
 * correlix-rum.js — Correlix first-party Real User Monitoring beacon.
 *
 * WHAT IT IS. ~7 KB of dependency-free browser JavaScript that posts
 * ExperienceEvents to your own Correlix deployment. There is no third party in
 * the path: the events go to your API, land on your bus and are stored in your
 * ClickHouse, under your tenant's row policy and your retention.
 *
 * WHAT IT DELIBERATELY DOES NOT DO.
 *   - It never reads cookies, localStorage, form fields or the URL's query
 *     string. `user_ref`, if you set one, is a PSEUDONYMOUS reference YOU hash
 *     per tenant before handing it over; the API refuses anything that looks
 *     like a direct identifier (an "@", a phone prefix) rather than silently
 *     hashing your mistake.
 *   - It records no DOM, no session replay and no page content.
 *   - It honours Do Not Track and Global Privacy Control: with either set it
 *     collects nothing and says so on the console once.
 *
 * INSTALL
 *   <script src="/correlix-rum.js"
 *           data-endpoint="https://correlix.example.com"
 *           data-key="cx_..."          <!-- an ingest:experience API key -->
 *           data-app="checkout"
 *           data-environment="production"
 *           data-release="2026.09.06"
 *           defer></script>
 *
 * THE KEY IS PUBLIC, AND THAT IS THE DESIGN. Anything in a page served to the
 * public must be assumed public. Mint a key with the `ingest:experience` scope
 * ONLY: it is write-only, bound to one tenant, and cannot read a single row of
 * anything. Never paste an operator token here.
 *
 * CROSS-ORIGIN. Your app and Correlix are usually different origins, so add
 * your app's origin to CORS_ALLOWED_ORIGINS on the deployment. Correlix
 * reflects only explicitly allowlisted origins — never a wildcard — so the
 * beacon fails loudly on a misconfiguration rather than half-working.
 *
 * MANUAL EVENTS
 *   window.correlixRum.track({ type: "journey_step", journey_id: "jny-…",
 *                              step_id: "pay", success: true, duration_ms: 812 });
 *   window.correlixRum.business({ business_event_type: "purchase",
 *                                 success: true, value: 42.5, currency: "USD" });
 */
(function () {
  "use strict";

  var script = document.currentScript;
  var cfg = window.CorrelixRUM || {};
  function opt(name, fallback) {
    if (cfg[name] !== undefined && cfg[name] !== null) return cfg[name];
    if (script && script.dataset && script.dataset[name] !== undefined) return script.dataset[name];
    return fallback;
  }

  var endpoint = String(opt("endpoint", "")).replace(/\/+$/, "");
  var key = String(opt("key", ""));
  var app = String(opt("app", ""));
  var environment = String(opt("environment", ""));
  var release = String(opt("release", ""));
  var userRef = String(opt("userRef", ""));
  var sampleRate = Number(opt("sampleRate", 1));

  // Privacy first: a browser that has asked not to be measured is not measured.
  var nav = window.navigator || {};
  if (nav.doNotTrack === "1" || window.doNotTrack === "1" || nav.globalPrivacyControl === true) {
    if (window.console) console.info("correlix-rum: Do Not Track is set; no experience events are collected.");
    return;
  }
  if (!endpoint || !key || !app) {
    // Fail LOUDLY and once. A beacon that silently collects nothing is
    // indistinguishable from an application nobody is having trouble with.
    if (window.console) console.warn("correlix-rum: endpoint, key and app are all required; nothing will be sent.");
    return;
  }
  if (!(sampleRate > 0)) return;
  if (sampleRate < 1 && Math.random() >= sampleRate) return;

  // ── bounded state (§9: nothing here may grow without limit) ───────────────
  var MAX_QUEUE = 100;   // events held before a flush; the oldest are dropped
  var MAX_BATCH = 50;    // events per request; the API caps a batch at 200
  var FLUSH_MS = 10000;  // idle flush cadence
  var queue = [];
  var businessQueue = [];
  var dropped = 0;
  var sessionId = uuid();

  function uuid() {
    if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID();
    var b = new Uint8Array(16);
    (window.crypto || {}).getRandomValues ? window.crypto.getRandomValues(b) : b.forEach(function (_, i) { b[i] = Math.floor(Math.random() * 256); });
    var s = "";
    for (var i = 0; i < 16; i++) s += ("0" + b[i].toString(16)).slice(-2);
    return s;
  }

  // route() strips the query string and any path segment that looks like an
  // identifier, so "/orders/1f9c/pay" becomes "/orders/:id/pay". A route that
  // carried an order number would be both a cardinality explosion and a
  // customer-data leak into a label, and the backend clips the label but never
  // scrubs it — this is the only place it can be done.
  //
  // The old rule redacted all-digit segments and hex runs of EIGHT OR MORE
  // characters, so it let through exactly the example above ("1f9c" is four)
  // along with every short token, id fragment and "user@host" segment. The rule
  // is now default-closed: a segment is KEPT only when it reads as a route
  // word, and anything else becomes :id.
  //
  // Known limit, stated rather than implied: a segment of pure letters is kept,
  // so "/users/jsmith" keeps the name. Shape cannot tell a username from a page
  // name; put ids in the segments this function redacts.
  function route(pathname) {
    return String(pathname || "/")
      .split("?")[0]
      .split("#")[0]
      .split("/")
      .map(function (seg) {
        if (!seg) return seg;
        if (/^v[0-9]+$/i.test(seg)) return seg;          // an API version is a route word
        if (/[0-9]/.test(seg)) return ":id";             // ANY digit: ids, dates, order numbers
        if (seg.length > 24) return ":id";               // a long opaque token
        if (!/^[A-Za-z][A-Za-z._~-]*$/.test(seg)) return ":id"; // anything that is not a plain word
        return seg;
      })
      .join("/");
  }

  function cohort() {
    var c = {};
    var conn = nav.connection || {};
    if (conn.type === "wifi" || conn.type === "cellular" || conn.type === "ethernet") {
      c.network_type = conn.type === "ethernet" ? "wired" : conn.type;
    }
    if (release) c.app_version = release;
    // Browser family only — never the full user-agent string, which is a
    // fingerprint. The family is what a cohort comparison actually needs.
    var ua = String(nav.userAgent || "");
    c.browser = /Edg\//.test(ua) ? "edge"
      : /Chrome\//.test(ua) ? "chrome"
      : /Firefox\//.test(ua) ? "firefox"
      : /Safari\//.test(ua) ? "safari" : "other";
    if (cfg.cohort && typeof cfg.cohort === "object") {
      for (var k in cfg.cohort) if (Object.prototype.hasOwnProperty.call(cfg.cohort, k)) c[k] = String(cfg.cohort[k]);
    }
    return c;
  }

  function enqueue(list, ev) {
    if (list.length >= MAX_QUEUE) {
      // The OLDEST is dropped and the loss is COUNTED, then reported on the
      // next successful flush. A silent drop would make a broken lane look
      // like a healthy application.
      list.shift();
      dropped++;
    }
    list.push(ev);
  }

  function track(partial) {
    var ev = {
      id: uuid(),
      session_id: sessionId,
      app: app,
      environment: environment || undefined,
      release: release || undefined,
      type: partial.type || "interaction",
      success: partial.success !== false,
      cohort: cohort(),
      event_at: new Date().toISOString()
    };
    if (userRef) ev.user_ref = userRef;
    ["action", "route", "duration_ms", "error", "status_code", "journey_id",
      "step_id", "trace_id", "span_id", "vitals", "feature_flags",
      "business_context", "actor_type"].forEach(function (f) {
      if (partial[f] !== undefined && partial[f] !== null) ev[f] = partial[f];
    });
    if (!ev.route) ev.route = route(location.pathname);
    enqueue(queue, ev);
    if (queue.length >= MAX_BATCH) flush();
  }

  function business(partial) {
    var ev = {
      id: uuid(),
      session_id: sessionId,
      app: app,
      business_event_type: String(partial.business_event_type || ""),
      success: partial.success !== false,
      cohort: cohort(),
      event_at: new Date().toISOString()
    };
    ["value", "currency", "quantity", "journey_id", "attributes"].forEach(function (f) {
      if (partial[f] !== undefined && partial[f] !== null) ev[f] = partial[f];
    });
    enqueue(businessQueue, ev);
  }

  // ── delivery health ───────────────────────────────────────────────────────
  // A failed POST is one of two things and they need opposite answers.
  //
  // RETRYABLE: the endpoint is there and busy or briefly broken (503 from the
  // API's bounded queue, 429, 408, any 5xx, or no answer at all because the
  // browser is offline). Keep the batch, back off, try again.
  //
  // PERMANENT: the request itself is wrong and every retry will be wrong the
  // same way — a refused key (401/403), a body the API will not decode (400,
  // which is what a custom CorrelixRUM.cohort key produces, because the API
  // decodes the cohort with DisallowUnknownFields), a wrong endpoint (404).
  // Retrying that forever is how an installer ends up unable to tell a healthy
  // application from a broken key: nothing on the console, nothing in Correlix.
  // Say what it is, once, and stop.
  var MAX_BACKOFF_MS = 60000;
  var backoffMs = 0;
  var retryAfter = 0;
  var halted = false;
  var said = {};

  function say(kind, msg) {
    if (said[kind] || !window.console) return;
    said[kind] = true;
    var write = kind === "halt" && console.error ? console.error : console.warn;
    write.call(console, "correlix-rum: " + msg);
  }

  function listFor(path) { return path === "/api/dem/events" ? queue : businessQueue; }

  // requeue puts a spliced batch back, through the SAME bounded enqueue the
  // rest of the beacon uses, so a batch is never silently thrown away and the
  // queue can still never grow without limit.
  function requeue(path, events) {
    var list = listFor(path);
    for (var i = 0; i < events.length; i++) enqueue(list, events[i]);
  }

  function retryLater(what) {
    backoffMs = backoffMs ? Math.min(backoffMs * 2, MAX_BACKOFF_MS) : 1000;
    retryAfter = Date.now() + Math.round(backoffMs * (0.5 + Math.random()));
    say("retry", what + " The batch is kept and will be retried with backoff.");
  }

  function halt(status, lost) {
    halted = true;
    var why;
    if (status === 401 || status === 403) {
      why = "the ingest key was refused (HTTP " + status + "). Mint a key with the ingest:experience scope for this tenant and set data-key to it.";
    } else if (status === 400) {
      why = "the endpoint refused the batch as malformed (HTTP 400). The usual cause is a CorrelixRUM.cohort key the API does not define; the accepted keys are site, isp, region, device_type, browser, app_version, network_type and feature_flag.";
    } else if (status === 404) {
      why = "no ingest endpoint at " + endpoint + " (HTTP 404). Check data-endpoint.";
    } else if (status === 413) {
      why = "the endpoint rejected the batch as too large (HTTP 413).";
    } else {
      why = "the endpoint answered HTTP " + status + " and will answer the same for every batch.";
    }
    say("halt", why + " Collection has STOPPED and " + lost + " events were discarded.");
    queue.length = 0;
    businessQueue.length = 0;
    dropped = 0;
  }

  function post(path, events) {
    if (!events.length) return;
    var body = JSON.stringify({ events: events });
    var url = endpoint + path;
    // fetch(keepalive) rather than navigator.sendBeacon, deliberately.
    // sendBeacon cannot carry an Authorization header, so using it would mean
    // putting the ingest key in the URL — and a credential in a URL lands in
    // every access log, proxy log and Referer between here and the API. The
    // key being public by design is not a reason to also make it durable.
    // keepalive survives unload for bodies under 64 KiB, which a bounded batch
    // always is.
    fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + key },
      body: body,
      keepalive: true,
      mode: "cors",
      credentials: "omit"
    }).then(function (res) {
      var status = res && res.status;
      if (status >= 200 && status < 300) {
        backoffMs = 0;
        retryAfter = 0;
        return;
      }
      if (status === 408 || status === 429 || status >= 500) {
        requeue(path, events);
        retryLater("the endpoint answered HTTP " + status + ".");
        return;
      }
      halt(status, events.length + queue.length + businessQueue.length);
    }).catch(function () {
      // No answer at all: offline, DNS, or a CORS preflight the deployment has
      // not allowed. All three can come back, so this is retryable.
      requeue(path, events);
      retryLater("could not reach " + endpoint + " (offline, or this origin is not in CORS_ALLOWED_ORIGINS).");
    });
  }

  function flush() {
    if (halted) return;
    if (retryAfter && Date.now() < retryAfter) return;
    if (dropped > 0 && queue.length < MAX_QUEUE) {
      queue.push({
        id: uuid(), session_id: sessionId, app: app, type: "error", success: false,
        action: "correlix_rum_queue_overflow", error: dropped + " experience events were dropped by the browser queue",
        cohort: cohort(), event_at: new Date().toISOString()
      });
      dropped = 0;
    }
    while (queue.length) post("/api/dem/events", queue.splice(0, MAX_BATCH));
    while (businessQueue.length) post("/api/dem/business-events", businessQueue.splice(0, MAX_BATCH));
  }

  // ── automatic collection ──────────────────────────────────────────────────

  function observe(type, cb) {
    if (!window.PerformanceObserver) return;
    try {
      var po = new PerformanceObserver(function (list) { list.getEntries().forEach(cb); });
      po.observe({ type: type, buffered: true });
    } catch (e) { /* an unsupported entry type is a missing measurement, not an error */ }
  }

  var vitals = {};
  observe("largest-contentful-paint", function (e) { vitals.lcp_ms = e.startTime; });
  observe("paint", function (e) { if (e.name === "first-contentful-paint") vitals.fcp_ms = e.startTime; });
  observe("layout-shift", function (e) { if (!e.hadRecentInput) vitals.cls = (vitals.cls || 0) + e.value; });
  observe("event", function (e) { if (e.duration > (vitals.inp_ms || 0)) vitals.inp_ms = e.duration; });

  window.addEventListener("load", function () {
    var navEntry = (performance.getEntriesByType && performance.getEntriesByType("navigation")[0]) || null;
    if (navEntry) vitals.ttfb_ms = navEntry.responseStart;
    track({
      type: "page_view",
      action: "load",
      duration_ms: navEntry ? navEntry.duration : undefined,
      vitals: Object.keys(vitals).length ? vitals : undefined
    });
  });

  window.addEventListener("error", function (e) {
    // The MESSAGE only — never the stack, which routinely contains query
    // strings and inlined values.
    track({ type: "error", success: false, action: "window_error", error: String((e && e.message) || "error") });
  });
  window.addEventListener("unhandledrejection", function () {
    track({ type: "error", success: false, action: "unhandled_rejection", error: "unhandled promise rejection" });
  });

  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") {
      // Re-send the vitals with their final values: LCP and CLS are only known
      // when the page stops being looked at.
      if (Object.keys(vitals).length) track({ type: "web_vital", action: "final", vitals: vitals });
      flush();
    }
  });
  window.addEventListener("pagehide", function () { flush(); });
  setInterval(function () { flush(); }, FLUSH_MS);

  window.correlixRum = { track: track, business: business, flush: function () { flush(); }, sessionId: sessionId };
})();
