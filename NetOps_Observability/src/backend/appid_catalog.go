package main

// appid_catalog.go — Application Identification resolver wiring (#81 P1). Loads the
// free, vendor-published IP-range feeds (AWS/Azure/GCP/M365) from an opt-in on-disk
// snapshot dir into an in-memory LPM catalog, swapped atomically (the EntityResolver
// hot-reload pattern), and serves a resolve API.
//
//   GET /api/appid/resolve?ip=<addr>   → app Verdict for a destination IP
//   GET /api/appid/status              → catalog size + whether feeds are configured
//
// The catalog is GLOBAL public data (vendor ranges are the same for every tenant),
// so the resolver does not vary by tenant yet — per-tenant overrides (app_catalog
// rows with a tenant_id) and the flow→app aggregation land in P1b. Fetching the
// feeds is out-of-band + opt-in (scripts/fetch-appid-feeds.sh); with no APPID_FEEDS_DIR
// the catalog is empty and every resolve is the honest first-class "unknown".

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"netops/backend/appid"
)

// appCatalogHolder carries the current catalog behind an atomic pointer for
// lock-free reads + atomic reload.
type appCatalogHolder struct {
	cur      atomic.Pointer[appid.Catalog]
	dom      atomic.Pointer[appid.DomainIndex] // global domain matcher (#81 P2, from M365 urls)
	feedsDir string
}

func newAppCatalogHolder() *appCatalogHolder {
	h := &appCatalogHolder{feedsDir: os.Getenv("APPID_FEEDS_DIR")}
	h.cur.Store(appid.NewCatalog(nil)) // empty until loaded; resolve is safe + unknown
	h.dom.Store(appid.NewDomainIndex())
	return h
}

func (h *appCatalogHolder) get() *appid.Catalog         { return h.cur.Load() }
func (h *appCatalogHolder) domains() *appid.DomainIndex { return h.dom.Load() }

// feedParsers maps a snapshot filename to its parser.
var feedParsers = []struct {
	file  string
	parse func([]byte) ([]appid.CatalogEntry, error)
}{
	{"aws.json", appid.ParseAWS},
	{"azure.json", appid.ParseAzure},
	{"gcp.json", appid.ParseGCP},
	{"m365.json", appid.ParseM365},
}

// reload rebuilds the catalog from the snapshot dir and swaps it in. Missing or
// unparseable files are skipped (best-effort, offline-safe); returns the new size.
// A per-file error is logged via the returned slice, never fatal.
func (h *appCatalogHolder) reload() (int, []error) {
	if h.feedsDir == "" {
		return 0, nil
	}
	var entries []appid.CatalogEntry
	var errs []error
	for _, fp := range feedParsers {
		raw, err := os.ReadFile(filepath.Join(h.feedsDir, fp.file))
		if err != nil {
			continue // feed not present — fine
		}
		es, perr := fp.parse(raw)
		if perr != nil {
			errs = append(errs, perr)
			continue
		}
		entries = append(entries, es...)
	}
	cat := appid.NewCatalog(entries)
	h.cur.Store(cat)
	// #81 P2: build the global domain matcher from the M365 endpoints feed's urls[].
	di := appid.NewDomainIndex()
	if raw, err := os.ReadFile(filepath.Join(h.feedsDir, "m365.json")); err == nil {
		if des, e := appid.M365Domains(raw); e == nil {
			for _, de := range des {
				di.Add(de.Pattern, de.App, appid.SrcDNS, 0) // a domain is a strong signal
			}
		}
	}
	h.dom.Store(di)
	return cat.Size(), errs
}

// startRefresh periodically re-reads the snapshot dir and hot-swaps the catalog,
// so an out-of-band feed refresh (cron running fetch-appid-feeds.sh) is picked up
// without an API restart. No-op unless feeds are configured. Interval from
// APPID_REFRESH_MINUTES (default 360 = 6h; ≤0 disables). The initial load already
// happened synchronously in newServer.
func (h *appCatalogHolder) startRefresh(ctx context.Context) {
	if h.feedsDir == "" {
		return
	}
	mins := envInt("APPID_REFRESH_MINUTES", 360)
	if mins <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(time.Duration(mins) * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n, errs := h.reload()
				if len(errs) > 0 {
					log.Printf("appid: refreshed catalog to %d prefixes (%d feed errors)", n, len(errs))
				}
			}
		}
	}()
}

// ── handlers ──────────────────────────────────────────────────────────────────

// keyAppSignals gathers every identification signal for one record key. An IP
// key consults the global vendor catalog + the tenant's operator prefix
// overrides; ANY key (IP, ENI, cloud resource id, …) additionally consults the
// NGFW app-id and cloud identity-map resolvers, which match exact keys. This is
// the ONE gather path shared by the single resolve, batch resolve and feed
// enrichment — a new source added here lands everywhere at once (#81 P3G).
// Nil-safe on every optional subsystem; tenant-scoped default-closed.
func (s *server) keyAppSignals(tenant string, cross bool, ov tenantOverrides, key string) []appid.Signal {
	var signals []appid.Signal
	if ip, err := netip.ParseAddr(key); err == nil {
		if s.appCatalog != nil {
			signals = append(signals, s.appCatalog.get().SignalsFor(ip)...)
		}
		signals = append(signals, ov.prefixes.SignalsFor(ip)...)
	}
	if sig, has := s.ngfw.signalFor(tenant, cross, key); has {
		signals = append(signals, sig)
	}
	// cloud inventory identity-map (private IP / resource → app) — the
	// authoritative cloud identity, consumed for every key shape (#81 P3F+1).
	if sig, has := s.cloudApp.signalFor(tenant, cross, key); has {
		signals = append(signals, sig)
	}
	return signals
}

func (s *server) handleAppIDResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	ipStr := strings.TrimSpace(r.URL.Query().Get("ip"))
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if ipStr == "" && domain == "" {
		writeError(w, http.StatusBadRequest, errors.New("a valid ?ip= or ?domain= is required"))
		return
	}
	tenant, cross := principalTenant(claims)
	ov, ovErr := s.overridesFor(r.Context(), tenant, cross)
	if ovErr != nil {
		// The operator layer outranks every other signal. Answering without it
		// would publish a lower-precedence guess wearing a confidence it has not
		// earned — refuse instead (§10).
		writeError(w, http.StatusBadGateway, ovErr)
		return
	}

	// Gather every signal (global IP catalog + operator prefix overrides + NGFW
	// app-id for an IP; global + operator domain matchers for a domain) and fuse once.
	var signals []appid.Signal
	if ipStr != "" {
		if _, err := netip.ParseAddr(ipStr); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid ?ip="))
			return
		}
		signals = append(signals, s.keyAppSignals(tenant, cross, ov, ipStr)...)
	}
	if domain != "" {
		signals = append(signals, s.appCatalog.domains().SignalsFor(domain)...)
		signals = append(signals, ov.domains.SignalsFor(domain)...)
	}
	// Per-tenant attribution precedence (Wave 4 #11 slice 3): a tenant's
	// governed class order decides winner selection among competing signals;
	// nil (unconfigured) keeps the intrinsic ladder — bit-identical to before.
	order, _ := s.governance.AttributionPrecedence(tenant)
	writeJSON(w, http.StatusOK, appid.FuseWithPrecedence(signals, order))
}

// ── batch resolve (#81 P3G) ───────────────────────────────────────────────────

// appIDBatchMaxKeys caps one batch request — a UI page never shows more IPs at
// once, and the cap bounds CPU per call (LLM04-style: no unbounded work).
const appIDBatchMaxKeys = 200

// appIDBatchMaxKeyLen bounds one key: the longest textual IPv6 form is 45
// chars ("::ffff:" + IPv4-mapped); anything longer is not an address.
const appIDBatchMaxKeyLen = 45

// appIDBatchVerdict is the per-key summary the batch endpoint returns — the
// fused verdict boiled down to what a list row renders: name, provenance,
// confidence. Unresolved keys are OMITTED from the response ("unknown" is the
// absence of a row, never a spammed label).
type appIDBatchVerdict struct {
	App        string  `json:"app"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
}

// validBatchKey charset-validates one batch key: IPv4/IPv6 textual characters
// only, bounded length. Shape-validate before parse (SR-011 house rule).
func validBatchKey(k string) bool {
	if k == "" || len(k) > appIDBatchMaxKeyLen {
		return false
	}
	for _, r := range k {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

// handleAppIDResolveBatch — POST /api/appid/resolve/batch {"keys":["ip",…]} →
// {key: {app, source, confidence}} for every key that resolves to a NAMED app.
// The shared client-side enrichment primitive: list views (top talkers, fan-out,
// tunnels) collect their visible IPs and name them in ONE call, through the SAME
// gather+fuse path as the single resolve. Tenant-scoped via principalTenant
// (default-closed); audited by the withAudit middleware like every /api read.
func (s *server) handleAppIDResolveBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	var body struct {
		Keys []string `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	if len(body.Keys) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("keys is required"))
		return
	}
	if len(body.Keys) > appIDBatchMaxKeys {
		writeError(w, http.StatusBadRequest, fmt.Errorf("too many keys (max %d)", appIDBatchMaxKeys))
		return
	}
	tenant, cross := principalTenant(claims)
	ov, ovErr := s.overridesFor(r.Context(), tenant, cross)
	if ovErr != nil {
		writeError(w, http.StatusBadGateway, ovErr) // see handleAppIDResolve: never answer without the top of the ladder
		return
	}
	order, _ := s.governance.AttributionPrecedence(tenant)

	out := make(map[string]appIDBatchVerdict, len(body.Keys))
	for _, raw := range body.Keys {
		k := strings.TrimSpace(raw)
		if !validBatchKey(k) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid key %q", sanitizeCHText(raw)))
			return
		}
		if _, err := netip.ParseAddr(k); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid key %q: not an IP address", k))
			return
		}
		if _, done := out[k]; done {
			continue // dedupe repeats — one resolution per key
		}
		v := appid.FuseWithPrecedence(s.keyAppSignals(tenant, cross, ov, k), order)
		if v.Tier == appid.Undetermined || v.App == "" || v.App == "unknown" {
			continue // unresolved: omit, never guess
		}
		out[k] = appIDBatchVerdict{App: v.App, Source: string(v.TopSource()), Confidence: v.Confidence}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleAppIDStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	ov, ovErr := s.overridesFor(r.Context(), tenant, cross)
	// The tenant's ACTIVE precedence order (default ladder when unset) — the
	// status surface stays inspectable after the editor ships.
	order, customOrder := s.governance.AttributionPrecedence(tenant)
	if !customOrder {
		order = appid.PrecedenceClasses()
	}
	// The engine's coverage at a glance (the design's "coverage is INSPECTABLE"):
	// global vendor catalog + domain matcher (shared), the firewall app-id overlay,
	// and THIS tenant's operator overrides.
	// -1 is the "unknown" sentinel (feedTotal's convention): a store that did not
	// answer must never render as a tenant with zero overrides on a page whose
	// whole job is to say what the engine can see.
	pfx, dom := -1, -1
	if ovErr == nil {
		pfx, dom = ov.prefixes.Size(), ov.domains.Size()
	}
	total := -1
	if ovErr == nil {
		total = pfx + dom
	}
	out := map[string]any{
		"attribution_precedence": order,
		"precedence_is_default":  !customOrder,
		"feeds_configured":       s.appCatalog.feedsDir != "",
		"catalog_prefixes":       s.appCatalog.get().Size(),
		"catalog_domains":        s.appCatalog.domains().Size(),
		"ngfw_attributions":      s.ngfw.count(),
		"cloud_attributions":     s.cloudApp.count(),
		"tenant_overrides":       total,
		"tenant_override_pfx":    pfx,
		"tenant_override_dom":    dom,
	}
	if ovErr != nil {
		out["tenant_overrides_unavailable"] = true
		logWarn("appid", "operator override store did not answer — status reports UNKNOWN, not zero",
			map[string]any{"tenant": tenant, "err": ovErr.Error()})
	}
	writeJSON(w, http.StatusOK, out)
}
