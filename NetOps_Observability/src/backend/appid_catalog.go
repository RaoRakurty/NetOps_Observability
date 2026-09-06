// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"netops/backend/appid"
)

// appCatalogHolder carries the current catalog behind an atomic pointer for
// lock-free reads + atomic reload.
// The catalog holder moved to appid/catalog_holder.go (Phase-2 W4.7).
type appCatalogHolder = appid.CatalogHolder

func newAppCatalogHolder() *appCatalogHolder {
	return appid.NewCatalogHolder(os.Getenv("APPID_FEEDS_DIR"))
}

func (s *server) keyAppSignals(tenant string, cross bool, ov tenantOverrides, key string) []appid.Signal {
	var signals []appid.Signal
	if ip, err := netip.ParseAddr(key); err == nil {
		if s.appCatalog != nil {
			signals = append(signals, s.appCatalog.Get().SignalsFor(ip)...)
		}
		signals = append(signals, ov.Prefixes.SignalsFor(ip)...)
	}
	if sig, has := s.ngfw.signalFor(tenant, cross, key); has {
		signals = append(signals, sig)
	}
	// cloud inventory identity-map (private IP / resource → app) — the
	// authoritative cloud identity, consumed for every key shape (#81 P3F+1).
	if sig, has := s.cloudApp.SignalFor(tenant, cross, key); has {
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
		signals = append(signals, s.appCatalog.Domains().SignalsFor(domain)...)
		signals = append(signals, ov.Domains.SignalsFor(domain)...)
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
	// The engine's coverage at a glance (the design's "coverage is INSPECTABLE"),
	// AS THE CALLER SEES IT (CLAUDE.md §3a, tracker 244). Every count on this
	// tenant-scoped route is the caller's own view:
	//   · catalog_prefixes / catalog_domains — the vendor-published feeds
	//     (AWS/Azure/GCP/M365 ranges). PUBLIC reference data owned by no tenant
	//     and resolved against in full for every tenant (see keyAppSignals), so
	//     the caller's view IS the whole feed. Nothing tenant-owned is in there.
	//   · ngfw_attributions / cloud_attributions — tenant-PARTITIONED indexes;
	//     counted through countFor/CountFor, which read only the caller's bucket.
	//     Before this fix they summed every tenant's bucket onto a tenant route.
	//   · tenant_override_* — this tenant's operator rows (already scoped).
	// "scope" states which reading the numbers are: "tenant" (the tenant named in
	// "tenant") or "platform" (the platform owner's cross-tenant view, the only
	// case in which the attribution counts span tenants).
	// -1 is the "unknown" sentinel (feedTotal's convention): a store that did not
	// answer must never render as a tenant with zero overrides on a page whose
	// whole job is to say what the engine can see.
	pfx, dom := -1, -1
	if ovErr == nil {
		pfx, dom = ov.Prefixes.Size(), ov.Domains.Size()
	}
	total := -1
	if ovErr == nil {
		total = pfx + dom
	}
	scope := "tenant"
	if cross {
		scope = "platform"
	}
	out := map[string]any{
		"scope":                  scope,
		"tenant":                 tenant,
		"attribution_precedence": order,
		"precedence_is_default":  !customOrder,
		"feeds_configured":       s.appCatalog.FeedsDir() != "",
		"catalog_prefixes":       s.appCatalog.Get().Size(),
		"catalog_domains":        s.appCatalog.Domains().Size(),
		"ngfw_attributions":      s.ngfw.countFor(tenant, cross),
		"cloud_attributions":     s.cloudApp.CountFor(tenant, cross),
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
