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
	"errors"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"netops/backend/appid"
)

// appCatalogHolder carries the current catalog behind an atomic pointer for
// lock-free reads + atomic reload.
type appCatalogHolder struct {
	cur      atomic.Pointer[appid.Catalog]
	feedsDir string
}

func newAppCatalogHolder() *appCatalogHolder {
	h := &appCatalogHolder{feedsDir: os.Getenv("APPID_FEEDS_DIR")}
	h.cur.Store(appid.NewCatalog(nil)) // empty until loaded; resolve is safe + unknown
	return h
}

func (h *appCatalogHolder) get() *appid.Catalog { return h.cur.Load() }

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

func (s *server) handleAppIDResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	ipStr := r.URL.Query().Get("ip")
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("a valid ?ip= is required"))
		return
	}
	// Layer the authoritative NGFW app-id (if the firewall classified this dst) over
	// the IP-catalog hit — tenant-scoped, fused by Resolve.
	var extra []appid.Signal
	tenant, cross := principalTenant(claims)
	if sig, has := s.ngfw.signalFor(tenant, cross, ipStr); has {
		extra = append(extra, sig)
	}
	v := s.appCatalog.get().Resolve(ip, extra...)
	writeJSON(w, http.StatusOK, v)
}

func (s *server) handleAppIDStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"prefixes":         s.appCatalog.get().Size(),
		"feeds_configured": s.appCatalog.feedsDir != "",
	})
}
