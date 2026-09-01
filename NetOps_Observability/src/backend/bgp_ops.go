// bgp_ops.go — BGP Operations (product wave item 10, 2026-08-25): the api-side
// half of the consolidated BGP outage page. v0.9 strategy per
// docs/design/research/BGP_OPS_CONSOLIDATION_RESEARCH_2026-08-25.md: serve the
// page LIVE from the licensing-clean remote APIs (RIPEstat with sourceapp
// attribution; RDAP with redirect-following bootstrap) behind a per-resource
// TTL cache, so the page ships real data with zero new containers. The local
// RIS Live consumer (bgp-ingest) upgrades this to streaming + a 72h buffer in
// a later deploy; these handlers keep their shape when that lands.
//
// Zero-trust posture (§3, §9): every outbound call has a hard client timeout
// and a bounded response body; remote JSON is decoded into typed structs and
// re-emitted (never proxied raw); the watchlist is tenant-scoped through
// FORCE-RLS via WithTenant (§3a — owner stamped from the principal, never the
// payload); resources are validated as prefix/ASN before any use.
//
// Corporate TLS interception (found live in this lab — Versa SASE re-signs
// egress): OUTBOUND_HTTPS_CA_FILE, when set, ADDS a CA bundle for OUTBOUND
// requests only (mesh-internal clients are untouched). Enterprises behind
// Zscaler/Netskope/Versa-class inspection need exactly this knob; verify=off
// is never an option (§8).

package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// ── watchlist store (PG, FORCE-RLS) ─────────────────────────────────────────

type bgpWatchEntry struct {
	Resource  string    `json:"resource"`
	Kind      string    `json:"kind"` // prefix | asn
	Note      string    `json:"note"`
	AddedBy   string    `json:"added_by"`
	CreatedAt time.Time `json:"created_at"`
}

type bgpTenantDB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type bgpWatchStore struct{ db bgpTenantDB }

func newBGPWatchStore(db bgpTenantDB) *bgpWatchStore { return &bgpWatchStore{db: db} }

func (s *bgpWatchStore) List(ctx context.Context, tenant string, cross bool) ([]bgpWatchEntry, error) {
	out := []bgpWatchEntry{}
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT resource, kind, note, added_by, created_at
			   FROM bgp_watchlist ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e bgpWatchEntry
			if err := rows.Scan(&e.Resource, &e.Kind, &e.Note, &e.AddedBy, &e.CreatedAt); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// bgpWatchTenant validates a WRITE-side tenant scope (§3a): watchlist rows are
// per-tenant data, so every mutation needs one concrete tenant — never empty,
// never the '*' cross-tenant wildcard. Fail-closed at the store so no future
// caller can reintroduce a wildcard write.
func bgpWatchTenant(tenant string) (string, error) {
	t := strings.ToLower(strings.TrimSpace(tenant))
	if t == "" || t == "*" {
		return "", errors.New("bgp watchlist: write requires a concrete tenant (cross-tenant writes are refused)")
	}
	return t, nil
}

// Add upserts a watchlist row for ONE tenant. Writes always run cross=false
// (the RLS GUC is the concrete tenant, never '*'), and tenant_id is stamped
// from the principal's tenant as a bound parameter — defense-in-depth alongside
// the FORCE-RLS WITH CHECK, and structurally unable to stamp '*'.
func (s *bgpWatchStore) Add(ctx context.Context, tenant string, e bgpWatchEntry) error {
	t, err := bgpWatchTenant(tenant)
	if err != nil {
		return err
	}
	return s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO bgp_watchlist (tenant_id, resource, kind, note, added_by)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (tenant_id, resource)
			 DO UPDATE SET note = EXCLUDED.note`,
			t, e.Resource, e.Kind, e.Note, e.AddedBy)
		return err
	})
}

// Delete removes ONE tenant's row for the resource. The explicit tenant_id
// predicate sits ON TOP of RLS (cross=false GUC): even a mis-scoped session
// can only ever delete the caller's own row, never every tenant's (§3a).
func (s *bgpWatchStore) Delete(ctx context.Context, tenant string, resource string) (bool, error) {
	t, err := bgpWatchTenant(tenant)
	if err != nil {
		return false, err
	}
	var found bool
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM bgp_watchlist WHERE tenant_id = $1 AND resource = $2`,
			t, resource)
		if err != nil {
			return err
		}
		found = tag.RowsAffected() > 0
		return nil
	})
	return found, err
}

// bgpNoteMaxBytes caps a watchlist note. The column is TEXT (unbounded), so
// this is the API's own storage bound — measured in BYTES (the original
// semantic of the cap), but always cut on a rune boundary: a multi-byte
// character straddling the cap must shorten the note, never corrupt it.
const bgpNoteMaxBytes = 300

// truncateUTF8 returns s cut to at most max bytes WITHOUT splitting a rune.
// A naive byte slice can bisect a multi-byte UTF-8 sequence, producing an
// invalid string that PostgreSQL rejects (SQLSTATE 22021) — turning a
// legitimate add into a 500.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ── resource validation ─────────────────────────────────────────────────────

var bgpASNRe = regexp.MustCompile(`^[Aa][Ss]([0-9]{1,10})$`)

// bgpNormalizeResource validates and canonicalizes a watch/query resource.
// Returns ("", "") for anything that is not a syntactically valid prefix or
// ASN — the fail-closed boundary that keeps arbitrary strings out of outbound
// URLs and the store.
func bgpNormalizeResource(raw string) (resource, kind string) {
	r := strings.TrimSpace(raw)
	if m := bgpASNRe.FindStringSubmatch(r); m != nil {
		n, err := strconv.ParseUint(m[1], 10, 32)
		if err != nil {
			return "", "" // ASN digits out of range (> 32-bit)
		}
		if n == 0 {
			return "", "" // AS0 is reserved (RFC 7607) — never a real resource
		}
		return "AS" + strconv.FormatUint(n, 10), "asn"
	}
	if p, err := netip.ParsePrefix(r); err == nil {
		return p.Masked().String(), "prefix"
	}
	// A bare address is accepted as its host prefix — operators paste IPs.
	if a, err := netip.ParseAddr(r); err == nil {
		bits := 32
		if a.Is6() {
			bits = 128
		}
		return netip.PrefixFrom(a, bits).String(), "prefix"
	}
	return "", ""
}

// ── outbound fetcher (RIPEstat + RDAP) with TTL cache ───────────────────────

const (
	bgpFetchTimeout   = 12 * time.Second
	bgpRespCap        = 4 << 20 // 4 MiB decoded-source cap; RIPEstat updates can be large
	bgpCacheCap       = 512     // bounded per-process (§9: all queues bounded)
	bgpCacheTTLStatus = 60 * time.Second
	bgpCacheTTLWhois  = 24 * time.Hour
	bgpSourceApp      = "sourceapp=correlix"
)

type bgpCacheEntry struct {
	at   time.Time
	ttl  time.Duration
	body []byte
}

type bgpFetcher struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]bgpCacheEntry
	// base URLs swapped by tests; production values in newBGPFetcher.
	ripestatBase string
	rdapBase     string
}

// newBGPFetcher builds the outbound client. OUTBOUND_HTTPS_CA_FILE (optional)
// APPENDS a corporate-proxy CA to the system pool for these outbound calls —
// never replaces it, never disables verification.
func newBGPFetcher() *bgpFetcher {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if extra := os.Getenv("OUTBOUND_HTTPS_CA_FILE"); extra != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if pem, err := os.ReadFile(extra); err != nil {
			logError("bgp", "OUTBOUND_HTTPS_CA_FILE unreadable — outbound TLS uses the system pool only", map[string]any{"path": extra, "err": err.Error()})
		} else if !pool.AppendCertsFromPEM(pem) {
			logError("bgp", "OUTBOUND_HTTPS_CA_FILE held no usable certificates", map[string]any{"path": extra})
		} else {
			tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
	}
	return &bgpFetcher{
		client:       &http.Client{Timeout: bgpFetchTimeout, Transport: tr},
		cache:        make(map[string]bgpCacheEntry),
		ripestatBase: "https://stat.ripe.net",
		rdapBase:     "https://rdap.arin.net/registry",
	}
}

func (f *bgpFetcher) cached(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.cache[key]
	if !ok || time.Since(e.at) > e.ttl {
		return nil, false
	}
	return e.body, true
}

func (f *bgpFetcher) cachePut(key string, ttl time.Duration, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cache) >= bgpCacheCap {
		// Evict the stalest entry — O(n) over ≤512 entries, write-rare.
		var oldest string
		var oldestAt time.Time
		for k, e := range f.cache {
			if oldest == "" || e.at.Before(oldestAt) {
				oldest, oldestAt = k, e.at
			}
		}
		delete(f.cache, oldest)
	}
	f.cache[key] = bgpCacheEntry{at: time.Now(), ttl: ttl, body: body}
}

func (f *bgpFetcher) getLive(ctx context.Context, key, rawURL string, ttl time.Duration) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(500+time.Now().UnixNano()%700) * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "correlix-bgp-ops/1.0")
		req.Header.Set("Accept", "application/json, application/rdap+json")
		resp, err := f.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, bgpRespCap))
		_ = resp.Body.Close() // read fully or capped; close error is not actionable
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("upstream %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("upstream answered %d", resp.StatusCode)
		}
		f.cachePut(key, ttl, body)
		return body, nil
	}
	return nil, fmt.Errorf("upstream unreachable after retry: %w", lastErr)
}

// fetchCached is the composed read path: cache hit or live fetch.
func (f *bgpFetcher) fetchCached(ctx context.Context, key, rawURL string, ttl time.Duration) ([]byte, error) {
	if body, ok := f.cached(key); ok {
		return body, nil
	}
	return f.getLive(ctx, key, rawURL, ttl)
}

func (f *bgpFetcher) ripestat(ctx context.Context, call, resource string, extra string, ttl time.Duration) (json.RawMessage, error) {
	u := fmt.Sprintf("%s/data/%s/data.json?resource=%s&%s", f.ripestatBase, call, url.QueryEscape(resource), bgpSourceApp)
	if extra != "" {
		u += "&" + extra
	}
	body, err := f.fetchCached(ctx, "rs:"+call+":"+resource+":"+extra, u, ttl)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("ripestat %s: bad envelope: %w", call, err)
	}
	if envelope.Status != "ok" {
		return nil, fmt.Errorf("ripestat %s: status %q", call, envelope.Status)
	}
	return envelope.Data, nil
}

// rdap resolves ownership. ARIN's RDAP redirects to the authoritative RIR for
// resources it does not hold, and the client follows — one base covers all
// five registries without a bootstrap file.
func (f *bgpFetcher) rdap(ctx context.Context, kind, resource string) (json.RawMessage, error) {
	var path string
	switch kind {
	case "asn":
		path = "/autnum/" + strings.TrimPrefix(resource, "AS")
	case "prefix":
		path = "/ip/" + strings.SplitN(resource, "/", 2)[0]
	default:
		return nil, errors.New("rdap: unknown resource kind")
	}
	body, err := f.fetchCached(ctx, "rdap:"+resource, f.rdapBase+path, bgpCacheTTLWhois)
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, errors.New("rdap: non-JSON answer")
	}
	return body, nil
}

// ── HTTP surface ────────────────────────────────────────────────────────────

// handleBGPWatchlist — GET list, POST {resource,note} add, DELETE ?resource= .
func (s *server) handleBGPWatchlist(w http.ResponseWriter, r *http.Request) {
	level := LevelRead
	if r.Method != http.MethodGet {
		level = LevelWrite
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	if s.bgpWatch == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("BGP watchlist requires the relational store"))
		return
	}
	// §3a: the watchlist is per-tenant data — a cross-tenant principal (platform
	// owner in the Global view) must scope into a concrete tenant via the tenant
	// switcher (X-Acting-Tenant / ?as_tenant=) before writing. Refused, never a
	// wildcard write (the codebase's established shape: nms_http, ticketing_http).
	if r.Method != http.MethodGet && (cross || tenant == "" || tenant == TenantGlobal) {
		writeError(w, http.StatusBadRequest, errors.New("select a tenant to edit its watchlist (cross-tenant writes are refused)"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := s.bgpWatch.List(r.Context(), tenant, cross)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"watchlist": list})
	case http.MethodPost:
		var req struct {
			Resource string `json:"resource"`
			Note     string `json:"note"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
			return
		}
		resource, kind := bgpNormalizeResource(req.Resource)
		if resource == "" {
			writeError(w, http.StatusBadRequest, errors.New("resource must be a prefix (203.0.113.0/24) or an ASN (AS64500)"))
			return
		}
		note := truncateUTF8(req.Note, bgpNoteMaxBytes)
		e := bgpWatchEntry{Resource: resource, Kind: kind, Note: note, AddedBy: claims.Sub}
		if err := s.bgpWatch.Add(r.Context(), tenant, e); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "resource": resource, "kind": kind})
	case http.MethodDelete:
		resource, _ := bgpNormalizeResource(r.URL.Query().Get("resource"))
		if resource == "" {
			writeError(w, http.StatusBadRequest, errors.New("resource query parameter required"))
			return
		}
		found, err := s.bgpWatch.Delete(r.Context(), tenant, resource)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, POST or DELETE"))
	}
}

// handleBGPResource — GET /api/bgp/resource?resource=X&view=status|updates|whois
// The page's data spine. Every view is independently cacheable and fails
// independently (a whois outage must not blank the routing verdict).
func (s *server) handleBGPResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	if s.bgpFetch == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("BGP fetcher not initialised"))
		return
	}
	resource, kind := bgpNormalizeResource(r.URL.Query().Get("resource"))
	if resource == "" {
		writeError(w, http.StatusBadRequest, errors.New("resource must be a prefix or an ASN"))
		return
	}
	ctx := r.Context()
	switch view := r.URL.Query().Get("view"); view {
	case "", "status":
		// One page-load bundle: routing status + RPKI verdict (+ AS-paths for
		// prefixes) — each part independent, partial answers are honest.
		out := map[string]any{"resource": resource, "kind": kind}
		if data, err := s.bgpFetch.ripestat(ctx, "routing-status", resource, "", bgpCacheTTLStatus); err != nil {
			out["routing_status_error"] = err.Error()
		} else {
			out["routing_status"] = data
		}
		if kind == "prefix" {
			// rpki-validation wants resource=<origin ASN> + prefix=<prefix>; the
			// origin comes from the live announcement so the verdict judges the
			// REAL route, not a hypothetical one.
			if origin := bgpAnnouncedOrigin(ctx, s.bgpFetch, resource); origin == "" {
				out["rpki_error"] = "origin ASN not determinable (prefix not announced?)"
			} else if data, err := s.bgpFetch.ripestat(ctx, "rpki-validation", "AS"+origin, "prefix="+url.QueryEscape(resource), bgpCacheTTLStatus); err != nil {
				out["rpki_error"] = err.Error()
			} else {
				out["rpki"] = data
				out["rpki_origin"] = "AS" + origin
			}
			if data, err := s.bgpFetch.ripestat(ctx, "looking-glass", resource, "", bgpCacheTTLStatus); err != nil {
				out["paths_error"] = err.Error()
			} else {
				out["paths"] = data
			}
		}
		writeJSON(w, http.StatusOK, out)
	case "updates":
		hours := 8
		if h, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && h >= 1 && h <= 72 {
			hours = h
		}
		start := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02T15:04")
		data, err := s.bgpFetch.ripestat(ctx, "bgp-updates", resource, "starttime="+url.QueryEscape(start), bgpCacheTTLStatus)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"resource": resource, "updates": data})
	case "whois":
		data, err := s.bgpFetch.rdap(ctx, kind, resource)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"resource": resource, "rdap": data})
	default:
		writeError(w, http.StatusBadRequest, fmt.Errorf("unknown view %q (status|updates|whois)", view))
	}
}

// bgpAnnouncedOrigin returns the prefix's dominant announced origin ASN
// (digits only, no "AS"), or "" when not determinable. Reads through the same
// cache as the status view, so a page load costs one routing-status fetch.
func bgpAnnouncedOrigin(ctx context.Context, f *bgpFetcher, prefix string) string {
	data, err := f.ripestat(ctx, "routing-status", prefix, "", bgpCacheTTLStatus)
	if err != nil {
		return ""
	}
	var rs struct {
		LastSeen struct {
			Origin string `json:"origin"`
		} `json:"last_seen"`
	}
	if json.Unmarshal(data, &rs) != nil || rs.LastSeen.Origin == "" {
		return ""
	}
	// origin can be "64500" or "{64500,64501}" — take the first token.
	origin := strings.Trim(rs.LastSeen.Origin, "{}")
	origin = strings.SplitN(origin, ",", 2)[0]
	return strings.TrimPrefix(origin, "AS")
}
