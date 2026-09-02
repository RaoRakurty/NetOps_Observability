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
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/bgpdepth"
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
	// webClient fetches URLs discovered in UNTRUSTED registry data (geofeeds).
	// It is a SEPARATE client whose dialer refuses non-public addresses — the
	// RIPEstat/RDAP client above talks only to hard-coded bases and needs no
	// such gate, while this one is pointed at whatever a third party published.
	webClient *http.Client
	mu        sync.Mutex
	cache     map[string]bgpCacheEntry
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
		webClient:    newBGPWebClient(tr.TLSClientConfig),
		cache:        make(map[string]bgpCacheEntry),
		ripestatBase: "https://stat.ripe.net",
		rdapBase:     "https://rdap.arin.net/registry",
	}
}

// newBGPWebClient builds the SSRF-gated client used for third-party URLs.
//
// The gate has two halves and both are needed: bgpdepth.SafeOutboundURL screens
// the URL, and this dialer's Control screens the address DNS actually resolved
// to — without the second half, "https://evil.example" resolving to
// 169.254.169.254 would sail through. Redirects are re-screened by CheckRedirect
// for the same reason (a 302 into the metadata service is the classic bypass).
//
// One exemption, stated plainly: when an egress proxy is configured, the dial
// target IS the proxy — often a private address — and the proxy, not us,
// resolves the host. The address gate is therefore skipped for proxied requests
// (the URL gate still applies); an enterprise that inspects egress already
// controls where these requests may go.
func newBGPWebClient(tlsCfg *tls.Config) *http.Client {
	proxied := os.Getenv("HTTPS_PROXY") != "" || os.Getenv("https_proxy") != "" ||
		os.Getenv("ALL_PROXY") != "" || os.Getenv("all_proxy") != ""
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !proxied {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			return bgpdepth.CheckDialAddress(address)
		}
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           d.DialContext,
		TLSClientConfig:       tlsCfg,
		MaxIdleConns:          4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	return &http.Client{
		Timeout:   45 * time.Second, // a published geofeed can be several MB
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			_, err := bgpdepth.SafeOutboundURL(req.URL.String())
			return err
		},
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
		if key != "" && ttl > 0 {
			f.cachePut(key, ttl, body)
		}
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

// ── BGP depth (item 10 completion): RPKI · ASPA · geofeed · AS-path graph ───
//
// The handlers below are the thin HTTP boundary over internal/bgpdepth (§2 —
// no domain logic in the root, and none in /cmd). Everything they add obeys the
// same posture as the rest of this file: resources are validated before any
// outbound call, unknown query parameters are REFUSED (a typo'd filter must not
// silently widen an answer), each panel fails independently and says so, and
// per-tenant surfaces (the watchlist-driven RPKI sweep and the update feed) are
// scoped by principalTenant with no wildcard read.

// bgpAllowedParams refuses a request carrying any query parameter this endpoint
// does not know (§3 fail-closed at the boundary). Silently ignoring an unknown
// parameter is how a "filter" that never filtered ships.
func bgpAllowedParams(r *http.Request, allowed ...string) error {
	ok := make(map[string]bool, len(allowed)+2)
	for _, a := range allowed {
		ok[a] = true
	}
	// The tenant switcher is a platform-wide selector, valid on every route.
	ok["as_tenant"] = true
	for k := range r.URL.Query() {
		if !ok[k] {
			return fmt.Errorf("unknown query parameter %q", truncateUTF8(k, 32))
		}
	}
	return nil
}

// RIPEstat satisfies bgpdepth.Fetcher over the cached client above. A zero ttl
// bypasses the cache (the live feed must never be handed a stale window).
func (f *bgpFetcher) RIPEstat(ctx context.Context, call, resource, extra string, ttl time.Duration) (json.RawMessage, error) {
	if ttl <= 0 {
		u := fmt.Sprintf("%s/data/%s/data.json?resource=%s&%s", f.ripestatBase, call, url.QueryEscape(resource), bgpSourceApp)
		if extra != "" {
			u += "&" + extra
		}
		body, err := f.getLive(ctx, "", u, 0)
		if err != nil {
			return nil, err
		}
		return bgpEnvelope(call, body)
	}
	return f.ripestat(ctx, call, resource, extra, ttl)
}

// bgpEnvelope unwraps the RIPEstat {status,data} envelope. Shared by the cached
// and uncached paths so a non-ok envelope can never be served as data.
func bgpEnvelope(call string, body []byte) (json.RawMessage, error) {
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

// Get satisfies bgpdepth.Fetcher for URLs discovered in UNTRUSTED registry data
// (a geofeed published in a whois remark) or configured by an operator. It runs
// on a SEPARATE client whose dialer refuses non-public addresses, so a hostname
// that resolves to 127.0.0.1 / 10.x / 169.254.169.254 cannot be reached — the
// SSRF hole a plain http.Get would open on this exact input.
func (f *bgpFetcher) Get(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	u, err := bgpdepth.SafeOutboundURL(rawURL)
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes > bgpdepth.GeofeedRespCap {
		maxBytes = bgpdepth.GeofeedRespCap
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "correlix-bgp-ops/1.0")
	req.Header.Set("Accept", "text/csv, application/json;q=0.8, */*;q=0.1")
	resp, err := f.webClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // body is read through a cap; close error is not actionable
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream answered %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

// bgpOrigin adapts bgpAnnouncedOrigin to bgpdepth.OriginResolver.
func (f *bgpFetcher) bgpOrigin(ctx context.Context, prefix string) string {
	return bgpAnnouncedOrigin(ctx, f, prefix)
}

// bgpTenantResources lists the caller's watchlist, kind-filtered. It is the
// ONLY place these handlers learn what a tenant watches, and it goes through
// the same FORCE-RLS store the watchlist API uses (§3a.4).
func (s *server) bgpTenantResources(ctx context.Context, tenant string, cross bool, kind string) []string {
	if s.bgpWatch == nil {
		return nil
	}
	list, err := s.bgpWatch.List(ctx, tenant, cross)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		if kind == "" || e.Kind == kind {
			out = append(out, e.Resource)
		}
	}
	return out
}

// handleBGPRPKI — GET /api/bgp/rpki[?resource=<prefix>]
//
// With no resource it validates the CALLER'S OWN watchlist prefixes (per-tenant
// data — which prefixes a tenant watches is itself tenant information, so this
// route is ledger-classified `scoped`). With ?resource= it validates that one
// prefix, which is a public routing fact.
func (s *server) handleBGPRPKI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	if err := bgpAllowedParams(r, "resource"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Input first, dependencies second: a malformed request is a 400 whether or
	// not the fetcher happens to be up, and validating first also guarantees no
	// unvalidated string can reach an outbound URL.
	tenant, cross := principalTenant(claims)
	var prefixes []string
	fromWatchlist := false
	if raw := r.URL.Query().Get("resource"); raw != "" {
		res, kind := bgpNormalizeResource(raw)
		if res == "" || kind != "prefix" {
			writeError(w, http.StatusBadRequest, errors.New("resource must be a prefix (RPKI validates prefix+origin, not an ASN)"))
			return
		}
		prefixes = []string{res}
	} else {
		fromWatchlist = true
		for _, res := range s.bgpTenantResources(r.Context(), tenant, cross, "prefix") {
			if p, kind := bgpNormalizeResource(res); kind == "prefix" {
				prefixes = append(prefixes, p)
			}
		}
	}
	if s.bgpFetch == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("BGP fetcher not initialised"))
		return
	}
	results, truncated, err := bgpdepth.ValidateRPKISet(r.Context(), s.bgpFetch, time.Now, s.bgpFetch.bgpOrigin, prefixes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	bgpdepth.SortRPKIWorstFirst(results)
	if results == nil {
		results = []bgpdepth.RPKIResult{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results":        results,
		"from_watchlist": fromWatchlist,
		"truncated":      truncated,
		"max_prefixes":   bgpdepth.RPKIMaxPrefixes,
	})
}

// handleBGPASPA — GET /api/bgp/aspa?resource=AS64500
//
// HONEST BY DEFAULT: no public per-ASN ASPA source exists (see
// internal/bgpdepth/aspa.go for the 2026-09-02 verification), so unless
// BGP_ASPA_PROVIDER_URL names an operator-run provider this answers 200 with
// configured=false and an explanation — never a fabricated verdict.
func (s *server) handleBGPASPA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	if err := bgpAllowedParams(r, "resource"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	res, kind := bgpNormalizeResource(r.URL.Query().Get("resource"))
	if res == "" || kind != "asn" {
		writeError(w, http.StatusBadRequest, errors.New("resource must be an ASN (ASPA authorizes a customer AS's providers)"))
		return
	}
	provider := s.bgpASPA
	if provider == nil {
		provider = bgpdepth.NoASPAProvider{}
	}
	out := map[string]any{"resource": res}
	result, err := provider.ASPA(r.Context(), res)
	switch {
	case errors.Is(err, bgpdepth.ErrNoASPASource):
		out["status"] = bgpdepth.NotConfiguredStatus()
	case err != nil:
		st := bgpdepth.ConfiguredStatus(os.Getenv(bgpdepth.EnvASPAProviderURL))
		st.Reason = "The configured ASPA provider did not answer: " + err.Error()
		out["status"] = st
		out["error"] = err.Error()
	default:
		out["status"] = bgpdepth.ConfiguredStatus(os.Getenv(bgpdepth.EnvASPAProviderURL))
		out["aspa"] = result
	}
	writeJSON(w, http.StatusOK, out)
}

// handleBGPGeofeed — GET /api/bgp/geofeed?resource=<prefix|ASN>
func (s *server) handleBGPGeofeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	if err := bgpAllowedParams(r, "resource"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	res, kind := bgpNormalizeResource(r.URL.Query().Get("resource"))
	if res == "" {
		writeError(w, http.StatusBadRequest, errors.New("resource must be a prefix or an ASN"))
		return
	}
	if s.bgpFetch == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("BGP fetcher not initialised"))
		return
	}
	writeJSON(w, http.StatusOK, bgpdepth.Geofeed(r.Context(), s.bgpFetch, time.Now, res, kind))
}

// bgpGraphNameLimit bounds the RDAP holder lookups one graph triggers. Naming
// every node would be hundreds of registry calls per page view (§9).
const bgpGraphNameLimit = 12

// handleBGPASPathGraph — GET /api/bgp/aspath-graph?prefix=203.0.113.0/24
func (s *server) handleBGPASPathGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	if err := bgpAllowedParams(r, "prefix"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	prefix, kind := bgpNormalizeResource(r.URL.Query().Get("prefix"))
	if prefix == "" || kind != "prefix" {
		writeError(w, http.StatusBadRequest, errors.New("prefix must be a prefix (203.0.113.0/24)"))
		return
	}
	if s.bgpFetch == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("BGP fetcher not initialised"))
		return
	}
	ctx := r.Context()

	// bgp-state is the richer source (paths as integer arrays); looking-glass is
	// the fallback so the panel degrades instead of blanking.
	var paths [][]uint32
	source := "bgp-state"
	var failure string
	if data, err := s.bgpFetch.RIPEstat(ctx, "bgp-state", prefix, "", bgpdepth.ASPathCacheTTL); err != nil {
		failure = err.Error()
	} else {
		paths = bgpdepth.ParseBGPState(data)
	}
	if len(paths) == 0 {
		if data, err := s.bgpFetch.RIPEstat(ctx, "looking-glass", prefix, "", bgpdepth.ASPathCacheTTL); err == nil {
			if lg := bgpdepth.ParseLookingGlass(data); len(lg) > 0 {
				paths, source, failure = lg, "looking-glass", ""
			}
		}
	}

	// The caller's OWN ASNs come from its watchlist (per-tenant), and are used
	// only to MARK nodes — they never filter the public graph, so the answer is
	// tenant-invariant apart from that highlight.
	tenant, cross := principalTenant(claims)
	tenantASNs := map[uint32]bool{}
	for _, res := range s.bgpTenantResources(ctx, tenant, cross, "asn") {
		if n, err := strconv.ParseUint(strings.TrimPrefix(res, "AS"), 10, 32); err == nil {
			tenantASNs[uint32(n)] = true
		}
	}

	g := bgpdepth.BuildASPathGraph(prefix, paths, tenantASNs, source, time.Now())
	if len(paths) == 0 && failure != "" {
		g.Error = failure
	}
	bgpdepth.AnnotateNames(&g, s.bgpASNNamer(ctx, g))
	writeJSON(w, http.StatusOK, g)
}

// bgpASNNamer returns a holder-name lookup for the graph's MOST IMPORTANT nodes
// only (origins first, then the busiest). Everything else keeps an empty name,
// which the UI renders as the bare ASN — honest, never a placeholder.
func (s *server) bgpASNNamer(ctx context.Context, g bgpdepth.ASPathGraph) func(uint32) string {
	want := map[uint32]bool{}
	for _, o := range g.Origins {
		if len(want) >= bgpGraphNameLimit {
			break
		}
		want[o] = true
	}
	for _, n := range g.Nodes { // already sorted depth-then-weight
		if len(want) >= bgpGraphNameLimit {
			break
		}
		want[n.ASN] = true
	}
	names := map[uint32]string{}
	for asn := range want {
		if ctx.Err() != nil {
			break
		}
		data, err := s.bgpFetch.rdap(ctx, "asn", "AS"+strconv.FormatUint(uint64(asn), 10))
		if err != nil {
			continue
		}
		var doc struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(data, &doc) == nil && doc.Name != "" {
			names[asn] = doc.Name
		}
	}
	return func(asn uint32) string { return names[asn] }
}

// handleBGPFeed — GET /api/bgp/feed[?since=&limit=]
//
// Per-tenant DATA (the ring holds the tenant's watched resources), so it is
// ledger-classified `scoped` and refuses a cross-tenant read: a platform owner
// must scope into a tenant with the switcher, exactly like the watchlist write.
func (s *server) handleBGPFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	if err := bgpAllowedParams(r, "since", "limit"); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.bgpFeed == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"updates": []any{},
			"status": map[string]any{
				"enabled": false, "producer": "ripestat-poll", "ring_size": bgpdepth.RingSize,
				"note": "The near-live feed is off. Set " + bgpdepth.EnvFeatureFlag + "=true to enable it.",
			},
		})
		return
	}
	tenant, cross := principalTenant(claims)
	if cross || tenant == "" || tenant == TenantGlobal {
		writeError(w, http.StatusBadRequest, errors.New("select a tenant to read its BGP feed (the buffer is per-tenant)"))
		return
	}
	var since uint64
	if v := r.URL.Query().Get("since"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("since must be the cursor from the previous page"))
			return
		}
		since = n
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > bgpdepth.FeedPageMax {
			writeError(w, http.StatusBadRequest, fmt.Errorf("limit must be 1..%d", bgpdepth.FeedPageMax))
			return
		}
		limit = n
	}
	resources := s.bgpTenantResources(r.Context(), tenant, false, "")
	page, err := s.bgpFeed.Page(r.Context(), tenant, resources, since, limit)
	if err != nil && !errors.Is(err, bgpdepth.ErrFeedDisabled) {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"updates": page.Updates,
		"next":    page.Next,
		"gap":     page.Gap,
		"status":  page.Status,
		"metrics": s.bgpFeed.Metrics(),
	})
}
