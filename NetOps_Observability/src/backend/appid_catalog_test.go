package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"netops/backend/appid"
)

// reload from a snapshot dir, then resolve over HTTP — exercises the feed loader,
// atomic swap, route wiring, and auth gate together.
func TestAppIDResolveEndpoint(t *testing.T) {
	srv, s := newTestServerState(t)

	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "m365.json"),
		[]byte(`[{"serviceArea":"Exchange","ips":["13.107.6.152/31"]}]`), 0o600))
	must(os.WriteFile(filepath.Join(dir, "aws.json"),
		[]byte(`{"prefixes":[{"ip_prefix":"52.94.0.0/22","service":"S3"}]}`), 0o600))

	// the harness builds the struct directly, so wire the holder here (like s.sites).
	s.appCatalog = appid.NewCatalogHolder(dir)
	if n, errs := s.appCatalog.Reload(); n != 2 || len(errs) != 0 {
		t.Fatalf("reload loaded %d prefixes, errs=%v", n, errs)
	}

	tok := adminToken(t, srv)

	// a known M365 Exchange IP → suspected
	st, body := do(t, srv, "GET", "/api/appid/resolve?ip=13.107.6.153", tok, nil)
	if st != 200 {
		t.Fatalf("resolve status %d: %s", st, body)
	}
	var v appid.Verdict
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if v.App != "Microsoft 365 Exchange" || v.Tier != appid.Suspected {
		t.Fatalf("unexpected verdict: %+v", v)
	}

	// a miss → first-class unknown
	_, body = do(t, srv, "GET", "/api/appid/resolve?ip=8.8.8.8", tok, nil)
	_ = json.Unmarshal(body, &v)
	if v.App != "unknown" {
		t.Fatalf("miss should be unknown, got %+v", v)
	}

	// bad ip → 400
	if st, _ := do(t, srv, "GET", "/api/appid/resolve?ip=notanip", tok, nil); st != 400 {
		t.Fatalf("bad ip want 400, got %d", st)
	}

	// unauthenticated → 401
	if st, _ := do(t, srv, "GET", "/api/appid/resolve?ip=8.8.8.8", "", nil); st != 401 {
		t.Fatalf("no token want 401, got %d", st)
	}

	// status endpoint reports the loaded size
	st, body = do(t, srv, "GET", "/api/appid/status", tok, nil)
	if st != 200 {
		t.Fatalf("status %d: %s", st, body)
	}
	var status struct {
		Prefixes        int  `json:"catalog_prefixes"`
		FeedsConfigured bool `json:"feeds_configured"`
	}
	_ = json.Unmarshal(body, &status)
	if status.Prefixes != 2 || !status.FeedsConfigured {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestAppCatalogEmptyDirIsSafe(t *testing.T) {
	h := appid.NewCatalogHolder("") // no feedsDir
	if n, errs := h.Reload(); n != 0 || errs != nil {
		t.Fatalf("empty holder reload should be a no-op, got n=%d errs=%v", n, errs)
	}
	if v := h.Get().Resolve(netip.MustParseAddr("1.2.3.4")); v.App != "unknown" {
		t.Fatalf("empty catalog must resolve unknown, got %+v", v)
	}
}

// route wiring + auth gate for the batch primitive (#81 P3G): the mounted
// endpoint resolves catalog-backed IPs over HTTP and rejects anonymous calls.
func TestAppIDResolveBatchEndpointWiring(t *testing.T) {
	srv, s := newTestServerState(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "aws.json"),
		[]byte(`{"prefixes":[{"ip_prefix":"52.94.0.0/22","service":"S3"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s.appCatalog = appid.NewCatalogHolder(dir)
	if n, errs := s.appCatalog.Reload(); n != 1 || len(errs) != 0 {
		t.Fatalf("reload: n=%d errs=%v", n, errs)
	}

	tok := adminToken(t, srv)
	st, body := do(t, srv, "POST", "/api/appid/resolve/batch", tok,
		map[string]any{"keys": []string{"52.94.0.9", "8.8.8.8"}})
	if st != 200 {
		t.Fatalf("batch status %d: %s", st, body)
	}
	var out map[string]struct {
		App    string `json:"app"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if v, ok := out["52.94.0.9"]; !ok || v.App != "AWS S3" || v.Source != "ip_catalog" {
		t.Fatalf("catalog key: %+v (ok=%v)", v, ok)
	}
	if _, has := out["8.8.8.8"]; has {
		t.Fatal("uncatalogued key must be omitted")
	}

	// anonymous → 401 (audited as a denial by withAudit)
	if st, _ := do(t, srv, "POST", "/api/appid/resolve/batch", "",
		map[string]any{"keys": []string{"8.8.8.8"}}); st != 401 {
		t.Fatalf("no token want 401, got %d", st)
	}
}
