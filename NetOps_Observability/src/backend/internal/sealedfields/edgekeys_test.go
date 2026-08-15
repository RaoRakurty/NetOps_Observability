package sealedfields

// edgekeys_test.go — the key-serving endpoint's refusals.
//
// This route hands out cryptographic key material. Everything worth testing is
// a way it must say no.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/sealing"
)

type fakeProvider struct {
	material map[string]sealing.EdgeMaterial
}

func (f fakeProvider) Seal(context.Context, sealing.Context, string) (string, error) {
	return "", errors.New("unused")
}
func (f fakeProvider) Unseal(context.Context, sealing.Context, string) (string, error) {
	return "", errors.New("unused")
}
func (f fakeProvider) Rotate(context.Context, string) (int, error) { return 0, errors.New("unused") }
func (f fakeProvider) EdgeKey(_ context.Context, tenant string) (sealing.EdgeMaterial, error) {
	m, ok := f.material[tenant]
	if !ok {
		return sealing.EdgeMaterial{}, errors.New("no custody")
	}
	return m, nil
}

func testProvider() sealing.CryptoProvider {
	seal := make([]byte, 32)
	mac := make([]byte, 32)
	for i := range seal {
		seal[i] = byte(i)
		mac[i] = byte(200 - i)
	}
	return fakeProvider{material: map[string]sealing.EdgeMaterial{
		"acme": {SealKey: seal, MACKey: mac, Version: 3},
	}}
}

func edgeRequest(t *testing.T, h http.HandlerFunc, tenant string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, EdgeKeyPath+"?tenant="+tenant, nil)
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func allow(*http.Request) bool { return true }
func deny(*http.Request) bool  { return false }

func TestEdgeKeysServeDerivedMaterial(t *testing.T) {
	h := EdgeKeyHandler(testProvider, allow, nil, nil)
	w := edgeRequest(t, h, "acme")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body)
	}
	var out edgeKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.KeyVersion != 3 {
		t.Fatalf("key version: got %d", out.KeyVersion)
	}
	// Padded standard base64 — VRL's decode_base64 rejects unpadded input, so
	// this encoding choice is load-bearing at the edge.
	for name, v := range map[string]string{"seal": out.SealKey, "mac": out.MACKey} {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			t.Errorf("%s key is not padded std base64: %v", name, err)
		}
		if len(raw) != 32 {
			t.Errorf("%s key must be 32 bytes, got %d", name, len(raw))
		}
	}
	if out.SealKey == out.MACKey {
		t.Fatal("seal and MAC keys are identical — one key for encryption and authentication is the classic misuse")
	}
	// A body carrying key material must never be cached by an intermediary.
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("key material served without no-store: %q", cc)
	}
}

// The whole point of the gate.
func TestEdgeKeysRefuseUnauthenticated(t *testing.T) {
	h := EdgeKeyHandler(testProvider, deny, nil, nil)
	w := edgeRequest(t, h, "acme")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "AAEC") {
		t.Fatalf("unauthenticated response leaked key material: %s", w.Body)
	}
}

// A nil authorizer must FAIL CLOSED. If a wiring mistake ever passes nil, the
// endpoint must refuse rather than serve key material to anything on the port.
func TestEdgeKeysFailClosedWithoutAnAuthorizer(t *testing.T) {
	h := EdgeKeyHandler(testProvider, nil, nil, nil)
	if w := edgeRequest(t, h, "acme"); w.Code != http.StatusUnauthorized {
		t.Fatalf("a nil authorizer must refuse, got %d", w.Code)
	}
}

// Tenants without custody must be indistinguishable from tenants that do not
// exist — otherwise this route enumerates who has sealing enabled.
func TestEdgeKeysDoNotEnumerateTenants(t *testing.T) {
	h := EdgeKeyHandler(testProvider, allow, nil, nil)
	known := edgeRequest(t, h, "no-custody-tenant")
	unknown := edgeRequest(t, h, "definitely-not-a-tenant")
	if known.Code != http.StatusNotFound || unknown.Code != http.StatusNotFound {
		t.Fatalf("both must 404: %d %d", known.Code, unknown.Code)
	}
	if known.Body.String() != unknown.Body.String() {
		t.Fatalf("responses differ, so tenants are enumerable:\n%s\n%s", known.Body, unknown.Body)
	}
}

func TestEdgeKeysRequireATenant(t *testing.T) {
	h := EdgeKeyHandler(testProvider, allow, nil, nil)
	r := httptest.NewRequest(http.MethodGet, EdgeKeyPath, nil)
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 without a tenant, got %d", w.Code)
	}
}

func TestEdgeKeysRejectNonGET(t *testing.T) {
	h := EdgeKeyHandler(testProvider, allow, nil, nil)
	r := httptest.NewRequest(http.MethodPost, EdgeKeyPath+"?tenant=acme", nil)
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
}

// With sealing off there is no provider, and the handler must say so rather
// than panic on a nil.
func TestEdgeKeysWithoutAProvider(t *testing.T) {
	h := EdgeKeyHandler(func() sealing.CryptoProvider { return nil }, allow, nil, nil)
	if w := edgeRequest(t, h, "acme"); w.Code != http.StatusNotImplemented {
		t.Fatalf("want 501, got %d", w.Code)
	}
}

// TestEdgeKeysRejectUnknownTenant pins that EdgeKey material is only minted for a
// REAL tenant (or a reserved engine scope). EdgeKey lazily mints+persists a DEK
// on first use, so without a scope guard a caller with the internal credential
// could mint a persisted DEK for any arbitrary string and grow the custody store
// unbounded.
func TestEdgeKeysRejectUnknownTenant(t *testing.T) {
	resolve := func(scope string) (string, bool) {
		if scope == "acme" {
			return "acme", true
		}
		return "", false
	}
	h := EdgeKeyHandler(testProvider, allow, resolve, nil)

	// A real tenant is served.
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/x?tenant=acme", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("known tenant: status %d, want 200", rec.Code)
	}
	// An unknown tenant is refused with the SAME 404 as an absent key (no
	// enumeration), and never reaches EdgeKey to mint.
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/x?tenant=made-up-tenant", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant: status %d, want 404", rec.Code)
	}
	// A resolver that answers "known" with an EMPTY canonical scope is treated
	// as a refusal — the key store must never be keyed by "".
	rec = httptest.NewRecorder()
	EdgeKeyHandler(testProvider, allow, func(string) (string, bool) { return "", true }, nil)(
		rec, httptest.NewRequest(http.MethodGet, "/x?tenant=acme", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("empty canonical scope: status %d, want 404", rec.Code)
	}
}

// TestEdgeKeysUseTheCanonicalScope pins that the handler fetches material under
// the CANONICAL scope the resolver returns — not the caller's spelling — so one
// tenant referenced as `Acme`, `ACME` or its slug maps to ONE custody row.
func TestEdgeKeysUseTheCanonicalScope(t *testing.T) {
	var minted []string
	p := recordingProvider{fakeProvider: testProvider().(fakeProvider), seen: &minted}
	resolve := func(scope string) (string, bool) {
		if strings.EqualFold(strings.TrimSpace(scope), "acme") {
			return "acme", true
		}
		return "", false
	}
	h := EdgeKeyHandler(func() sealing.CryptoProvider { return p }, allow, resolve, nil)
	for _, spelling := range []string{"acme", "Acme", "ACME"} {
		rec := edgeRequest(t, h, spelling)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: status %d, want 200", spelling, rec.Code)
		}
	}
	for _, got := range minted {
		if got != "acme" {
			t.Fatalf("EdgeKey was asked for scope %q — must be the canonical \"acme\"", got)
		}
	}
	if len(minted) != 3 {
		t.Fatalf("expected 3 EdgeKey calls, got %d", len(minted))
	}
}

// recordingProvider records the scope every EdgeKey call is made with.
type recordingProvider struct {
	fakeProvider
	seen *[]string
}

func (r recordingProvider) EdgeKey(ctx context.Context, tenant string) (sealing.EdgeMaterial, error) {
	*r.seen = append(*r.seen, tenant)
	return r.fakeProvider.EdgeKey(ctx, tenant)
}
