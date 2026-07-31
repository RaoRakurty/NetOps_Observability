package sealing

// sealing_test.go — the security contract of Sealed Fields.
//
// These are not "does it round-trip" tests. Each one pins a property that, if
// it broke, would be a security incident rather than a bug report: cross-tenant
// recovery, silent acceptance of tampered ciphertext, plaintext leaking on a
// failure path, or two seals of the same value becoming linkable.

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// fakeKeys is an in-memory KeyProvider with per-tenant material and versions —
// the vault's shape without the vault's custody machinery.
type fakeKeys struct {
	mu       sync.Mutex
	material map[string]map[int][]byte // tenant → version → key material
	active   map[string]int
	fail     map[string]bool // tenants whose custody is "unavailable"
}

func newFakeKeys(tenants ...string) *fakeKeys {
	f := &fakeKeys{material: map[string]map[int][]byte{}, active: map[string]int{}, fail: map[string]bool{}}
	for _, t := range tenants {
		f.mint(t, 1)
	}
	return f
}

func (f *fakeKeys) mint(tenant string, version int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.material[tenant] == nil {
		f.material[tenant] = map[int][]byte{}
	}
	m := make([]byte, 32)
	if _, err := rand.Read(m); err != nil {
		panic(err)
	}
	f.material[tenant][version] = m
	f.active[tenant] = version
}

func (f *fakeKeys) TenantKey(_ context.Context, tenant string) ([]byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail[tenant] {
		return nil, 0, errors.New("custody not configured")
	}
	v, ok := f.active[tenant]
	if !ok {
		return nil, 0, fmt.Errorf("no key for tenant %q", tenant)
	}
	return f.material[tenant][v], v, nil
}

func (f *fakeKeys) TenantKeyVersion(_ context.Context, tenant string, version int) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.material[tenant][version]
	if !ok {
		return nil, fmt.Errorf("key version %d retired for tenant %q", version, tenant)
	}
	return m, nil
}

func (f *fakeKeys) RotateTenant(_ context.Context, tenant string) (int, error) {
	f.mu.Lock()
	next := f.active[tenant] + 1
	f.mu.Unlock()
	f.mint(tenant, next)
	return next, nil
}

func ctxFor(tenant, field string) Context {
	return Context{Tenant: tenant, ProcessorID: "proc-1", Field: field, DataType: "card"}
}

func newProvider(tenants ...string) (CryptoProvider, *fakeKeys) {
	k := newFakeKeys(tenants...)
	return NewAESCTRProvider(k), k
}

// ── round trip ──────────────────────────────────────────────────────────────

func TestSealUnsealRoundTrip(t *testing.T) {
	p, _ := newProvider("acme")
	ctx := context.Background()
	c := ctxFor("acme", "card")

	for _, plaintext := range []string{
		"4111111111111111",
		"a",
		"jsmith@example.org",
		"café-naïve — multibyte ✓",
		strings.Repeat("x", 1024),
	} {
		sealed, err := p.Seal(ctx, c, plaintext)
		if err != nil {
			t.Fatalf("seal %q: %v", plaintext, err)
		}
		// The property is that the CIPHERTEXT is not the plaintext. Testing the
		// whole token with strings.Contains is wrong: for a short value the
		// base64 alphabet reproduces it by chance (a one-character plaintext
		// hits roughly always), which is a false alarm, not a leak.
		tok, err := parseToken(sealed)
		if err != nil {
			t.Fatalf("parse own token: %v", err)
		}
		if string(tok.Ciphertext) == plaintext {
			t.Fatalf("CIPHERTEXT IS PLAINTEXT for %q", plaintext)
		}
		if bytes.Contains(tok.Ciphertext, []byte(plaintext)) {
			t.Fatalf("ciphertext contains the plaintext: %q", plaintext)
		}
		if !IsSealed(sealed) {
			t.Fatalf("not recognisable as sealed: %q", sealed)
		}
		got, err := p.Unseal(ctx, c, sealed)
		if err != nil {
			t.Fatalf("unseal: %v", err)
		}
		if got != plaintext {
			t.Fatalf("round trip: got %q want %q", got, plaintext)
		}
	}
}

// Two seals of the SAME value must not be equal — otherwise an observer can
// link records by ciphertext without ever decrypting (the exact leak that makes
// deterministic encryption unsuitable as a default).
func TestSealIsRandomized(t *testing.T) {
	p, _ := newProvider("acme")
	ctx, c := context.Background(), ctxFor("acme", "card")
	a, err := p.Seal(ctx, c, "4111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Seal(ctx, c, "4111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("identical plaintexts produced identical tokens — sealed values are linkable")
	}
}

// ── tenant isolation ────────────────────────────────────────────────────────

func TestTenantIsolation(t *testing.T) {
	p, _ := newProvider("acme", "globex")
	ctx := context.Background()
	sealed, err := p.Seal(ctx, ctxFor("acme", "card"), "4111111111111111")
	if err != nil {
		t.Fatal(err)
	}

	// Another tenant presenting acme's token must be refused — and must get a
	// CONTEXT error, not a tampering error: nothing was corrupted, someone
	// presented a value they do not own.
	if _, err := p.Unseal(ctx, ctxFor("globex", "card"), sealed); !errors.Is(err, ErrWrongContext) {
		t.Fatalf("cross-tenant unseal must fail with ErrWrongContext, got %v", err)
	}

	// Even a tenant whose token was re-labelled cannot read it: rewriting the
	// tenant in the token breaks the MAC.
	forged := strings.Replace(sealed, b64.EncodeToString([]byte("acme")), b64.EncodeToString([]byte("globex")), 1)
	if _, err := p.Unseal(ctx, ctxFor("globex", "card"), forged); err == nil {
		t.Fatal("a token re-labelled to another tenant must not unseal")
	}
}

// ── context binding ─────────────────────────────────────────────────────────

func TestContextBindingPreventsReplay(t *testing.T) {
	p, _ := newProvider("acme")
	ctx := context.Background()
	sealed, err := p.Seal(ctx, ctxFor("acme", "card"), "4111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		c    Context
	}{
		{"different field", Context{Tenant: "acme", ProcessorID: "proc-1", Field: "ssn", DataType: "card"}},
		{"different processor", Context{Tenant: "acme", ProcessorID: "proc-2", Field: "card", DataType: "card"}},
		{"different data type", Context{Tenant: "acme", ProcessorID: "proc-1", Field: "card", DataType: "email"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.Unseal(ctx, tc.c, sealed); err == nil {
				t.Fatalf("a value sealed for one context must not unseal in another (%s)", tc.name)
			}
		})
	}
}

// ── tampering ───────────────────────────────────────────────────────────────

func TestTamperedCiphertextIsRejected(t *testing.T) {
	p, _ := newProvider("acme")
	ctx, c := context.Background(), ctxFor("acme", "card")
	sealed, err := p.Seal(ctx, c, "4111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(sealed, tokenPrefix), tokenSuffix), ":")

	flip := func(idx int) string {
		raw, err := b64.DecodeString(parts[idx])
		if err != nil || len(raw) == 0 {
			t.Fatalf("decode part %d: %v", idx, err)
		}
		mutated := append([]byte(nil), raw...)
		mutated[0] ^= 0x01
		cp := append([]string(nil), parts...)
		cp[idx] = b64.EncodeToString(mutated)
		return tokenPrefix + strings.Join(cp, ":") + tokenSuffix
	}

	for _, tc := range []struct {
		name string
		idx  int
	}{{"ciphertext", 4}, {"iv", 3}, {"mac", 5}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := p.Unseal(ctx, c, flip(tc.idx))
			if err == nil {
				t.Fatalf("tampered %s unsealed to %q — MUST fail closed", tc.name, got)
			}
			if got != "" {
				t.Fatalf("failure path returned data: %q", got)
			}
			if !errors.Is(err, ErrTampered) && !errors.Is(err, ErrWrongContext) {
				t.Fatalf("tampered %s: want integrity failure, got %v", tc.name, err)
			}
		})
	}
}

func TestMalformedTokensAreRejected(t *testing.T) {
	p, _ := newProvider("acme")
	ctx, c := context.Background(), ctxFor("acme", "card")
	for _, bad := range []string{
		"", "plaintext", "<enc:>", "<enc:v1:only:three:parts>",
		"<enc:v1:YWNtZQ:notanumber:aXY:Y3Q:bWFj>",
		"<enc:v9:YWNtZQ:1:aXY:Y3Q:bWFj>", // future version
	} {
		if _, err := p.Unseal(ctx, c, bad); err == nil {
			t.Errorf("malformed token %q must not unseal", bad)
		}
	}
	// A future version is "cannot read", NOT "malformed" — different operator
	// action (upgrade vs investigate corruption).
	if _, err := p.Unseal(ctx, c, "<enc:v9:YWNtZQ:1:aXY:Y3Q:bWFj>"); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("an unknown token version should report ErrKeyUnavailable, got %v", err)
	}
}

// ── key rotation ────────────────────────────────────────────────────────────

func TestKeyRotationKeepsOldValuesReadable(t *testing.T) {
	p, keys := newProvider("acme")
	ctx, c := context.Background(), ctxFor("acme", "card")

	oldSealed, err := p.Seal(ctx, c, "old-secret")
	if err != nil {
		t.Fatal(err)
	}
	v1, ok := KeyVersionOf(oldSealed)
	if !ok || v1 != 1 {
		t.Fatalf("expected key version 1, got %d", v1)
	}

	v2, err := p.Rotate(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if v2 != 2 {
		t.Fatalf("rotate should advance to 2, got %d", v2)
	}

	// New seals use the new version…
	newSealed, err := p.Seal(ctx, c, "new-secret")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := KeyVersionOf(newSealed); v != 2 {
		t.Fatalf("post-rotation seal should use v2, got %d", v)
	}
	// …and BOTH remain readable. Rotation must never orphan stored data.
	if got, err := p.Unseal(ctx, c, oldSealed); err != nil || got != "old-secret" {
		t.Fatalf("pre-rotation value must stay readable: %q %v", got, err)
	}
	if got, err := p.Unseal(ctx, c, newSealed); err != nil || got != "new-secret" {
		t.Fatalf("post-rotation value: %q %v", got, err)
	}

	// A RETIRED key version reports unavailability rather than pretending.
	keys.mu.Lock()
	delete(keys.material["acme"], 1)
	keys.mu.Unlock()
	if _, err := p.Unseal(ctx, c, oldSealed); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("a retired key version must report ErrKeyUnavailable, got %v", err)
	}
}

// ── key custody failures ────────────────────────────────────────────────────

func TestUnavailableCustodyFailsClosed(t *testing.T) {
	p, keys := newProvider("acme")
	keys.fail["acme"] = true
	ctx, c := context.Background(), ctxFor("acme", "card")
	if _, err := p.Seal(ctx, c, "secret"); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("sealing without custody must fail closed, got %v", err)
	}
}

// ── edge key ────────────────────────────────────────────────────────────────

// The key handed to the ingest runtime must be the DERIVED seal key, never the
// tenant DEK — a router compromise must not yield the key that protects stored
// credentials.
func TestEdgeKeyIsDerivedNotTheDEK(t *testing.T) {
	p, keys := newProvider("acme")
	ctx := context.Background()
	edge, err := p.EdgeKey(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(edge.SealKey) != 32 || len(edge.MACKey) != 32 {
		t.Fatalf("edge keys must be 32 bytes, got seal=%d mac=%d", len(edge.SealKey), len(edge.MACKey))
	}
	dek, _, err := keys.TenantKey(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(edge.SealKey, dek) || bytes.Equal(edge.MACKey, dek) {
		t.Fatal("the edge must receive DERIVED keys, never the tenant DEK itself")
	}
	// The two edge keys must also differ from each other: encrypt-then-MAC with
	// one key for both jobs is the classic misuse.
	if bytes.Equal(edge.SealKey, edge.MACKey) {
		t.Fatal("seal and MAC keys are identical — encryption and authentication must not share a key")
	}
	if edge.Version != 1 {
		t.Fatalf("edge key version: got %d", edge.Version)
	}
	// Different tenants get different edge keys — isolation holds at the edge.
	keys.mint("globex", 1)
	other, err := p.EdgeKey(ctx, "globex")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other.SealKey, edge.SealKey) || bytes.Equal(other.MACKey, edge.MACKey) {
		t.Fatal("edge keys must differ per tenant")
	}
}

// ── display form ────────────────────────────────────────────────────────────

func TestDisplayMasksButKeepsTail(t *testing.T) {
	cases := []struct {
		in, want string
		keep     int
	}{
		{"4111111111111111", "************1111", 4},
		{"short", "*****", 0},
		{"abc", "**c", 1},
		{"café", "***é", 1}, // rune-safe, not byte-safe
	}
	for _, c := range cases {
		if got := Display(c.in, c.keep); got != c.want {
			t.Errorf("Display(%q,%d) = %q, want %q", c.in, c.keep, got, c.want)
		}
	}
	// A very long value must not become an unreadable wall of asterisks.
	if got := Display(strings.Repeat("x", 500), 4); len(got) > displayHeadCap+4 {
		t.Errorf("display head is unbounded: %d chars", len(got))
	}
}

// ── concurrency ─────────────────────────────────────────────────────────────

// The ingest path seals continuously while operators unseal; the provider must
// be safe under concurrent use (the derived-key cache is shared state).
func TestConcurrentSealUnseal(t *testing.T) {
	p, _ := newProvider("acme", "globex")
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tenant := []string{"acme", "globex"}[i%2]
			c := ctxFor(tenant, "card")
			want := fmt.Sprintf("value-%d", i)
			sealed, err := p.Seal(ctx, c, want)
			if err != nil {
				t.Errorf("seal: %v", err)
				return
			}
			got, err := p.Unseal(ctx, c, sealed)
			if err != nil || got != want {
				t.Errorf("round trip under load: %q %v", got, err)
			}
		}(i)
	}
	wg.Wait()
}
