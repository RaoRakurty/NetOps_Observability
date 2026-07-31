package backend

// sealed_fields_test.go — the wiring, end to end.
//
// The unit tests in sealing/ and processors/ each prove one side of the seam
// against a stub. Only this file proves the seam is actually CONNECTED: a
// processor rule, compiled and previewed through the real vault, the real
// cipher and the real generator, producing a token the real unseal path opens.
// Everything can pass individually and still be wired to nothing.

import (
	"context"
	"os"
	"strings"
	"testing"

	"netops/backend/internal/vault"
	"netops/backend/processors"
	"netops/backend/sealing"
)

// liveSealing builds the production object graph over an in-memory custody
// store, and restores the package-level engine afterwards.
func liveSealing(t *testing.T) (*vault.Vault, sealing.CryptoProvider) {
	t.Helper()
	v, err := vault.NewWithProvider(context.Background(), &memSealing{},
		&memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	provider := sealing.NewAESCTRProvider(vaultKeyProvider{v: v})

	prev := processors.SealAvailable()
	processors.SetSealEngine(sealEngine{p: provider})
	t.Cleanup(func() {
		if !prev {
			processors.SetSealEngine(nil)
		}
	})
	return v, provider
}

// A rule sealed through the live engine must be readable through the live
// unseal path — the property the whole feature rests on.
func TestSealedFieldsWiringRoundTrips(t *testing.T) {
	_, provider := liveSealing(t)

	r := processors.Rule{
		ID: "p-1", TenantID: "acme", Lane: "applogs", Type: processors.TypeSeal,
		Enabled: true, Field: "card", DataType: "card", KeepLast: 4, Order: 10,
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("a seal rule must validate once the engine is installed: %v", err)
	}

	// Through the PUBLIC simulator — the same call the preview endpoint makes.
	res := processors.SimulateChain([]processors.Rule{r}, "applogs", "acme",
		map[string]any{"card": "4111111111111111", "tenant_id": "acme"})
	if len(res.Applied) != 1 {
		t.Fatalf("seal did not fire in the simulator: %+v", res.Applied)
	}
	sealed, _ := res.Event["card"].(string)
	if !sealing.IsSealed(sealed) {
		t.Fatalf("simulator did not produce a sealed token: %q", sealed)
	}

	opened, err := provider.Unseal(context.Background(), sealing.Context{
		Tenant: "acme", ProcessorID: "p-1", Field: "card", DataType: "card",
	}, sealed)
	if err != nil {
		t.Fatalf("the live unseal path could not open a live-sealed value: %v", err)
	}
	if opened != "4111111111111111" {
		t.Fatalf("round trip: got %q", opened)
	}
}

// The generated router config must carry a real seal snippet naming this
// tenant's secrets — proof the compiler reached sealing rather than emitting
// nothing.
func TestSealedFieldsReachTheRouterConfig(t *testing.T) {
	liveSealing(t)

	out := processors.GenerateRouterConfig([]processors.Rule{{
		ID: "p-1", TenantID: "acme", Lane: "applogs", Type: processors.TypeSeal,
		Enabled: true, Field: "card", DataType: "card", Order: 10,
	}})
	for _, want := range []string{
		`encrypt!`,
		`hmac(`,
		sealing.EdgeSecretRef(sealing.EdgeSealBackend, "acme"),
		sealing.EdgeSecretRef(sealing.EdgeMACBackend, "acme"),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated config is missing %q:\n%s", want, out)
		}
	}
	// The plaintext field must be OVERWRITTEN, not copied somewhere.
	if strings.Contains(out, "_cx_seal_pt\n.") {
		t.Error("generated config appears to keep the plaintext on the event")
	}
}

// Rotation must change what NEW values are sealed under while leaving old ones
// readable — checked here through the production adapter, not the stub.
func TestRotationThroughTheAdapter(t *testing.T) {
	v, provider := liveSealing(t)
	ctx := context.Background()
	c := sealing.Context{Tenant: "acme", ProcessorID: "p-1", Field: "card", DataType: "card"}

	before, err := provider.Seal(ctx, c, "4111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.RotateTenantKey("acme"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	after, err := provider.Seal(ctx, c, "4111111111111111")
	if err != nil {
		t.Fatal(err)
	}

	v1, ok1 := sealing.KeyVersionOf(before)
	v2, ok2 := sealing.KeyVersionOf(after)
	if !ok1 || !ok2 || v2 <= v1 {
		t.Fatalf("rotation did not advance the token key version: %d → %d", v1, v2)
	}
	// Both must still open: rotation may never orphan stored data.
	for name, tok := range map[string]string{"pre-rotation": before, "post-rotation": after} {
		got, err := provider.Unseal(ctx, c, tok)
		if err != nil || got != "4111111111111111" {
			t.Errorf("%s value unreadable after rotation: %q %v", name, got, err)
		}
	}
}

// With the feature off, no engine is installed and a seal rule is REFUSED —
// never accepted-but-inert, which would leave an operator believing a field is
// protected.
func TestSealRefusedWhenFeatureDisabled(t *testing.T) {
	prev := os.Getenv("FEATURE_SEALED_FIELDS")
	t.Setenv("FEATURE_SEALED_FIELDS", "")
	defer func() { _ = os.Setenv("FEATURE_SEALED_FIELDS", prev) }()

	processors.SetSealEngine(nil)
	t.Cleanup(func() { processors.SetSealEngine(nil) })

	if sealedFieldsEnabled() {
		t.Fatal("the feature must be off when the flag is unset")
	}
	r := processors.Rule{
		ID: "p-1", TenantID: "acme", Lane: "applogs", Type: processors.TypeSeal,
		Enabled: true, Field: "card", DataType: "card",
	}
	if err := r.Validate(); err == nil {
		t.Fatal("a seal rule must be refused when sealing is not configured")
	}
}

// Asking for sealing without key custody must ABORT rather than start a
// deployment whose sensitive-data rules silently do nothing.
func TestSealedFieldsFailsClosedWithoutCustody(t *testing.T) {
	t.Setenv("FEATURE_SEALED_FIELDS", "true")
	t.Setenv("SEAL_PROVIDER", "") // dormant vault

	dormant, err := vault.New(context.Background(),
		&memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	err = initSealedFields(dormant, func(string, string, map[string]any) {})
	if err == nil {
		t.Fatal("FEATURE_SEALED_FIELDS=true with no custody must fail closed")
	}
	if !strings.Contains(err.Error(), "SEAL_PROVIDER") {
		t.Fatalf("the error must name the remedy, got: %v", err)
	}
}
