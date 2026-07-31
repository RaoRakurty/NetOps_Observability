package processors

// seal_test.go — the `seal` action's contract inside the processor framework.
//
// The cipher itself is package sealing's problem and is tested there against
// the real Vector binary. What is tested HERE is the part the framework owns:
// that seal refuses the configurations it cannot honour, that the simulator
// seals through the same engine the edge uses, and that a preview never shows
// an operator something the pipeline will not do.

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// stubSealEngine stands in for package sealing. It is deliberately NOT a cipher:
// a fake that "encrypts" would tempt this file into asserting crypto properties
// that belong to the parity tests, where they can be checked against the real
// runtime instead of against another fake.
type stubSealEngine struct {
	mu       sync.Mutex
	failFor  map[string]bool // tenants with no key custody
	sealed   int
	snippets int
}

func newStubSealEngine() *stubSealEngine {
	return &stubSealEngine{failFor: map[string]bool{}}
}

func (s *stubSealEngine) EdgeSnippet(tenant, processorID, field, dataType, path string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failFor[tenant] {
		return "", fmt.Errorf("no key custody for %q", tenant)
	}
	s.snippets++
	return fmt.Sprintf("# seal %s/%s/%s\n%s = \"<enc:v1:stub>\"\n", processorID, field, dataType, path), nil
}

func (s *stubSealEngine) SealValue(tenant, processorID, field, dataType, plaintext string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failFor[tenant] {
		return "", fmt.Errorf("no key custody for %q", tenant)
	}
	s.sealed++
	return fmt.Sprintf("<enc:v1:%s:1:iv:%s:mac>", tenant, dataType), nil
}

func (s *stubSealEngine) DisplayForm(plaintext string, keepLast int) string {
	return maskedValue(plaintext, keepLast)
}

// withSealEngine installs an engine for the duration of a test and restores the
// previous one, so tests cannot leak state into each other through the package
// level seam.
func withSealEngine(t *testing.T, e SealEngine) {
	t.Helper()
	prev := currentSealEngine()
	SetSealEngine(e)
	t.Cleanup(func() { SetSealEngine(prev) })
}

func sealRule(t *testing.T, mutate func(*Rule)) Rule {
	t.Helper()
	r := Rule{
		ID: "p-seal", Name: "Seal card numbers", TenantID: "acme", Lane: "applogs",
		Type: TypeSeal, Enabled: true, Field: "card", DataType: "card", KeepLast: 4, Order: 10,
	}
	if mutate != nil {
		mutate(&r)
	}
	return r
}

// Sealing must be refused outright when it is not configured. Half-working
// encryption is worse than none: the operator believes the field is protected.
func TestSealRefusedWhenNotConfigured(t *testing.T) {
	withSealEngine(t, nil)
	r := sealRule(t, nil)
	if err := r.Validate(); err == nil {
		t.Fatal("seal must not validate when no sealing engine is configured")
	}
}

// A whole-event sweep cannot be sealed: the field name is part of what the
// token is bound to, so a swept value could never be unsealed again.
func TestSealRefusesTheWholeEventSweep(t *testing.T) {
	withSealEngine(t, newStubSealEngine())
	r := sealRule(t, func(r *Rule) { r.Field = FieldAll })
	err := r.Validate()
	if err == nil {
		t.Fatal("seal must refuse the * sweep — a sealed value is bound to one field")
	}
	if !strings.Contains(err.Error(), FieldAll) {
		t.Fatalf("the error should name the sweep so the operator can fix it, got: %v", err)
	}
}

func TestSealRequiresATenant(t *testing.T) {
	withSealEngine(t, newStubSealEngine())
	r := sealRule(t, func(r *Rule) { r.TenantID = "" })
	if err := r.Validate(); err == nil {
		t.Fatal("seal must refuse a processor with no owning tenant — keys are per tenant")
	}
}

// The simulator must seal through the SAME engine the edge uses, so preview
// shows a real token. A preview that showed a placeholder would hide the very
// failures preview exists to surface.
func TestSealSimulatesThroughTheEngine(t *testing.T) {
	eng := newStubSealEngine()
	withSealEngine(t, eng)
	r := sealRule(t, nil)

	ev := map[string]any{"card": "4111111111111111", "host": "r1"}
	spec, ok := lookupAction(TypeSeal)
	if !ok {
		t.Fatal("seal action is not registered")
	}
	if !spec.Apply(ev, r) {
		t.Fatal("seal did not fire on a present field")
	}
	got, _ := ev["card"].(string)
	if got == "4111111111111111" {
		t.Fatal("the plaintext survived the simulated seal")
	}
	if !strings.HasPrefix(got, "<enc:") {
		t.Fatalf("preview must show a real sealed token, got %q", got)
	}
	if ev["host"] != "r1" {
		t.Fatal("seal disturbed a field it does not target")
	}
	if eng.sealed != 1 {
		t.Fatalf("expected exactly one seal through the engine, got %d", eng.sealed)
	}
}

// Absent / empty / non-string values must be left alone rather than sealed into
// a token that wraps nothing.
func TestSealLeavesNothingToSealAlone(t *testing.T) {
	withSealEngine(t, newStubSealEngine())
	spec, _ := lookupAction(TypeSeal)
	r := sealRule(t, nil)

	for name, ev := range map[string]map[string]any{
		"absent": {"host": "r1"},
		"empty":  {"card": ""},
	} {
		before := fmt.Sprint(ev)
		if spec.Apply(ev, r) {
			t.Errorf("%s: seal reported firing on nothing", name)
		}
		if fmt.Sprint(ev) != before {
			t.Errorf("%s: event changed: %v", name, ev)
		}
	}
}

// A tenant with no key custody must not compile to a config that silently drops
// the rule while the operator believes the field is protected.
func TestSealCompilesToNothingWithoutCustody(t *testing.T) {
	eng := newStubSealEngine()
	eng.failFor["acme"] = true
	withSealEngine(t, eng)

	spec, _ := lookupAction(TypeSeal)
	if got := spec.CompileVRL(sealRule(t, nil)); got != "" {
		t.Fatalf("a tenant without custody must compile to nothing, got:\n%s", got)
	}
}

// DataType is part of the cryptographic binding, so the framework must never
// hand the engine an empty one — two processors with empty types would produce
// interchangeable tokens.
func TestSealAlwaysBindsADataType(t *testing.T) {
	eng := newStubSealEngine()
	withSealEngine(t, eng)
	r := sealRule(t, func(r *Rule) { r.DataType = "" })
	if got := r.DataTypeOrField(); got != "card" {
		t.Fatalf("an unset data type must fall back to the field name, got %q", got)
	}
	ev := map[string]any{"card": "4111111111111111"}
	spec, _ := lookupAction(TypeSeal)
	spec.Apply(ev, r)
	if s, _ := ev["card"].(string); !strings.Contains(s, "card") {
		t.Fatalf("the binding did not carry a data type: %q", s)
	}
}

// The generated config must actually contain the seal statement for an enabled
// rule — the end-to-end check that registration, compilation and lane wiring
// all line up.
func TestSealReachesTheGeneratedConfig(t *testing.T) {
	withSealEngine(t, newStubSealEngine())
	out := GenerateRouterConfig([]Rule{sealRule(t, nil)})
	if !strings.Contains(out, "# seal p-seal/card/card") {
		t.Fatalf("seal statement missing from the generated router config:\n%s", out)
	}
}

// A sealer that FAILS must not preview as "nothing matched". An operator whose
// key custody is down would otherwise see the field sitting in the clear, read
// it as "my rule is too narrow", and ship a processor that protects nothing.
func TestSealFailureIsVisibleInPreview(t *testing.T) {
	eng := newStubSealEngine()
	eng.failFor["acme"] = true
	withSealEngine(t, eng)

	spec, _ := lookupAction(TypeSeal)
	ev := map[string]any{"card": "4111111111111111"}
	if !spec.Apply(ev, sealRule(t, nil)) {
		t.Fatal("a failed seal must still report that the rule fired — silence reads as 'matched nothing'")
	}
	got, _ := ev["card"].(string)
	if got == "4111111111111111" {
		t.Fatal("preview left the PLAINTEXT visible after a seal failure")
	}
	if got != SealFailureMarker {
		t.Fatalf("preview must show the failure, got %q", got)
	}
	// And the marker must never be mistakable for a real sealed value.
	if strings.HasPrefix(got, "<enc:") {
		t.Fatal("the failure marker is token-shaped — it could be mistaken for a real seal")
	}
}
