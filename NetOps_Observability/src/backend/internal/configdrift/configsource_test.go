package configdrift

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/configstore"
	"netops/backend/internal/hardening"
)

// putVersion seeds a stored version + its sealed blob.
func putVersion(t *testing.T, f *fixture, tenant, device, text string, at time.Time, status string) configstore.Version {
	t.Helper()
	sha := configstore.SHA256Hex(text)
	ref, err := f.blobs.Put(tenant, device, sha, seal(text))
	if err != nil {
		t.Fatalf("blob put: %v", err)
	}
	v := configstore.Version{
		TenantID: tenant, DeviceID: device, SHA: sha, CapturedAt: at,
		SizeBytes: int64(len(text)), BlobRef: ref, Vendor: string(configstore.VendorCisco),
		Status: status, Drift: StateUnknown,
	}
	if err := f.vers.Put(context.Background(), tenant, false, v); err != nil {
		t.Fatalf("version put: %v", err)
	}
	return v
}

// TestConfigSourceReturnsTheLatestVersion is the wire that ends the hardening
// lane's blanket "not assessed" verdict.
func TestConfigSourceReturnsTheLatestVersion(t *testing.T) {
	f := newFixture(t, nil)
	base := f.now
	putVersion(t, f, "acme", "d1", cfgText("edge-old"), base, configstore.StatusOK)
	putVersion(t, f, "acme", "d1", cfgText("edge-new"), base.Add(time.Hour), configstore.StatusOK)

	src := f.eval.ConfigSourceFor("acme")
	got, ok, err := src.RunningConfig(context.Background(), "d1")
	if err != nil || !ok {
		t.Fatalf("RunningConfig = ok %v err %v", ok, err)
	}
	if !strings.Contains(got, "hostname edge-new") {
		t.Fatalf("the source returned a stale version:\n%s", got)
	}
	// UNREDACTED by design: the hardening rules detect exactly what redaction
	// masks, so a redacted config would make every credential rule pass.
	if !strings.Contains(got, canarySecret) {
		t.Fatal("the hardening source must see the real configuration, redacted text would false-pass every credential rule")
	}
}

// TestConfigSourceFailsClosedWhenNothingIsCaptured: ok=false, so the engine's
// StatusUnknown path runs — never a fabricated empty config that reads as clean.
func TestConfigSourceFailsClosedWhenNothingIsCaptured(t *testing.T) {
	f := newFixture(t, nil)
	src := f.eval.ConfigSourceFor("acme")
	got, ok, err := src.RunningConfig(context.Background(), "d1")
	if err != nil {
		t.Fatalf("an absent config is not an error: %v", err)
	}
	if ok || got != "" {
		t.Fatalf("RunningConfig = (%q, %v), want empty+false", got, ok)
	}
}

// TestConfigSourceIgnoresFailedCaptures.
func TestConfigSourceIgnoresFailedCaptures(t *testing.T) {
	f := newFixture(t, nil)
	failed := configstore.Version{
		TenantID: "acme", DeviceID: "d1", SHA: configstore.SHA256Hex("fail"),
		CapturedAt: f.now.Add(time.Hour), Status: configstore.StatusFailed, Error: "unreachable",
	}
	if err := f.vers.Put(context.Background(), "acme", false, failed); err != nil {
		t.Fatal(err)
	}
	src := f.eval.ConfigSourceFor("acme")
	if _, ok, _ := src.RunningConfig(context.Background(), "d1"); ok {
		t.Fatal("a failed capture must not be served as a running config")
	}
}

// TestConfigSourceIsTenantBound is the §3a obligation: the hardening interface
// takes only a device id, so a source that could see other tenants' configs
// would be a cross-tenant read waiting to happen.
func TestConfigSourceIsTenantBound(t *testing.T) {
	f := newFixture(t, nil)
	putVersion(t, f, "globex", "d2", cfgText("globex-edge"), f.now, configstore.StatusOK)

	acme := f.eval.ConfigSourceFor("acme")
	if got, ok, err := acme.RunningConfig(context.Background(), "d2"); ok || got != "" || err != nil {
		t.Fatalf("CROSS-TENANT LEAK: acme read globex's config: (%q, %v, %v)", got, ok, err)
	}
	globex := f.eval.ConfigSourceFor("globex")
	if _, ok, err := globex.RunningConfig(context.Background(), "d2"); !ok || err != nil {
		t.Fatalf("the owning tenant must see its own config: ok=%v err=%v", ok, err)
	}
}

// TestConfigSourceDistinguishesTransportFailureFromAbsence: a store outage must
// not read as "this device has no configuration".
func TestConfigSourceDistinguishesTransportFailureFromAbsence(t *testing.T) {
	f := newFixture(t, nil)
	boom := errors.New("postgres is down")
	src := NewConfigSource("acme", errStore{err: boom}, func(configstore.Version) (string, error) { return "", nil })
	_, ok, err := src.RunningConfig(context.Background(), "d1")
	if ok {
		t.Fatal("a store failure must not report a config")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the transport error propagated", err)
	}
	_ = f
}

// TestConfigSourceSatisfiesTheHardeningInterface pins the contract structurally.
func TestConfigSourceSatisfiesTheHardeningInterface(t *testing.T) {
	f := newFixture(t, nil)
	var src hardening.ConfigSource = f.eval.ConfigSourceFor("acme")
	if src == nil {
		t.Fatal("nil config source")
	}
	// The engine must accept it in place of the MemConfigSource stub.
	eng := hardening.NewEngine(hardening.DefaultCatalog(), src, hardening.MemSeamResolver{})
	if eng == nil {
		t.Fatal("hardening engine refused the config source")
	}
}

// errStore is a Store whose reads always fail.
type errStore struct{ err error }

func (e errStore) List(context.Context, string, bool, string) ([]configstore.Version, error) {
	return nil, e.err
}
func (e errStore) Get(context.Context, string, bool, string, string) (configstore.Version, error) {
	return configstore.Version{}, e.err
}
func (e errStore) Latest(context.Context, string, bool, string) (configstore.Version, bool, error) {
	return configstore.Version{}, false, e.err
}
func (e errStore) Golden(context.Context, string, bool, string) (configstore.Version, bool, error) {
	return configstore.Version{}, false, e.err
}
func (e errStore) Put(context.Context, string, bool, configstore.Version) error { return e.err }
func (e errStore) SetGolden(context.Context, string, bool, string, string) error {
	return e.err
}
func (e errStore) RecordDrift(context.Context, string, bool, string, string, string, int, int) error {
	return e.err
}
func (e errStore) Prune(context.Context, string, bool, string, int) ([]configstore.Version, error) {
	return nil, e.err
}

var _ configstore.Store = errStore{}

// TestHardeningSourceResolvesTheOwnerFromInventory is the seam the security lane
// binds: each device is read under ITS OWN tenant, and an unknown device fails
// closed rather than triggering a cross-tenant search.
func TestHardeningSourceResolvesTheOwnerFromInventory(t *testing.T) {
	f := newFixture(t, nil)
	putVersion(t, f, "acme", "d1", cfgText("acme-edge"), f.now, configstore.StatusOK)
	putVersion(t, f, "globex", "d2", cfgText("globex-edge"), f.now, configstore.StatusOK)

	owners := map[string]string{"d1": "acme", "d2": "globex"}
	src := f.eval.HardeningSource(func(id string) (string, bool) {
		t, ok := owners[id]
		return t, ok
	})

	got, ok, err := src.RunningConfig(context.Background(), "d1")
	if err != nil || !ok || !strings.Contains(got, "acme-edge") {
		t.Fatalf("d1 = (%q, %v, %v)", got, ok, err)
	}
	got, ok, err = src.RunningConfig(context.Background(), "d2")
	if err != nil || !ok || !strings.Contains(got, "globex-edge") {
		t.Fatalf("d2 = (%q, %v, %v)", got, ok, err)
	}
	// An unknown device fails closed.
	if _, ok, err := src.RunningConfig(context.Background(), "ghost"); ok || err != nil {
		t.Fatalf("ghost = ok %v err %v, want fail-closed", ok, err)
	}
	// A device whose inventory row says globex can never read acme's config.
	wrong := f.eval.HardeningSource(func(string) (string, bool) { return "globex", true })
	if got, ok, _ := wrong.RunningConfig(context.Background(), "d1"); ok || got != "" {
		t.Fatalf("CROSS-TENANT LEAK: %q", got)
	}
}
