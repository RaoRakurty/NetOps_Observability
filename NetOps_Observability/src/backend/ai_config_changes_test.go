// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_config_changes_test.go — the server side of the assistant's configuration-
// change tools (design item 10, plan N-A2), run through the REAL capture path:
// configstore.Manager (fake gateway + fake sealer) → version register →
// configdrift.Evaluator → drift state — then read back through the seams.
//
// §3a isolation pinned here: a scoped tenant sees only its own devices' changes
// and diffs; another tenant's device is ai.ErrNotFound (indistinguishable from
// absent); the platform owner's Global view sees both; acting INTO a tenant
// narrows to it; a Deny principal (operator-visibility restriction) sees nothing.

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/configdrift"
	"netops/backend/internal/configstore"
	"netops/backend/models"
)

type ccSealer struct{}

const ccMarker = "cc1:"

func (ccSealer) Active() bool   { return true }
func (ccSealer) Marker() string { return ccMarker }
func (ccSealer) Seal(tenant, field, plain string) (string, error) {
	return ccMarker + base64.StdEncoding.EncodeToString([]byte(tenant+"|"+field+"|"+plain)), nil
}
func (ccSealer) Open(tenant, field, sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, ccMarker))
	if err != nil {
		return "", err
	}
	prefix := tenant + "|" + field + "|"
	if !strings.HasPrefix(string(raw), prefix) {
		return "", errors.New("aad mismatch")
	}
	return strings.TrimPrefix(string(raw), prefix), nil
}

type ccGateway struct {
	mu  sync.Mutex
	cfg map[string]string
}

func (g *ccGateway) Run(_ context.Context, dev configstore.Device, _ string, _ int64) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cfg[dev.ID], nil
}

func (g *ccGateway) set(id, cfg string) {
	g.mu.Lock()
	g.cfg[id] = cfg
	g.mu.Unlock()
}

// ccFixture wires config backup + drift on a test server with one device in
// each of two tenants, each captured twice (so each has one real change).
func ccFixture(t *testing.T) *server {
	t.Helper()
	_, s := newTestServerState(t)
	for _, d := range []models.Device{
		{ID: "dev-a", Name: "edge-a", Vendor: "cisco", TenantID: "t-a"},
		{ID: "dev-b", Name: "edge-b", Vendor: "cisco", TenantID: "t-b"},
	} {
		if err := s.discovery.Upsert(d); err != nil {
			t.Fatal(err)
		}
	}
	versions := configstore.NewFileStore("")
	sealer := ccSealer{}
	blobs, err := configstore.NewFileBlobStore(t.TempDir(), sealer.Marker())
	if err != nil {
		t.Fatal(err)
	}
	open := func(v configstore.Version) (string, error) {
		sealed, gerr := blobs.Get(v.BlobRef)
		if gerr != nil {
			return "", gerr
		}
		return sealer.Open(configstore.NormTenant(v.TenantID), configstore.BlobField(v.DeviceID, v.SHA), sealed)
	}
	noop := func(string, map[string]any) {}
	drift, err := configdrift.New(configdrift.Deps{
		Now: func() time.Time { return time.Now().UTC() }, Store: configdrift.NewFileStore(""),
		Versions: versions, Open: open,
		Publish: func(_ context.Context, _ string, recs []configdrift.Record) (int, error) { return len(recs), nil },
		Metrics: configdrift.NewMetrics(), Authz: s.configDriftAuthz,
		WriteJSON: writeJSON, WriteError: writeError, LogWarn: noop, LogError: noop, Scrub: scrubLogValue,
	})
	if err != nil {
		t.Fatal(err)
	}
	gw := &ccGateway{cfg: map[string]string{}}
	mgr, err := configstore.New(configstore.Deps{
		Now:          func() time.Time { return time.Now().UTC() },
		Tenants:      func() []string { return []string{"t-a", "t-b"} },
		Devices:      s.configBackupDevices,
		LookupDevice: s.configLookupDevice,
		Gateway:      gw, Sealer: sealer, Blobs: blobs, Store: versions,
		Metrics: configstore.NewMetrics(), OnCapture: drift.Observe, OnFailure: drift.OnFailure,
		Authz: s.configAuthz, WriteJSON: writeJSON, WriteError: writeError,
		LogWarn: noop, LogError: noop, Scrub: scrubLogValue,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.configBackup, s.configDrift = mgr, drift

	ctx := context.Background()
	for _, id := range []string{"dev-a", "dev-b"} {
		dev, _ := s.configLookupDevice(id)
		gw.set(id, "hostname "+id+"\ninterface Gi0/0\n description WAN-ATT\n")
		if _, err := mgr.Capture(ctx, dev, dev.TenantID, "test"); err != nil {
			t.Fatalf("first capture %s: %v", id, err)
		}
		time.Sleep(5 * time.Millisecond) // distinct CapturedAt for a stable order
		gw.set(id, "hostname "+id+"\ninterface Gi0/0\n description WAN-COMCAST\n")
		if _, err := mgr.Capture(ctx, dev, dev.TenantID, "test"); err != nil {
			t.Fatalf("second capture %s: %v", id, err)
		}
	}
	return s
}

var (
	ccTenantA = jwtClaims{Sub: "user-a", Tenant: "t-a", Role: "operator"}
	ccOwner   = jwtClaims{Sub: "owner", Tenant: "", Role: "super-admin"}
)

func ccDeviceIDs(rep ai.ChangeReport) map[string]bool {
	out := map[string]bool{}
	for _, c := range rep.Changes {
		out[c.DeviceID] = true
	}
	return out
}

func TestAIRecentChangesIsolation(t *testing.T) {
	s := ccFixture(t)
	ctx := context.Background()
	week := ai.ChangeQuery{SinceSeconds: 7 * 24 * 3600, Limit: ai.MaxRecentChanges}

	// Scoped tenant, estate-wide: own devices only.
	rep, err := s.aiRecentChanges(ccTenantA)(ctx, ai.Principal{}, week)
	if err != nil {
		t.Fatal(err)
	}
	if ids := ccDeviceIDs(rep); !ids["dev-a"] || ids["dev-b"] {
		t.Fatalf("tenant A estate read = %v — must be exactly its own device", ids)
	}

	// Scoped tenant, another tenant's device: not-found, never "no changes".
	q := week
	q.DeviceID, q.Limit = "dev-b", ai.MaxDeviceChangeVersions
	if _, err := s.aiRecentChanges(ccTenantA)(ctx, ai.Principal{}, q); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("foreign device must be ErrNotFound, got %v", err)
	}

	// Own device: both captures, newest first, the newer one pointing at the older.
	q.DeviceID = "dev-a"
	rep, err = s.aiRecentChanges(ccTenantA)(ctx, ai.Principal{}, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Changes) != 2 || rep.Changes[0].PreviousSHA != rep.Changes[1].SHA || rep.Changes[1].PreviousSHA != "" {
		t.Fatalf("device history = %+v", rep.Changes)
	}

	// Platform owner, Global view: both tenants.
	rep, err = s.aiRecentChanges(ccOwner)(ctx, ai.Principal{}, week)
	if err != nil {
		t.Fatal(err)
	}
	if ids := ccDeviceIDs(rep); !ids["dev-a"] || !ids["dev-b"] {
		t.Fatalf("owner Global view = %v — must see both tenants", ids)
	}

	// Owner acting INTO tenant B: narrowed to B.
	acting := ccOwner
	acting.ActingTenant = "t-b"
	rep, err = s.aiRecentChanges(acting)(ctx, ai.Principal{}, week)
	if err != nil {
		t.Fatal(err)
	}
	if ids := ccDeviceIDs(rep); ids["dev-a"] || !ids["dev-b"] {
		t.Fatalf("owner acting into t-b = %v — must be narrowed to t-b", ids)
	}
}

func TestAIRecentChangesDenyPrincipalSeesNothing(t *testing.T) {
	s := ccFixture(t)
	ctx := context.Background()
	deny := configstore.Principal{Tenant: TenantGlobal, Cross: true, Deny: true}
	since := time.Now().Add(-time.Hour)
	if _, err := s.aiDeviceChangeHistory(ctx, deny, ai.ChangeQuery{DeviceID: "dev-a", Limit: 5}, since); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("a denied principal must get ErrNotFound for a device, got %v", err)
	}
	rep, err := s.aiEstateChanges(ctx, deny, ai.ChangeQuery{Limit: 5}, since)
	if err != nil || len(rep.Changes) != 0 {
		t.Fatalf("a denied principal must see no estate changes: %+v %v", rep, err)
	}
}

func TestAIRecentChangesWindowExcludesOlder(t *testing.T) {
	s := ccFixture(t)
	rep, err := s.aiRecentChanges(ccTenantA)(context.Background(), ai.Principal{},
		ai.ChangeQuery{DeviceID: "dev-a", SinceSeconds: 0, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Changes) != 0 {
		t.Fatalf("a zero-length window must exclude every capture, got %d", len(rep.Changes))
	}
}

func TestAIConfigDiffIsolationAndAnchors(t *testing.T) {
	s := ccFixture(t)
	ctx := context.Background()
	r := newAITestRequest(t, ccTenantA)
	diff := s.aiConfigDiff(r, ccTenantA)

	if _, err := diff(ctx, ai.Principal{}, ai.ConfigDiffRequest{DeviceID: "dev-b", From: ai.DiffAnchorPrevious, To: ai.DiffAnchorLatest}); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("foreign device diff must be ErrNotFound, got %v", err)
	}
	rep, err := diff(ctx, ai.Principal{}, ai.ConfigDiffRequest{DeviceID: "dev-a", From: ai.DiffAnchorPrevious, To: ai.DiffAnchorLatest})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Added == 0 || rep.Removed == 0 || !strings.Contains(rep.Unified, "WAN-COMCAST") || !strings.Contains(rep.Unified, "WAN-ATT") {
		t.Fatalf("diff = %+v", rep)
	}
	if rep.FromLabel != "the capture before it" || rep.ToLabel != "latest capture" || rep.FromSHA == rep.ToSHA {
		t.Fatalf("labels/shas = %+v", rep)
	}

	// A version id prefix resolves; the golden anchor with no golden is a STATE.
	rep2, err := diff(ctx, ai.Principal{}, ai.ConfigDiffRequest{DeviceID: "dev-a", From: rep.FromSHA[:10], To: ai.DiffAnchorLatest})
	if err != nil || rep2.FromSHA != rep.FromSHA {
		t.Fatalf("prefix resolution = %+v %v", rep2, err)
	}
	rep3, err := diff(ctx, ai.Principal{}, ai.ConfigDiffRequest{DeviceID: "dev-a", From: ai.DiffAnchorGolden, To: ai.DiffAnchorLatest})
	if err != nil || !strings.Contains(rep3.Unavailable, "golden") {
		t.Fatalf("no golden must be Unavailable, got %+v %v", rep3, err)
	}
	rep4, err := diff(ctx, ai.Principal{}, ai.ConfigDiffRequest{DeviceID: "dev-a", From: "deadbeefdead", To: ai.DiffAnchorLatest})
	if err != nil || rep4.Unavailable == "" {
		t.Fatalf("an unknown version must be Unavailable, got %+v %v", rep4, err)
	}
}

func TestAIChangeSeamsNotWired(t *testing.T) {
	_, s := newTestServerState(t)
	rep, err := s.aiRecentChanges(ccTenantA)(context.Background(), ai.Principal{}, ai.ChangeQuery{})
	if err != nil || rep.NotWired == "" {
		t.Fatalf("with backup disabled the seam must say so: %+v %v", rep, err)
	}
	deps := s.aiTroubleshootDeps(newAITestRequest(t, ccTenantA), ccTenantA)
	if deps.RecentChanges != nil || deps.ConfigDiff != nil {
		t.Fatal("the change seams must not be wired when config backup is disabled")
	}
}

// newAITestRequest is an authenticated GET carrying `claims` exactly where the
// auth middleware puts them, for seams that record an audit event from it.
func newAITestRequest(t *testing.T, claims jwtClaims) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", nil)
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, claims))
}
