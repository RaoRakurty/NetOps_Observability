// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discoveryscope

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/discovery"
)

// memKV is an in-memory PrefixKV.
type memKV struct {
	mu   sync.Mutex
	m    map[string][]byte
	fail bool
}

func newMemKV() *memKV { return &memKV{m: map[string][]byte{}} }

func (k *memKV) Save(key string, b []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail {
		return errors.New("kv down")
	}
	k.m[key] = append([]byte(nil), b...)
	return nil
}

func (k *memKV) LoadPrefix(prefix string) (map[string][]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail {
		return nil, errors.New("kv down")
	}
	out := map[string][]byte{}
	for key, v := range k.m {
		if strings.HasPrefix(key, prefix) {
			out[key] = append([]byte(nil), v...)
		}
	}
	return out, nil
}

func (k *memKV) Delete(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, key)
	return nil
}

var t0 = time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)

func scope(id, tenant string, ranges ...string) Scope {
	return Scope{ID: id, TenantID: tenant, Name: "edges", Ranges: ranges, Enabled: true, CreatedBy: "admin", CreatedAt: t0, UpdatedAt: t0}
}

func sid(n int) string { return fmt.Sprintf("ds-%016x", n) }

func TestValidateNormalizesAndRefuses(t *testing.T) {
	sc := scope(sid(1), " T_Retail ", "10.70.0.81/32", " 10.70.0.0/30 ")
	sc.CredentialRefs = []string{" p1 ", "p1", "p2"}
	if err := Validate(&sc); err != nil {
		t.Fatal(err)
	}
	if sc.TenantID != "t_retail" || strings.Join(sc.Ranges, ",") != "10.70.0.81/32,10.70.0.0/30" || strings.Join(sc.CredentialRefs, ",") != "p1,p2" {
		t.Fatalf("normalized: %+v", sc)
	}
	for name, mut := range map[string]func(*Scope){
		"client-chosen id":  func(s *Scope) { s.ID = "my-scope" },
		"platform owner":    func(s *Scope) { s.TenantID = "" },
		"global owner":      func(s *Scope) { s.TenantID = "Global" },
		"no name":           func(s *Scope) { s.Name = "  " },
		"control char name": func(s *Scope) { s.Name = "a\nb" },
		"long name":         func(s *Scope) { s.Name = strings.Repeat("x", 81) },
		"no range":          func(s *Scope) { s.Ranges = nil },
		"public range":      func(s *Scope) { s.Ranges = []string{"8.8.8.0/30"} },
		"oversized range":   func(s *Scope) { s.Ranges = []string{"10.0.0.0/8"} },
		"empty ref":         func(s *Scope) { s.CredentialRefs = []string{""} },
		"too many refs": func(s *Scope) {
			s.CredentialRefs = nil
			for i := 0; i <= MaxCredentialRefs; i++ {
				s.CredentialRefs = append(s.CredentialRefs, fmt.Sprint(i))
			}
		},
	} {
		s := scope(sid(1), "t_retail", "10.70.0.0/30")
		mut(&s)
		if err := Validate(&s); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	pub := scope(sid(1), "t_retail", "8.8.8.0/30")
	pub.AllowNonPrivate = true
	if err := Validate(&pub); err != nil {
		t.Fatalf("acknowledged public range: %v", err)
	}
}

// TestFileStoreIsTenantScoped is §3a rule 4 for the file backend: the store
// itself never hands one tenant another's scope.
func TestFileStoreIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	st := NewFileStore("/data/discovery_scopes.json", newMemKV())
	for _, sc := range []Scope{scope(sid(1), "t_a", "10.1.0.0/30"), scope(sid(2), "t_b", "10.2.0.0/30"), scope(sid(3), "t_a", "10.3.0.0/30")} {
		if err := st.Put(ctx, sc); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(tenant string, cross bool) string {
		l, err := st.List(ctx, tenant, cross)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range l {
			out = append(out, s.ID[len(s.ID)-1:])
		}
		return strings.Join(out, ",")
	}
	if got := ids("t_a", false); got != "1,3" {
		t.Fatalf("CROSS-TENANT LEAK: t_a lists %q", got)
	}
	if got := ids("T_B", false); got != "2" {
		t.Fatalf("t_b lists %q", got)
	}
	if got := ids("", false); got != "" {
		t.Fatalf("the platform partition holds no scopes, read %q", got)
	}
	if got := ids("", true); got != "1,3,2" {
		t.Fatalf("cross lists %q", got)
	}
	if _, found, _ := st.Get(ctx, "t_b", false, sid(1)); found {
		t.Fatal("t_b read t_a's scope by id")
	}
	if ok, _ := st.Delete(ctx, "t_b", sid(1)); ok {
		t.Fatal("t_b deleted t_a's scope")
	}
	if _, found, _ := st.Get(ctx, "t_a", false, sid(1)); !found {
		t.Fatal("t_a's scope must survive another tenant's delete")
	}
	// An id another tenant holds is never re-filed under a second tenant.
	if err := st.Put(ctx, scope(sid(1), "t_b", "10.9.0.0/30")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an id held by another tenant must be refused, got %v", err)
	}
	if ok, err := st.Delete(ctx, "t_a", sid(1)); !ok || err != nil {
		t.Fatalf("own delete: %v %v", ok, err)
	}
}

func TestFileStoreBoundsAndCorruption(t *testing.T) {
	ctx := context.Background()
	kv := newMemKV()
	st := NewFileStore("/data/discovery_scopes.json", kv)
	for i := 0; i < MaxPerTenant; i++ {
		if err := st.Put(ctx, scope(sid(i+1), "t_a", fmt.Sprintf("10.10.%d.0/30", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Put(ctx, scope(sid(99), "t_a", "10.11.0.0/30")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("the per-customer bound must hold, got %v", err)
	}
	if err := st.Put(ctx, scope(sid(1), "t_a", "10.12.0.0/30")); err != nil {
		t.Fatalf("an update at the bound is not a new scope: %v", err)
	}
	// A record whose name and content disagree refuses the whole load.
	for k, v := range kv.m {
		kv.m[k+"x"] = v
		break
	}
	if _, err := st.List(ctx, "t_a", false); err == nil {
		t.Fatal("a misnamed record must refuse the load")
	}
	kv2 := newMemKV()
	kv2.m["/data/discovery_scopes.json.d/scopes/abc"] = []byte("{not json")
	if _, err := NewFileStore("/data/discovery_scopes.json", kv2).List(ctx, "", true); err == nil {
		t.Fatal("an undecodable record must refuse the load")
	}
}

func TestRegistryKeepsTheLastGoodSetAndMapsTurnedOnScopes(t *testing.T) {
	ctx := context.Background()
	kv := newMemKV()
	st := NewFileStore("/data/discovery_scopes.json", kv)
	on := scope(sid(1), "t_a", "10.1.0.0/30")
	on.CredentialRefs = []string{"p-a"}
	off := scope(sid(2), "t_b", "10.2.0.0/30")
	off.Enabled = false
	for _, sc := range []Scope{on, off} {
		if err := st.Put(ctx, sc); err != nil {
			t.Fatal(err)
		}
	}
	reg := NewRegistry(st)
	if err := reg.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	got := reg.ScanScopes(func(sc Scope) []discovery.ScanCredential {
		return []discovery.ScanCredential{{ProfileID: sc.TenantID + ":" + strings.Join(sc.CredentialRefs, "+")}}
	})
	if len(got) != 1 || got[0].ID != sid(1) || got[0].TenantID != "t_a" || got[0].Credentials[0].ProfileID != "t_a:p-a" {
		t.Fatalf("only the turned-on scope is a channel, with its own credentials: %+v", got)
	}
	kv.mu.Lock()
	kv.fail = true
	kv.mu.Unlock()
	if err := reg.Reload(ctx); err == nil || reg.LoadError() == nil {
		t.Fatal("a failed reload must be reported and remembered")
	}
	if n := len(reg.Snapshot()); n != 2 {
		t.Fatalf("a store blip must not turn every customer's scan off: %d scopes left", n)
	}
	kv.mu.Lock()
	kv.fail = false
	kv.mu.Unlock()
	if err := reg.Reload(ctx); err != nil || reg.LoadError() != nil {
		t.Fatalf("recovery: %v", err)
	}
}

// versionStore answers List with the version current when the read STARTED;
// the first read can be held mid-flight to model a slow store.
type versionStore struct {
	Store
	mu      sync.Mutex
	version int
	hold    chan struct{} // closed to release the held read
	entered chan struct{} // closed when the held read has started
	held    bool
}

func (v *versionStore) List(ctx context.Context, tenant string, cross bool) ([]Scope, error) {
	v.mu.Lock()
	ver := v.version
	holdThis := !v.held
	v.held = true
	v.mu.Unlock()
	if holdThis {
		close(v.entered)
		<-v.hold
	}
	return []Scope{{ID: sid(ver), TenantID: "t_a"}}, nil
}

// TestConcurrentReloadsNeverPublishAStaleSet: reload A reads the store, then
// stalls; the store changes; reload B starts. Whatever the interleaving, the
// set in force afterwards is the newer one — A must not finish last and put
// its older read back.
func TestConcurrentReloadsNeverPublishAStaleSet(t *testing.T) {
	vs := &versionStore{version: 1, hold: make(chan struct{}), entered: make(chan struct{})}
	reg := NewRegistry(vs)
	ctx := context.Background()
	aDone := make(chan error, 1)
	go func() { aDone <- reg.Reload(ctx) }()
	<-vs.entered // A has read version 1 and is stalled
	vs.mu.Lock()
	vs.version = 2 // a committed write lands
	vs.mu.Unlock()
	bDone := make(chan error, 1)
	go func() { bDone <- reg.Reload(ctx) }()
	// Give an unserialized B every chance to read version 2 and publish first.
	select {
	case err := <-bDone:
		bDone <- err
	case <-time.After(200 * time.Millisecond):
	}
	close(vs.hold) // A finishes now — last, if B was not made to wait
	if err := <-aDone; err != nil {
		t.Fatal(err)
	}
	if err := <-bDone; err != nil {
		t.Fatal(err)
	}
	snap := reg.Snapshot()
	if len(snap) != 1 || snap[0].ID != sid(2) {
		t.Fatalf("a slow reload published its older read over a newer one: %+v", snap)
	}
}
