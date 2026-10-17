// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package featureflags

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeEnv struct {
	mu sync.Mutex
	m  map[string]string
}

func newEnv(kv ...string) *fakeEnv {
	e := &fakeEnv{m: map[string]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		e.m[kv[i]] = kv[i+1]
	}
	return e
}

func (e *fakeEnv) Lookup(k string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.m[k]
	return v, ok
}

func (e *fakeEnv) Set(k, v string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.m[k] = v
	return nil
}

type fakeStore struct {
	b       []byte
	loadErr error
	saveErr error
	saves   int
}

func (s *fakeStore) Load() ([]byte, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	if s.b == nil {
		return nil, fmt.Errorf("absent: %w", os.ErrNotExist)
	}
	return s.b, nil
}

func (s *fakeStore) Save(b []byte) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saves++
	s.b = append([]byte(nil), b...)
	return nil
}

var specs = []Spec{
	{Env: "FEATURE_LIVE", Label: "live", Apply: ApplyLive},
	{Env: "ENABLE_RESTART", Label: "restart", Apply: ApplyRestart, Semantics: OnUnlessFalse},
	{Env: "FEATURE_RISKY", Label: "risky", Apply: ApplyLive, Risky: true},
	{Env: "FEATURE_ONUNLESS", Label: "on unless false", Apply: ApplyRestart, Semantics: OnUnlessFalse},
}

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func get(t *testing.T, r *Registry, env string) State {
	t.Helper()
	st, ok := r.Get(env)
	if !ok {
		t.Fatalf("no %s", env)
	}
	return st
}

func TestPrecedenceConsoleOverInstallOverDefault(t *testing.T) {
	env := newEnv("FEATURE_LIVE", "true")
	store := &fakeStore{b: []byte(`{"ENABLE_RESTART":{"value":false,"updated_by":"owner","updated_at":"2026-10-10T00:00:00Z"}}`)}
	r := New(specs, env, store)
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	if st := get(t, r, "FEATURE_LIVE"); !st.Running || st.Source != SourceInstall || st.InstallValue == nil || !*st.InstallValue {
		t.Errorf("install value: %+v", st)
	}
	if st := get(t, r, "ENABLE_RESTART"); st.Running || st.Source != SourceConsole || st.UpdatedBy != "owner" || st.RestartPending {
		t.Errorf("console value applied at boot: %+v", st)
	}
	if v, _ := env.Lookup("ENABLE_RESTART"); v != "false" {
		t.Errorf("saved value not applied to the environment before readers run: %q", v)
	}
	if st := get(t, r, "FEATURE_RISKY"); st.Running || st.Source != SourceDefault {
		t.Errorf("default: %+v", st)
	}
	if st := get(t, r, "FEATURE_ONUNLESS"); !st.Running {
		t.Errorf("OnUnlessFalse with nothing set must read on: %+v", st)
	}
}

func TestLiveFlagAppliesNowRestartFlagWaits(t *testing.T) {
	env := newEnv()
	store := &fakeStore{}
	r := New(specs, env, store)
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	if _, after, err := r.Set("FEATURE_LIVE", true, "", "owner", t0); err != nil || !after.Running || after.RestartPending {
		t.Fatalf("live: %+v %v", after, err)
	}
	if v, _ := env.Lookup("FEATURE_LIVE"); v != "true" {
		t.Fatalf("live flag not in force: %q", v)
	}
	before, after, err := r.Set("ENABLE_RESTART", false, "", "owner", t0)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Running || !after.Running || after.Desired || !after.RestartPending {
		t.Fatalf("restart flag must report running=true desired=false pending: %+v", after)
	}
	if v, ok := env.Lookup("ENABLE_RESTART"); ok && v == "false" {
		t.Fatal("a restart-class flag must not change the running process")
	}
	// After a restart (a new registry over the same store) it runs.
	r2 := New(specs, newEnv(), store)
	if err := r2.Load(); err != nil {
		t.Fatal(err)
	}
	if st := get(t, r2, "ENABLE_RESTART"); st.Running || st.RestartPending || st.Source != SourceConsole {
		t.Fatalf("after restart: %+v", st)
	}
}

func TestRiskyFlagNeedsAcknowledgementToTurnOnNotOff(t *testing.T) {
	r := New(specs, newEnv(), &fakeStore{})
	_ = r.Load()
	if _, _, err := r.Set("FEATURE_RISKY", true, "", "owner", t0); !errors.Is(err, ErrAckRequired) {
		t.Fatalf("want ErrAckRequired, got %v", err)
	}
	if _, _, err := r.Set("FEATURE_RISKY", true, "FEATURE_LIVE", "owner", t0); !errors.Is(err, ErrAckRequired) {
		t.Fatal("an acknowledgement for another flag must not count")
	}
	if _, after, err := r.Set("FEATURE_RISKY", true, "FEATURE_RISKY", "owner", t0); err != nil || !after.Running {
		t.Fatalf("%+v %v", after, err)
	}
	if _, _, err := r.Set("FEATURE_RISKY", false, "", "owner", t0); err != nil {
		t.Fatal("turning a risky flag OFF must never need an acknowledgement")
	}
}

func TestUnknownFlagAndStoreFailureChangeNothing(t *testing.T) {
	env := newEnv()
	store := &fakeStore{}
	r := New(specs, env, store)
	_ = r.Load()
	if _, _, err := r.Set("FEATURE_SEALED_FIELDS", true, "", "owner", t0); !errors.Is(err, ErrUnknownFlag) {
		t.Fatalf("an unlisted flag must be refused: %v", err)
	}
	store.saveErr = errors.New("disk full")
	if _, _, err := r.Set("FEATURE_LIVE", true, "", "owner", t0); !errors.Is(err, ErrStoreFailure) {
		t.Fatalf("want ErrStoreFailure, got %v", err)
	}
	if v, ok := env.Lookup("FEATURE_LIVE"); ok && v == "true" {
		t.Fatal("a value that was not persisted must not be applied")
	}
	if st := get(t, r, "FEATURE_LIVE"); st.Source == SourceConsole {
		t.Fatal("an unsaved value must not be reported as saved")
	}
}

// An unreadable store must not stop the boot, and must not leave a risky
// switch on: the install values stand, risky flags are forced off.
func TestUnreadableStoreFailsClosedForRiskyFlagsOnly(t *testing.T) {
	env := newEnv("FEATURE_RISKY", "true", "FEATURE_LIVE", "true")
	r := New(specs, env, &fakeStore{loadErr: errors.New("connection refused")})
	err := r.Load()
	if err == nil || r.LoadError() == nil {
		t.Fatal("the failure must be reported")
	}
	if get(t, r, "FEATURE_RISKY").Running {
		t.Error("risky flag must be off after an unreadable store")
	}
	if !get(t, r, "FEATURE_LIVE").Running {
		t.Error("a non-risky install value must stand")
	}
	r2 := New(specs, newEnv(), &fakeStore{b: []byte("{not json")})
	if err := r2.Load(); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("corrupt store: %v", err)
	}
}

func TestSpecTableRejectsDuplicates(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate Env must panic")
		}
	}()
	New([]Spec{{Env: "A"}, {Env: "A"}}, newEnv(), &fakeStore{})
}

// Concurrent Set and Enabled must not race (meaningful under -race in CI).
func TestConcurrentSetAndRead(t *testing.T) {
	r := New(specs, newEnv(), &fakeStore{})
	_ = r.Load()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_, _, _ = r.Set("FEATURE_LIVE", i%2 == 0, "", "owner", t0)
		}(i)
		go func() {
			defer wg.Done()
			_ = r.Enabled("FEATURE_LIVE")
			_ = r.List()
		}()
	}
	wg.Wait()
}
