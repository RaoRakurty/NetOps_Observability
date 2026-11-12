// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Round trip: what is saved comes back, the secrets are SEALED at rest (under
// their own field ids), and nothing in the stored bytes is the plaintext.
func TestStoreRoundTripSealsSecretsAtRest(t *testing.T) {
	kv, logs := newMemKV(), &logSpy{}
	s := newTestStore(t, kv, logs)
	c := validNtfyOnly()
	c.Ntfy.Token = fakeSecret("ntfy")
	sms := validSMSOnly()
	c.SMS = sms.SMS
	if err := s.Save(c, false); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw := kv.raw()
	for _, secret := range []string{c.Ntfy.Token, c.SMS.AuthToken} {
		if strings.Contains(raw, secret) {
			t.Fatalf("a secret is stored in the clear: %s", raw)
		}
	}
	if !strings.Contains(raw, "sealed:"+FieldNtfyToken+":") || !strings.Contains(raw, "sealed:"+FieldSMSAuthToken+":") {
		t.Fatalf("secrets must be sealed under their own field ids: %s", raw)
	}

	// A fresh store (a restart, or another replica) opens them again.
	s2 := newTestStore(t, kv, &logSpy{})
	got := s2.Current()
	if got.Ntfy.Token != c.Ntfy.Token || got.SMS.AuthToken != c.SMS.AuthToken || got.Ntfy.Topic != c.Ntfy.Topic {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if !got.PageRouted() {
		t.Fatal("a reloaded live record must route pages")
	}
	if strings.Contains(logs.all(), c.Ntfy.Token) || strings.Contains(logs.all(), c.SMS.AuthToken) {
		t.Fatal("a secret reached the log")
	}
}

func TestStoreAbsentRecordIsTheDefaultNotAFailure(t *testing.T) {
	s := newTestStore(t, newMemKV(), &logSpy{})
	ok, everRead := s.Health()
	if !ok || !everRead {
		t.Fatalf("absent record: ok=%v everRead=%v — absent is a valid state", ok, everRead)
	}
	if s.Current().PageRouted() {
		t.Fatal("absent record routes nothing")
	}
}

// An unreadable store keeps the LAST GOOD record in force and is loud — once
// per transition, not once per refresh — and recovers on its own.
func TestStoreUnreadableKeepsLastGoodAndIsLoudOnce(t *testing.T) {
	kv, logs := newMemKV(), &logSpy{}
	s := newTestStore(t, kv, logs)
	if err := s.Save(validNtfyOnly(), false); err != nil {
		t.Fatal(err)
	}
	kv.setLoadErr(errors.New("pg: connection refused"))
	for i := 0; i < 3; i++ {
		if err := s.Refresh(); err == nil {
			t.Fatal("a failed read must report an error")
		}
	}
	if !s.Current().PageRouted() {
		t.Fatal("the last good record must stay in force while the store is unreadable")
	}
	if ok, everRead := s.Health(); ok || !everRead {
		t.Fatalf("health = ok:%v everRead:%v, want stale (false, true)", ok, everRead)
	}
	if n := logs.count("could NOT be read"); n != 1 {
		t.Fatalf("unreadable store logged %d times, want exactly once per transition\n%s", n, logs.all())
	}
	if s.readFailures.Load() != 3 {
		t.Errorf("every failed read must be counted: %d", s.readFailures.Load())
	}
	kv.setLoadErr(nil)
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Health(); !ok || logs.count("readable again") != 1 {
		t.Fatal("recovery must be noticed and logged")
	}
}

// A record this process could NEVER read holds sealed, write-only secrets: a
// save is refused unless the administrator explicitly replaces it.
func TestStoreRefusesToOverwriteANeverReadRecordWithoutConsent(t *testing.T) {
	kv, logs := newMemKV(), &logSpy{}
	kv.put(t, sealedForKV(t, validSMSOnly()))
	kv.setLoadErr(errors.New("disk: permission denied"))
	s := newTestStore(t, kv, logs)
	if ok, everRead := s.Health(); ok || everRead {
		t.Fatalf("never-read store: ok=%v everRead=%v", ok, everRead)
	}
	if !strings.Contains(logs.all(), "reach NOBODY") {
		t.Fatalf("a never-read store must say platform alerts reach nobody:\n%s", logs.all())
	}
	kv.setLoadErr(nil) // the backend recovers for writes but we have not re-read yet
	if err := s.Save(validNtfyOnly(), false); !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("Save without consent = %v, want ErrStoreUnreadable", err)
	}
	if err := s.Save(validNtfyOnly(), true); err != nil {
		t.Fatalf("Save with explicit replace = %v", err)
	}
	if !s.Current().PageRouted() {
		t.Fatal("the replacement must be in force")
	}
}

// F-78: a record that was not written is not adopted.
func TestStoreSaveFailureChangesNothing(t *testing.T) {
	kv := newMemKV()
	s := newTestStore(t, kv, &logSpy{})
	kv.saveErr = errors.New("disk full")
	if err := s.Save(validNtfyOnly(), false); err == nil {
		t.Fatal("a failed write must fail the save")
	}
	if s.Current().PageRouted() {
		t.Fatal("a record that was not written must not be in force")
	}
	if s.saveFailures.Load() != 1 {
		t.Error("save failure not counted")
	}
	if err := s.Save(Config{Ntfy: NtfyChannel{Enabled: true, Server: "http://x"}}, false); !errors.Is(err, ErrNtfyServer) {
		t.Fatalf("Save must validate: %v", err)
	}
}

// A secret sealed under one field must not open under another (AAD binding):
// a tampered record is a read failure, not a silently swapped credential.
func TestStoreRejectsASecretSealedUnderTheWrongField(t *testing.T) {
	kv, logs := newMemKV(), &logSpy{}
	c := validNtfyOnly()
	sealed, err := fakeSeal(FieldSMSAuthToken, fakeSecret("swapped"))
	if err != nil {
		t.Fatal(err)
	}
	c.Ntfy.Token = sealed
	kv.put(t, c)
	s := newTestStore(t, kv, logs)
	if ok, _ := s.Health(); ok {
		t.Fatal("a secret sealed under another field must fail the read")
	}
	if s.Current().PageRouted() {
		t.Fatal("nothing from a tampered record may be in force")
	}
}

// A change saved by ANOTHER replica reaches this one through RefreshLoop.
func TestRefreshLoopPicksUpAnotherReplicasChange(t *testing.T) {
	kv := newMemKV()
	s := newTestStore(t, kv, &logSpy{})
	v0 := s.Version()
	other := newTestStore(t, kv, &logSpy{})
	if err := other.Save(validNtfyOnly(), false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.RefreshLoop(ctx, 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for !s.Current().PageRouted() {
		if time.Now().After(deadline) {
			t.Fatal("RefreshLoop never picked up the other replica's save")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if s.Version() == v0 {
		t.Fatal("a changed record must bump the version (the router rebuilds on it)")
	}
}

// Two administrators saving at once cannot interleave a merge with the
// other's write: Update holds one lock across read-merge-write.
func TestUpdateSerializesConcurrentWriters(t *testing.T) {
	kv := newMemKV()
	s := newTestStore(t, kv, &logSpy{})
	if err := s.Save(validSMSOnly(), false); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() {
			_, err := s.Update(false, func(cur Config) (Config, error) {
				cur.SMS.MaxPerHour = cur.SMS.MaxPerHour%MaxSMSPerHour + 1
				return cur, nil
			})
			errs <- err
		}()
	}
	for i := 0; i < 20; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if s.Current().SMS.AuthToken == "" {
		t.Fatal("a concurrent update dropped the write-only secret")
	}
}
