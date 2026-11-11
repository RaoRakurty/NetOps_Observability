// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

// bootcache_test.go — review 2026-11-11, reliability items 1 and 3.
//
// The failure the cache exists for: the api boots while the store cannot be
// read (Postgres flapping, a record that will not open). Without a fallback
// every page is counted not_configured while the heartbeat still lands, so
// AlertDeliveryBroken stays quiet and the watchdog reads green: pages reach
// nobody while every layer is healthy — the 2026-09-02 shape.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withCache(path string) func(d *StoreDeps) {
	return func(d *StoreDeps) {
		d.CachePath = path
		d.ReadCache = os.ReadFile
		d.WriteCache = func(p string, b []byte) error { return os.WriteFile(p, b, 0o600) }
	}
}

func metricsTextOf(s *Store, r *Router) string {
	var b strings.Builder
	WriteMetrics(&b, s, r)
	return b.String()
}

// A good read mirrors the SEALED record to the cache (0600, no plaintext
// secret), and does not rewrite an unchanged record.
func TestGoodReadMirrorsTheSealedRecordToTheCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lastgood.json")
	r := newRouterRigBoot(t, nil, func(_ *memKV, d *StoreDeps, _ Config) { withCache(path)(d) })
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the cache was not written on a good read: %v", err)
	}
	if strings.Contains(string(raw), fakeSecret("ntfy")) || strings.Contains(string(raw), fakeSecret("twilio")) {
		t.Fatalf("the cache must hold the SEALED record: %s", raw)
	}
	if !strings.Contains(string(raw), "sealed:"+FieldNtfyToken) {
		t.Fatalf("cache content: %s", raw)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %v (%v), want 0600", st.Mode().Perm(), err)
	}
	before, _ := os.Stat(path)
	if err := r.store.Refresh(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("an unchanged record must not rewrite the cache every refresh")
	}
}

// THE FIX: the store is unreadable at boot, a cached last-good copy exists →
// a page still reaches the configured ntfy (and every SMS recipient), the
// gauges say "cached", not "nothing in force".
func TestUnreadableStoreAtBootUsesTheCacheAndStillDeliversAPage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lastgood.json")
	e := newE2EBoot(t, nil, func(kv *memKV, d *StoreDeps, cfg Config) {
		withCache(path)(d)
		b := mustJSON(t, sealedForKV(t, cfg))
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		kv.setLoadErr(errors.New("pg: the database system is starting up"))
	})
	if ok, everRead := e.store.Health(); ok || !everRead || !e.store.FromCache() {
		t.Fatalf("health ok=%v everRead=%v fromCache=%v, want the cache in force", ok, everRead, e.store.FromCache())
	}
	e.post(t, "CorrelationConsumerDead", "page")
	if got := e.ntfy.await(t, 1)[0]; got.Path != "/corr-platform-test" {
		t.Fatalf("delivered to %q", got.Path)
	}
	e.twilio.await(t, 2)
	txt := metricsTextOf(e.store, e.router)
	for _, want := range []string{
		"netops_platform_alert_store_readable 0",
		"netops_platform_alert_store_ever_read 1",
		"netops_platform_alert_store_from_cache 1",
		"netops_platform_alert_page_routed 1",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
	// When the store comes back, it wins and the cache flag clears.
	e.kv.setLoadErr(nil)
	if err := e.store.Refresh(); err != nil {
		t.Fatal(err)
	}
	if e.store.FromCache() {
		t.Fatal("a good read must replace the cached copy")
	}
}

// The cache is NEVER used when the store reads fine — even when it differs —
// and the good read overwrites it.
func TestCacheIsIgnoredWhenTheStoreReadsFine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lastgood.json")
	r := newRouterRigBoot(t, func(c *Config) { c.SMS.Enabled = false }, func(_ *memKV, d *StoreDeps, cfg Config) {
		withCache(path)(d)
		stale := cfg
		stale.Ntfy.Topic = "stale-topic-from-cache"
		stale.SMS.Enabled = true
		if err := os.WriteFile(path, mustJSON(t, sealedForKV(t, stale)), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if r.store.FromCache() {
		t.Fatal("a readable store must never be overruled by the cache")
	}
	if got := r.store.Current(); got.Ntfy.Topic != "corr-platform-test" || got.SMS.Enabled {
		t.Fatalf("record in force: %+v", got)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "stale-topic-from-cache") {
		t.Fatal("the good read must overwrite a differing cache")
	}
}

// An ABSENT record mirrors the default to the cache, so a later unreadable
// boot cannot resurrect settings that were removed from the store.
func TestAbsentRecordMirrorsTheDefaultToTheCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lastgood.json")
	kv := newMemKV()
	if err := os.WriteFile(path, mustJSON(t, sealedForKV(t, validNtfyOnly())), 0o600); err != nil {
		t.Fatal(err)
	}
	d := StoreDeps{Key: DefaultKey, Load: kv.Load, Save: kv.Save, Seal: fakeSeal, Open: fakeOpen}
	withCache(path)(&d)
	_ = NewStore(d) // absent record → default mirrored
	kv.setLoadErr(errors.New("pg: down"))
	s := NewStore(d)
	if s.Current().PageRouted() {
		t.Fatal("a removed record came back from the cache")
	}
}

// The vault is the one dependency the cache cannot remove: a cache whose
// secrets will not open leaves nothing in force, loudly.
func TestCacheThatWillNotUnsealLeavesNothingInForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lastgood.json")
	logs := &logSpy{}
	kv := newMemKV()
	kv.setLoadErr(errors.New("pg: down"))
	c := validNtfyOnly()
	c.Ntfy.Token = "sealed:wrong-field:" + "eA=="
	if err := os.WriteFile(path, mustJSON(t, c), 0o600); err != nil {
		t.Fatal(err)
	}
	d := StoreDeps{Key: DefaultKey, Load: kv.Load, Save: kv.Save, Seal: fakeSeal, Open: fakeOpen, Log: logs.log}
	withCache(path)(&d)
	s := NewStore(d)
	if _, everRead := s.Health(); everRead || s.FromCache() {
		t.Fatal("an unopenable cache must not be put in force")
	}
	if !strings.Contains(logs.all(), "could not be unsealed (vault)") {
		t.Fatalf("the vault failure must be named:\n%s", logs.all())
	}
}

// Review item 3: a store NEVER read at boot (and no cache) → the receiver
// counts not_configured, the delivery gauge reads 0, the config gauges read 0
// — the inputs the PlatformAlertsReachNobody page rule and the watchdog read.
func TestNeverReadStoreAtBootIsNotConfiguredAndGaugesReadZero(t *testing.T) {
	e := newE2EBoot(t, nil, func(kv *memKV, _ *StoreDeps, _ Config) {
		kv.setLoadErr(errors.New("vault: decrypt failed"))
	})
	e.post(t, "ClickHouseWritesRejected", "page")
	e.ntfy.quiet(t)
	e.twilio.quiet(t)
	recv := e.metricsText()
	if !strings.Contains(recv, `reason="not_configured"} 1`) || !strings.Contains(recv, "netops_alert_webhook_host_route_enabled 0") {
		t.Fatalf("receiver accounting:\n%s", recv)
	}
	cfg := metricsTextOf(e.store, e.router)
	for _, want := range []string{
		"netops_platform_alert_store_readable 0",
		"netops_platform_alert_store_ever_read 0",
		"netops_platform_alert_store_from_cache 0",
		"netops_platform_alert_page_routed 0",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q in\n%s", want, cfg)
		}
	}
}
