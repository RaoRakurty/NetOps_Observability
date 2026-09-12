// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// store_unreadable_test.go — the silent-data-loss regression for the four
// file-backed stores that live in this package. Each of them folded an
// unreadable file into the ABSENT case: the store started empty with nothing
// logged, and the next write renamed a temp file over the original. A chmod is
// enough to stage it, because the directory stays writable so the rename still
// succeeds.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stageUnreadableStoreFile makes path unreadable and returns its bytes from
// before. It skips the test where a 0000 file can still be read (as root).
func stageUnreadableStoreFile(t *testing.T, path string) []byte {
	t.Helper()
	before, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read seeded file: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := os.ReadFile(path); err == nil { // #nosec G304 -- test-owned temp path
		t.Skip("this environment can read a 0000 file (running as root?), so the case cannot be staged")
	}
	return before
}

// assertStoreFileUntouched proves the file on disk is byte-identical.
func assertStoreFileUntouched(t *testing.T, path string, before []byte) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read file after: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("the file was rewritten while it could not be read:\nbefore %s\nafter  %s", before, after)
	}
}

// ── device locations ────────────────────────────────────────────────────────

// Coordinates an operator typed are not derivable from anything, so an
// unreadable file is an ERROR the entrypoint turns into a refusal to boot — the
// same answer an unparsable file has always got here.
func TestUnreadableDeviceLocationFileIsAnErrorNotAnEmptyMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_locations.json")
	seed, err := newDeviceLocationStore(path)
	if err != nil {
		t.Fatalf("open seed store: %v", err)
	}
	seed.mu.Lock()
	seed.items["ip:10.0.0.1"] = DeviceLocation{Token: "ip:10.0.0.1", Site: "dc1", Lat: 1, Lng: 2}
	ferr := seed.flushLocked()
	seed.mu.Unlock()
	if ferr != nil {
		t.Fatalf("seed flush: %v", ferr)
	}
	before := stageUnreadableStoreFile(t, path)

	s, oerr := newDeviceLocationStore(path)
	if oerr == nil {
		t.Fatal("an unreadable device-location store opened silently — every placed device falls off the map with no reason, and the next placement destroys the file")
	}
	if s != nil {
		t.Fatal("a failed open still handed back a store")
	}
	if !strings.Contains(oerr.Error(), path) {
		t.Fatalf("the error does not name the file the operator must repair: %v", oerr)
	}

	assertStoreFileUntouched(t, path, before)
	reopened, rerr := newDeviceLocationStore(path)
	if rerr != nil {
		t.Fatalf("the repaired file no longer loads: %v", rerr)
	}
	if _, ok := reopened.items["ip:10.0.0.1"]; !ok {
		t.Fatalf("the seeded location did not survive: %+v", reopened.items)
	}
}

// A file that is ABSENT is still just an empty map. This is the half the fix
// must NOT break.
func TestAbsentDeviceLocationFileStaysAnEmptyMap(t *testing.T) {
	s, err := newDeviceLocationStore(filepath.Join(t.TempDir(), "never-written.json"))
	if err != nil {
		t.Fatalf("a store that was never written failed to open: %v", err)
	}
	if len(s.items) != 0 {
		t.Fatalf("a fresh store is not empty: %+v", s.items)
	}
}

// ── SSH host-key pins (TOFU) ────────────────────────────────────────────────

// The pin store FAILS CLOSED. Reading an unreadable pin file as "no pins yet"
// re-armed trust-on-first-use for every device at once, then wrote the newly
// trusted key over the pins nobody read — a silent MITM window.
func TestUnreadableSSHHostPinsRefuseEverySessionAndAreNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh_known_hosts.json")
	seed := newSSHHostStore(path)
	if first, ok := seed.check("10.0.0.1:22", "SHA256:originalkey"); !first || !ok {
		t.Fatalf("seed pin: first=%v ok=%v", first, ok)
	}
	before := stageUnreadableStoreFile(t, path)

	s := newSSHHostStore(path)
	if s.unreadable() == nil {
		t.Fatal("an unreadable pin file loaded silently — every device is re-trusted on first use and the pins are then overwritten")
	}
	// ANY key is refused, including one that would have matched: we cannot tell.
	if first, ok := s.check("10.0.0.1:22", "SHA256:originalkey"); ok || first {
		t.Fatalf("a session was allowed while the pins could not be read: first=%v ok=%v", first, ok)
	}
	if _, ok := s.check("10.0.0.9:22", "SHA256:attackerkey"); ok {
		t.Fatal("an UNKNOWN host was trusted on first use while the pins could not be read")
	}

	assertStoreFileUntouched(t, path, before)
	reopened := newSSHHostStore(path)
	if reopened.unreadable() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.unreadable())
	}
	if first, ok := reopened.check("10.0.0.1:22", "SHA256:originalkey"); first || !ok {
		t.Fatalf("the original pin did not survive: first=%v ok=%v", first, ok)
	}
}

// A pin file that is ABSENT is a genuine first run, so TOFU still applies.
func TestAbsentSSHHostPinsStillTrustOnFirstUse(t *testing.T) {
	s := newSSHHostStore(filepath.Join(t.TempDir(), "never-written.json"))
	if err := s.unreadable(); err != nil {
		t.Fatalf("a pin file that was never written reported %v", err)
	}
	if first, ok := s.check("10.0.0.1:22", "SHA256:key"); !first || !ok {
		t.Fatalf("first use on a fresh pin store: first=%v ok=%v", first, ok)
	}
}

// ── notification channel config ─────────────────────────────────────────────

// The config file holds SEVEN channels and their vault-sealed secrets, so a save
// over contents we never read would delete every channel the operator was not
// editing. The old code was worse than that: the unreadable branch fell into the
// first-run env seed, which SAVES, so the api overwrote the file at BOOT with no
// operator action at all.
func TestUnreadableNotifyConfigIsNeverOverwrittenAtBootOrOnSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify_config.json")
	seed := newNotifyConfigStore(path, nil)
	seed.cfg.Slack.Enabled = true
	seed.cfg.Slack.WebhookURL = "https://hooks.example/seeded"
	if err := seed.save(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	before := stageUnreadableStoreFile(t, path)

	s := newNotifyConfigStore(path, nil)
	if s.unreadable == nil {
		t.Fatal("an unreadable notification config loaded silently — every channel reads as unconfigured and the boot seed overwrites the file")
	}
	if err := s.save(); !errors.Is(err, errNotifyConfigUnreadable) {
		t.Fatalf("a save over an unreadable notification config returned %v", err)
	}

	// The boot path itself must not have written anything either.
	assertStoreFileUntouched(t, path, before)
	reopened := newNotifyConfigStore(path, nil)
	if reopened.unreadable != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.unreadable)
	}
	if !reopened.cfg.Slack.Enabled || reopened.cfg.Slack.WebhookURL != "https://hooks.example/seeded" {
		t.Fatalf("the seeded channel did not survive: %+v", reopened.cfg.Slack)
	}
}

// A config file that is ABSENT is still a first run: seed from env and save.
func TestAbsentNotifyConfigStillSeedsAndSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-written.json")
	s := newNotifyConfigStore(path, nil)
	if s.unreadable != nil {
		t.Fatalf("a config that was never written reported %v", s.unreadable)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the first-run seed did not persist: %v", err)
	}
	if err := s.save(); err != nil {
		t.Fatalf("a save on a fresh config failed: %v", err)
	}
}

// ── NetBox connection config ────────────────────────────────────────────────

// This one RECOVERS rather than refuses: the file holds ONE object the admin PUT
// replaces whole, so an operator re-entering the connection is performing the
// repair. The recovery must be explicit — reported on the read, and refusing the
// one shortcut that would silently drop the stored token.
func TestUnreadableNetboxConfigIsReportedAndRecoversOnlyOnAnExplicitSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netbox_config.json")
	seed := newNetboxConfigStore(path, nil)
	if _, err := seed.set(netboxConfig{Enabled: true, URL: "https://netbox.example", Token: "seeded-token"}); err != nil {
		t.Fatalf("seed netbox config: %v", err)
	}
	before := stageUnreadableStoreFile(t, path)

	s := newNetboxConfigStore(path, nil)
	if s.unavailable() == nil {
		t.Fatal("an unreadable NetBox config loaded silently — discovery stops using NetBox and nobody is told")
	}
	// The blank-token shortcut means "keep the stored one". There is none we can
	// read, so it must be refused rather than saved as an empty token behind a
	// redacted form.
	if _, err := s.set(netboxConfig{Enabled: true, URL: "https://netbox.example"}); err == nil {
		t.Fatal("a blank token was accepted while the stored one could not be read — the connection would report itself configured with no credential")
	}
	assertStoreFileUntouched(t, path, before)

	// An EXPLICIT full save is the repair, and it is allowed.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	out, err := s.set(netboxConfig{Enabled: true, URL: "https://netbox.example", Token: "re-entered"})
	if err != nil {
		t.Fatalf("an explicit re-entry could not repair the config: %v", err)
	}
	if out.Token != "re-entered" {
		t.Fatalf("the re-entered token did not stick: %+v", out)
	}
	if s.unavailable() != nil {
		t.Fatalf("the store still reports itself unreadable after the repair: %v", s.unavailable())
	}
	reopened := newNetboxConfigStore(path, nil)
	if reopened.unavailable() != nil {
		t.Fatalf("the rewritten file no longer loads: %v", reopened.unavailable())
	}
	if reopened.effective().URL != "https://netbox.example" {
		t.Fatalf("the repaired config did not land: %+v", reopened.effective())
	}
}

// A NetBox config that is ABSENT is simply one nobody configured from the UI.
func TestAbsentNetboxConfigIsNotReportedUnreadable(t *testing.T) {
	s := newNetboxConfigStore(filepath.Join(t.TempDir(), "never-written.json"), nil)
	if err := s.unavailable(); err != nil {
		t.Fatalf("a config that was never written reported %v", err)
	}
	if _, err := s.set(netboxConfig{Enabled: true, URL: "https://netbox.example", Token: "t"}); err != nil {
		t.Fatalf("the first save on a fresh config failed: %v", err)
	}
}
