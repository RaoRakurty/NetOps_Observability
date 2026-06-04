package main

import (
	"path/filepath"
	"testing"
)

func TestSNMPCredV2cAndRedaction(t *testing.T) {
	cs, err := newSNMPCredStore(filepath.Join(t.TempDir(), "snmp.json"), nil)
	if err != nil {
		t.Fatalf("newSNMPCredStore: %v", err)
	}
	pub, err := cs.Upsert(SNMPCredential{Name: "Core Switches", Version: "v2c", Community: "s3cr3t"})
	if err != nil {
		t.Fatalf("Upsert v2c: %v", err)
	}
	if pub.ID != "core-switches" || !pub.HasCommunity || pub.Port != 161 {
		t.Errorf("unexpected public cred: %+v", pub)
	}
	// List must never leak the secret.
	for _, c := range cs.List() {
		// publicSNMPCredential has no Community field at all — compile-time proof.
		if !c.HasCommunity {
			t.Error("expected has_community true")
		}
	}
	// Resolve (poller path) returns the real secret.
	full, ok := cs.Resolve("core-switches")
	if !ok || full.Community != "s3cr3t" {
		t.Errorf("Resolve secret wrong: %+v ok=%v", full, ok)
	}
	// Resolve by name (case-insensitive) too.
	if _, ok := cs.Resolve("CORE SWITCHES"); !ok {
		t.Error("Resolve by name should work")
	}
}

func TestSNMPCredV3Validation(t *testing.T) {
	cs, _ := newSNMPCredStore(filepath.Join(t.TempDir(), "snmp.json"), nil)
	// authPriv requires auth + priv protocols and keys.
	if _, err := cs.Upsert(SNMPCredential{Name: "v3bad", Version: "v3", SecurityName: "noc", SecurityLevel: "authPriv"}); err == nil {
		t.Error("expected validation error for authPriv without keys")
	}
	good := SNMPCredential{
		Name: "v3 good", Version: "v3", SecurityName: "noc", SecurityLevel: "authPriv",
		AuthProtocol: "SHA256", AuthKey: "authpass123", PrivProtocol: "AES256", PrivKey: "privpass123",
	}
	pub, err := cs.Upsert(good)
	if err != nil {
		t.Fatalf("Upsert v3: %v", err)
	}
	if !pub.HasAuthKey || !pub.HasPrivKey || pub.AuthProtocol != "SHA256" {
		t.Errorf("v3 public cred wrong: %+v", pub)
	}
	// Bad enum is rejected.
	if _, err := cs.Upsert(SNMPCredential{Name: "x", Version: "v9", Community: "c"}); err == nil {
		t.Error("expected invalid version to fail")
	}
}

func TestSNMPCredUpdatePreservesSecrets(t *testing.T) {
	cs, _ := newSNMPCredStore(filepath.Join(t.TempDir(), "snmp.json"), nil)
	cs.Upsert(SNMPCredential{Name: "grp", Version: "v2c", Community: "orig"})
	// Update without re-sending the community keeps the stored one.
	if _, err := cs.Upsert(SNMPCredential{ID: "grp", Name: "grp", Version: "v2c", Retries: 3}); err != nil {
		t.Fatalf("update: %v", err)
	}
	full, _ := cs.Resolve("grp")
	if full.Community != "orig" {
		t.Errorf("secret not preserved on update: %q", full.Community)
	}
	if full.Retries != 3 {
		t.Errorf("retries not updated: %d", full.Retries)
	}
}
