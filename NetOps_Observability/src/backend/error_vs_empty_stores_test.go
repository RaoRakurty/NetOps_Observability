package main

// error_vs_empty_stores_test.go — proof for the file-backed store half of the
// CLAUDE.md §10 conflation cleanup (see silent_failure_guards_test.go for the
// mechanical guard and cloud_monitor_eval.go for the three-state reference).
//
// Every store below used to do:
//
//	b, err := platformdb.Load(s.path)
//	if err != nil || len(b) == 0 { return }   // load() returned nothing at all
//
// so "the store did not answer" and "nothing has been saved yet" produced the
// SAME empty in-memory state. Two consequences, both silent:
//
//  1. every tenant read as un-configured (verification OFF, no monitors, no
//     SLOs, default governance) while the platform looked healthy, and
//  2. the next single-tenant write flushed that empty map back over the file,
//     DESTROYING the tenants that were still on disk.
//
// Each test here fails against that old behaviour: it makes the read fail
// (corrupt bytes — deterministic and permission-independent, unlike chmod which
// root ignores) and asserts the store now (a) says so and (b) refuses to
// overwrite what it never read, while the genuinely-absent path still loads
// silently as an empty store.

import (
	"os"

	"netops/backend/internal/verify"
	"path/filepath"
	"testing"

	"netops/backend/models"
)

// corruptStore writes bytes that are readable but not decodable, so kvLoad
// succeeds and the DECODE fails — the "the store did not answer" state.
func corruptStore(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyConfigUnreadableIsNotAnOptedOutTenant(t *testing.T) {
	dir := t.TempDir()

	// Control: a genuinely absent store is NOT a failure.
	fresh := verify.NewConfigStore(filepath.Join(dir, "absent.json"), nil)
	if err := fresh.Unavailable(); err != nil {
		t.Fatalf("an absent store must load clean, got %v", err)
	}
	if _, ok := fresh.PublicView("t-1", false)["config_unavailable"]; ok {
		t.Fatal("a fresh install must not report config_unavailable")
	}

	// The defect: an unreadable store.
	path := corruptStore(t, dir, "verify_config.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st := verify.NewConfigStore(path, nil)

	if st.Unavailable() == nil {
		t.Fatal("an unreadable verification config must be reported, not swallowed: " +
			"every tenant then reads as OPTED OUT while suspected cases pile up")
	}
	if len(st.EnabledTenants()) != 0 {
		t.Fatal("nothing was loaded, so no tenant can be enabled")
	}
	view := st.PublicView("t-1", false)
	if view["config_unavailable"] != true {
		t.Fatalf("publicView must say the stored config is UNKNOWN, not render enabled=false as an operator choice: %v", view)
	}

	// A write must not flush the empty map over the file we never read.
	on := true
	if _, err := st.Set("t-1", verifySettingsPatch{Enabled: &on}); err == nil {
		t.Fatal("a save against an unread store must fail — it would erase every other tenant's opt-in and SSH credential")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the stored file was overwritten by a store that never read it: %q", after)
	}
}

func TestDeviceStoreUnreadableDoesNotResurrectDeletedDevices(t *testing.T) {
	dir := t.TempDir()

	// Control: absent file → empty store, writes work.
	fresh := newDeviceStore(filepath.Join(dir, "absent.json"))
	if err := fresh.Unreadable(); err != nil {
		t.Fatalf("an absent device store must load clean, got %v", err)
	}
	if err := fresh.Put(models.Device{ID: "d1", Name: "sw1"}); err != nil {
		t.Fatalf("write to a fresh store: %v", err)
	}

	// The defect: a boot read failure used to look exactly like "no manual
	// devices and no tombstones", so a deleted device came back and the first
	// write flushed the empty maps over the survivors.
	path := corruptStore(t, dir, "devices.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st := newDeviceStore(path)
	if st.Unreadable() == nil {
		t.Fatal("a device store whose file could not be read must say so — an empty map is not the same fact")
	}
	if err := st.Put(models.Device{ID: "d9", Name: "new"}); err == nil {
		t.Fatal("a write against an unread device store must fail rather than flush empty maps over the stored devices and tombstones")
	}
	if err := st.Remove("d9"); err == nil {
		t.Fatal("a delete against an unread device store must fail for the same reason")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the stored device file was overwritten by a store that never read it: %q", after)
	}
}

func TestTenantMapStoresRefuseToOverwriteWhatTheyNeverRead(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name string
		save func(path string) error // constructs the store and attempts a write
	}{
		{"cloud_slo", func(p string) error {
			s := newCloudSLOStore(p)
			s.mu.Lock()
			defer s.mu.Unlock()
			s.slos["t-1"] = []cloudSLO{{AppName: "checkout", TargetPct: 99.9, WindowDays: 30}}
			return s.saveLocked()
		}},
		{"cloud_monitors", func(p string) error {
			return newCloudMonitorStore(p).SeedForTest("t-1", []cloudMonitor{{ID: "m1", TenantID: "t-1", Name: "cpu"}})
		}},
		{"tenant_display", func(p string) error {
			s := newTenantDisplayStore(p)
			s.mu.Lock()
			defer s.mu.Unlock()
			s.cfgs["t-1"] = tenantDisplayConfig{TenantID: "t-1"}
			return s.saveLocked()
		}},
		{"tenant_governance", func(p string) error {
			return newTenantGovernanceStore(p).SeedForTest("t-1", tenantGovernanceConfig{TenantID: "t-1"})
		}},
		{"ai_tenant_config", func(p string) error {
			return newAITenantConfigStore(p, nil).SeedForTest("t-1", aiTenantConfig{TenantID: "t-1"})
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Control: an absent store saves fine (first run must still work).
			okPath := filepath.Join(dir, c.name+"-fresh.json")
			if err := c.save(okPath); err != nil {
				t.Fatalf("write to a fresh %s store: %v", c.name, err)
			}

			path := corruptStore(t, dir, c.name+".json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.save(path); err == nil {
				t.Fatalf("%s: a save against a store whose file was never read must fail — "+
					"the in-memory map holds ONE tenant and the file holds all of them", c.name)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("%s: stored file was overwritten by a store that never read it: %q", c.name, after)
			}
		})
	}
}

func TestDiscoveryConfigUnreadableFailsClosedInsteadOfScanningTheEnvDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENABLE_SNMP_DISCOVERY", "true")
	t.Setenv("SNMP_CIDR_RANGES", "10.0.0.0/8")
	t.Setenv("SNMP_COMMUNITY", "public")

	// Control: no saved config at all → the env bootstrap IS the policy.
	fresh := newDiscoveryConfigStore(filepath.Join(dir, "absent.json"), nil)
	if err := fresh.unavailable(); err != nil {
		t.Fatalf("an absent discovery config must load clean, got %v", err)
	}
	if eff := fresh.effective(); !eff.Enabled || len(eff.Ranges) != 1 {
		t.Fatalf("a fresh install must still honour the env bootstrap: %+v", eff)
	}

	// The defect: an unreadable SAVED config used to fall through to the env
	// bootstrap — sweeping a range (and community) the operator never chose.
	st := newDiscoveryConfigStore(corruptStore(t, dir, "discovery_config.json"), nil)
	if st.unavailable() == nil {
		t.Fatal("an unreadable discovery config must be reported")
	}
	eff := st.effective()
	if eff.Enabled || len(eff.Ranges) != 0 {
		t.Fatalf("an unreadable saved config must fail CLOSED, not silently sweep the env default %v: %+v",
			os.Getenv("SNMP_CIDR_RANGES"), eff)
	}
}

func TestUserRulesReadFailureIsNotAnEmptyRuleSet(t *testing.T) {
	dir := t.TempDir()

	// Control: absent file = first run, genuinely no user rules.
	fresh := newUserRulesStore(filepath.Join(dir, "absent.json"))
	rules, err := fresh.load()
	if err != nil || len(rules) != 0 {
		t.Fatalf("absent user-rules file must be an empty set with no error: %d rules, err=%v", len(rules), err)
	}

	// The defect: an unreadable file returned (nil, nil) — the engine ran with
	// NO user rules and add() then rewrote the file with only the new rule.
	st := newUserRulesStore(corruptStore(t, dir, "user_rules.json"))
	if _, err := st.load(); err == nil {
		t.Fatal("an unreadable user-rules file must return an error, not an empty rule set: " +
			"every operator-created monitor silently stops evaluating")
	}
}

// TestExportPolicyReadFailureIsLoudNotADefaultReversion pins the security-relevant
// case: the stored anti-exfiltration caps are the operator's, and an unreadable
// file reverts them to the (looser) env defaults. The revert is unavoidable, the
// silence was not — load() now reports it.
func TestExportPolicyReadFailureIsLoudNotADefaultReversion(t *testing.T) {
	dir := t.TempDir()
	fresh := newExportPolicyStore(filepath.Join(dir, "absent.json"))
	if err := fresh.load(); err != nil {
		t.Fatalf("an absent export policy must load clean, got %v", err)
	}
	st := newExportPolicyStore(corruptStore(t, dir, "export_policy.json"))
	if err := st.load(); err == nil {
		t.Fatal("an unreadable export policy must return an error — the tightened caps have silently reverted to the env defaults")
	}
	tp := newTokenPolicyStore(corruptStore(t, dir, "token_policy.json"), nil)
	if err := tp.load(); err == nil {
		t.Fatal("an unreadable token policy must return an error — the stored token lifetimes are not in force")
	}
}
