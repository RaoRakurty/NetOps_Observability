// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package featureflags

import (
	"errors"
	"testing"
)

// The AI switches (owner 2026-11-12/13): console-only, licence-gated, seeded
// once on upgrade.

var aiSpecs = []Spec{
	{Env: "IRIS_AI_MODELS", Label: "Iris AI models", Apply: ApplyLive, Risky: true, ConsoleOnly: true, Requires: "iris_model"},
	{Env: "PLAIN_CONSOLE", Label: "plain console-only", Apply: ApplyLive, ConsoleOnly: true},
}

func licensed(yes bool) Requirement {
	return func(name string) (bool, string) {
		if name == "iris_model" && yes {
			return true, ""
		}
		return false, "not included in your Team license"
	}
}

// TestConsoleOnlyIgnoresTheEnvironment: no .env line turns a console-only flag
// on, and saving it never writes the environment.
func TestConsoleOnlyIgnoresTheEnvironment(t *testing.T) {
	env := newEnv("PLAIN_CONSOLE", "true", "IRIS_AI_MODELS", "true")
	r := New(aiSpecs, env, &fakeStore{})
	r.SetRequirements(licensed(true))
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"PLAIN_CONSOLE", "IRIS_AI_MODELS"} {
		st := get(t, r, f)
		if st.Running || st.InstallValue != nil || st.Source != SourceDefault {
			t.Fatalf("%s: the environment must have no say: %+v", f, st)
		}
	}
	if _, _, err := r.Set("PLAIN_CONSOLE", true, "", "owner", t0); err != nil {
		t.Fatal(err)
	}
	if !r.Enabled("PLAIN_CONSOLE") {
		t.Fatal("the console value must run")
	}
	env.m["PLAIN_CONSOLE"] = "false"
	if !r.Enabled("PLAIN_CONSOLE") {
		t.Fatal("changing the environment must not change a console-only flag")
	}
	if v := env.m["IRIS_AI_MODELS"]; v != "true" {
		t.Fatalf("the registry must not write the environment for console-only flags (got %q)", v)
	}
}

// TestRequiresGatesTurningOnAndRunning: unlicensed, turning on is refused;
// a saved "on" reads off while the licence is missing and comes back with it.
func TestRequiresGatesTurningOnAndRunning(t *testing.T) {
	store := &fakeStore{}
	r := New(aiSpecs, newEnv(), store)
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	if st := get(t, r, "IRIS_AI_MODELS"); st.Available || st.Running {
		t.Fatalf("with no licence check injected the flag must read unavailable and off: %+v", st)
	}
	r.SetRequirements(licensed(false))
	if _, _, err := r.Set("IRIS_AI_MODELS", true, "IRIS_AI_MODELS", "owner", t0); !errors.Is(err, ErrNotLicensed) {
		t.Fatalf("turning on an unlicensed flag must be refused, got %v", err)
	}
	if store.saves != 0 {
		t.Fatal("a refused change must not be saved")
	}
	// Turning OFF is always allowed.
	if _, _, err := r.Set("IRIS_AI_MODELS", false, "", "owner", t0); err != nil {
		t.Fatalf("turning off never needs a licence: %v", err)
	}
	r.SetRequirements(licensed(true))
	if _, _, err := r.Set("IRIS_AI_MODELS", true, "", "owner", t0); !errors.Is(err, ErrAckRequired) {
		t.Fatalf("licensed, it is still risky and needs the acknowledgement: %v", err)
	}
	if _, _, err := r.Set("IRIS_AI_MODELS", true, "IRIS_AI_MODELS", "owner", t0); err != nil {
		t.Fatal(err)
	}
	if !r.Enabled("IRIS_AI_MODELS") {
		t.Fatal("licensed and on must run")
	}
	// The licence lapses: the saved choice stays, what runs is off.
	r.SetRequirements(licensed(false))
	st := get(t, r, "IRIS_AI_MODELS")
	if st.Running || !st.Desired || st.Available || st.Unavailable == "" {
		t.Fatalf("a lapsed licence turns it off but keeps the choice: %+v", st)
	}
	if r.Enabled("IRIS_AI_MODELS") {
		t.Fatal("Enabled must honour the requirement")
	}
	r.SetRequirements(licensed(true))
	if !r.Enabled("IRIS_AI_MODELS") {
		t.Fatal("the saved choice comes back with the licence")
	}
}

// TestSeedIsOneShotAndNeverOverwrites is the upgrade rule: the first boot of a
// release that adds the switch records the install's existing behaviour once;
// after that only the page changes it.
func TestSeedIsOneShotAndNeverOverwrites(t *testing.T) {
	store := &fakeStore{}
	r := New(aiSpecs, newEnv(), store)
	r.SetRequirements(licensed(true))
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	seeded, err := r.Seed("IRIS_AI_MODELS", true, "upgrade", t0)
	if err != nil || !seeded {
		t.Fatalf("first seed: %v %v", seeded, err)
	}
	if !r.Enabled("IRIS_AI_MODELS") {
		t.Fatal("seeded on, without an acknowledgement — it preserves what already ran")
	}
	if st := get(t, r, "IRIS_AI_MODELS"); st.UpdatedBy != "upgrade" || st.Source != SourceConsole {
		t.Fatalf("the seed must be attributed: %+v", st)
	}
	// The operator turns it off; a later boot's seed must not undo that.
	if _, _, err := r.Set("IRIS_AI_MODELS", false, "", "owner", t0); err != nil {
		t.Fatal(err)
	}
	r2 := New(aiSpecs, newEnv(), store)
	r2.SetRequirements(licensed(true))
	if err := r2.Load(); err != nil {
		t.Fatal(err)
	}
	if seeded, err := r2.Seed("IRIS_AI_MODELS", true, "upgrade", t0); seeded || err != nil {
		t.Fatalf("a flag that was ever saved must never be re-seeded: %v %v", seeded, err)
	}
	if r2.Enabled("IRIS_AI_MODELS") {
		t.Fatal("the operator's off must survive a restart")
	}
	// A fresh install seeds OFF, and that is final too.
	fresh := New(aiSpecs, newEnv(), &fakeStore{})
	fresh.SetRequirements(licensed(true))
	_ = fresh.Load() // nothing saved: os.ErrNotExist is not an error
	if seeded, err := fresh.Seed("IRIS_AI_MODELS", false, "install default", t0); !seeded || err != nil {
		t.Fatalf("fresh seed: %v %v", seeded, err)
	}
	if seeded, _ := fresh.Seed("IRIS_AI_MODELS", true, "upgrade", t0); seeded {
		t.Fatal("a later key must not flip a recorded off")
	}
}

func TestSeedRefusesWhenUnlicensedOrStoreUnread(t *testing.T) {
	r := New(aiSpecs, newEnv(), &fakeStore{})
	r.SetRequirements(licensed(false))
	_ = r.Load()
	if seeded, err := r.Seed("IRIS_AI_MODELS", true, "upgrade", t0); !seeded || err != nil {
		t.Fatalf("seed: %v %v", seeded, err)
	}
	if st := get(t, r, "IRIS_AI_MODELS"); st.Desired || st.Running {
		t.Fatalf("an unlicensed install is recorded OFF, never on: %+v", st)
	}

	broken := &fakeStore{loadErr: errors.New("disk")}
	b := New(aiSpecs, newEnv(), broken)
	b.SetRequirements(licensed(true))
	if err := b.Load(); err == nil {
		t.Fatal("want the load error")
	}
	if _, err := b.Seed("IRIS_AI_MODELS", true, "upgrade", t0); !errors.Is(err, ErrStoreUnread) {
		t.Fatalf("a seed must not overwrite settings it could not read: %v", err)
	}
	if broken.saves != 0 {
		t.Fatal("nothing may be written")
	}
	if b.Enabled("IRIS_AI_MODELS") {
		t.Fatal("unreadable store: the AI switch reads off")
	}
}

func TestConsoleOnlySpecShapeIsEnforced(t *testing.T) {
	for _, bad := range []Spec{
		{Env: "X", ConsoleOnly: true, Apply: ApplyRestart},
		{Env: "X", ConsoleOnly: true, Apply: ApplyLive, Semantics: OnUnlessFalse},
		{Env: "X", Apply: ApplyLive, Requires: "iris_model"},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("spec %+v must be refused", bad)
				}
			}()
			New([]Spec{bad}, newEnv(), &fakeStore{})
		}()
	}
}

func TestNilRegistryReadsOff(t *testing.T) {
	var r *Registry
	if r.Enabled("IRIS_AI_MODELS") {
		t.Fatal("no registry wired: every flag reads off")
	}
	r.SetRequirements(licensed(true)) // nil-safe
}

// TestThePlatformAISwitches pins the shipped specs to the owner's decision.
func TestThePlatformAISwitches(t *testing.T) {
	found := 0
	for _, s := range PlatformSpecs() {
		if s.Env != "IRIS_AI_MODELS" && s.Env != "IRIS_AI_INVESTIGATIONS" {
			continue
		}
		found++
		if !s.ConsoleOnly || !s.Risky || s.Apply != ApplyLive || s.Requires != "iris_model" || s.Semantics != TrueOnly {
			t.Fatalf("%s must be console-only, risky, live, default off and need iris_model: %+v", s.Env, s)
		}
	}
	if found != 2 {
		t.Fatalf("want the two AI switches, found %d", found)
	}
}
