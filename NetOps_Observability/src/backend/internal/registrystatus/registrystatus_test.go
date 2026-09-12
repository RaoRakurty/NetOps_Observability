// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package registrystatus

import "testing"

// The whole point of this package is that four states stay four states. These
// tests fail if any of them is ever collapsed into another — in particular if a
// registry configured for one backend is ever reported as active on a different
// one, which would be the report saying a failover happened.

func spec() Spec {
	return Spec{Registry: "applications", Label: "Application registry",
		Backends: []string{BackendPostgres, BackendMemory}}
}

func TestEvaluateHealthyPersistent(t *testing.T) {
	st := Evaluate(spec(), BackendPostgres, true, "")
	if !st.Available || !st.Healthy {
		t.Fatalf("healthy postgres must be available: %+v", st)
	}
	if st.ActiveBackend != BackendPostgres || st.Persistence != Persistent {
		t.Fatalf("wrong backend/persistence: %+v", st)
	}
	if st.Reason != "" {
		t.Fatalf("a healthy registry needs no reason: %+v", st)
	}
}

func TestEvaluateUnhealthyKeepsTheConfiguredBackend(t *testing.T) {
	st := Evaluate(spec(), BackendPostgres, false, ReasonUnavailable)
	if st.Available || st.Healthy {
		t.Fatalf("an unreachable backend is not available: %+v", st)
	}
	if st.ActiveBackend != BackendPostgres {
		t.Fatalf("active_backend changed to %q during an outage — that would claim a failover", st.ActiveBackend)
	}
	if st.Persistence != Persistent || st.Reason == "" {
		t.Fatalf("an outage keeps the persistence characteristic and states a reason: %+v", st)
	}
}

func TestEvaluateUnsupportedClaimsNothing(t *testing.T) {
	st := Evaluate(spec(), BackendFile, true, "")
	if st.Available || st.Healthy {
		t.Fatalf("an unsupported backend cannot be available: %+v", st)
	}
	if st.ActiveBackend != "" || st.Persistence != "" {
		t.Fatalf("nothing stores the registry, so nothing may be claimed: %+v", st)
	}
	if st.ConfiguredBackend != BackendFile || st.Reason != ReasonUnsupported {
		t.Fatalf("the configured backend and the reason must both be reported: %+v", st)
	}
	// A healthy backend must not promote an unsupported registry.
	if Evaluate(spec(), BackendFile, true, "").Available {
		t.Fatal("backend health must never make an unsupported registry available")
	}
}

func TestEvaluateEphemeralSaysSo(t *testing.T) {
	st := Evaluate(spec(), BackendMemory, true, "")
	if !st.Available || st.Persistence != Ephemeral || st.Reason == "" {
		t.Fatalf("memory must be available, ephemeral and self-describing: %+v", st)
	}
}

func TestPersistenceOfNeverOverClaims(t *testing.T) {
	if PersistenceOf("cassandra") != "" {
		t.Fatal("an unknown backend must make no durability claim")
	}
	if PersistenceOf(BackendMemory) != Ephemeral || PersistenceOf(BackendFile) != Persistent {
		t.Fatal("known kinds must map to their real durability")
	}
}

func TestBuildEvaluatesEveryRegistryIndependently(t *testing.T) {
	specs := []Spec{
		spec(),
		{Registry: "service_catalog", Label: "Service catalog", Backends: []string{BackendPostgres}},
	}
	rep := Build(specs, BackendMemory, true, "")
	if len(rep.Registries) != 2 {
		t.Fatalf("want one row per registry, got %+v", rep.Registries)
	}
	if !rep.Registries[0].Available {
		t.Fatal("applications support memory and must be available")
	}
	if rep.Registries[1].Available || rep.Registries[1].ActiveBackend != "" {
		t.Fatal("the service catalog has no memory implementation and must not borrow the other's verdict")
	}
}
