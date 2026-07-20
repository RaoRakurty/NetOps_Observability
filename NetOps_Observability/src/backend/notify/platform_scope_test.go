package notify

// platform_scope_test.go — #103: the platform self-health lane accepts ONLY
// allowlisted stack-health alert classes; customer-network raw alerts are
// rejected (they page via the per-tenant RCA policy lane instead).

import (
	"testing"

	"netops/backend/models"
)

type recChannel struct {
	sent     []models.Alert
	resolved []models.Alert
}

func (r *recChannel) Name() string              { return "rec" }
func (r *recChannel) Send(a models.Alert) error { r.sent = append(r.sent, a); return nil }
func (r *recChannel) SendResolve(a models.Alert) error {
	r.resolved = append(r.resolved, a)
	return nil
}

func TestPlatformScopeFilter_RejectsCustomerAlerts(t *testing.T) {
	rec := &recChannel{}
	f := NewPlatformScopeFilter(rec)

	customer := []models.Alert{
		{ID: "1", Rule: "InterfaceDown", Severity: "critical",
			Labels: map[string]string{"device": "leaf1", "index": "3"}},
		{ID: "2", Rule: "BGPSessionDown", Severity: "critical",
			Labels: map[string]string{"device": "spine1", "peer": "10.0.0.1"}},
		{ID: "3", Rule: "CriticalCPU", Severity: "critical",
			Labels: map[string]string{"device": "wan-r2", "vendor": "arista"}},
		{ID: "4", Rule: "NoLabelsAtAll", Severity: "critical"},
	}
	for _, a := range customer {
		if err := f.Send(a); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	if len(rec.sent) != 0 {
		t.Fatalf("customer alerts leaked into the platform lane: %v", rec.sent)
	}

	platform := []models.Alert{
		{ID: "5", Rule: "ContainerDown", Severity: "critical",
			Labels: map[string]string{"layer": "stack"}},
		{ID: "6", Rule: "HostOOMKillerFired", Severity: "critical",
			Labels: map[string]string{"layer": "host"}},
		{ID: "7", Rule: "CHMemoryLimitExceeded", Severity: "critical",
			Labels: map[string]string{"layer": "clickhouse"}},
		{ID: "8", Rule: "ScrapeTargetDown", Severity: "critical",
			Labels: map[string]string{"layer": "platform"}},
	}
	for _, a := range platform {
		if err := f.Send(a); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	if len(rec.sent) != len(platform) {
		t.Fatalf("platform alerts blocked: sent=%d want=%d", len(rec.sent), len(platform))
	}

	// E1: resolutions bypass SEVERITY, never SCOPE. Customer / untyped
	// resolutions are rejected; platform-scoped ones pass.
	if err := f.SendResolve(models.Alert{ID: "1", Rule: "InterfaceDown",
		Labels: map[string]string{"device": "leaf1"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.SendResolve(models.Alert{ID: "2"}); err != nil { // untyped
		t.Fatal(err)
	}
	if len(rec.resolved) != 0 {
		t.Fatalf("customer/untyped resolution crossed into the platform lane: %v", rec.resolved)
	}
	if err := f.SendResolve(models.Alert{ID: "5", Rule: "ContainerDown",
		Labels: map[string]string{"layer": "stack"}}); err != nil {
		t.Fatal(err)
	}
	// spoofed/garbage scope metadata stays default-closed
	if err := f.SendResolve(models.Alert{ID: "9",
		Labels: map[string]string{"layer": "STACK; drop"}}); err != nil {
		t.Fatal(err)
	}
	if len(rec.resolved) != 1 || rec.resolved[0].ID != "5" {
		t.Fatalf("scope validation on resolve wrong: %v", rec.resolved)
	}
}

// E5: deployment identity namespaces dedup keys — staging can never resolve
// production's incident; regions never collide; unset = legacy keys.
func TestPagerDuty_DeploymentIdentityDedup(t *testing.T) {
	base := NewPagerDuty("rk")
	prodUS := base.WithDeploymentIdentity("production", "us-central")
	prodEU := base.WithDeploymentIdentity("production", "eu-west")
	stg := base.WithDeploymentIdentity("staging", "us-central")

	if got := base.dedupFor("alert-1"); got != "alert-1" {
		t.Fatalf("legacy key changed: %q", got)
	}
	keys := map[string]bool{
		prodUS.dedupFor("alert-1"): true,
		prodEU.dedupFor("alert-1"): true,
		stg.dedupFor("alert-1"):    true,
	}
	if len(keys) != 3 {
		t.Fatalf("env/region identities collide: %v", keys)
	}
}
