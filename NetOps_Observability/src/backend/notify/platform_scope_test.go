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

func (r *recChannel) Name() string                      { return "rec" }
func (r *recChannel) Send(a models.Alert) error         { r.sent = append(r.sent, a); return nil }
func (r *recChannel) SendResolve(a models.Alert) error  { r.resolved = append(r.resolved, a); return nil }

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

	// resolutions always pass (closing is never noise), even label-less
	if err := f.SendResolve(models.Alert{ID: "1"}); err != nil {
		t.Fatal(err)
	}
	if len(rec.resolved) != 1 {
		t.Fatal("resolve suppressed by platform filter")
	}
}
