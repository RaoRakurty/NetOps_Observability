package notify

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"netops/backend/models"
)

// ---- G10: severity floors and channel identity ------------------------------

// TestDefaultChannelFloors pins the shipped posture for the two channels G10
// brought under management. Teams is chat-class (warning); SNS wakes a phone
// (critical). Before G10 both were env-registered with NO gate at all — every
// alert at every severity went out.
func TestDefaultChannelFloors(t *testing.T) {
	d := DefaultChannelConfig()
	if d.Teams.MinSeverity != "warning" {
		t.Errorf("teams default min_severity = %q, want warning", d.Teams.MinSeverity)
	}
	if d.SNS.MinSeverity != "critical" {
		t.Errorf("sns default min_severity = %q, want critical", d.SNS.MinSeverity)
	}
	if d.Teams.Enabled || d.SNS.Enabled {
		t.Error("new channels must ship disabled (default-closed)")
	}
}

func TestBuildTeamsAndSNSChannelNames(t *testing.T) {
	// The dispatcher keys channels by Name() for Replace/Remove — every wrapper
	// (severity gate, platform scope filter) must preserve the inner name.
	if n := BuildTeamsChannel(TeamsConfig{WebhookURL: "https://x.example/y", MinSeverity: "warning"}).Name(); n != "teams" {
		t.Errorf("teams channel name = %q", n)
	}
	if n := BuildSNSChannel(SNSConfig{TopicARN: "arn:aws:sns:us-east-1:123456789012:t", MinSeverity: "critical"}, "ak", "sk").Name(); n != "sns" {
		t.Errorf("sns channel name = %q", n)
	}
	if n := BuildSNSChannel(SNSConfig{Region: "us-east-1", PhoneNumbers: "+14155550123", MinSeverity: "critical", Scope: "platform"}, "ak", "sk").Name(); n != "sns" {
		t.Errorf("platform-scoped sns channel name = %q", n)
	}
}

// countingChannel records what actually reached a destination.
type countingChannel struct {
	name string
	got  atomic.Int64
	last atomic.Value // models.Alert
}

func (c *countingChannel) Name() string { return c.name }
func (c *countingChannel) Send(a models.Alert) error {
	c.got.Add(1)
	c.last.Store(a)
	return nil
}

// TestSeverityGatePerChannel proves each channel's floor filters independently:
// a warning reaches Teams (floor warning) and never reaches SNS (floor critical).
func TestSeverityGatePerChannel(t *testing.T) {
	teams := &countingChannel{name: "teams"}
	sns := &countingChannel{name: "sns"}
	gTeams := NewSeverityGate(teams, DefaultChannelConfig().Teams.MinSeverity)
	gSNS := NewSeverityGate(sns, DefaultChannelConfig().SNS.MinSeverity)

	for _, sev := range []string{"info", "notice", "warning", "error", "critical"} {
		if err := gTeams.Send(models.Alert{Rule: "R", Severity: sev}); err != nil {
			t.Fatalf("teams send: %v", err)
		}
		if err := gSNS.Send(models.Alert{Rule: "R", Severity: sev}); err != nil {
			t.Fatalf("sns send: %v", err)
		}
	}
	if got := teams.got.Load(); got != 3 {
		t.Errorf("teams received %d alerts, want 3 (warning/error/critical)", got)
	}
	if got := sns.got.Load(); got != 1 {
		t.Errorf("sns received %d alerts, want 1 (critical only)", got)
	}
}

// TestSNSScopeFiltering: scope=platform restricts the globally-credentialled
// pager to Correlix self-health alerts (default-closed on an untyped alert),
// while the default "all" keeps the pre-G10 behavior.
func TestSNSScopeFiltering(t *testing.T) {
	customer := models.Alert{Rule: "InterfaceDown", Severity: "critical"}
	platform := models.Alert{Rule: "ContainerDown", Severity: "critical", Labels: map[string]string{"layer": "stack"}}

	scoped := &countingChannel{name: "sns"}
	filter := NewPlatformScopeFilter(NewSeverityGate(scoped, "critical"))
	if err := filter.Send(customer); err != nil {
		t.Fatalf("send: %v", err)
	}
	if scoped.got.Load() != 0 {
		t.Error("scope=platform must drop a customer-network alert (default-closed)")
	}
	if err := filter.Send(platform); err != nil {
		t.Fatalf("send: %v", err)
	}
	if scoped.got.Load() != 1 {
		t.Error("scope=platform must forward a platform self-health alert")
	}

	// NormalizeSNSScope: unlike PagerDuty, an unset SNS scope means "all" —
	// SNS has no per-tenant RCA adapter to route customer alerts to instead.
	for _, in := range []string{"", "  ", "all", "nonsense"} {
		if got := NormalizeSNSScope(in); got != "all" {
			t.Errorf("NormalizeSNSScope(%q) = %q, want all", in, got)
		}
	}
	if got := NormalizeSNSScope(" Platform "); got != "platform" {
		t.Errorf("NormalizeSNSScope(platform) = %q", got)
	}
}

// ---- G10: validation --------------------------------------------------------

func TestValidateWebhookURL(t *testing.T) {
	ok := []string{"", "https://example.webhook.office.com/webhookb2/abc@def/IncomingWebhook/ghi/jkl"}
	for _, u := range ok {
		if err := ValidateWebhookURL(u); err != nil {
			t.Errorf("ValidateWebhookURL(%q) = %v, want nil", u, err)
		}
	}
	bad := map[string]string{
		"http://example.webhook.office.com/hook": "https",
		"ftp://example.com/hook":                 "https",
		"https://":                               "host",
		"https://user:pw@example.com/hook":       "userinfo",
	}
	for u, want := range bad {
		err := ValidateWebhookURL(u)
		if err == nil {
			t.Errorf("ValidateWebhookURL(%q) must be refused — a webhook URL carries a bearer secret", u)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateWebhookURL(%q) = %v, want a message mentioning %q", u, err, want)
		}
	}
}

func TestValidateSNSTopicARN(t *testing.T) {
	good := []string{
		"",
		"arn:aws:sns:us-east-1:123456789012:correlix-alerts",
		"arn:aws-us-gov:sns:us-gov-west-1:123456789012:t_1",
		"arn:aws-cn:sns:cn-north-1:123456789012:topic.fifo",
	}
	for _, a := range good {
		if err := ValidateSNSTopicARN(a); err != nil {
			t.Errorf("ValidateSNSTopicARN(%q) = %v, want nil", a, err)
		}
	}
	bad := []string{
		"not-an-arn",
		"arn:aws:sns:us-east-1:123456789012",                     // too few fields
		"arn:aws:sns:us-east-1:123456789012:topic:extra",         // too many
		"urn:aws:sns:us-east-1:123456789012:t",                   // not arn:
		"arn:evil:sns:us-east-1:123456789012:t",                  // bad partition
		"arn:aws:sqs:us-east-1:123456789012:t",                   // wrong service
		"arn:aws:sns:Not-A-Region:123456789012:t",                // bad region
		"arn:aws:sns:us-east-1:12345:t",                          // short account
		"arn:aws:sns:us-east-1:123456789012:bad topic",           // illegal name
		"arn:aws:sns:us-east-1:123456789012:../../etc/passwd",    // traversal-ish
		"arn:aws:sns:us-east-1/@evil.example.com:123456789012:t", // host smuggling
	}
	for _, a := range bad {
		if err := ValidateSNSTopicARN(a); err == nil {
			t.Errorf("ValidateSNSTopicARN(%q) = nil, want a rejection", a)
		}
	}
	if got := SNSRegionFromARN("arn:aws:sns:eu-west-2:123456789012:t"); got != "eu-west-2" {
		t.Errorf("SNSRegionFromARN = %q", got)
	}
	if got := SNSRegionFromARN("garbage"); got != "" {
		t.Errorf("SNSRegionFromARN(garbage) = %q, want empty", got)
	}
}

func TestValidateSNSConfig(t *testing.T) {
	cases := []struct {
		name    string
		in      SNSConfig
		wantErr string // "" = must pass
	}{
		{"topic only", SNSConfig{Enabled: true, TopicARN: "arn:aws:sns:us-east-1:123456789012:t"}, ""},
		{"numbers only", SNSConfig{Enabled: true, Region: "us-east-1", PhoneNumbers: "+14155550123"}, ""},
		{"disabled and empty", SNSConfig{}, ""},
		{"bad region", SNSConfig{Region: "Us_East_1"}, "not a valid AWS region"},
		{"bad arn", SNSConfig{TopicARN: "arn:aws:sqs:us-east-1:123456789012:t"}, "service"},
		{"region disagrees with arn", SNSConfig{Region: "us-west-2", TopicARN: "arn:aws:sns:us-east-1:123456789012:t"}, "does not match"},
		{"enabled with no destination", SNSConfig{Enabled: true, Region: "us-east-1"}, "topic ARN or at least one phone number"},
		{"enabled with no region", SNSConfig{Enabled: true, PhoneNumbers: "+14155550123"}, "region is required"},
		{"non-E164 number", SNSConfig{Enabled: true, Region: "us-east-1", PhoneNumbers: "555-0123"}, "E.164"},
		{"bad scope", SNSConfig{Region: "us-east-1", Scope: "everything"}, "scope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateSNSConfig(c.in)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("want nil, got %v", err)
			case c.wantErr != "" && err == nil:
				t.Fatalf("want an error mentioning %q, got nil", c.wantErr)
			case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
				t.Fatalf("error %v does not mention %q", err, c.wantErr)
			}
		})
	}
}

func TestValidateTeamsConfig(t *testing.T) {
	if err := ValidateTeamsConfig(TeamsConfig{Enabled: true}); err == nil {
		t.Fatal("enabling Teams with no webhook must be refused")
	}
	if err := ValidateTeamsConfig(TeamsConfig{Enabled: true, WebhookURL: "http://x.example/h"}); err == nil {
		t.Fatal("a plaintext webhook must be refused")
	}
	if err := ValidateTeamsConfig(TeamsConfig{Enabled: true, WebhookURL: "https://x.example/h"}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// ---- G10: the env-migration latch ------------------------------------------

func TestEnvSeededLatchIsNilSafeAndIdempotent(t *testing.T) {
	c := DefaultChannelConfig()
	if c.IsEnvSeeded("teams") {
		t.Fatal("a fresh config must not claim anything was migrated")
	}
	c.MarkEnvSeeded("teams")
	c.MarkEnvSeeded("teams")
	if !c.IsEnvSeeded("teams") || c.IsEnvSeeded("sns") {
		t.Fatalf("latch leaked across channels: %+v", c.EnvSeeded)
	}
	c.MarkEnvSeeded("not-a-channel") // unknown names are a no-op, never a panic
	if c.IsEnvSeeded("not-a-channel") {
		t.Fatal("an unknown channel must never report as seeded")
	}
}

// ---- G10: dispatcher fan-out -----------------------------------------------

// TestDispatcherFanOutIncludesTeamsAndSNS drives the real dispatcher (bounded
// worker pool + retries) with the real Teams and SNS channels against local
// fakes, proving the new destinations are reached by a plain Dispatch.
func TestDispatcherFanOutIncludesTeamsAndSNS(t *testing.T) {
	var teamsHits, snsHits atomic.Int64
	done := make(chan struct{}, 2)
	teamsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		teamsHits.Add(1)
		done <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer teamsSrv.Close()
	snsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snsHits.Add(1)
		done <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer snsSrv.Close()

	d := NewDispatcher()
	d.Register(BuildTeamsChannel(TeamsConfig{Enabled: true, WebhookURL: teamsSrv.URL, MinSeverity: "warning"}))
	d.Register(NewSeverityGate(
		NewSNS("ak", "sk", "us-east-1", "+14155550123", "").WithEndpoint(snsSrv.URL+"/"), "critical"))

	names := d.Names()
	if len(names) != 2 || names[0] != "teams" || names[1] != "sns" {
		t.Fatalf("registered channel names = %v, want [teams sns]", names)
	}

	d.Dispatch(models.Alert{Rule: "HostOOM", Severity: "critical", Summary: "host memory exhausted"})
	for i := 0; i < 2; i++ {
		<-done
	}
	if teamsHits.Load() != 1 || snsHits.Load() != 1 {
		t.Fatalf("fan-out: teams=%d sns=%d, want 1/1", teamsHits.Load(), snsHits.Load())
	}

	// And the floors still apply on the fan-out path: a warning reaches Teams
	// only. Wait on the Teams hit, then assert SNS did not move.
	d.Dispatch(models.Alert{Rule: "LinkFlap", Severity: "warning", Summary: "flapping"})
	<-done
	if teamsHits.Load() != 2 {
		t.Fatalf("teams hits = %d, want 2", teamsHits.Load())
	}
	if snsHits.Load() != 1 {
		t.Fatalf("sns received a warning despite a critical floor (hits=%d)", snsHits.Load())
	}
}
