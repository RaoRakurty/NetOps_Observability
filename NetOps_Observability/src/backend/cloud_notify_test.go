package backend

// cloud_notify_test.go — routing-decision + tenant-isolation tests for the
// cloud signal notification sweeper (Wave 4 #12 slice 1, CLAUDE.md §3a.5).

import (
	"strings"
	"testing"
	"time"

	"netops/backend/models"

	"netops/backend/internal/ticketing"
)

// Routing decision: only enabled lanes WITH a secret route; nothing else does.
func TestCloudNotifyLanes(t *testing.T) {
	cases := []struct {
		name string
		cfg  itsmConfig
		want []string
	}{
		{"nothing configured", itsmConfig{}, nil},
		{"slack enabled", itsmConfig{Slack: slackRCAConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/T/A"}}, []string{"slack"}},
		{"pagerduty enabled", itsmConfig{PagerDuty: pagerDutyRCAConfig{Enabled: true, RoutingKey: "rk-1"}}, []string{"pagerduty"}},
		{"both", itsmConfig{
			Slack:     slackRCAConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/T/A"},
			PagerDuty: pagerDutyRCAConfig{Enabled: true, RoutingKey: "rk-1"},
		}, []string{"slack", "pagerduty"}},
		{"enabled but secret-less never routes", itsmConfig{
			Slack:     slackRCAConfig{Enabled: true},
			PagerDuty: pagerDutyRCAConfig{Enabled: true},
		}, nil},
		{"configured but disabled never routes", itsmConfig{
			Slack:     slackRCAConfig{WebhookURL: "https://hooks.slack.com/services/T/A"},
			PagerDuty: pagerDutyRCAConfig{RoutingKey: "rk-1"},
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cloudNotifyLanes(tc.cfg)
			if len(got) != len(tc.want) {
				t.Fatalf("lanes = %+v, want %v", got, tc.want)
			}
			for i, w := range tc.want {
				if got[i].System != w || got[i].Secret == "" {
					t.Fatalf("lane[%d] = %+v, want system %q with a secret", i, got[i], w)
				}
			}
		})
	}
}

// ISOLATION: tenant A's signal must resolve ONLY tenant A's channel config —
// never tenant B's, and an unknown tenant gets nothing (default-closed). Mirrors
// the contact-point / ITSM per-tenant resolve assertions.
func TestCloudNotifyTargetsAreTenantIsolated(t *testing.T) {
	st := ticketing.NewITSMConfigStoreForTest(map[string]itsmConfig{
		"acme": {Slack: slackRCAConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/ACME"}},
		"globex": {
			Slack:     slackRCAConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/GLOBEX"},
			PagerDuty: pagerDutyRCAConfig{Enabled: true, RoutingKey: "rk-globex"},
		},
		"": {PagerDuty: pagerDutyRCAConfig{Enabled: true, RoutingKey: "rk-platform"}},
	})
	acme := rcaNotifyTargets(st, "acme")
	if len(acme) != 1 || acme[0].System != "slack" {
		t.Fatalf("acme targets = %+v, want exactly its own slack lane", acme)
	}
	for _, tg := range acme {
		if strings.Contains(tg.Secret, "GLOBEX") || strings.Contains(tg.Secret, "rk-globex") {
			t.Fatalf("acme resolve leaked globex's secret: %+v", tg)
		}
	}
	if got := rcaNotifyTargets(st, "globex"); len(got) != 2 {
		t.Fatalf("globex targets = %+v, want its own two lanes", got)
	}
	// Unknown tenant: default-closed, NOT a fallback onto anyone else's config.
	if got := rcaNotifyTargets(st, "initech"); len(got) != 0 {
		t.Fatalf("unknown tenant must resolve zero targets, got %+v", got)
	}
	// ""/global collapse to the same platform key (itsmKey), like every ITSM resolve.
	if got := rcaNotifyTargets(st, TenantGlobal); len(got) != 1 || got[0].Secret != "rk-platform" {
		t.Fatalf("global tenant should resolve the platform config, got %+v", got)
	}
}

// End-to-end routing through the sweeper: a candidate owned by acme must only
// ever be handed to acme's lanes; a tenant with no lanes is a no-op.
func TestCloudNotifyDispatchNeverCrossesTenants(t *testing.T) {
	byTenant := map[string][]cloudNotifyTarget{
		"acme":   {{System: "slack", Secret: "https://hooks.slack.com/services/ACME"}},
		"globex": {{System: "pagerduty", Secret: "rk-globex"}},
	}
	var sentSecrets []string
	sw := &cloudNotifySweeper{
		resolve: func(tenant string) []cloudNotifyTarget { return byTenant[tenant] },
		send: func(tg cloudNotifyTarget, a models.Alert) error {
			sentSecrets = append(sentSecrets, tg.Secret)
			return nil
		},
		seen: make(map[string]bool),
	}
	if !sw.dispatch(cloudNotifyCandidate{id: "c-1", tenant: "acme", tier: "suspected"}) {
		t.Fatal("acme candidate should dispatch via acme's lane")
	}
	for _, s := range sentSecrets {
		if strings.Contains(s, "globex") || s == "rk-globex" {
			t.Fatalf("acme's signal reached globex's channel: %v", sentSecrets)
		}
	}
	if len(sentSecrets) != 1 || !strings.Contains(sentSecrets[0], "ACME") {
		t.Fatalf("expected exactly acme's lane, got %v", sentSecrets)
	}
	// Tenant with no configured lane: honest no-op.
	if sw.dispatch(cloudNotifyCandidate{id: "c-2", tenant: "initech"}) {
		t.Fatal("tenant with no lanes must not dispatch")
	}
}

// At-most-once: an object notifies once per process, and objects opened before
// process start (restart) never re-page.
func TestCloudNotifyShouldNotifyOnce(t *testing.T) {
	start := time.Now().UTC()
	sw := &cloudNotifySweeper{startedAt: start, seen: make(map[string]bool)}
	after := start.Add(time.Minute)
	if !sw.shouldNotify("c-1", after) {
		t.Fatal("fresh object should notify")
	}
	sw.markSeen("c-1")
	if sw.shouldNotify("c-1", after) {
		t.Fatal("seen object must not notify twice")
	}
	if sw.shouldNotify("c-old", start.Add(-time.Minute)) {
		t.Fatal("object opened before process start must not page on restart")
	}
	if sw.shouldNotify("", after) {
		t.Fatal("empty id never notifies")
	}
}

// Severity comes from the engine's own verdict tier — never invented.
func TestCloudNotifySeverity(t *testing.T) {
	cases := map[string]string{
		"confirmed": "critical",
		"suspected": "error",
		"weak":      "warning",
		"":          "warning",
	}
	for tier, want := range cases {
		if got := cloudNotifySeverity(tier); got != want {
			t.Errorf("cloudNotifySeverity(%q) = %q, want %q", tier, got, want)
		}
	}
}

// The alert is operator-readable and carries the routing facts as labels.
func TestCloudNotifyAlert(t *testing.T) {
	a := cloudNotifyAlert(cloudNotifyCandidate{
		id: "abc", tenant: "acme", tier: "confirmed",
		hypothesis: "NAT gateway saturation", apps: []string{"store-api"},
	})
	if a.ID != "cloud-rca-abc" || a.Rule != "cloud_rca_open" || a.Severity != "critical" {
		t.Fatalf("alert identity wrong: %+v", a)
	}
	if !strings.Contains(a.Summary, "NAT gateway saturation") || !strings.Contains(a.Summary, "store-api") {
		t.Fatalf("summary should carry hypothesis + affected apps: %q", a.Summary)
	}
	if a.Labels["tenant"] != "acme" || a.Labels["correlation_id"] != "abc" || a.Labels["layer"] != "cloud" {
		t.Fatalf("labels wrong: %+v", a.Labels)
	}
}

// The candidate scan obeys the #100 read contract: bounded window + LIMIT,
// named columns, open-state cloud objects only, chaos fixtures excluded.
func TestCloudNotifyCandidatesSQLBounded(t *testing.T) {
	sql := cloudNotifyCandidatesSQL(1800, 200)
	for _, want := range []string{
		"INTERVAL 1800 SECOND",
		"LIMIT 200",
		"state = 'open'",
		"source = 'cloud'",
		"chaos_fixture = ''",
		"merged_into IS NULL",
		// The hot projection, read FINAL. Matched in two parts because the
		// table now carries a TABLE ALIAS (`AS c`): the id predicate must be
		// qualified or the `toString(correlation_id) AS correlation_id`
		// projection shadows it and the IN-subquery compares String to UUID
		// (tracker 200 — alias resolution reaches inside WHERE).
		"netops.corr_current",
		"FINAL",
		"c.correlation_id IN (",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("candidates SQL missing %q:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "SELECT *") {
		t.Fatalf("candidates SQL must name its columns:\n%s", sql)
	}
}
