package seclane

// seclane_test.go — the producer lane's unit + §3a isolation tests.
//
// The fake publisher RECORDS (topic, key, value) for every record, because the
// two things a tenant-keyed producer must get right are exactly those: the
// topic the correlation engine consumes and the partition KEY the engine's
// tenant-keyed assignment depends on. A test that only counted findings would
// pass against a producer that shipped every tenant's evidence under one key.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/advisory"
	"netops/backend/internal/hardening"
	"netops/backend/internal/secbus"
	"netops/backend/internal/secfindings"
	"netops/backend/secapi"
)

// ── fakes ───────────────────────────────────────────────────────────────────

type sentRecord struct {
	Topic string
	Key   string
	Value any
}

type fakePublisher struct {
	sent []sentRecord
	// failTopics makes Publish fail for the named topics (models a broker /
	// bus-bridge outage on one lane but not another).
	failTopics map[string]error
}

func (f *fakePublisher) publish(_ context.Context, topic string, recs []Record) (int, error) {
	if err, bad := f.failTopics[topic]; bad {
		return 0, err
	}
	for _, r := range recs {
		f.sent = append(f.sent, sentRecord{Topic: topic, Key: r.Key, Value: r.Value})
	}
	return len(recs), nil
}

func (f *fakePublisher) on(topic string) []sentRecord {
	var out []sentRecord
	for _, r := range f.sent {
		if r.Topic == topic {
			out = append(out, r)
		}
	}
	return out
}

// osResponse renders a canned OpenSearch _search reply from raw `_source` bodies.
func osResponse(sources ...string) *http.Response {
	body := `{"took":1,"hits":{"total":{"value":` + itoa(len(sources)) + `},"hits":[`
	parts := make([]string, 0, len(sources))
	for _, s := range sources {
		parts = append(parts, `{"_source":`+s+`}`)
	}
	body += strings.Join(parts, ",") + `]}}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
		Header:     http.Header{},
	}
}

// laneFixture is one fully-injected lane plus the fakes behind it.
type laneFixture struct {
	lane *Lane
	pub  *fakePublisher
	// searched records the index pattern of every OpenSearch call — the at-rest
	// half of the §3a chokepoint.
	searched []string
	// chScopes records the tenant_scope every ClickHouse read carried.
	chScopes []string
	states   map[string]map[string]bool // tenant → rule id → enabled
	devices  map[string][]Device
	logs     map[string][]string // tenant → canned _source docs
	spoolErr error
	spooled  int
	warns    []string
	errs     []string
}

var fixedNow = time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)

func newFixture(t *testing.T, mut func(*Deps)) *laneFixture {
	t.Helper()
	fx := &laneFixture{
		pub:     &fakePublisher{failTopics: map[string]error{}},
		states:  map[string]map[string]bool{},
		devices: map[string][]Device{},
		logs:    map[string][]string{},
	}
	d := Deps{
		Now:      func() time.Time { return fixedNow },
		Tenants:  func() []string { return []string{"acme", "globex"} },
		Devices:  func(tenant string) []Device { return fx.devices[tenant] },
		Interval: time.Hour,
		RuleStates: func(_ context.Context, tenant string) (map[string]bool, error) {
			return fx.states[tenant], nil
		},
		Publish: fx.pub.publish,
		Search: func(_, path string, _ any) (*http.Response, error) {
			fx.searched = append(fx.searched, path)
			for tenant, docs := range fx.logs {
				if strings.Contains(path, "netops-syslog-"+tenant+"-*") {
					return osResponse(docs...), nil
				}
			}
			return osResponse(), nil
		},
		CHQuery: func(_ context.Context, scope, _ string) ([]map[string]any, error) {
			fx.chScopes = append(fx.chScopes, scope)
			return nil, nil
		},
		Seams: func(context.Context, string) ([]SeamRow, error) { return nil, nil },
		Authz: func(http.ResponseWriter, *http.Request, secapi.Gate) (secapi.Principal, bool) {
			return secapi.Principal{}, false
		},
		WriteJSON:  func(http.ResponseWriter, int, any) {},
		WriteError: func(http.ResponseWriter, int, error) {},
		LogWarn:    func(msg string, _ map[string]any) { fx.warns = append(fx.warns, msg) },
		LogError:   func(msg string, _ map[string]any) { fx.errs = append(fx.errs, msg) },
		Scrub:      func(s string) string { return s },
		TenantSeg:  TenantSeg,
		Spool: func(_ string, recs []Record, _ error) error {
			if fx.spoolErr != nil {
				return fx.spoolErr
			}
			fx.spooled += len(recs)
			return nil
		},
	}
	if mut != nil {
		mut(&d)
	}
	lane, err := New(d)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fx.lane = lane
	return fx
}

func dev(id, tenant string) Device {
	return Device{ID: id, Name: id, Address: "10.0.0.1", Vendor: "cisco",
		OS: "IOS-XE 17.9.1", Model: "C8300", TenantID: tenant}
}

// ── §3a: per-tenant iteration + tenant keying ───────────────────────────────

func TestScanAllIteratesTenantsAndKeysEveryRecordByTenant(t *testing.T) {
	fx := newFixture(t, nil)
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}
	fx.devices["globex"] = []Device{dev("globex-core", "globex")}

	fx.lane.ScanAll(context.Background())

	sent := fx.pub.on(secbus.TopicSecurityEvidence)
	if len(sent) == 0 {
		t.Fatal("the lane emitted nothing — the producer is still inert")
	}
	seenKeys := map[string]bool{}
	for _, r := range sent {
		if r.Topic != secbus.TopicSecurityEvidence {
			t.Fatalf("record went to %q, want %q", r.Topic, secbus.TopicSecurityEvidence)
		}
		ev, ok := r.Value.(secbus.EvidenceEvent)
		if !ok {
			t.Fatalf("record value is %T, want secbus.EvidenceEvent", r.Value)
		}
		if r.Key != ev.TenantID {
			t.Fatalf("partition key %q != event tenant %q — the engine's tenant-keyed "+
				"partition assignment depends on these being identical", r.Key, ev.TenantID)
		}
		if r.Key == "" {
			t.Fatal("a record shipped with an EMPTY partition key — tenant ordering is lost")
		}
		// The subject must belong to the keyed tenant: acme's key may never
		// carry a globex device and vice versa.
		if strings.HasPrefix(ev.EntityID, "globex") && r.Key != "globex" {
			t.Fatalf("TENANT LEAK: globex device %q emitted under key %q", ev.EntityID, r.Key)
		}
		if strings.HasPrefix(ev.EntityID, "acme") && r.Key != "acme" {
			t.Fatalf("TENANT LEAK: acme device %q emitted under key %q", ev.EntityID, r.Key)
		}
		seenKeys[r.Key] = true
	}
	if !seenKeys["acme"] || !seenKeys["globex"] {
		t.Fatalf("the pass did not cover both tenants: keys=%v", seenKeys)
	}
	for _, tenant := range []string{"acme", "globex"} {
		st := fx.lane.StatusFor(tenant, false)
		if len(st) != 1 || st[0].ScanID == "" {
			t.Fatalf("no status row recorded for %s: %+v", tenant, st)
		}
	}
}

func TestScanNamesOnlyTheCallersOwnIndicesAndCHScope(t *testing.T) {
	fx := newFixture(t, nil)
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}
	fx.devices["globex"] = []Device{dev("globex-core", "globex")}

	fx.lane.ScanAll(context.Background())

	for _, path := range fx.searched {
		if strings.Contains(path, "netops-syslog-acme-") && strings.Contains(path, "globex") {
			t.Fatalf("TENANT LEAK: one syslog read named two tenants' indices: %s", path)
		}
	}
	if len(fx.chScopes) == 0 {
		t.Fatal("no ClickHouse read carried a tenant_scope")
	}
	for _, scope := range fx.chScopes {
		if scope == "__all__" || scope == "" {
			t.Fatalf("a per-tenant flow read ran at scope %q — that is a cross-tenant read", scope)
		}
	}
}

// TestDisabledRuleIsPerTenant is the §3a rule-5 core: tenant B's disabled rule
// must not change what tenant A assesses.
func TestDisabledRuleIsPerTenant(t *testing.T) {
	const ruleID = "telnet-vty-enabled"
	fx := newFixture(t, nil)
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}
	fx.devices["globex"] = []Device{dev("globex-core", "globex")}
	fx.states["globex"] = map[string]bool{ruleID: false} // ONLY globex disables it

	fx.lane.ScanAll(context.Background())

	acmeHas, globexHas := false, false
	for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
		ev := r.Value.(secbus.EvidenceEvent)
		if ev.Attrs["raw_rule_id"] != ruleID {
			continue
		}
		switch r.Key {
		case "acme":
			acmeHas = true
		case "globex":
			globexHas = true
		}
	}
	if !acmeHas {
		t.Fatalf("acme lost %q because ANOTHER tenant disabled it — rule state leaked across tenants", ruleID)
	}
	if globexHas {
		t.Fatalf("globex disabled %q but it was still emitted for globex", ruleID)
	}
}

func TestRuleStateFailureFailsClosed(t *testing.T) {
	fx := newFixture(t, func(d *Deps) {
		d.RuleStates = func(context.Context, string) (map[string]bool, error) {
			return nil, errors.New("control-plane unreadable")
		}
	})
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}

	fx.lane.ScanAll(context.Background())

	if n := len(fx.pub.on(secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("emitted %d findings under an UNKNOWN rule-enablement set — the run must fail closed", n)
	}
	st := fx.lane.StatusFor("acme", false)
	if len(st) != 1 || st[0].Outcome != OutcomeError {
		t.Fatalf("outcome = %+v, want %q", st, OutcomeError)
	}
	if fx.lane.Metrics().RunsFor("acme", OutcomeError) != 1 {
		t.Fatal("the failed run was not counted under outcome=error")
	}
}

// ── §5g honesty: unassessed, never a false clear ────────────────────────────

func TestHardeningWithNoConfigCaptureYieldsUnassessedNotPass(t *testing.T) {
	fx := newFixture(t, nil) // ConfigSource nil → the empty/"not built" path
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	posture, unknown, pass := 0, 0, 0
	for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
		ev := r.Value.(secbus.EvidenceEvent)
		if ev.Kind != secbus.KindPosture {
			continue
		}
		posture++
		switch ev.Attrs["status"] {
		case secfindings.StatusUnknown.String():
			unknown++
		case secfindings.StatusPass.String():
			pass++
		}
	}
	if posture == 0 {
		t.Fatal("no posture findings emitted at all")
	}
	if unknown != posture {
		t.Fatalf("%d/%d posture findings are Unknown — every unassessed control MUST be "+
			"Unknown, never a verdict", unknown, posture)
	}
	if pass != 0 {
		t.Fatalf("%d posture findings claimed Pass with NO config captured — that is a false clear", pass)
	}
}

func TestHardeningWithAConfigProducesRealVerdicts(t *testing.T) {
	cfg := hardening.MemConfigSource{"acme-core": "line vty 0 4\n transport input telnet\n"}
	fx := newFixture(t, func(d *Deps) { d.ConfigSource = cfg })
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	fail := 0
	for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
		ev := r.Value.(secbus.EvidenceEvent)
		if ev.Attrs["raw_rule_id"] == "telnet-vty-enabled" &&
			ev.Attrs["status"] == secfindings.StatusFail.String() {
			fail++
		}
	}
	if fail != 1 {
		t.Fatalf("telnet-on-vty fails = %d, want 1 (a real config must produce a real verdict)", fail)
	}
}

// ── advisory lane ───────────────────────────────────────────────────────────

func TestAdvisoryMockProviderYieldsFindingForKnownVulnerableVersion(t *testing.T) {
	mock := advisory.NewMockProvider("mock").Add("cisco", "IOS-XE", advisory.Advisory{
		CVE: "CVE-2026-0001", Severity: secfindings.SeverityCritical, CVSS: 9.8, KEV: true,
		Summary:         "Remote code execution in the web UI",
		AffectedVersion: advisory.VersionConstraint{Exact: "17.9.1"},
	})
	fx := newFixture(t, func(d *Deps) {
		d.Advisory = mock
		d.ParseSoftware = func(_, _, _ string) (string, string) { return "IOS-XE", "17.9.1" }
	})
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	found := false
	for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
		ev := r.Value.(secbus.EvidenceEvent)
		if ev.Attrs["control_id"] == "CVE-2026-0001" {
			found = true
			if ev.Kind != secbus.KindExposure {
				t.Fatalf("advisory finding kind = %q, want %q", ev.Kind, secbus.KindExposure)
			}
			if ev.Attrs["status"] != secfindings.StatusFail.String() {
				t.Fatalf("a matched advisory must be a Fail, got %v", ev.Attrs["status"])
			}
			if ev.Severity != secfindings.SeverityCritical {
				t.Fatalf("severity = %q, want critical", ev.Severity)
			}
		}
	}
	if !found {
		t.Fatal("the mock provider's advisory produced no exposure finding")
	}
}

func TestAdvisoryUnassessableDeviceIsUnassessedNotClear(t *testing.T) {
	mock := advisory.NewMockProvider("mock")
	fx := newFixture(t, func(d *Deps) {
		d.Advisory = mock
		d.ParseSoftware = func(_, _, _ string) (string, string) { return "", "" } // no version parsed
	})
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	found := false
	for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
		ev := r.Value.(secbus.EvidenceEvent)
		if ev.Attrs["control_id"] == "advisory-unassessed" {
			found = true
			if ev.Attrs["status"] != secfindings.StatusUnknown.String() {
				t.Fatalf("an unassessable device must be Unknown, got %v", ev.Attrs["status"])
			}
		}
	}
	if !found {
		t.Fatal("a device whose version could not be parsed produced NO finding — silence reads as 'clear'")
	}
}

func TestAdvisoryProviderCanBeDisabledPerTenant(t *testing.T) {
	mock := advisory.NewMockProvider(advisory.SourceOfflineFeed).Add("cisco", "IOS-XE", advisory.Advisory{
		CVE: "CVE-2026-0002", Severity: secfindings.SeverityHigh,
		AffectedVersion: advisory.VersionConstraint{Exact: "17.9.1"},
	})
	fx := newFixture(t, func(d *Deps) {
		d.Advisory = mock
		d.ParseSoftware = func(_, _, _ string) (string, string) { return "IOS-XE", "17.9.1" }
	})
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}
	fx.states["acme"] = map[string]bool{advisory.SourceOfflineFeed: false}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
		if r.Value.(secbus.EvidenceEvent).Attrs["control_id"] == "CVE-2026-0002" {
			t.Fatal("the tenant disabled the advisory provider but its findings were emitted anyway")
		}
	}
}

// ── threat lane ─────────────────────────────────────────────────────────────

func TestThreatLaneDetectsOverFixtureDeviceLogs(t *testing.T) {
	fx := newFixture(t, nil)
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}
	fx.logs["acme"] = []string{
		`{"hostname":"acme-core","timestamp":"2026-09-02T02:30:00Z","facility":"SEC","severity":"notice",` +
			`"message":"%SEC-5-CONFIG: username backdoor privilege 15 secret 5 $1$redacted"}`,
	}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	found := false
	for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
		ev := r.Value.(secbus.EvidenceEvent)
		if ev.Kind != secbus.KindSignal {
			continue
		}
		if ev.Attrs["raw_rule_id"] == "log-new-local-user" {
			found = true
			if ev.EntityID != "acme-core" {
				t.Fatalf("signal grounded on %q, want the device id", ev.EntityID)
			}
			if ev.Attrs["control_id"] != "T1136.001" {
				t.Fatalf("MITRE technique = %v, want T1136.001", ev.Attrs["control_id"])
			}
		}
	}
	if !found {
		t.Fatal("the new-local-user detection did not fire over the fixture syslog document")
	}
}

func TestThreatLaneLogSourceFailureDoesNotSuppressOtherLanes(t *testing.T) {
	fx := newFixture(t, func(d *Deps) {
		d.Search = func(string, string, any) (*http.Response, error) {
			return nil, errors.New("opensearch unreachable")
		}
	})
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	if n := len(fx.pub.on(secbus.TopicSecurityEvidence)); n == 0 {
		t.Fatal("a syslog outage silenced the hardening + advisory lanes too")
	}
	st := fx.lane.StatusFor("acme", false)
	if len(st) != 1 || st[0].Outcome != OutcomePartial {
		t.Fatalf("outcome = %+v, want %q with the failure named", st, OutcomePartial)
	}
	if len(st[0].Errors) == 0 || !strings.Contains(strings.Join(st[0].Errors, "|"), "threat-device-log") {
		t.Fatalf("the degraded lane is not named on the status row: %+v", st[0].Errors)
	}
}

// ── bounds: truncation ──────────────────────────────────────────────────────

func TestTruncationCapsTheRunAndCountsWhatWasDropped(t *testing.T) {
	fx := newFixture(t, func(d *Deps) { d.MaxFindings = 5 })
	fx.devices["acme"] = []Device{dev("acme-core", "acme"), dev("acme-edge", "acme")}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	sent := fx.pub.on(secbus.TopicSecurityEvidence)
	if len(sent) != 5 {
		t.Fatalf("emitted %d records, want exactly the cap (5)", len(sent))
	}
	st := fx.lane.StatusFor("acme", false)
	if len(st) != 1 || st[0].Truncated <= 0 {
		t.Fatalf("truncation was not reported on the status row: %+v", st)
	}
	if got := fx.lane.Metrics().Snapshot()["findings_truncated_total"]; got != int64(st[0].Truncated) {
		t.Fatalf("truncation counter = %d, status says %d", got, st[0].Truncated)
	}
	if st[0].Outcome != OutcomePartial {
		t.Fatalf("a truncated run must not report %q", st[0].Outcome)
	}
}

func TestTruncationIsDeterministic(t *testing.T) {
	run := func() []string {
		fx := newFixture(t, func(d *Deps) { d.MaxFindings = 4 })
		fx.devices["acme"] = []Device{dev("acme-core", "acme"), dev("acme-edge", "acme")}
		fx.lane.ScanTenant(context.Background(), "acme", "manual")
		var ids []string
		for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
			ids = append(ids, r.Value.(secbus.EvidenceEvent).NativeID)
		}
		return ids
	}
	a, b := run(), run()
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("two identical runs truncated to DIFFERENT prefixes:\n%v\n%v", a, b)
	}
}

// ── failure ladder: retry → dead-letter → spool → lost ──────────────────────

func TestProducerFailureDeadLettersOntoTheBusAndNeverCountsLost(t *testing.T) {
	fx := newFixture(t, nil)
	fx.pub.failTopics[secbus.TopicSecurityEvidence] = errors.New("bus bridge 503")
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	if n := len(fx.pub.on(secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("the failing topic accepted %d records", n)
	}
	dl := fx.pub.on(DeadLetterTopic)
	if len(dl) == 0 {
		t.Fatal("nothing was dead-lettered — the evidence vanished silently")
	}
	for _, r := range dl {
		row := r.Value.(map[string]any)
		if row["lane"] != "security_lane" || row["reason"] != "producer_retries_exhausted" {
			t.Fatalf("dead-letter row does not match the vector deadletter_encoded shape: %+v", row)
		}
		if r.Key == "" {
			t.Fatal("a dead-lettered record lost its tenant key")
		}
	}
	m := fx.lane.Metrics().Snapshot()
	if m["lost_total"] != 0 {
		t.Fatalf("lost_total moved (%d) for evidence sitting in the DEAD-LETTER topic — "+
			"lost is reserved for records with no durable copy at all (the 189 contract)", m["lost_total"])
	}
	if m["dead_lettered_total"] != int64(len(dl)) {
		t.Fatalf("dead_lettered_total = %d, want %d", m["dead_lettered_total"], len(dl))
	}
	if m["emit_failures_total"] == 0 {
		t.Fatal("the exhausted retry was not counted")
	}
	if fx.lane.Metrics().RunsFor("acme", OutcomeError) != 1 {
		t.Fatal("a run that emitted nothing must be counted under outcome=error")
	}
}

func TestDeadLetterTopicFailureFallsBackToTheSpool(t *testing.T) {
	fx := newFixture(t, nil)
	fx.pub.failTopics[secbus.TopicSecurityEvidence] = errors.New("bus bridge 503")
	fx.pub.failTopics[DeadLetterTopic] = errors.New("bus bridge 503")
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	if fx.spooled == 0 {
		t.Fatal("the local spool received nothing when both topics were down")
	}
	m := fx.lane.Metrics().Snapshot()
	if m["lost_total"] != 0 {
		t.Fatalf("lost_total moved for evidence written to the SPOOL: %d", m["lost_total"])
	}
	if m["dead_lettered_total"] != int64(fx.spooled) {
		t.Fatalf("dead_lettered_total = %d, spooled = %d", m["dead_lettered_total"], fx.spooled)
	}
}

func TestOnlyWhenEverySinkFailsDoesLostMove(t *testing.T) {
	fx := newFixture(t, nil)
	fx.pub.failTopics[secbus.TopicSecurityEvidence] = errors.New("bus bridge 503")
	fx.pub.failTopics[DeadLetterTopic] = errors.New("bus bridge 503")
	fx.spoolErr = errors.New("disk full")
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	m := fx.lane.Metrics().Snapshot()
	if m["lost_total"] == 0 {
		t.Fatal("every sink refused the evidence and lost_total still reads 0 — that is a silent loss")
	}
	if m["dead_lettered_total"] != 0 {
		t.Fatalf("dead_lettered_total = %d although no sink accepted anything", m["dead_lettered_total"])
	}
	joined := strings.Join(fx.errs, "|")
	if !strings.Contains(joined, "LOST") {
		t.Fatalf("the loss was not logged at error level: %v", fx.errs)
	}
}

// ── manual trigger + non-overlap ────────────────────────────────────────────

func TestEnqueueRefusesASecondScanForTheSameTenant(t *testing.T) {
	fx := newFixture(t, nil)
	if err := fx.lane.Enqueue("acme"); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if err := fx.lane.Enqueue("acme"); !errors.Is(err, ErrScanInFlight) {
		t.Fatalf("second enqueue err = %v, want ErrScanInFlight (the 429)", err)
	}
	// A DIFFERENT tenant is unaffected — the claim is per tenant, not global.
	if err := fx.lane.Enqueue("globex"); err != nil {
		t.Fatalf("another tenant was blocked by acme's in-flight scan: %v", err)
	}
}

func TestEnqueueRefusesWhenTheBoundedQueueIsFull(t *testing.T) {
	fx := newFixture(t, nil)
	for i := 0; i < scanQueueDepth; i++ {
		if err := fx.lane.Enqueue("t" + itoa(i)); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if err := fx.lane.Enqueue("overflow"); !errors.Is(err, ErrScanInFlight) {
		t.Fatalf("queue-full err = %v, want ErrScanInFlight", err)
	}
	// The refused tenant must not stay claimed — a rejected request may retry.
	fx.lane.inflightMu.Lock()
	stuck := fx.lane.inflight["overflow"]
	fx.lane.inflightMu.Unlock()
	if stuck {
		t.Fatal("a refused enqueue left the tenant permanently claimed")
	}
}

func TestOverlappingPassIsSkippedNotStacked(t *testing.T) {
	fx := newFixture(t, nil)
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}
	// Hold the pass lock as a concurrent pass would.
	fx.lane.passMu.Lock()
	fx.lane.ScanTenant(context.Background(), "acme", "manual")
	fx.lane.passMu.Unlock()

	if n := len(fx.pub.on(secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("the overlapping run emitted %d records instead of yielding", n)
	}
	if fx.lane.Metrics().RunsFor("acme", OutcomeSkipped) != 1 {
		t.Fatal("the skipped run was not counted under outcome=skipped")
	}
	st := fx.lane.StatusFor("acme", false)
	if len(st) != 1 || st[0].Outcome != OutcomeSkipped {
		t.Fatalf("status = %+v, want a skipped row", st)
	}
}

// ── status scoping ──────────────────────────────────────────────────────────

func TestStatusForIsOwnTenantOnlyUnlessCross(t *testing.T) {
	fx := newFixture(t, nil)
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}
	fx.devices["globex"] = []Device{dev("globex-core", "globex")}
	fx.lane.ScanAll(context.Background())

	own := fx.lane.StatusFor("acme", false)
	if len(own) != 1 || own[0].TenantID != "acme" {
		t.Fatalf("acme saw %+v — a tenant must see ONLY its own row", own)
	}
	cross := fx.lane.StatusFor("", true)
	if len(cross) != 2 {
		t.Fatalf("the platform admin saw %d rows, want 2", len(cross))
	}
	none := fx.lane.StatusFor("nosuch", false)
	if len(none) != 0 {
		t.Fatalf("an unrelated tenant saw %+v", none)
	}
}

// ── idempotency ─────────────────────────────────────────────────────────────

func TestNativeIDIsDeterministicWithinAScanAndCarriesTheScanID(t *testing.T) {
	fx := newFixture(t, nil)
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}
	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	seen := map[string]bool{}
	for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
		ev := r.Value.(secbus.EvidenceEvent)
		if ev.NativeID == "" {
			t.Fatal("a record shipped with an EMPTY native_id — the router cannot mint a doc id")
		}
		if seen[ev.NativeID] {
			t.Fatalf("duplicate native_id %q in ONE scan — the router's "+
				"hash(native_id|scan_id) would collapse two distinct verdicts", ev.NativeID)
		}
		seen[ev.NativeID] = true
		if ev.Attrs["scan_id"] == "" || ev.Attrs["scan_id"] == nil {
			t.Fatal("a record shipped without a scan_id — the doc identity needs BOTH halves")
		}
	}
}

// ── construction ────────────────────────────────────────────────────────────

func TestNewRefusesAnIncompleteDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New accepted an empty Deps — a lane that cannot produce must not be constructed")
	}
}

func TestFlowSourceRefusesAMalformedTenantToken(t *testing.T) {
	fx := newFixture(t, nil)
	src := fx.lane.FlowSource("acme'; DROP TABLE netops.flows--", nil, time.Hour)
	if _, err := src.Flows(context.Background()); err == nil {
		t.Fatal("the flow reader accepted a tenant token that is not a valid scope")
	}
}

// ── metrics exposition ──────────────────────────────────────────────────────

func TestMetricsWriteEmitsEverySeriesTheRunbookNames(t *testing.T) {
	fx := newFixture(t, nil)
	fx.devices["acme"] = []Device{dev("acme-core", "acme")}
	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	var buf bytes.Buffer
	fx.lane.Metrics().Write(&buf)
	out := buf.String()

	for _, want := range []string{
		`netops_security_scan_runs_total{tenant_seg="acme",outcome="ok"}`,
		`netops_security_findings_emitted_total{class="posture"}`,
		`netops_security_findings_emitted_total{class="exposure"}`,
		`netops_security_findings_emitted_total{class="signal"}`,
		"netops_security_scan_duration_seconds_bucket{le=\"+Inf\"}",
		"netops_security_scan_duration_seconds_sum",
		"netops_security_scan_duration_seconds_count",
		`netops_security_last_scan_timestamp_seconds{tenant_seg="acme"}`,
		`netops_security_last_scan_duration_seconds{tenant_seg="acme"}`,
		"netops_security_findings_truncated_total",
		"netops_security_emit_failures_total",
		"netops_security_dead_lettered_total",
		"netops_security_lost_total",
		"netops_security_ungroundable_total",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing series %q in:\n%s", want, out)
		}
	}
	// Every emitted class series must exist even at ZERO — an absent series and
	// a zero series mean different things to an alert.
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "#") || strings.TrimSpace(ln) == "" {
			continue
		}
		if len(strings.Fields(ln)) != 2 {
			t.Fatalf("malformed exposition line %q", ln)
		}
	}
}

func TestMetricsSnapshotIsNilSafe(t *testing.T) {
	var m *Metrics
	if got := m.Snapshot(); len(got) != 0 {
		t.Fatalf("nil metrics snapshot = %v", got)
	}
	m.Write(io.Discard) // must not panic
	m.RecordRun("acme", OutcomeOK, fixedNow, 0)
	if m.RunsFor("acme", OutcomeOK) != 0 {
		t.Fatal("nil metrics recorded a run")
	}
}

// ── the platform token: inventory row → dialect → the device's control set ──

// ─── dialect packs, synthetic ────────────────────────────────────────────────
//
// The dialects beyond the core Cisco IOS-XE one are the `security_dialects`
// commercial entitlement and live in src/backend/enterprise/dialects, which this
// Apache-2.0 package must never import (licensing-gate.py check E). The lane
// takes them as DATA through Deps.Dialects, so what belongs HERE is the seam:
// that a pack handed to the lane reaches the engine, that a device is then
// scored on ITS OWN control set, and that no foreign dialect leaks in.
//
// These packs therefore bind exactly the rule ids the shipped srlinux and arista
// packs bind — the counts below are load-bearing in the tests — with trivial
// `set …` / `management …` detections instead of the real crosswalks. The REAL
// bindings, scored against the real lab captures, are asserted by
// enterprise/dialects' own tests, which own the fixtures.

// srlinuxTestRules / aristaTestRules are the rule ids each dialect binds.
var (
	srlinuxTestRules = []string{
		"http-server-nontls", "local-user-weak-secret", "mgmt-api-unencrypted",
		"no-central-logging", "no-ntp-server", "no-remote-aaa",
		"no-service-password-encryption", "snmp-default-community",
		"snmp-no-source-acl", "snmp-v1v2c-community", "ssh-not-v2",
		"telnet-vty-enabled", "tls-no-client-auth", "weak-enable-password",
	}
	aristaTestRules = []string{
		"http-server-nontls", "local-user-weak-secret", "mgmt-api-unencrypted",
		"no-central-logging", "no-ntp-server", "no-remote-aaa",
		"no-service-password-encryption", "ntp-no-authentication",
		"snmp-default-community", "snmp-no-source-acl", "snmp-v1v2c-community",
		"ssh-not-v2", "telnet-vty-enabled", "weak-enable-password",
	}
)

// testDialectPacks builds the synthetic packs. Each binding trips when the
// config carries the line "TRIP <rule-id>", so a test can choose exactly which
// controls fail without owning any dialect grammar.
func testDialectPacks() []hardening.DialectPack {
	build := func(v hardening.Vendor, ids []string) hardening.DialectPack {
		bind := make(map[string]hardening.VendorBinding, len(ids))
		for _, id := range ids {
			bind[id] = hardening.VendorBinding{
				Detect:      hardening.DetectPresent(`^TRIP `+regexp.QuoteMeta(id)+`$`, "not tripped"),
				Remediation: "fix " + id,
			}
		}
		return hardening.DialectPack{Vendor: v, Bindings: bind}
	}
	return []hardening.DialectPack{
		build(hardening.VendorSRLinux, srlinuxTestRules),
		build(hardening.VendorArista, aristaTestRules),
	}
}

// tripConfig renders a config that trips exactly the named rules.
func tripConfig(ids ...string) string {
	var b strings.Builder
	b.WriteString("hostname lab\n")
	for _, id := range ids {
		b.WriteString("TRIP " + id + "\n")
	}
	return b.String()
}

// TestDevicePlatformTokenBindsTheRightDialect walks the WHOLE binding chain the
// lab defect of 2026-09-03 broke, over the inventory shapes that actually exist
// on this platform:
//
//	inventory row (vendor, os, model) → seclane.Device.Platform()
//	  → hardening.VendorFromPlatform (vendorprofile's ranked platform_contains)
//	    → the rules that carry a binding for that dialect
//
// The manual "nokia" + "SR Linux" row is the one that mattered: it must reach
// the srlinux dialect and NOT the SR OS one (rank 29 beats rank 30, which is
// why the rank is data and not code), and the emitted control set must be the
// srlinux bindings — never the Cisco IOS catalogue.
func TestDevicePlatformTokenBindsTheRightDialect(t *testing.T) {
	cat := hardening.DefaultCatalog(testDialectPacks()...)
	// A rule id that exists ONLY in the IOS catalogue: its presence on any
	// non-Cisco device is the exact regression this test guards.
	const iosOnlyRule = "cdp-run-global"

	cases := []struct {
		name        string
		dev         Device
		wantToken   string
		wantVendor  hardening.Vendor
		wantMustSee []string // rule ids the device's own control set must contain
	}{
		{
			// The lab spines: added by hand, no sysDescr, no model.
			name:        "manual nokia + SR Linux (lab spine1/spine2)",
			dev:         Device{ID: "spine1", Name: "spine1", Vendor: "nokia", OS: "SR Linux", TenantID: "t1"},
			wantToken:   "nokia SR Linux",
			wantVendor:  hardening.VendorSRLinux,
			wantMustSee: []string{"mgmt-api-unencrypted", "tls-no-client-auth", "no-ntp-server"},
		},
		{
			// SNMP discovery: OS is the (truncated) sysDescr, model from the
			// entity MIB.
			name: "discovered SNMP sysDescr (Cisco IOS-XE)",
			dev: Device{ID: "d2", Name: "core-1", Vendor: "cisco",
				OS:    "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE",
				Model: "C9300-48P", TenantID: "t1"},
			wantVendor:  hardening.VendorCiscoIOSXE,
			wantMustSee: []string{iosOnlyRule, "vty-no-access-class", "exposure-telnet"},
		},
		{
			name:        "Arista EOS release string",
			dev:         Device{ID: "leaf1", Name: "leaf1", Vendor: "arista", OS: "Arista EOS 4.36.0.1F", TenantID: "t1"},
			wantToken:   "arista Arista EOS 4.36.0.1F",
			wantVendor:  hardening.VendorArista,
			wantMustSee: []string{"mgmt-api-unencrypted", "no-remote-aaa"},
		},
		{
			name:       "unknown platform",
			dev:        Device{ID: "d4", Name: "mystery", Vendor: "acme", OS: "WidgetOS 1.0", TenantID: "t1"},
			wantToken:  "acme WidgetOS 1.0",
			wantVendor: hardening.VendorUnknown,
		},
		{
			name:       "no vendor and no OS at all",
			dev:        Device{ID: "d5", Name: "bare", TenantID: "t1"},
			wantToken:  "",
			wantVendor: hardening.VendorUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := tc.dev.Platform()
			if tc.wantToken != "" || tc.dev.Vendor == "" {
				if token != tc.wantToken {
					t.Fatalf("Platform() = %q, want %q", token, tc.wantToken)
				}
			}
			vendor := hardening.VendorFromPlatform(token)
			if vendor != tc.wantVendor {
				t.Fatalf("VendorFromPlatform(%q) = %q, want %q", token, vendor, tc.wantVendor)
			}

			eng := hardening.NewEngine(cat,
				hardening.MemConfigSource{tc.dev.ID: "hostname " + tc.dev.Name + "\n"},
				hardening.MemSeamResolver{tc.dev.ID: {{SeamID: "s", SeamType: "mgmt"}}})
			fs, err := eng.Evaluate(context.Background(), hardening.Device{
				ID: tc.dev.ID, Hostname: tc.dev.Name, Platform: token, TenantID: tc.dev.TenantID,
			})
			if err != nil {
				t.Fatal(err)
			}
			emitted := map[string]secfindings.StatusID{}
			for _, f := range fs {
				emitted[f.RawRuleID] = f.StatusID
			}

			if vendor == hardening.VendorUnknown {
				if len(emitted) != 1 {
					t.Fatalf("unresolved platform emitted %d checks (%v), want exactly the unassessed one", len(emitted), emitted)
				}
				st, ok := emitted[hardening.RulePlatformUnresolved]
				if !ok {
					t.Fatalf("unresolved platform did not emit %q: %v", hardening.RulePlatformUnresolved, emitted)
				}
				if st != secfindings.StatusUnknown {
					t.Fatalf("%q = %v, want Unknown", hardening.RulePlatformUnresolved, st)
				}
				return
			}

			for _, id := range tc.wantMustSee {
				if _, ok := emitted[id]; !ok {
					t.Errorf("%q is bound for %q but was not evaluated; emitted=%v", id, vendor, emitted)
				}
			}
			if vendor != hardening.VendorCiscoIOSXE {
				if _, ok := emitted[iosOnlyRule]; ok {
					t.Errorf("the Cisco IOS rule %q was evaluated against a %q device", iosOnlyRule, vendor)
				}
			}
			if _, ok := emitted[hardening.RulePlatformUnresolved]; ok {
				t.Errorf("a RESOLVED platform (%q) emitted the platform-unresolved finding", vendor)
			}
			// Every emitted id must actually be bound for this dialect.
			for id := range emitted {
				bound := false
				for _, r := range cat.Rules() {
					if r.ID == id {
						_, bound = r.Binding(vendor)
					}
				}
				for _, p := range cat.Probes() {
					if p.ID == id {
						_, bound = p.Binding(vendor)
					}
				}
				if !bound {
					t.Errorf("emitted %q, which has no %q binding", id, vendor)
				}
			}
		})
	}
}

func srlinuxDevice(id, tenant string) Device {
	return Device{ID: id, Name: id, Address: "172.40.40.11",
		Vendor: "nokia", OS: "SR Linux", TenantID: tenant}
}

// TestLaneEmitsTheDeviceOwnControlSetWithRealVerdicts is the end-to-end shape of
// the 2026-09-03 lab defect, from the inventory row to the bus record.
//
// As observed: a lane whose Deps.ConfigSource was nil (main.go constructed the
// lane ABOVE the config-backup module that assigns it) emitted 32 checks per
// spine — the whole catalog, Cisco IOS rules included — every one of them
// Unknown. With the source wired, the packs handed in and the binding gate
// resolved first, one SR Linux spine emits its OWN 14 controls and exactly the
// FAILs its config predicts.
//
// The dialect here is the synthetic pack (see testDialectPacks): what this test
// owns is the LANE — packs in through Deps, the device's own control set out on
// the bus. The same walk over the REAL spine1 capture, against the real
// bindings, is enterprise/dialects' TestSRLinuxSpineAsFoundVerdicts, which owns
// that fixture.
func TestLaneEmitsTheDeviceOwnControlSetWithRealVerdicts(t *testing.T) {
	wantFail := []string{
		"http-server-nontls", "mgmt-api-unencrypted", "tls-no-client-auth",
		"snmp-v1v2c-community", "no-remote-aaa", "no-ntp-server",
	}
	cfg := hardening.MemConfigSource{"spine1": tripConfig(wantFail...)}
	fx := newFixture(t, func(d *Deps) {
		d.ConfigSource = cfg
		d.Dialects = testDialectPacks()
	})
	fx.devices["acme"] = []Device{srlinuxDevice("spine1", "acme")}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	fails, emitted := map[string]bool{}, map[string]string{}
	for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
		ev := r.Value.(secbus.EvidenceEvent)
		if ev.Kind != secbus.KindPosture {
			continue // the advisory lane's exposure finding is not this test's subject
		}
		id, _ := ev.Attrs["raw_rule_id"].(string)
		status, _ := ev.Attrs["status"].(string)
		emitted[id] = status
		if status == secfindings.StatusFail.String() {
			fails[id] = true
		}
	}

	for _, id := range wantFail {
		if !fails[id] {
			t.Errorf("spine1 did not FAIL %q (got %q); emitted=%v", id, emitted[id], emitted)
		}
	}
	if len(fails) != len(wantFail) {
		t.Errorf("spine1 FAIL count = %d (%v), want %d", len(fails), fails, len(wantFail))
	}
	// Not one Cisco IOS rule may appear on an SR Linux spine.
	for _, iosOnly := range []string{"cdp-run-global", "pad-service", "vty-no-access-class",
		"no-aaa-new-model", "no-control-plane-protection", "ftp-server-enabled"} {
		if st, ok := emitted[iosOnly]; ok {
			t.Errorf("the Cisco IOS rule %q was evaluated against an SR Linux spine (%s)", iosOnly, st)
		}
	}
	if len(emitted) != len(srlinuxTestRules) {
		t.Errorf("spine1 emitted %d posture checks, want its %d srlinux-bound controls: %v",
			len(emitted), len(srlinuxTestRules), emitted)
	}
}

// TestUnassessedFindingsCarryTheirReasonOnTheBus: every non-verdict the lane
// publishes must say WHY on the wire. Before the fix the indexed document
// carried only attrs.status, so "Unknown" reached the operator with no reason
// at all — §5g's never-false-clear rule without the half that makes it
// actionable.
func TestUnassessedFindingsCarryTheirReasonOnTheBus(t *testing.T) {
	// Two devices, two DIFFERENT reasons: one SR Linux spine with no config on
	// file, one device whose platform resolves to no dialect at all.
	// ConfigSource nil → nothing captured. The packs are still handed in, so
	// spine1's own controls are the ones reported unassessed.
	fx := newFixture(t, func(d *Deps) { d.Dialects = testDialectPacks() })
	fx.devices["acme"] = []Device{
		srlinuxDevice("spine1", "acme"),
		{ID: "mystery", Name: "mystery", Vendor: "acme", OS: "WidgetOS 1.0", TenantID: "acme"},
	}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	reasons := map[string]map[string]string{} // device → rule → reason
	for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
		ev := r.Value.(secbus.EvidenceEvent)
		if ev.Kind != secbus.KindPosture {
			continue
		}
		status, _ := ev.Attrs["status"].(string)
		if status == secfindings.StatusPass.String() || status == secfindings.StatusFail.String() {
			continue
		}
		id, _ := ev.Attrs["raw_rule_id"].(string)
		detail, ok := ev.Attrs["status_detail"].(string)
		if !ok || strings.TrimSpace(detail) == "" {
			t.Errorf("%s/%s is %s with NO reason on the wire — a bare grey chip for the operator",
				ev.EntityID, id, status)
			continue
		}
		if reasons[ev.EntityID] == nil {
			reasons[ev.EntityID] = map[string]string{}
		}
		reasons[ev.EntityID][id] = detail
	}

	if got := reasons["spine1"]["no-ntp-server"]; !strings.Contains(got, "running-config unavailable") {
		t.Errorf("spine1/no-ntp-server reason = %q, want the config-unavailable reason", got)
	}
	if got := reasons["mystery"][hardening.RulePlatformUnresolved]; !strings.Contains(got, "unassessed: platform unresolved") {
		t.Errorf("mystery reason = %q, want the platform-unresolved reason", got)
	}
	if n := len(reasons["mystery"]); n != 1 {
		t.Errorf("an unresolvable platform produced %d posture findings (%v), want exactly 1",
			n, reasons["mystery"])
	}
}

// TestAdvisoryUsesTheRowsVersionLeafWhenTheOSLabelHasNone is tracker 231 in the
// PRODUCER lane (the twin of the /api/vulns read).
//
// The reference lab's SR Linux spines carry `os: "SR Linux"` — a product label
// and no version — because the platform's ACL refuses the SNMP collector and
// there is no sysDescr to parse. The lane reported them unassessed forever. It
// now hands ParseSoftware BOTH strings the row can carry, so a version learned
// over any transport reaches the advisory query; the default splitter proves
// the seam works even with no platform parser injected.
func TestAdvisoryUsesTheRowsVersionLeafWhenTheOSLabelHasNone(t *testing.T) {
	mock := advisory.NewMockProvider("mock").Add("nokia", "SR", advisory.Advisory{
		CVE: "CVE-2026-9001", Severity: secfindings.SeverityHigh, CVSS: 8.1,
		Summary:         "SR Linux advisory",
		AffectedVersion: advisory.VersionConstraint{Exact: "26.3.2"},
	})
	fx := newFixture(t, func(d *Deps) {
		d.Advisory = mock
		// No ParseSoftware: defaultParseSoftware is the one under test.
	})
	withLeaf := dev("spine1", "acme")
	withLeaf.Vendor, withLeaf.OS, withLeaf.OSVersion = "nokia", "SR", "26.3.2"
	noLeaf := dev("spine2", "acme")
	noLeaf.Vendor, noLeaf.OS, noLeaf.OSVersion = "nokia", "SR", ""
	fx.devices["acme"] = []Device{withLeaf, noLeaf}

	fx.lane.ScanTenant(context.Background(), "acme", "manual")

	matched, unassessed := 0, 0
	for _, r := range fx.pub.on(secbus.TopicSecurityEvidence) {
		ev := r.Value.(secbus.EvidenceEvent)
		switch ev.Attrs["control_id"] {
		case "CVE-2026-9001":
			matched++
		case "advisory-unassessed":
			unassessed++
		}
	}
	if matched != 1 {
		t.Fatalf("advisory matches = %d, want 1 — the row's version leaf never reached the query", matched)
	}
	// The device WITHOUT a leaf is still honestly unassessed: the leaf makes a
	// device assessable, it never makes an unassessable one look clear.
	if unassessed != 1 {
		t.Fatalf("unassessed findings = %d, want 1 (spine2 has no version anywhere)", unassessed)
	}
}
