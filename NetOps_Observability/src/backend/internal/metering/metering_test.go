package metering

// metering_test.go — the vocabulary and the roll-up arithmetic.
//
// The arithmetic is what a customer will redo by hand against a signed report,
// so every rule it follows is pinned here rather than left to be inferred from
// the implementation.

import (
	"math"
	"testing"
	"time"
)

func day(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestVocabularyIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range Meters() {
		switch {
		case d.Name == "":
			t.Fatalf("a meter has no name")
		case seen[d.Name]:
			t.Fatalf("meter %q is declared twice", d.Name)
		case d.Label == "":
			t.Errorf("meter %q has no operator-facing label", d.Name)
		case d.Unit == "":
			t.Errorf("meter %q has no unit token", d.Name)
		case d.Doc == "":
			t.Errorf("meter %q has no doc sentence — a number nobody can interpret is not a meter", d.Name)
		case d.Kind != KindEntitlement && d.Kind != KindDiagnostic:
			t.Errorf("meter %q has kind %q, outside the vocabulary", d.Name, d.Kind)
		case d.Scope != ScopeTenant && d.Scope != ScopePlatform && d.Scope != ScopeAny:
			t.Errorf("meter %q has scope %q, outside the vocabulary", d.Name, d.Scope)
		}
		switch d.Agg {
		case AggPeak, AggUnique, AggSum, AggLast:
		default:
			t.Errorf("meter %q has aggregation %q, outside the vocabulary", d.Name, d.Agg)
		}
		seen[d.Name] = true
	}
	if len(seen) < 20 {
		t.Fatalf("only %d meters declared — the vocabulary guard is reading nothing", len(seen))
	}
	// The primary meter must exist and must be counted from configuration's
	// unique aggregation: it is the priced unit.
	d, ok := Lookup(MeterMonitoredDevicesUnique)
	if !ok || d.Agg != AggUnique || d.Kind != KindEntitlement {
		t.Fatalf("the primary meter is not an entitlement/unique meter: %+v", d)
	}
}

func TestReadingValidationRefusesADishonestRecord(t *testing.T) {
	cases := []struct {
		name string
		in   Reading
	}{
		{"meter outside the vocabulary", Reading{Meter: "devices_i_made_up", Source: SourceConfiguration, Tenant: "acme"}},
		{"source outside the vocabulary", Reading{Meter: MeterWatchedPrefixes, Tenant: "acme", Source: "guessed"}},
		{"not_measured with no reason", Reading{Meter: MeterWatchedPrefixes, Tenant: "acme", Source: SourceNotMeasured}},
		{"negative value", Reading{Meter: MeterWatchedPrefixes, Tenant: "acme", Source: SourceConfiguration, Value: -1}},
		{"non-finite value", Reading{Meter: MeterWatchedPrefixes, Tenant: "acme", Source: SourceConfiguration, Value: math.Inf(1)}},
		{"tenant-only meter read for the installation", Reading{Meter: MeterAITokensInput, Tenant: ScopeInstallation, Source: SourceCounter, Value: 5}},
		{"installation meter read for a tenant", Reading{Meter: MeterTenants, Tenant: "acme", Source: SourceConfiguration, Value: 3}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.in.Validate(); err == nil {
				t.Fatalf("accepted a reading that should have been refused: %+v", c.in)
			}
		})
	}
	ok := []Reading{
		Measured(MeterWatchedPrefixes, "acme", 4),
		NotMeasured(MeterTraceSpans, ScopeInstallation, "no trace pipeline is configured"),
		Unique(MeterMonitoredDevicesUnique, "acme", []string{"a", "b"}),
		Counted(MeterMetricSamples, ScopeInstallation, 1200),
	}
	for _, r := range ok {
		if err := r.Validate(); err != nil {
			t.Errorf("refused a valid reading %q: %v", r.Meter, err)
		}
	}
}

func TestFoldAppliesEachMetersOwnAggregation(t *testing.T) {
	row := DailyRecord{Day: "2026-09-05", TenantID: "acme"}
	var err error
	row, err = Fold(row, []Reading{
		Unique(MeterMonitoredDevicesUnique, "acme", []string{"d1", "d2"}),
		Measured(MeterMonitoredDevicesPeak, "acme", 2),
		Counted(MeterDEMChecks, "acme", 10),
	}, day("2026-09-05T01:00:00Z"))
	if err != nil {
		t.Fatalf("fold 1: %v", err)
	}
	row, err = Fold(row, []Reading{
		// Monitoring MOVED: two different devices. Unique goes to 4, peak stays 2.
		Unique(MeterMonitoredDevicesUnique, "acme", []string{"d3", "d4"}),
		Measured(MeterMonitoredDevicesPeak, "acme", 2),
		Counted(MeterDEMChecks, "acme", 12),
	}, day("2026-09-05T02:00:00Z"))
	if err != nil {
		t.Fatalf("fold 2: %v", err)
	}
	want := map[string]float64{
		MeterMonitoredDevicesUnique: 4,
		MeterMonitoredDevicesPeak:   2,
		MeterDEMChecks:              22,
	}
	for name, v := range want {
		got := row.Meters[name]
		if got.Value == nil {
			t.Fatalf("%s has no value", name)
		}
		if *got.Value != v {
			t.Errorf("%s = %v, want %v", name, *got.Value, v)
		}
	}
	if row.Samples != 2 {
		t.Errorf("samples = %d, want 2", row.Samples)
	}
	if row.Sealed() {
		t.Errorf("the open day should still carry its identity set")
	}
	if len(row.Seal().Open) != 0 {
		t.Errorf("Seal did not drop the accumulator state")
	}
}

func TestFoldRefusesTheWrongDayAndTheWrongTenant(t *testing.T) {
	row := DailyRecord{Day: "2026-09-05", TenantID: "acme"}
	if _, err := Fold(row, nil, day("2026-09-06T00:00:00Z")); err == nil {
		t.Errorf("folded a sample from another day into the row")
	}
	if _, err := Fold(row, []Reading{Measured(MeterWatchedPrefixes, "globex", 1)}, day("2026-09-05T00:00:00Z")); err == nil {
		t.Errorf("folded another tenant's reading into the row")
	}
}

func TestNotMeasuredNeverOverwritesAMeasurement(t *testing.T) {
	row := DailyRecord{Day: "2026-09-05", TenantID: "acme"}
	row, err := Fold(row, []Reading{Measured(MeterWatchedPrefixes, "acme", 7)}, day("2026-09-05T01:00:00Z"))
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	row, err = Fold(row, []Reading{NotMeasured(MeterWatchedPrefixes, "acme", "the watchlist could not be read")}, day("2026-09-05T02:00:00Z"))
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	mv := row.Meters[MeterWatchedPrefixes]
	if mv.Value == nil || *mv.Value != 7 {
		t.Fatalf("a failed sample erased a real measurement: %+v", mv)
	}
	if mv.Samples != 1 {
		t.Errorf("samples = %d, want 1 — the failed hour must not count as measured", mv.Samples)
	}
}

func TestAMeasurementReplacesNotMeasured(t *testing.T) {
	row := DailyRecord{Day: "2026-09-05", TenantID: "acme"}
	row, _ = Fold(row, []Reading{NotMeasured(MeterWatchedPrefixes, "acme", "the watchlist could not be read")}, day("2026-09-05T01:00:00Z"))
	row, err := Fold(row, []Reading{Measured(MeterWatchedPrefixes, "acme", 3)}, day("2026-09-05T02:00:00Z"))
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	mv := row.Meters[MeterWatchedPrefixes]
	if mv.Value == nil || *mv.Value != 3 || mv.Source != SourceConfiguration || mv.Reason != "" {
		t.Fatalf("a real number did not replace the admission of not having one: %+v", mv)
	}
}

func TestNotMeasuredIsNeverAZero(t *testing.T) {
	row := DailyRecord{Day: "2026-09-05", TenantID: ScopeInstallation}
	row, err := Fold(row, []Reading{NotMeasured(MeterTraceSpans, ScopeInstallation, "no trace pipeline is configured on this installation")}, day("2026-09-05T01:00:00Z"))
	if err != nil {
		t.Fatalf("fold: %v", err)
	}
	mv := row.Meters[MeterTraceSpans]
	if mv.Value != nil {
		t.Fatalf("an unmeasured meter carries a value %v — a fabricated zero is the failure this contract exists to prevent", *mv.Value)
	}
	if mv.Reason == "" || mv.Source != SourceNotMeasured {
		t.Fatalf("an unmeasured meter must say why: %+v", mv)
	}
}

func TestRollUpAcrossDays(t *testing.T) {
	mk := func(d string, unique, peak, checks float64) DailyRecord {
		row := DailyRecord{Day: d, TenantID: "acme"}
		row, err := Fold(row, []Reading{
			Reading{Meter: MeterMonitoredDevicesUnique, Tenant: "acme", Source: SourceConfiguration, Value: unique, IDs: ids(int(unique))},
			Measured(MeterMonitoredDevicesPeak, "acme", peak),
			Counted(MeterDEMChecks, "acme", checks),
		}, day(d+"T01:00:00Z"))
		if err != nil {
			t.Fatalf("fold %s: %v", d, err)
		}
		return row.Seal()
	}
	rows := []DailyRecord{
		mk("2026-09-03", 10, 8, 100),
		mk("2026-09-04", 12, 12, 150),
		mk("2026-09-05", 9, 9, 50),
	}
	got := map[string]MeterValue{}
	for _, mv := range RollUp(rows) {
		got[mv.Meter] = mv
	}
	if v := got[MeterMonitoredDevicesUnique]; v.Value == nil || *v.Value != 12 {
		t.Errorf("period unique = %+v, want the peak DAY (12)", v)
	}
	if v := got[MeterMonitoredDevicesUnique]; v.Reason != PeriodUniqueNote {
		t.Errorf("a multi-day unique roll-up must say it is the highest day, got %q", v.Reason)
	}
	if v := got[MeterMonitoredDevicesPeak]; v.Value == nil || *v.Value != 12 {
		t.Errorf("period peak = %+v, want 12", v)
	}
	if v := got[MeterDEMChecks]; v.Value == nil || *v.Value != 300 {
		t.Errorf("period checks = %+v, want 300 (summed)", v)
	}
}

func TestRollUpKeepsNotMeasuredAsABlank(t *testing.T) {
	row := DailyRecord{Day: "2026-09-05", TenantID: ScopeInstallation}
	row, _ = Fold(row, []Reading{NotMeasured(MeterTraceSpans, ScopeInstallation, "no trace pipeline")}, day("2026-09-05T01:00:00Z"))
	for _, mv := range RollUp([]DailyRecord{row}) {
		if mv.Meter != MeterTraceSpans {
			continue
		}
		if mv.Value != nil || mv.Reason == "" {
			t.Fatalf("the roll-up turned an unmeasured meter into a number: %+v", mv)
		}
		return
	}
	t.Fatalf("the unmeasured meter vanished from the roll-up entirely — it must be listed, with its reason")
}

func TestValidDay(t *testing.T) {
	for _, s := range []string{"2026-09-05", "1999-01-31"} {
		if !ValidDay(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"", "2026-9-5", "2026/09/05", "2026-09-05T00:00:00Z", "abcd-ef-gh"} {
		if ValidDay(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func ids(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, string(rune('a'+i%26))+string(rune('0'+i/26)))
	}
	return out
}
