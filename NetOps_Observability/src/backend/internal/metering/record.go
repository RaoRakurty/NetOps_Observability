// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package metering

// record.go — the DATA CONTRACT: what one sample is, what one daily row is,
// and the pure functions that turn the first into the second.
//
// Everything here is a value-to-value transformation with no IO and no clock
// of its own. That is what makes the roll-up checkable: the customer and
// Correlix run the same arithmetic over the same rows and must land on the
// same number, which is the whole promise of the signed report.

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// A sample
// ─────────────────────────────────────────────────────────────────────────────

// Reading is one collector's answer for one meter, for one tenant, at one
// sampling instant.
//
// A reading either HAS a value or explains why it does not. Source
// SourceNotMeasured carries a Reason and no value; the other two carry a value
// and no reason. Fold refuses anything else, so "we did not look" can never be
// stored as a number and a number can never arrive without a provenance.
type Reading struct {
	// Meter is a name from the closed vocabulary.
	Meter string
	// Tenant is the owning tenant, or ScopeInstallation for an
	// installation-wide meter.
	Tenant string
	// Source is where the value came from.
	Source Source
	// Value is the measurement. Ignored when Source is SourceNotMeasured.
	Value float64
	// IDs are the identities observed in this sample, for an AggUnique meter
	// (the monitored device ids). Ignored for every other aggregation.
	IDs []string
	// Reason is REQUIRED when Source is SourceNotMeasured: the operator
	// sentence saying why there is no number.
	Reason string
}

// NotMeasured builds a reading that admits there is no counter for a meter.
func NotMeasured(meter, tenant, reason string) Reading {
	return Reading{Meter: meter, Tenant: tenant, Source: SourceNotMeasured, Reason: reason}
}

// Measured builds a reading from configuration.
func Measured(meter, tenant string, v float64) Reading {
	return Reading{Meter: meter, Tenant: tenant, Source: SourceConfiguration, Value: v}
}

// Counted builds a reading from a counter the platform already keeps.
func Counted(meter, tenant string, v float64) Reading {
	return Reading{Meter: meter, Tenant: tenant, Source: SourceCounter, Value: v}
}

// Unique builds an AggUnique reading from the identities observed.
func Unique(meter, tenant string, ids []string) Reading {
	return Reading{Meter: meter, Tenant: tenant, Source: SourceConfiguration, Value: float64(len(ids)), IDs: ids}
}

// Validate checks a reading against the vocabulary and the source rules.
func (r Reading) Validate() error {
	if !ValidMeter(r.Meter) {
		return errUnknownMeter(r.Meter)
	}
	if !ValidSource(r.Source) {
		return fmt.Errorf("metering: meter %q has source %q, which is outside the closed vocabulary", r.Meter, r.Source)
	}
	if r.Source == SourceNotMeasured {
		if r.Reason == "" {
			// A blank with no reason is the exact failure this package exists
			// to prevent: an operator reading "not measured" with no
			// explanation cannot tell a gap from a bug.
			return fmt.Errorf("metering: meter %q is not_measured with no reason — say why, or do not record it", r.Meter)
		}
		return nil
	}
	if math.IsNaN(r.Value) || math.IsInf(r.Value, 0) {
		return fmt.Errorf("metering: meter %q has a non-finite value", r.Meter)
	}
	if r.Value < 0 {
		return fmt.Errorf("metering: meter %q has a negative value %v", r.Meter, r.Value)
	}
	d, _ := Lookup(r.Meter)
	if want, got := d.Scope, scopeOf(r.Tenant); want != ScopeAny && want != got {
		return fmt.Errorf("metering: meter %q is an %s meter but was read for scope %s", r.Meter, want, got)
	}
	return nil
}

func scopeOf(tenant string) Scope {
	if NormaliseTenant(tenant) == ScopeInstallation {
		return ScopePlatform
	}
	return ScopeTenant
}

// ─────────────────────────────────────────────────────────────────────────────
// A daily row
// ─────────────────────────────────────────────────────────────────────────────

// MeterValue is one meter's state on one day.
//
// Value is a POINTER for the same reason the Licence page's ceiling `current`
// is: a meter with no counter is `null` with a sibling Reason, never a
// fabricated 0. Do not coerce one into the other on the way in or out.
type MeterValue struct {
	Meter  string   `json:"meter"`
	Value  *float64 `json:"value"`
	Unit   string   `json:"unit"`
	Source Source   `json:"source"`
	Reason string   `json:"reason,omitempty"`
	// Samples is how many hourly samples contributed to this value. Zero on a
	// not_measured meter. Present so a reader can tell a full day from a day
	// the api was down for twenty hours.
	Samples int `json:"samples"`
}

// DailyRecord is one (UTC day, tenant) row: the persisted unit of the contract.
type DailyRecord struct {
	// Day is the UTC day key, DayFormat.
	Day string `json:"day"`
	// TenantID is the owning tenant, or ScopeInstallation.
	TenantID string `json:"tenant_id"`
	// Meters is meter name → its state that day.
	Meters map[string]MeterValue `json:"meters"`
	// Samples is how many snapshots folded into this row.
	Samples int `json:"samples"`
	// UpdatedAt is when the last snapshot folded in (UTC).
	UpdatedAt time.Time `json:"updated_at"`
	// Open carries the accumulator state that only the CURRENT day needs — the
	// identity sets behind an AggUnique meter. It is cleared when the day is
	// sealed (Seal), because a closed day's unique COUNT is the answer and
	// keeping thousands of device ids per tenant per day for 400 days is a
	// storage bill nobody asked for.
	Open map[string][]string `json:"open,omitempty"`
}

// MeterList returns the row's meters in vocabulary order.
func (r DailyRecord) MeterList() []MeterValue {
	out := make([]MeterValue, 0, len(r.Meters))
	for _, name := range sortedMeterNames(r.Meters) {
		out = append(out, r.Meters[name])
	}
	return out
}

// Seal drops the open-day accumulator state. Idempotent.
func (r DailyRecord) Seal() DailyRecord {
	r.Open = nil
	return r
}

// Sealed reports whether the row still carries accumulator state.
func (r DailyRecord) Sealed() bool { return len(r.Open) == 0 }

// MaxUniqueIDs bounds the identity set an open day accumulates for one meter.
//
// A bound is not optional (CLAUDE.md §9: all queues bounded). Past it the
// count keeps rising but the set stops growing, and the meter says so through
// its Source staying configuration with the value it has — an installation with
// more than this many distinct devices in one day is far outside anything the
// licensing model prices, and a metering row must never be the thing that
// fills a disk.
const MaxUniqueIDs = 50000

// ─────────────────────────────────────────────────────────────────────────────
// Folding a snapshot into the day
// ─────────────────────────────────────────────────────────────────────────────

// Fold applies one snapshot's readings to a day's row and returns the new row.
//
// It is PURE: same row plus same readings gives the same result, whatever the
// wall clock says. `at` is the sampling instant, supplied by the caller.
//
// Rules, one per aggregation, and the aggregation is the METER's property so
// two call sites cannot disagree:
//
//	AggPeak    the higher of the stored value and this sample
//	AggUnique  the size of the union of the identities seen so far
//	AggSum     the stored value plus this sample
//	AggLast    this sample, replacing whatever was there
//
// A not_measured reading NEVER overwrites a measured value: a collector that
// worked at 09:00 and failed at 10:00 leaves the day reading what it measured,
// with the sample count showing it was not measured every hour. The reverse
// direction — a measured reading arriving where a not_measured one is stored —
// DOES replace it, because a real number is strictly better than an admission
// of not having one.
func Fold(row DailyRecord, readings []Reading, at time.Time) (DailyRecord, error) {
	at = at.UTC()
	day := at.Format(DayFormat)
	if row.Day == "" {
		row.Day = day
	}
	if row.Day != day {
		return row, fmt.Errorf("metering: refusing to fold a %s sample into the %s row", day, row.Day)
	}
	if row.Meters == nil {
		row.Meters = map[string]MeterValue{}
	}
	for _, rd := range readings {
		if err := rd.Validate(); err != nil {
			return row, err
		}
		if NormaliseTenant(rd.Tenant) != NormaliseTenant(row.TenantID) {
			return row, fmt.Errorf("metering: reading for tenant %q folded into the %q row", rd.Tenant, row.TenantID)
		}
		d, _ := Lookup(rd.Meter)
		prev, had := row.Meters[rd.Meter]

		if rd.Source == SourceNotMeasured {
			if had && prev.Value != nil {
				// Keep the measurement we have. Recording "not measured" over a
				// real number would erase a fact to record the absence of one.
				continue
			}
			row.Meters[rd.Meter] = MeterValue{
				Meter: rd.Meter, Unit: d.Unit, Source: SourceNotMeasured,
				Reason: rd.Reason, Samples: 0,
			}
			continue
		}

		next := rd.Value
		samples := 1
		if had && prev.Value != nil {
			samples = prev.Samples + 1
			switch d.Agg {
			case AggPeak:
				next = math.Max(*prev.Value, rd.Value)
			case AggSum:
				next = *prev.Value + rd.Value
			case AggLast:
				next = rd.Value
			case AggUnique:
				next = *prev.Value
			}
		}
		if d.Agg == AggUnique {
			if row.Open == nil {
				row.Open = map[string][]string{}
			}
			union, size := mergeIDs(row.Open[rd.Meter], rd.IDs)
			row.Open[rd.Meter] = union
			next = float64(size)
		}
		v := next
		row.Meters[rd.Meter] = MeterValue{
			Meter: rd.Meter, Value: &v, Unit: d.Unit, Source: rd.Source, Samples: samples,
		}
	}
	row.Samples++
	row.UpdatedAt = at
	return row, nil
}

// mergeIDs unions two identity sets, keeping the result sorted and bounded.
// It returns the (possibly truncated) union and its size.
func mergeIDs(have, add []string) ([]string, int) {
	if len(add) == 0 {
		return have, len(have)
	}
	seen := make(map[string]bool, len(have)+len(add))
	out := make([]string, 0, len(have)+len(add))
	for _, s := range have {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range add {
		if s == "" || seen[s] {
			continue
		}
		if len(out) >= MaxUniqueIDs {
			break
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out, len(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Rolling a period up
// ─────────────────────────────────────────────────────────────────────────────

// RollUp folds a period's daily rows into one set of period totals, using each
// meter's own aggregation.
//
// The unique meter is the one that cannot be rolled up honestly across days:
// the identity sets behind a sealed day are gone, so a period's "unique
// devices" is reported as the PEAK of the daily unique counts and says so in
// its reason. Inventing a union we do not have would be a fabricated number in
// the one place a customer is most entitled to a true one.
func RollUp(rows []DailyRecord) []MeterValue {
	acc := map[string]MeterValue{}
	reasons := map[string]string{}
	for _, row := range rows {
		for _, name := range sortedMeterNames(row.Meters) {
			mv := row.Meters[name]
			d, ok := Lookup(name)
			if !ok {
				continue
			}
			if mv.Value == nil {
				if _, have := acc[name]; !have {
					reasons[name] = mv.Reason
				}
				continue
			}
			cur, had := acc[name]
			if !had || cur.Value == nil {
				v := *mv.Value
				acc[name] = MeterValue{Meter: name, Value: &v, Unit: d.Unit, Source: mv.Source, Samples: mv.Samples}
				continue
			}
			v := *cur.Value
			switch d.Agg {
			case AggSum:
				v += *mv.Value
			case AggPeak, AggUnique:
				v = math.Max(v, *mv.Value)
			case AggLast:
				v = *mv.Value
			}
			acc[name] = MeterValue{Meter: name, Value: &v, Unit: d.Unit, Source: mv.Source, Samples: cur.Samples + mv.Samples}
		}
	}
	out := make([]MeterValue, 0, len(meters))
	for _, d := range meters {
		if mv, ok := acc[d.Name]; ok {
			if d.Agg == AggUnique && len(rows) > 1 {
				mv.Reason = PeriodUniqueNote
			}
			out = append(out, mv)
			continue
		}
		if r, ok := reasons[d.Name]; ok {
			out = append(out, MeterValue{Meter: d.Name, Unit: d.Unit, Source: SourceNotMeasured, Reason: r})
		}
	}
	return out
}

// PeriodUniqueNote is the sentence beside a multi-day unique roll-up. It states
// plainly that the number is the highest DAY, not a union across days, because
// a customer comparing it against their own count must know which arithmetic
// produced it.
const PeriodUniqueNote = "the highest single day in the period — daily unique sets are not kept once a day closes, so this is not a union across days"

// Totals is the period roll-up plus the days it covers.
type Totals struct {
	From   string       `json:"from"`
	To     string       `json:"to"`
	Days   int          `json:"days"`
	Meters []MeterValue `json:"meters"`
}
