// Package metering records WHAT A CUSTOMER ACTUALLY CONSUMED. It is a
// SEPARATE DATA CONTRACT from internal/entitlement + internal/licence, which
// answer a different question, and the two must never be conflated (owner
// strategy, docs/design/research/LICENSING_TIERING_STRATEGY_2026-09-05.md,
// "Operational, security and go-to-market design"):
//
//	ENTITLEMENTS   "What is this customer ALLOWED to do?"   internal/entitlement
//	METERING       "What did this customer actually USE?"   THIS PACKAGE
//
// Conflating them is how a monitoring product ends up refusing work because a
// counter moved, or billing for something nobody bought. So nothing here gates
// anything: this package has no admission path, no refusal, no ceiling, and no
// opinion about price. It observes, rolls up by UTC day, and can hand the
// result over as a signed document. Design of record:
// docs/design/METERING_2026-09-05.md.
//
// # Where the numbers come from
//
// The PRIMARY meter — monitored devices — is counted from CONFIGURATION, never
// from telemetry activity (owner decision, 2026-09-05):
//
//	counts:      a collector is enabled on this device
//	NEVER:       a packet arrived from this device in the last 15 minutes
//
// That is not a detail. A device counted by recent traffic drops out of the
// meter during the outage the customer bought the product to diagnose, and the
// bill moves while the network is down. Configuration does not do that.
//
// Every meter therefore declares its SOURCE, and one of the three values is an
// admission that we did not measure it:
//
//	configuration   read from the platform's own configured state
//	counter         read from a counter the platform already keeps
//	not_measured    there is no counter for this on this installation — with
//	                the REASON recorded beside it
//
// A meter with no counter is recorded as not_measured with its reason. It is
// NEVER recorded as zero. A zero means "we counted, and it was none"; a blank
// means "nobody counted", and a usage report that merges the two is lying in
// one of the two cases.
//
// # No phone-home
//
// Nothing in this package, and nothing that calls it, opens a connection to
// Correlix. The records live in the customer's own store; the report is a file
// the customer downloads and chooses to send. That is the whole design: the
// customer and Correlix must be able to derive the SAME counts independently,
// which is why the report is signed and its canonical bytes are pinned
// (report.go).
package metering

import (
	"fmt"
	"sort"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Scope
// ─────────────────────────────────────────────────────────────────────────────

// ScopeInstallation is the reserved tenant key for meters that describe the
// INSTALLATION rather than any one tenant — the tenant and org counts, the
// configured retention windows, and the pipeline-wide diagnostic counters.
//
// It is the empty string deliberately. A tenant id is never empty (the stores
// refuse one), so no tenant can collide with it; and the Postgres row policy
// `tenant_id = current_setting('app.tenant_id')` therefore never matches an
// installation row for a tenant-scoped read. Only the '*' platform scope sees
// these rows, which is exactly the isolation posture they need: how many
// tenants an installation has is the provider's number, not a tenant's
// (CLAUDE.md §3a rule 1).
const ScopeInstallation = ""

// Scope says which kind of row a meter belongs on.
type Scope string

const (
	// ScopeTenant — the meter is measured per tenant and lives on that tenant's
	// row.
	ScopeTenant Scope = "tenant"
	// ScopePlatform — the meter describes the whole installation and lives only
	// on the installation row.
	ScopePlatform Scope = "installation"
	// ScopeAny — the meter is recorded on BOTH: on a tenant's row it is that
	// tenant's number, on the installation row it is the platform-wide total.
	//
	// The two are not a sum of each other and must not be added up. A device
	// nobody has assigned to a tenant is platform-owned: it appears in the
	// installation total and on no tenant's row, so the tenant rows add up to
	// LESS than the installation figure whenever untagged devices are being
	// monitored. The installation number is the one the licence ceiling counts.
	ScopeAny Scope = "any"
)

// ─────────────────────────────────────────────────────────────────────────────
// Source
// ─────────────────────────────────────────────────────────────────────────────

// Source is where a recorded value came from. A closed vocabulary: a reading
// that cannot name its source is refused rather than stored as an anonymous
// number.
type Source string

const (
	// SourceConfiguration — read from the platform's configured state (the
	// monitored set, the tenant register, the retention knobs). The primary
	// meter is always this.
	SourceConfiguration Source = "configuration"
	// SourceCounter — read from a counter the platform already keeps, either
	// in-process or in the metrics store.
	SourceCounter Source = "counter"
	// SourceNotMeasured — there is no counter for this meter on this
	// installation. Carries a Reason; carries NO value.
	SourceNotMeasured Source = "not_measured"
)

// ValidSource reports whether s is in the closed vocabulary.
func ValidSource(s Source) bool {
	switch s {
	case SourceConfiguration, SourceCounter, SourceNotMeasured:
		return true
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregation
// ─────────────────────────────────────────────────────────────────────────────

// Aggregation is how a day's hourly samples become one daily number. It is a
// property of the METER, declared once here, so the roll-up cannot differ
// between the API, the report and the page.
type Aggregation string

const (
	// AggPeak — the highest sample of the day. The honest answer for a
	// standing quantity: a fleet that touched 300 devices and settled at 260
	// was a 300 fleet that day.
	AggPeak Aggregation = "peak"
	// AggUnique — the size of the UNION of the day's samples. Distinct from
	// peak: 25 devices in the morning and 25 different ones in the afternoon is
	// a peak of 25 and a unique of 50, and a device-priced product must be able
	// to say which it means.
	AggUnique Aggregation = "unique"
	// AggSum — the sum of the day's samples. For interval counters, where each
	// sample is "what happened since the last one".
	AggSum Aggregation = "sum"
	// AggLast — the last sample of the day. For configuration facts, where an
	// average or a peak would be meaningless.
	AggLast Aggregation = "last"
)

// ─────────────────────────────────────────────────────────────────────────────
// Kind
// ─────────────────────────────────────────────────────────────────────────────

// Kind separates the meters that bound a licence from the ones that exist to
// tell an operator (and, later, us) what an installation costs to run.
type Kind string

const (
	// KindEntitlement — the meters an entitlement is expressed in. These are
	// the numbers a true-up conversation uses.
	KindEntitlement Kind = "entitlement"
	// KindDiagnostic — measured because it is useful, NOT because anything is
	// charged for it. On-prem, ingestion is explicitly not metered for money
	// (strategy doc: "Do not meter ingestion on-prem. Correlix is not paying
	// for the customer's disks, network or compute").
	KindDiagnostic Kind = "diagnostic"
)

// ─────────────────────────────────────────────────────────────────────────────
// The closed meter vocabulary
// ─────────────────────────────────────────────────────────────────────────────

// Meter names. Closed vocabulary: a reading naming anything else is refused at
// the door (Fold), so a typo in a collector can never become a silent meter
// nobody reads.
const (
	// ── entitlement meters ──
	MeterMonitoredDevicesUnique = "monitored_devices_unique"
	MeterMonitoredDevicesPeak   = "monitored_devices_peak"
	MeterWatchedPrefixes        = "watched_prefixes"
	MeterTenants                = "tenants"
	MeterOrgs                   = "orgs"
	MeterRetentionLogs          = "effective_retention_days_logs"
	MeterRetentionFlows         = "effective_retention_days_flows"
	MeterRetentionFindings      = "effective_retention_days_findings"
	MeterRetentionCorrelation   = "effective_retention_days_correlation"
	MeterRetentionMetrics       = "effective_retention_days_metrics"

	// ── diagnostic meters ──
	MeterMetricSamples     = "metric_samples_ingested"
	MeterMetricSeries      = "metric_series_active"
	MeterLogRecords        = "log_accepted_records"
	MeterFlowRecords       = "flow_accepted_records"
	MeterTraceSpans        = "trace_accepted_spans"
	MeterDEMChecks         = "dem_checks_run"
	MeterAITokens          = "hosted_ai_tokens_estimated"
	MeterAITokensInput     = "hosted_ai_tokens_input"
	MeterAITokensOutput    = "hosted_ai_tokens_output"
	MeterProcessorInput    = "processor_input_records"
	MeterProcessorOutput   = "processor_output_records"
	MeterProcessorRatio    = "processor_output_input_ratio"
	MeterMonitoredWithheld = "monitored_devices_withheld"
)

// Units. Machine tokens, so a client keys behaviour off the unit rather than
// off the label it renders.
const (
	UnitDevices  = "monitored_devices"
	UnitPrefixes = "watched_prefixes"
	UnitTenants  = "tenants"
	UnitOrgs     = "orgs"
	UnitDays     = "days"
	UnitRecords  = "records"
	UnitSamples  = "samples"
	UnitSeries   = "series"
	UnitChecks   = "checks"
	UnitTokens   = "tokens"
	UnitRatio    = "ratio"
)

// Descriptor is one meter's complete declaration. Declared as DATA so a new
// meter cannot ship without a label, a unit, a scope, a roll-up rule and a
// sentence saying what it does and does not mean.
type Descriptor struct {
	Name string
	// Label is the operator-facing name.
	Label string
	// Unit is the machine token for what the number counts.
	Unit string
	Kind Kind
	Agg  Aggregation
	// Scope says which row the meter belongs on.
	Scope Scope
	// Doc is the sentence shown beside the number. It says what the meter
	// means AND, where it matters, what it is not.
	Doc string
}

// meters is the vocabulary, in report order: the primary unit first, the rest
// of the entitlement meters after it, diagnostics last.
var meters = []Descriptor{
	{
		Name: MeterMonitoredDevicesUnique, Label: "Monitored devices (unique)", Unit: UnitDevices,
		Kind: KindEntitlement, Agg: AggUnique, Scope: ScopeAny,
		Doc: "Distinct devices with at least one collector enabled at any point in the day. Counted from configuration, not from traffic: a device that stopped answering still counts, and discovery does not consume the allowance.",
	},
	{
		Name: MeterMonitoredDevicesPeak, Label: "Monitored devices (peak)", Unit: UnitDevices,
		Kind: KindEntitlement, Agg: AggPeak, Scope: ScopeAny,
		Doc: "The highest number of monitored devices seen in a single sample that day. Lower than the unique count whenever monitoring moved between devices during the day.",
	},
	{
		Name: MeterMonitoredWithheld, Label: "Devices withheld at the ceiling", Unit: UnitDevices,
		Kind: KindEntitlement, Agg: AggPeak, Scope: ScopePlatform,
		Doc: "Devices in the inventory that would be monitored but are not, because the licensed allowance is full. Nothing about them has been deleted or hidden.",
	},
	{
		Name: MeterWatchedPrefixes, Label: "Watched prefixes", Unit: UnitPrefixes,
		Kind: KindEntitlement, Agg: AggPeak, Scope: ScopeAny,
		Doc: "BGP prefixes on the watchlist, at the day's peak.",
	},
	{
		Name: MeterTenants, Label: "Tenants", Unit: UnitTenants,
		Kind: KindEntitlement, Agg: AggPeak, Scope: ScopePlatform,
		Doc: "Tenants on this installation, at the day's peak.",
	},
	{
		Name: MeterOrgs, Label: "Organisations", Unit: UnitOrgs,
		Kind: KindEntitlement, Agg: AggPeak, Scope: ScopePlatform,
		Doc: "Organisations on this installation, at the day's peak.",
	},
	{
		Name: MeterRetentionLogs, Label: "Log retention", Unit: UnitDays,
		Kind: KindEntitlement, Agg: AggLast, Scope: ScopePlatform,
		Doc: "The configured log retention window. What is configured, not what happens to be on disk.",
	},
	{
		Name: MeterRetentionFlows, Label: "Flow retention", Unit: UnitDays,
		Kind: KindEntitlement, Agg: AggLast, Scope: ScopePlatform,
		Doc: "The configured flow retention window.",
	},
	{
		Name: MeterRetentionFindings, Label: "Findings retention", Unit: UnitDays,
		Kind: KindEntitlement, Agg: AggLast, Scope: ScopePlatform,
		Doc: "The configured findings retention window.",
	},
	{
		Name: MeterRetentionCorrelation, Label: "Correlation history retention", Unit: UnitDays,
		Kind: KindEntitlement, Agg: AggLast, Scope: ScopePlatform,
		Doc: "The configured retention for correlation history — the versioned objects, edges and evidence behind an RCA.",
	},
	{
		Name: MeterRetentionMetrics, Label: "Metric retention", Unit: UnitDays,
		Kind: KindEntitlement, Agg: AggLast, Scope: ScopePlatform,
		Doc: "The configured metric retention window.",
	},
	{
		Name: MeterMetricSamples, Label: "Metric samples ingested", Unit: UnitSamples,
		Kind: KindDiagnostic, Agg: AggSum, Scope: ScopePlatform,
		Doc: "Metric samples written to the time-series store. Diagnostic: on-premises ingestion is not metered for money.",
	},
	{
		Name: MeterMetricSeries, Label: "Active metric series", Unit: UnitSeries,
		Kind: KindDiagnostic, Agg: AggPeak, Scope: ScopePlatform,
		Doc: "Distinct metric series active in the hour, at the day's peak. The cardinality number, not a volume.",
	},
	{
		Name: MeterLogRecords, Label: "Log records accepted", Unit: UnitRecords,
		Kind: KindDiagnostic, Agg: AggSum, Scope: ScopePlatform,
		Doc: "Log records that reached the log store AFTER the pipeline's processors ran — what was kept, not what arrived.",
	},
	{
		Name: MeterFlowRecords, Label: "Flow records accepted", Unit: UnitRecords,
		Kind: KindDiagnostic, Agg: AggSum, Scope: ScopePlatform,
		Doc: "Flow records that reached the flow store after processing.",
	},
	{
		Name: MeterTraceSpans, Label: "Trace spans accepted", Unit: UnitRecords,
		Kind: KindDiagnostic, Agg: AggSum, Scope: ScopePlatform,
		Doc: "Trace spans that reached the trace store after processing.",
	},
	{
		Name: MeterDEMChecks, Label: "Experience checks run", Unit: UnitChecks,
		Kind: KindDiagnostic, Agg: AggSum, Scope: ScopeAny,
		Doc: "Synthetic experience checks executed for this tenant's targets.",
	},
	{
		Name: MeterAITokens, Label: "AI tokens (estimated)", Unit: UnitTokens,
		Kind: KindDiagnostic, Agg: AggPeak, Scope: ScopeAny,
		Doc: "Provider tokens charged against this tenant's daily AI budget. A coarse estimate kept for a spend ceiling, not an accounting figure, and it counts input and output together.",
	},
	{
		Name: MeterAITokensInput, Label: "AI tokens in", Unit: UnitTokens,
		Kind: KindDiagnostic, Agg: AggSum, Scope: ScopeTenant,
		Doc: "Provider tokens sent to a hosted model.",
	},
	{
		Name: MeterAITokensOutput, Label: "AI tokens out", Unit: UnitTokens,
		Kind: KindDiagnostic, Agg: AggSum, Scope: ScopeTenant,
		Doc: "Provider tokens returned by a hosted model.",
	},
	{
		Name: MeterProcessorInput, Label: "Pipeline records in", Unit: UnitRecords,
		Kind: KindDiagnostic, Agg: AggSum, Scope: ScopePlatform,
		Doc: "Records entering the telemetry pipeline, before the processors run.",
	},
	{
		Name: MeterProcessorOutput, Label: "Pipeline records out", Unit: UnitRecords,
		Kind: KindDiagnostic, Agg: AggSum, Scope: ScopePlatform,
		Doc: "Records leaving the telemetry pipeline into a store, after the processors run.",
	},
	{
		Name: MeterProcessorRatio, Label: "Pipeline out/in ratio", Unit: UnitRatio,
		Kind: KindDiagnostic, Agg: AggLast, Scope: ScopePlatform,
		Doc: "Records out divided by records in. Below 1 means filtering and sampling are removing volume — a cost saving, never a charge.",
	},
}

// byName is the vocabulary lookup, built once.
var byName = func() map[string]Descriptor {
	m := make(map[string]Descriptor, len(meters))
	for _, d := range meters {
		m[d.Name] = d
	}
	return m
}()

// Meters returns the vocabulary in report order.
func Meters() []Descriptor { return append([]Descriptor(nil), meters...) }

// MetersFor returns the meters that belong on a row of the given scope.
func MetersFor(s Scope) []Descriptor {
	out := make([]Descriptor, 0, len(meters))
	for _, d := range meters {
		if d.Scope == s {
			out = append(out, d)
		}
	}
	return out
}

// Lookup returns a meter's declaration.
func Lookup(name string) (Descriptor, bool) {
	d, ok := byName[name]
	return d, ok
}

// ValidMeter reports whether name is in the closed vocabulary.
func ValidMeter(name string) bool {
	_, ok := byName[name]
	return ok
}

// MeterNames returns the vocabulary's names in report order.
func MeterNames() []string {
	out := make([]string, 0, len(meters))
	for _, d := range meters {
		out = append(out, d.Name)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Day keys
// ─────────────────────────────────────────────────────────────────────────────

// DayFormat is the UTC day key. One installation, one clock, one format —
// every record, every query parameter and every report boundary uses it.
const DayFormat = "2006-01-02"

// ValidDay reports whether s is a well-formed UTC day key.
func ValidDay(s string) bool {
	if len(s) != len(DayFormat) {
		return false
	}
	for i, c := range s {
		switch i {
		case 4, 7:
			if c != '-' {
				return false
			}
		default:
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// NormaliseTenant lowercases and trims a tenant key. The installation key
// (ScopeInstallation) survives unchanged, because it is the empty string.
func NormaliseTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// sortedMeterNames returns the keys of m in vocabulary order, with any name
// outside the vocabulary last in byte order. Used so a record's meters render
// in one stable sequence everywhere.
func sortedMeterNames[T any](m map[string]T) []string {
	rank := make(map[string]int, len(meters))
	for i, d := range meters {
		rank[d.Name] = i
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, oki := rank[out[i]]
		rj, okj := rank[out[j]]
		switch {
		case oki && okj:
			return ri < rj
		case oki:
			return true
		case okj:
			return false
		}
		return out[i] < out[j]
	})
	return out
}

// errUnknownMeter is the refusal for a reading outside the vocabulary.
func errUnknownMeter(name string) error {
	return fmt.Errorf("metering: %q is not a meter in the closed vocabulary", name)
}
