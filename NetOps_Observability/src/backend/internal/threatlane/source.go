package threatlane

import "context"

// LogSource yields the normalized device-log events to run the device-log
// detections over. It is the narrow input seam between this engine and the live
// syslog pipeline: the engine never reaches for logs itself, it asks this
// interface. Returning an error means the source is UNAVAILABLE (transport/store
// failure) — the engine FAILS CLOSED on that (propagates, never a false clean
// result). A healthy source with nothing to report returns an empty slice + nil
// error, which is the honest "evaluated, no events" outcome.
//
// The window is bounded by the caller (via ctx deadline and whatever the concrete
// source scopes to); this interface takes no unbounded "all history" mode.
//
// TODO(deploy): wire a real LogSource backed by the OpenSearch/ClickHouse syslog
// index, tenant-scoped, over a bounded time window. Until then MemLogSource is
// the only implementation and is used by tests and any dormant, flag-off call
// site — the lane stays fully decoupled from the running stack.
type LogSource interface {
	// LogEvents returns the normalized log events for the assessment window.
	// A non-nil error is a source failure (fail-closed); a nil error with an
	// empty slice is a clean, empty read.
	LogEvents(ctx context.Context) ([]LogEvent, error)
}

// FlowSource yields the normalized flow records to run the flow-behavioral
// detections over. Same seam contract as LogSource: error → unavailable (fail
// closed), empty slice + nil → clean empty read. The concrete source is
// responsible for bounding the window and tenant-scoping the rows.
//
// TODO(deploy): wire a real FlowSource backed by the netops.flows ClickHouse
// table, tenant-scoped, over a bounded window. MemFlowSource is the stub.
type FlowSource interface {
	// Flows returns the normalized flow records for the assessment window.
	Flows(ctx context.Context) ([]FlowRecord, error)
}

// MemLogSource is an in-memory LogSource for tests and dormant call sites. A nil
// slice is a clean, empty read (not an error). It copies its input on read so a
// caller cannot mutate the backing store through the returned slice.
type MemLogSource []LogEvent

// LogEvents implements LogSource.
func (m MemLogSource) LogEvents(_ context.Context) ([]LogEvent, error) {
	if len(m) == 0 {
		return nil, nil
	}
	out := make([]LogEvent, len(m))
	copy(out, m)
	return out, nil
}

// MemFlowSource is an in-memory FlowSource for tests and dormant call sites.
type MemFlowSource []FlowRecord

// Flows implements FlowSource.
func (m MemFlowSource) Flows(_ context.Context) ([]FlowRecord, error) {
	if len(m) == 0 {
		return nil, nil
	}
	out := make([]FlowRecord, len(m))
	copy(out, m)
	return out, nil
}

// errSource is a source that always fails — the fail-closed test fixture. It is
// exported-for-tests-only via the constructor below to keep the surface honest.
type errSource struct{ err error }

func (e errSource) LogEvents(context.Context) ([]LogEvent, error) { return nil, e.err }
func (e errSource) Flows(context.Context) ([]FlowRecord, error)   { return nil, e.err }

// FailingLogSource returns a LogSource that always fails with err — used to
// exercise the fail-closed path in tests and any deliberate degraded-mode wiring.
func FailingLogSource(err error) LogSource { return errSource{err: err} }

// FailingFlowSource returns a FlowSource that always fails with err.
func FailingFlowSource(err error) FlowSource { return errSource{err: err} }
