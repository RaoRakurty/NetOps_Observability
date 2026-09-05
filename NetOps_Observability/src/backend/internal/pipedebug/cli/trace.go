package cli

// trace.go — the `trace` verb.
//
// SHAPE OF A TRACE, and why it is this shape:
//
//	1. open the session directory (one log file per module, §3);
//	2. START THE VECTOR TAPS FIRST. A tap is a LIVE subscription — it sees only
//	   events that cross the transform after it attaches — so attaching after
//	   injection would guarantee an empty ingress and parser stage and report a
//	   healthy pipeline as broken;
//	3. inject ONE marked synthetic record through the API (the API is inside the
//	   compose network and owns the ingress sockets; the CLI is on the host);
//	4. poll the server-side follow while the taps run;
//	5. join both halves into one ordered timeline and write summary.txt.
//
// PRIVACY (§3a). The taps see EVERY tenant's traffic crossing those transforms.
// Only lines carrying THIS trace's marker are written to disk; everything else
// is counted and dropped. A debug session must not become an unfiltered copy of
// the fleet's telemetry sitting in a directory.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/pipedebug"
)

// TraceOptions is the parsed `trace` invocation.
type TraceOptions struct {
	Kind    pipedebug.Kind
	Device  string
	Tenant  string
	TTL     time.Duration
	Passive bool
	Since   time.Duration
	Path    string // gNMI path filter for a passive follow
	Root    string // data/debug
	Project string // compose project
}

// tapResult is one host-side stage's collected evidence.
type tapResult struct {
	stage     pipedebug.Stage
	service   string
	component string
	matched   []string
	scanned   int
	err       error
}

// RunTrace executes the verb and returns the process exit code.
func RunTrace(ctx context.Context, opts TraceOptions, cl *Client, coll *Collector, out io.Writer) (int, error) {
	now := time.Now().UTC()
	sess, err := pipedebug.NewSession(opts.Root, "trace", "", now, pipedebug.Manifest{
		Kind: opts.Kind, Device: opts.Device, Tenant: opts.Tenant,
		Actor: cl.User(), APIBase: cl.Base(),
		Flags: map[string]string{
			"kind": string(opts.Kind), "device": opts.Device, "tenant": opts.Tenant,
			"ttl": opts.TTL.String(), "passive": fmt.Sprint(opts.Passive),
			"since": opts.Since.String(), "path": opts.Path,
		},
	})
	if err != nil {
		return 2, err
	}
	fmt.Fprintf(out, "session: %s\n", sess.Dir())

	if opts.Passive {
		// PASSIVE NEVER INJECTS. The whole branch is separate — it does not
		// share a line of code with the injection path below — because the one
		// unacceptable outcome is a `--passive` run that puts a synthetic
		// record into a customer's pipeline. The api enforces the same split on
		// its side; this is the second lock, not the only one.
		return runPassive(ctx, opts, sess, cl, coll, now, out)
	}

	// 2. Taps first (see the file comment).
	tapWindow := opts.TTL + 5*time.Second
	tapCtx, cancelTaps := context.WithTimeout(ctx, tapWindow+10*time.Second)
	defer cancelTaps()

	var wg sync.WaitGroup
	results := make([]*tapResult, 0, 3)
	untapped := make([]pipedebug.Entry, 0, 2)
	for _, stage := range []pipedebug.Stage{pipedebug.StageIngress, pipedebug.StageParser, pipedebug.StageRouter} {
		service, component, ok := TapComponents(opts.Kind, stage)
		if !ok {
			// NOT a `continue`. A stage with no tap must appear in the timeline
			// with the third verdict and the reason; dropping the row would
			// leave a reader to conclude the hop was fine.
			reason := TapMissingReason(opts.Kind, stage)
			note(sess, sess.NotObservable(stage, reason))
			untapped = append(untapped, pipedebug.Entry{
				Stage: stage, Module: string(stage),
				Verdict: pipedebug.VerdictNotObservable, Reason: reason,
				Query: "(no Vector tap exists for this lane)",
			})
			continue
		}
		res := &tapResult{stage: stage, service: service, component: component}
		results = append(results, res)
		wg.Add(1)
		go func(res *tapResult) {
			defer wg.Done()
			var lines []string
			scanned := 0
			err := coll.VectorTap(tapCtx, res.service, res.component, tapWindow, func(line string) {
				scanned++
				// PRIVACY (§3a): the tap sees EVERY tenant's traffic crossing
				// this transform. Only marked lines are buffered here — and
				// writeTapStage then narrows to THIS trace's marker, which is
				// not yet known when this goroutine starts (the tap must attach
				// BEFORE the record is injected). Everything else is counted
				// and dropped without ever leaving memory.
				if m := markerLine(line); m != "" {
					lines = append(lines, m+"\t"+line)
				}
			})
			res.matched, res.scanned, res.err = lines, scanned, err
		}(res)
	}
	// Give the taps a moment to attach before the record is injected.
	select {
	case <-time.After(1500 * time.Millisecond):
	case <-ctx.Done():
	}

	// 3. Inject.
	receipt, err := cl.StartTrace(ctx, TraceRequest{
		Kind: opts.Kind, Device: opts.Device, Tenant: opts.Tenant, TTL: opts.TTL,
	})
	if err != nil {
		cancelTaps()
		wg.Wait()
		note(sess, sess.EnsureAllModules(func(pipedebug.Stage) string {
			return "the trace never started: " + err.Error()
		}))
		note(sess, sess.Close(time.Now().UTC()))
		return 2, err
	}
	if err := sess.SetMarker(receipt.Marker); err != nil {
		sess.Warn("the API returned a marker this build does not recognise: %v", err)
	}
	fmt.Fprintf(out, "marker : %s (synthetic, tagged %s)\n", receipt.Marker, pipedebug.SyntheticTag)
	if !receipt.Injected {
		fmt.Fprintf(out, "WARNING: injection failed: %s\n", receipt.InjectErr)
	}

	// 4. Poll the server-side follow.
	status := pollTrace(ctx, cl, receipt.Marker, opts.TTL, out)

	// 5. Join.
	cancelTaps()
	wg.Wait()

	entries := make([]pipedebug.Entry, 0, len(pipedebug.Stages))
	entries = append(entries, untapped...)
	for _, res := range results {
		e := writeTapStage(sess, res, receipt.Marker, tapWindow)
		if e.Stage == pipedebug.StageParser {
			e = mergeGoParser(ctx, sess, cl, opts, receipt.Marker, e)
		}
		entries = append(entries, e)
	}
	for _, e := range status.Stages {
		writeServerStage(sess, e)
		entries = append(entries, e)
	}
	entries = append(entries, uiStage(ctx, sess, cl, opts, receipt.Marker, receipt.Tenant))

	timeline := pipedebug.BuildTimeline(receipt.Marker, opts.Kind, opts.Device, receipt.Tenant, now, entries)
	if err := sess.WriteTimeline(timeline); err != nil {
		sess.Warn("writing timeline.json failed: %v", err)
	}
	summary := pipedebug.RenderSummary(timeline, sess.Dir())
	if err := sess.WriteSummary(summary); err != nil {
		sess.Warn("writing summary.txt failed: %v", err)
	}
	if err := sess.EnsureAllModules(nil); err != nil {
		sess.Warn("writing the not-observable placeholders failed: %v", err)
	}
	if err := sess.Close(time.Now().UTC()); err != nil {
		return 2, err
	}
	fmt.Fprint(out, "\n"+summary)
	return timeline.ExitCode(), nil
}

// pollTrace polls the server-side follow until it reports done or the TTL runs
// out, printing progress so a human sees the trace advancing.
func pollTrace(ctx context.Context, cl *Client, marker string, ttl time.Duration, out io.Writer) pipedebug.TraceStatus {
	deadline := time.Now().Add(ttl + 10*time.Second)
	var last pipedebug.TraceStatus
	for time.Now().Before(deadline) {
		st, err := cl.TraceStatus(ctx, marker)
		if err == nil {
			last = st
			if st.Done {
				return st
			}
		}
		select {
		case <-ctx.Done():
			return last
		case <-time.After(2 * time.Second):
		}
		fmt.Fprint(out, ".")
	}
	fmt.Fprintln(out)
	return last
}

// writeTapStage writes one host-side stage's module file and returns its entry.
func writeTapStage(sess *pipedebug.Session, res *tapResult, marker string, window time.Duration) pipedebug.Entry {
	how := fmt.Sprintf("docker exec %s vector tap --outputs-of %s (events filtered to this trace's marker; everything else counted and dropped)", res.service, res.component)
	e := pipedebug.Entry{Stage: res.stage, Module: string(res.stage), Query: how}
	if err := sess.Header(res.stage, string(res.stage), how, window); err != nil {
		e.Verdict = pipedebug.VerdictNotObservable
		e.Reason = "could not open the module log file: " + err.Error()
		return e
	}
	if res.err != nil {
		e.Verdict = pipedebug.VerdictNotObservable
		e.Reason = fmt.Sprintf("the Vector tap on %s/%s failed: %v", res.service, res.component, res.err)
		note(sess, sess.Line(res.stage, "warn", "tap failed", map[string]any{"reason": e.Reason}))
		return e
	}
	// Narrow to THIS trace's marker. The tap goroutine buffered every MARKED
	// line it saw, because the marker is minted by the api and is not yet known
	// when the tap has to attach; a concurrent trace's probe crossing the same
	// transform must not be filed as this one's evidence.
	mine := make([]string, 0, len(res.matched))
	for _, tagged := range res.matched {
		if m, line, ok := strings.Cut(tagged, "\t"); ok && m == marker {
			mine = append(mine, line)
		}
	}
	note(sess, sess.Line(res.stage, "info", "tap finished", map[string]any{
		"scanned": res.scanned, "marked_seen": len(res.matched), "matched": len(mine),
		"note": "only events carrying THIS trace's marker are retained; the rest are counted and dropped without leaving memory",
	}))
	if len(mine) == 0 {
		e.Verdict = pipedebug.VerdictNotSeen
		e.Reason = fmt.Sprintf("the tap saw %d events on %s without this trace's marker", res.scanned, res.component)
		return e
	}
	for _, line := range mine {
		note(sess, sess.Raw(res.stage, "vector-tap:"+res.component, line))
	}
	e.Verdict = pipedebug.VerdictSeen
	e.EvidenceRef = res.stage.LogFile()
	e.FirstSeen = tapTimestamp(mine[0])
	return e
}

// writeServerStage renders one API-supplied stage into its module file.
func writeServerStage(sess *pipedebug.Session, e pipedebug.Entry) {
	how := "GET /api/debug/stage/" + string(e.Stage) + " (the API's own store/bus query)"
	note(sess, sess.Header(e.Stage, string(e.Stage), how, 0))
	note(sess, sess.Line(e.Stage, verdictLevel(e.Verdict), "stage evidence", map[string]any{
		"verdict": string(e.Verdict), "reason": e.Reason,
		"query": e.Query, "evidence_ref": e.EvidenceRef,
	}))
	if e.Detail != nil {
		note(sess, sess.Line(e.Stage, "info", "evidence detail", e.Detail))
	}
}

// uiStage is stage 10: the api runs the query the SPA ITSELF issues for this
// record and reports whether the record came back.
//
// A failure to REACH the api is not a UI verdict, so it lands as
// not_observable with the transport error rather than as "the UI cannot see
// it" — the distinction the whole verdict vocabulary exists for.
func uiStage(ctx context.Context, sess *pipedebug.Session, cl *Client, opts TraceOptions, marker, tenant string) pipedebug.Entry {
	how := "GET /api/debug/stage/ui — the api runs the SPA's own query for this record (contract table: internal/pipedebug/uiquery.go)"
	note(sess, sess.Header(pipedebug.StageUI, string(pipedebug.StageUI), how, 0))
	e, err := cl.Stage(ctx, pipedebug.StageUI, opts.Kind, marker, tenant, opts.Device, opts.Path)
	if err != nil {
		reason := "the UI-query stage could not be fetched from the api: " + err.Error()
		note(sess, sess.Line(pipedebug.StageUI, "warn", "stage unavailable", map[string]any{"reason": reason}))
		return pipedebug.Entry{
			Stage: pipedebug.StageUI, Module: string(pipedebug.StageUI),
			Verdict: pipedebug.VerdictNotObservable, Reason: reason,
		}
	}
	note(sess, sess.Line(pipedebug.StageUI, verdictLevel(e.Verdict), "stage evidence", map[string]any{
		"verdict": string(e.Verdict), "reason": e.Reason, "query": e.Query,
	}))
	if e.Detail != nil {
		note(sess, sess.Line(pipedebug.StageUI, "info", "ui-query contract", e.Detail))
	}
	return e
}

// mergeGoParser folds the GO collectors' decision path into the parser stage.
//
// Stage 2 has two halves — the Vector tap (with the transforms' own
// `cx_parse_trace` decision string) and the in-process Go decoder — and the
// operator reads ONE parser.log. A Go-side miss never DOWNGRADES a tap that saw
// the record: for a syslog probe there is no Go parser at all, so treating its
// silence as evidence would turn every healthy syslog trace into a parser
// failure.
func mergeGoParser(ctx context.Context, sess *pipedebug.Session, cl *Client, opts TraceOptions, marker string, tapped pipedebug.Entry) pipedebug.Entry {
	e, err := cl.Stage(ctx, pipedebug.StageParser, opts.Kind, marker, opts.Tenant, "", "")
	if err != nil {
		note(sess, sess.Line(pipedebug.StageParser, "warn", "the Go-collector decision path could not be fetched", map[string]any{"reason": err.Error()}))
		return tapped
	}
	note(sess, sess.Line(pipedebug.StageParser, verdictLevel(e.Verdict), "go parser decision path", map[string]any{
		"verdict": string(e.Verdict), "reason": e.Reason, "query": e.Query,
	}))
	if e.Detail != nil {
		note(sess, sess.Line(pipedebug.StageParser, "info", "go parser decisions", e.Detail))
	}
	if tapped.Verdict == pipedebug.VerdictSeen {
		return tapped
	}
	if e.Verdict == pipedebug.VerdictSeen {
		return e
	}
	return tapped
}

// note records a session-write failure on the manifest instead of dropping it.
//
// §5 forbids ignored errors, and a blanket `// best-effort:` is the wrong answer
// here: a debug session that could not write its own evidence has to SAY so, or
// the reader is looking at a file that is silently short. The write is still not
// fatal — losing one line must not abort a trace that is mid-flight — so the
// failure lands in manifest.json's warnings, where §10 can see it.
func note(sess *pipedebug.Session, err error) {
	if err != nil {
		sess.Warn("writing a session line failed: %v", err)
	}
}

func verdictLevel(v pipedebug.Verdict) string {
	if v == pipedebug.VerdictSeen {
		return "info"
	}
	return "warn"
}

// markerLine returns the marker a tapped line carries, or "".
func markerLine(line string) string {
	return pipedebug.MarkerIn(line, nil)
}

// tapTimestamp pulls the event timestamp out of a tapped JSON line. An
// undecodable line yields the zero time, which BuildTimeline renders as "no
// latency" rather than a fabricated one.
func tapTimestamp(line string) time.Time {
	var ev map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &ev); err != nil {
		return time.Time{}
	}
	for _, key := range []string{"timestamp", "ts", "@timestamp"} {
		if raw, ok := ev[key].(string); ok {
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
				if t, err := time.Parse(layout, raw); err == nil {
					return t.UTC()
				}
			}
		}
	}
	return time.Time{}
}
