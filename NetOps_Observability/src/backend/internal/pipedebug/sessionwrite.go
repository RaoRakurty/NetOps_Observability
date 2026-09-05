package pipedebug

// sessionwrite.go — the api's own session writer.
//
// WHY THE API WRITES SESSIONS AT ALL. The design's §3 output is a DIRECTORY,
// one log file per module, and the host-side CLI writes it for the traces it
// starts. A trace started from the GUI has no host-side process, so without
// this file it would leave nothing behind: no timeline.json, no summary.txt, no
// per-module evidence to reopen tomorrow, nothing to bundle for support. The
// session routes (sessions.go) would then serve an index that is always empty.
//
// WHAT IT CAN AND CANNOT WRITE, stated in the files themselves. The api sees
// the SERVER-side stages (bus, the three stores, correlation, api) and the two
// hybrid ones it can answer without a request. It cannot see `docker logs` or
// attach a Vector tap — those are the CLI's, on the host — so the ingress,
// parser-Vector-half and router files get the honest one-line NOT-OBSERVABLE
// record naming the CLI command that CAN collect them. An empty file, or a
// missing one, would read as "nothing happened at this hop" (§10).
//
// FAILURE POLICY. A session that cannot be written must never break the trace:
// the evidence the caller is polling for is already in memory and served by
// GET /api/debug/trace/{marker}. A write failure is LOGGED into the trace's own
// ring (so it surfaces in the api stage) and dropped.

import (
	"fmt"
	"strings"
	"time"
)

// persistSpec is a decided-in-the-handler intent to write a session directory.
// It is built where the principal is (the handler), never inside the follow
// goroutine, so the actor recorded in the manifest is the authenticated caller
// and not whatever the goroutine could reach.
type persistSpec struct {
	ID   string
	Root string
	// Started is the time the ID was derived from. It travels with the spec so
	// the writer names the directory from the SAME instant the receipt promised
	// — re-reading the clock in the follow goroutine would, once an hour, put a
	// session in `…1100Z-trace-…` after telling the caller `…1059Z-trace-…`.
	Started time.Time
	Actor   string
	Flags   map[string]string
}

// persistSpecFor decides whether a trace writes a session, and under what id.
// It returns nil (with a reason) when persistence was asked for but cannot be
// honoured, so the receipt can say so instead of promising a directory that
// will never exist.
func (a *API) persistSpecFor(want bool, p Principal, kind Kind, device, tenant, marker string, now time.Time, passive bool) (*persistSpec, string) {
	if !want {
		return nil, ""
	}
	root := strings.TrimSpace(a.deps.SessionRoot)
	if root == "" {
		return nil, "this API build has no debug session root configured, so nothing was written to disk — the trace is still followed and pollable, and the host-side `correlix-debug trace` writes its own session"
	}
	return &persistSpec{
		ID:      SessionDirName(now, "trace", marker),
		Root:    root,
		Started: now,
		Actor:   p.Subject,
		Flags: map[string]string{
			"kind": string(kind), "device": device, "tenant": tenant,
			"passive": fmt.Sprint(passive), "source": "gui",
		},
	}, ""
}

// hostOnlyReason explains, per stage, why the api could not observe it. It is
// the text that lands in the module file, and it names the command that CAN
// collect the stage rather than merely reporting a gap.
func hostOnlyReason(st Stage) string {
	switch st {
	case StageIngress:
		return "collected on the HOST, not by the api: the ingress collector's own debug lines come from `docker logs` on the syslog-ng / trap / flow receiver. Run `correlix-debug trace` on the host to capture this stage"
	case StageParser:
		return "the api holds only the GO collectors' decision lines for this marker; the Vector half of the parser stage comes from a `vector tap` on the aggregator, which is a host-side subscription. Run `correlix-debug trace` on the host for the full parser path"
	case StageRouter:
		return "collected on the HOST: the router lane is observed with a `vector tap` on vector-router, a live subscription the api does not hold. Run `correlix-debug trace` on the host to capture this stage"
	case StageUI:
		return "the UI-query stage is answered on demand (GET /api/debug/stage/ui?marker=…) because it must run under the caller's own request scope; the async follow that wrote this session had no request"
	default:
		return "no collector ran for this stage in this session"
	}
}

// writeSession persists a finished follow as a §3 session directory.
//
// It is called from the follow goroutine, after the entries have settled, and
// returns the directory it wrote (or an error, which the caller records rather
// than propagates).
func (a *API) writeSession(spec *persistSpec, st TraceStatus, entries []Entry) (string, error) {
	if spec == nil {
		return "", nil
	}
	now := a.deps.now()
	man := Manifest{
		Marker: st.Marker, Kind: st.Kind, Device: st.Device, Tenant: st.Tenant,
		Actor: spec.Actor, Flags: spec.Flags, Tool: "correlix-debug (api)",
	}
	// NewSession derives the directory name from the time it is given and the
	// marker. The handler already published that name in the receipt, so the
	// writer uses the instant the receipt was derived from — never a fresh
	// reading of the clock.
	sess, err := NewSession(spec.Root, "trace", st.Marker, spec.Started, man)
	if err != nil {
		return "", err
	}
	if st.Passive {
		sess.Warn("passive follow: nothing was injected; the stages below observed REAL traffic")
	}
	sess.Warn("started from the GUI: this session holds the api-side stages only — see each host-only module file for the CLI command that collects it")

	for _, e := range entries {
		if err := sess.Header(e.Stage, e.Module, "api-side stage query (GET /api/debug/stage/"+string(e.Stage)+")", 0); err != nil {
			_ = sess.Close(now)
			return "", err
		}
		fields := map[string]any{
			"verdict": string(e.Verdict),
			"query":   e.Query,
		}
		if e.Reason != "" {
			fields["reason"] = e.Reason
		}
		if !e.FirstSeen.IsZero() {
			fields["t_first_seen"] = e.FirstSeen.UTC().Format(time.RFC3339Nano)
		}
		if e.LatencyFromPrevMS != nil {
			fields["latency_from_prev_ms"] = *e.LatencyFromPrevMS
		}
		for k, v := range e.Detail {
			fields["detail_"+k] = v
		}
		level := "info"
		if e.Verdict == VerdictNotObservable {
			level = "warn"
		}
		if err := sess.Line(e.Stage, level, "stage "+string(e.Stage)+": "+string(e.Verdict), fields); err != nil {
			_ = sess.Close(now)
			return "", err
		}
	}
	// Every remaining module file gets the honest one-liner, never an empty
	// file (§3) — and the reason names the CLI verb that CAN collect it.
	if err := sess.EnsureAllModules(hostOnlyReason); err != nil {
		_ = sess.Close(now)
		return "", err
	}

	tl := BuildTimeline(st.Marker, st.Kind, st.Device, st.Tenant, st.Started, entries)
	if err := sess.WriteTimeline(tl); err != nil {
		_ = sess.Close(now)
		return "", err
	}
	if err := sess.WriteSummary(RenderSummary(tl, sess.Dir())); err != nil {
		_ = sess.Close(now)
		return "", err
	}
	if err := sess.Close(now); err != nil {
		return "", err
	}
	return sess.Dir(), nil
}

// persistFinished writes the session and records the outcome where a reader
// will see it: the trace's own ring, which is the api stage's evidence.
func (a *API) persistFinished(spec *persistSpec, st TraceStatus, entries []Entry) {
	if spec == nil {
		return
	}
	dir, err := a.writeSession(spec, st, entries)
	if err != nil {
		a.ring(st.Marker, "trace", "the debug session directory could not be written — the trace itself is unaffected and still pollable", map[string]any{
			"session": spec.ID, "err": err.Error(),
		})
		return
	}
	a.ring(st.Marker, "trace", "debug session written", map[string]any{"session": spec.ID, "dir": dir})
}
