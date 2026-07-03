package nms

import (
	"context"
	"errors"
	"time"
)

// run_integration.go — the poll-cycle driver. Given a connector + its config +
// resolved credentials, it authenticates, polls each configured stream through
// the rate-limited/retried Doer, transforms and routes the results, and returns
// the class-routed output plus the advanced checkpoints. Re-authenticates once
// on a 401. This is the unit the scheduler calls per integration per tick.

// IntegrationConfig is the per-run configuration (resolved from PG + Vault).
type IntegrationConfig struct {
	Tenant        string
	IntegrationID string
	Vendor        string
	BaseURL       string
	Streams       []string
	Backfill      time.Duration
	Creds         Credentials
}

// RunResult is one poll cycle's output.
type RunResult struct {
	Routed      Routed
	Checkpoints map[string]Checkpoint // stream → advanced checkpoint
	Errors      map[string]error      // stream → error (partial success allowed)
}

// RunPoll executes one poll cycle for an integration. Pure orchestration over
// the injected connector + Doer + checkpoint store — fully testable with an
// httptest server.
func RunPoll(ctx context.Context, conn Connector, cfg IntegrationConfig, do Doer, cps CheckpointStore, pipe *Pipeline) (RunResult, error) {
	res, _, err := RunPollSession(ctx, conn, cfg, do, cps, pipe, Session{})
	return res, err
}

// RunPollSession is RunPoll with a caller-held session cache: a still-valid
// cached Session skips the login round-trip (a scheduler polling every 30-60s
// would otherwise log in on every cycle — controllers rate-limit and audit
// logins, so steady-state polls must reuse the token until it expires). It
// returns the session that ended the cycle so the caller can cache it; the
// per-stream 401 re-auth stays the safety net for tokens the controller
// invalidates early. A zero cached Session (or an expired one) authenticates
// exactly like RunPoll.
func RunPollSession(ctx context.Context, conn Connector, cfg IntegrationConfig, do Doer, cps CheckpointStore, pipe *Pipeline, cached Session) (RunResult, Session, error) {
	res := RunResult{Checkpoints: map[string]Checkpoint{}, Errors: map[string]error{}}
	poller := conn.Poller()
	if poller == nil {
		return res, Session{}, errors.New("connector is webhook-only (no poller)")
	}

	// A zero Session has a nil Header; Valid() alone can't reject it because a
	// zero ExpiresAt legitimately means "non-expiring" (static API key).
	sess := cached
	if sess.Header == nil || !sess.Valid(time.Now().UTC()) {
		var err error
		if sess, err = conn.Auth().Authenticate(ctx, cfg.BaseURL, cfg.Creds, do); err != nil {
			return res, Session{}, err
		}
	}

	for _, stream := range cfg.Streams {
		cp, _ := cps.Load(ctx, cfg.Tenant, cfg.IntegrationID, stream)
		in := PollInput{
			Base: cfg.BaseURL, Stream: stream, Session: sess, Checkpoint: cp,
			Backfill: cfg.Backfill, Do: do, Params: cfg.Creds.Extra,
		}
		raws, next, perr := poller.Poll(ctx, in)
		// One re-auth retry on 401 (token expired mid-cycle or a cached session
		// the controller invalidated early).
		if errors.Is(perr, ErrUnauthorized) {
			if fresh, aerr := conn.Auth().Authenticate(ctx, cfg.BaseURL, cfg.Creds, do); aerr == nil {
				sess = fresh
				in.Session = sess
				raws, next, perr = poller.Poll(ctx, in)
			}
		}
		if perr != nil {
			res.Errors[stream] = perr
			continue
		}
		for _, raw := range raws {
			batch, terr := conn.Transformer().Transform(cfg.Tenant, cfg.IntegrationID, raw)
			if terr != nil {
				res.Errors[stream] = terr
				continue
			}
			routed := pipe.Route(batch)
			res.Routed.MetricLines = append(res.Routed.MetricLines, routed.MetricLines...)
			res.Routed.Events = append(res.Routed.Events, routed.Events...)
			res.Routed.States = append(res.Routed.States, routed.States...)
			res.Routed.StateChanges = append(res.Routed.StateChanges, routed.StateChanges...)
		}
		res.Checkpoints[stream] = next
		_ = cps.Save(ctx, cfg.Tenant, cfg.IntegrationID, stream, next)
	}
	return res, sess, nil
}
