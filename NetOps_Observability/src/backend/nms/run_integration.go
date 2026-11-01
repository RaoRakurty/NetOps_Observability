// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"errors"
	"fmt"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/wireless"
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
	// Streams is the per-stream outcome, in the order the streams were
	// configured — one entry for every stream of the cycle, including the
	// ones the cycle's deadline never reached (skipped_deadline). It is what
	// makes a half-working integration visible: before it, one failed stream
	// marked the whole run "error" and a dead stream hid behind live ones.
	Streams []StreamResult
}

// StreamResult is one stream's outcome within a poll cycle (persisted in
// connector_run_history.streams, migration 0064).
type StreamResult struct {
	Stream string `json:"stream"`
	// Status is one of the closed poll-result set (PollResults): ok, error,
	// auth_failed, unreachable, timeout, circuit_open, skipped_deadline.
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	Payloads   int    `json:"payloads"`
	DurationMS int64  `json:"durationMs"`
}

// maxStreamErrorLen bounds the error text a stream result carries (a hostile
// or broken controller must not grow a run-history row without limit).
const maxStreamErrorLen = 512

func boundedErrorText(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > maxStreamErrorLen {
		s = s[:maxStreamErrorLen] + "…"
	}
	return s
}

// RunPollSession executes one poll cycle for an integration — pure
// orchestration over the injected connector + Doer + checkpoint store, fully
// testable with an httptest server — with a caller-held session cache: a
// still-valid cached Session skips the login round-trip (a scheduler polling
// every 30-60s would otherwise log in on every cycle — controllers rate-limit
// and audit logins, so steady-state polls must reuse the token until it
// expires). It returns the session that ended the cycle so the caller can
// cache it; the per-stream 401 re-auth stays the safety net for tokens the
// controller invalidates early. A zero cached Session (or an expired one)
// authenticates afresh.
//
// A login failure is returned wrapped in ErrAuthFailed. A ctx that ends
// mid-cycle (the runtime's per-integration deadline) stops the cycle at the
// next stream boundary: the streams it never reached are reported
// skipped_deadline and are not polled.
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
			return res, Session{}, fmt.Errorf("%w: %w", ErrAuthFailed, err)
		}
	}

	// A controller inventory snapshot is COMPLETE only when an inventory
	// stream was polled and every one of its payloads transformed cleanly this
	// cycle. Only a complete snapshot may replace what is stored — a partial
	// list must never prune devices the controller still has.
	invSeen, invFailed := false, false
	for _, stream := range cfg.Streams {
		if ctx.Err() != nil {
			// The cycle's deadline (or shutdown) ended before this stream: it
			// is reported, never silently dropped, and the controller is not
			// called. Its checkpoint is untouched, so the next cycle resumes it.
			res.Streams = append(res.Streams, StreamResult{Stream: stream, Status: ResultSkippedDeadline})
			continue
		}
		streamStart := time.Now()
		sr := StreamResult{Stream: stream}
		cp, _ := cps.Load(ctx, cfg.Tenant, cfg.IntegrationID, stream) // best-effort: a checkpoint read error restarts the stream from the top
		in := PollInput{
			Base: cfg.BaseURL, Stream: stream, Session: sess, Checkpoint: cp,
			Backfill: cfg.Backfill, Do: do, Params: cfg.Creds.Extra,
		}
		raws, next, perr := poller.Poll(ctx, in)
		// One re-auth retry on 401 (token expired mid-cycle or a cached session
		// the controller invalidated early).
		if errors.Is(perr, ErrUnauthorized) {
			fresh, aerr := conn.Auth().Authenticate(ctx, cfg.BaseURL, cfg.Creds, do)
			if aerr == nil {
				sess = fresh
				in.Session = sess
				raws, next, perr = poller.Poll(ctx, in)
			} else {
				perr = fmt.Errorf("%w: re-login after 401: %w", ErrAuthFailed, aerr)
			}
		}
		if perr != nil {
			res.Errors[stream] = perr
			sr.Status, _ = classifyPollError(perr)
			sr.Error = boundedErrorText(perr)
			sr.DurationMS = time.Since(streamStart).Milliseconds()
			res.Streams = append(res.Streams, sr)
			continue
		}
		sr.Payloads = len(raws)
		streamHadDevices, streamFailed := false, false
		var firstTransformErr error
		for _, raw := range raws {
			var batch Batch
			var terr error
			if st, ok := conn.Transformer().(StreamTransformer); ok {
				batch, terr = st.TransformStream(cfg.Tenant, cfg.IntegrationID, stream, raw)
			} else {
				batch, terr = conn.Transformer().Transform(cfg.Tenant, cfg.IntegrationID, raw)
			}
			if terr != nil {
				res.Errors[stream] = terr
				streamFailed = true
				if firstTransformErr == nil {
					firstTransformErr = terr
				}
				continue
			}
			if batch.Devices != nil {
				streamHadDevices = true
			}
			routed := pipe.Route(batch)
			res.Routed.MetricLines = append(res.Routed.MetricLines, routed.MetricLines...)
			res.Routed.Events = append(res.Routed.Events, routed.Events...)
			res.Routed.States = append(res.Routed.States, routed.States...)
			res.Routed.StateChanges = append(res.Routed.StateChanges, routed.StateChanges...)
			if routed.Devices != nil {
				res.Routed.Devices = append(res.Routed.Devices, routed.Devices...)
			}
			if routed.Wireless != nil {
				if res.Routed.Wireless == nil {
					res.Routed.Wireless = &wireless.Inventory{}
				}
				res.Routed.Wireless.Merge(routed.Wireless)
			}
		}
		if streamHadDevices {
			invSeen = true
			invFailed = invFailed || streamFailed
		}
		// A payload the transformer rejected is the controller answering with
		// something we cannot read: the stream is "error" (not a transport
		// class), even when its other payloads landed.
		sr.Status = ResultOK
		if firstTransformErr != nil {
			sr.Status = ResultError
			sr.Error = boundedErrorText(firstTransformErr)
		}
		res.Checkpoints[stream] = next
		if err := cps.Save(ctx, cfg.Tenant, cfg.IntegrationID, stream, next); err != nil {
			// The next poll re-fetches from the old checkpoint (idempotent
			// ingest), but a persistently failing store must not be silent.
			applog.Warn("nms", "checkpoint not persisted", map[string]any{
				"integration": cfg.IntegrationID, "stream": stream, "error": err.Error()})
		}
		sr.DurationMS = time.Since(streamStart).Milliseconds()
		res.Streams = append(res.Streams, sr)
	}
	res.Routed.DevicesComplete = invSeen && !invFailed
	return res, sess, nil
}
