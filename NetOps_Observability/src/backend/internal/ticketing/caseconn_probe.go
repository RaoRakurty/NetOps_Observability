// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_probe.go — the read-only CONNECTION TEST behind the Test button.
//
// WHY A PROBE AND NOT A CASE. Storing a credential proves nothing: the shape can
// be right and the credential dead, and the first the operator would hear of it
// is a failed escalation on the worst night of the quarter. So the settings form
// can ask the vendor one question — and the ONLY questions allowed here are the
// ones that read:
//
//	Jira        GET /rest/api/2/myself           (who am I)
//	ServiceNow  GET the incident table, limit 1  (can I read, am I authorised)
//	email       SMTP connect + EHLO + STARTTLS   (is the relay there, does it
//	                                              offer the TLS we require)
//	Juniper     the API's own /getlov list       (does the token mint, is the
//	                                              onboarding live)
//
// NOTHING HERE CREATES, UPDATES, ATTACHES TO OR CLOSES A CASE. A connector with
// no read-only question to ask says so — Cisco CXD holds no stored credential at
// all (its token is per-case), Smart Bonding publishes no read endpoint we could
// reach without an SR, and a portal-only vendor has no API by definition — and
// "unsupported" is a first-class outcome, not a failure.
//
// EVERY PROBE IS BOUNDED (§9): one caller-supplied timeout wraps the whole
// attempt, and a probe that runs past it is reported as timed out rather than
// left to hang a browser. The outcome is a NAMED value, never a raw error
// string, and the note is truncated and carries no credential (§8).

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// ProbeOutcome is the closed set of answers a connection test can give. The UI
// renders one sentence per value, so a new outcome is a deliberate act.
type ProbeOutcome string

const (
	// ProbeOK — the vendor answered and accepted the stored credential.
	ProbeOK ProbeOutcome = "ok"
	// ProbeNotConfigured — nothing to test yet: the connector is off, or its
	// settings are incomplete. A state, not a failure.
	ProbeNotConfigured ProbeOutcome = "not_configured"
	// ProbeRefused — the vendor answered and said no (bad credential, no
	// permission, entitlement). Retrying identical settings cannot fix it.
	ProbeRefused ProbeOutcome = "refused"
	// ProbeUnreachable — we never got an answer (DNS, connect, TLS, 5xx).
	ProbeUnreachable ProbeOutcome = "unreachable"
	// ProbeTimedOut — the attempt ran past its bound.
	ProbeTimedOut ProbeOutcome = "timed_out"
	// ProbeUnsupported — this path publishes no read-only check.
	ProbeUnsupported ProbeOutcome = "unsupported"
)

// DefaultProbeTimeout bounds one connection test. Long enough for a slow ITSM
// instance behind a corporate proxy, short enough that the form answers.
const DefaultProbeTimeout = 12 * time.Second

// ProbeResult is what the Test button renders.
type ProbeResult struct {
	ConnectorID string       `json:"connector_id"`
	Outcome     ProbeOutcome `json:"outcome"`
	// Note is the operator-facing reason. It is the vendor's own words where we
	// have them, truncated, and never a credential.
	Note      string    `json:"note"`
	CheckedAt time.Time `json:"checked_at"`
	ElapsedMS int64     `json:"elapsed_ms"`
}

// ConnectorProber is implemented by a connector that can prove its configuration
// WITHOUT writing anything at the vendor. A connector that cannot answers
// ProbeUnsupported by simply not implementing it — the type system is the
// declaration, so a probe cannot be claimed and then quietly not performed.
type ConnectorProber interface {
	Probe(ctx context.Context, cfg TACConnectorConfig) error
}

// probeUnsupportedReason names, per connector, WHY there is no read-only check.
// A blank answer would read as an outage; each of these is a published fact.
func probeUnsupportedReason(id string) string {
	switch id {
	case "cisco-cxd":
		return "CXD stores no credential: the SR number and its upload token are per-case and are supplied when you attach."
	case "cisco-smart-bonding":
		return "Cisco publishes no read-only Smart Bonding endpoint; the first real exchange is a case."
	}
	if strings.HasPrefix(id, "portal-") {
		return "This vendor publishes no API, so there is nothing to connect to. Correlix prepares the text and the bundle for the portal."
	}
	return "This path publishes no read-only check."
}

// ProbeConnector runs c's read-only probe under a bounded timeout and names the
// outcome. It never returns an error: every way a test can end is one of the
// outcomes above, because "the test itself failed" is not a thing an operator
// can act on.
func ProbeConnector(ctx context.Context, c CaseConnector, cfg TACConnectorConfig, timeout time.Duration, now func() time.Time) ProbeResult {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	res := ProbeResult{CheckedAt: now()}
	if c == nil {
		res.Outcome, res.Note = ProbeUnsupported, "No connector answers to that id."
		return res
	}
	res.ConnectorID = c.Name()
	prober, ok := c.(ConnectorProber)
	if !ok {
		res.Outcome, res.Note = ProbeUnsupported, probeUnsupportedReason(c.Name())
		return res
	}
	// Validation first: an incomplete configuration is a state the operator can
	// fix on the form in front of them, and asking the vendor about it would
	// only turn a clear answer into a network error.
	if err := c.ValidateConfig(cfg); err != nil {
		res.Outcome, res.Note = classifyProbeError(err)
		res.ElapsedMS = elapsedMS(now, res.CheckedAt)
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := prober.Probe(ctx, cfg)
	res.ElapsedMS = elapsedMS(now, res.CheckedAt)
	switch {
	case err == nil:
		res.Outcome, res.Note = ProbeOK, "The vendor answered and accepted the stored credential."
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		res.Outcome = ProbeTimedOut
		res.Note = fmt.Sprintf("No answer within %s.", timeout)
	default:
		res.Outcome, res.Note = classifyProbeError(err)
	}
	return res
}

func elapsedMS(now func() time.Time, from time.Time) int64 {
	d := now().Sub(from)
	if d < 0 {
		return 0
	}
	return d.Milliseconds()
}

// classifyProbeError maps a connector's error onto a named outcome. It reads the
// TYPED errors this package already defines rather than matching on message
// text, so a reworded vendor error cannot silently change an outcome.
func classifyProbeError(err error) (ProbeOutcome, string) {
	var entitlement EntitlementError
	var permanent PermanentDeliveryError
	var rate RateLimitedError
	var netErr net.Error
	switch {
	case errors.Is(err, ErrNotConfigured):
		return ProbeNotConfigured, "Nothing to test yet: bring the credentials above and save."
	case errors.Is(err, ErrNotOnboarded):
		return ProbeNotConfigured, Truncate(err.Error(), 400)
	case errors.Is(err, ErrUnsupported):
		return ProbeUnsupported, Truncate(err.Error(), 400)
	case errors.As(err, &entitlement):
		return ProbeRefused, Truncate(entitlement.Error(), 400)
	case errors.As(err, &permanent):
		return ProbeRefused, Truncate(permanent.Error(), 400)
	case errors.As(err, &rate):
		return ProbeRefused, "The vendor is rate-limiting us. " + Truncate(rate.Error(), 200)
	case errors.As(err, &netErr) && netErr.Timeout():
		return ProbeTimedOut, "No answer before the timeout."
	default:
		return ProbeUnreachable, Truncate(err.Error(), 400)
	}
}

// ── the probes themselves ───────────────────────────────────────────────────

// Probe asks ServiceNow to read one incident row: it proves the instance is
// reachable AND that the stored credential may read the table the attach path
// writes to. It creates nothing.
func (c *ServiceNowCaseConnector) Probe(ctx context.Context, cfg TACConnectorConfig) error {
	return c.adapter.HealthCheck(ctx, cfg.ITSM)
}

// Probe asks Jira who we are (/rest/api/2/myself). It is the cheapest call that
// proves both reachability and authentication, and it writes nothing.
func (c *JiraCaseConnector) Probe(ctx context.Context, cfg TACConnectorConfig) error {
	return c.adapter.HealthCheck(ctx, cfg.ITSM)
}

// Probe fetches the API's own list of legal priority values. It is a READ that
// exercises the whole chain — token mint, appId, customerSourceID — and it is
// the same call the case form already makes before a human sees it.
func (c *JuniperConnector) Probe(ctx context.Context, cfg TACConnectorConfig) error {
	_, err := c.FetchSeverityValues(ctx, cfg)
	return err
}

// Probe opens ONE bounded SMTP conversation and stops at the greeting: connect,
// EHLO, the TLS this transport requires, and QUIT. No MAIL, no RCPT, no DATA —
// nothing that could put a message in front of a vendor's case robot.
func (c *EmailCaseConnector) Probe(ctx context.Context, cfg TACConnectorConfig) error {
	probe := c.probeFn
	if probe == nil {
		probe = probeSMTP
	}
	return probe(ctx, cfg.Email)
}

// probeSMTP runs the OPENING of the conversation sendSMTP runs, and stops.
//
// It deliberately repeats sendSMTP's dial/greet/TLS sequence rather than calling
// it with an empty message: sendSMTP's next step is MAIL FROM, and a probe that
// could reach MAIL FROM is one refactor away from mailing a vendor. The two
// share the constants and the TLS RULE — a relay that offers no STARTTLS is
// refused here exactly as it is there, because a test that passes against a
// plaintext relay would certify a path the sender will not use.
func probeSMTP(ctx context.Context, cfg EmailConnectorConfig) error {
	host, _, err := net.SplitHostPort(cfg.Host)
	if err != nil {
		return PermanentDeliveryError{errors.New("smtp: host must be host:port")}
	}
	deadline := time.Now().Add(emailSMTPDeadline)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	d := &net.Dialer{Timeout: emailSMTPDialTimeout}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	if cfg.TLSOnConnect {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsCfg}).DialContext(ctx, "tcp", cfg.Host)
	} else {
		conn, err = d.DialContext(ctx, "tcp", cfg.Host)
	}
	if err != nil {
		return errors.New("smtp: the relay did not accept a connection")
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close() // best-effort: nothing actionable on a close failure
		return fmt.Errorf("smtp: set deadline: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close() // best-effort: nothing actionable on a close failure
		return errors.New("smtp: the relay sent no usable greeting")
	}
	defer func() { _ = c.Close() }() // Quit is attempted below; a double close is harmless
	if !cfg.TLSOnConnect {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return PermanentDeliveryError{errors.New("smtp: the relay offers no STARTTLS and a TAC bundle is never sent in the clear")}
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return errors.New("smtp: STARTTLS was refused by the relay")
		}
	}
	if cfg.User != "" {
		// Credentials are stored, so prove the relay will take them. The
		// exchange itself is AUTH only — it never reaches a message.
		if ok, _ := c.Extension("AUTH"); !ok {
			return PermanentDeliveryError{errors.New("smtp: a user is configured but the relay advertises no AUTH")}
		}
		if err := c.Auth(smtp.PlainAuth("", cfg.User, cfg.Password, host)); err != nil {
			// The reply can quote the server but never the password.
			return PermanentDeliveryError{errors.New("smtp: the relay rejected the stored credentials")}
		}
	}
	return c.Quit()
}

var (
	_ ConnectorProber = (*ServiceNowCaseConnector)(nil)
	_ ConnectorProber = (*JiraCaseConnector)(nil)
	_ ConnectorProber = (*JuniperConnector)(nil)
	_ ConnectorProber = (*EmailCaseConnector)(nil)
)
