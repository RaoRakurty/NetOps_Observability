package notify

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"netops/backend/models"
	"netops/backend/safehttp"
)

// Ntfy publishes alerts to an ntfy.sh topic — free push notifications to phone
// and desktop. A no-cost alternative to Twilio for testing critical-alert pushes
// (Twilio is metered/paid; ntfy is free for public topics). Same wiring: gate it
// to "critical" via a SeverityGate to get phone pushes only for critical alerts.
//
// API: POST https://<server>/<topic> with the message as the body; Title,
// Priority (1-5) and Tags as headers. Public topics need no auth; protected
// topics take a bearer token.
//
// TWO CALLERS, ONE CLIENT. Send() is the product/tenant path (a models.Alert
// composed by the platform's notification channels). Push() is the same request
// with an already-composed title/body/priority, used by the PLATFORM
// self-health route in internal/alertwebhook, which applies the alert *tier*
// rather than the severity ladder. Send delegates to Push, so there is exactly
// one HTTP client, one request shape and one place that sanitizes what goes on
// the wire.
type Ntfy struct {
	server string
	topic  string
	token  string
	client *http.Client

	// budget is the SHARED per-server-host token bucket (pushbudget.go). nil =
	// no guard. The PRODUCT channel takes its token here, inside Push, because
	// this is the only place that knows a request is about to be made; the
	// HOST route deliberately attaches NO budget to its sender and takes the
	// token at ENQUEUE instead (internal/alertwebhook/hostroute.go), so its
	// refusal is decided and counted synchronously with the alert that caused
	// it. Both take from the SAME bucket when they name the same server.
	budget *PushBudget
	// pager records that the operator configured this channel AS A PAGER
	// (min_severity = critical). Only a critical alert on a pager channel may
	// spend the budget's page reserve — see Pages.
	pager bool
}

func NewNtfy(server, topic, token string) *Ntfy {
	if server == "" {
		server = DefaultNtfyServer
	}
	return &Ntfy{
		server: strings.TrimRight(server, "/"),
		topic:  topic,
		token:  token,
		client: safehttp.Client(10 * time.Second),
	}
}

// WithBudget attaches the shared per-server push budget. Returns the receiver
// so it composes with the constructor at the wiring site.
func (n *Ntfy) WithBudget(b *PushBudget) *Ntfy {
	n.budget = b
	return n
}

// WithPagePolicy records the channel's configured minimum severity so Pages can
// tell a PAGER from a FEED. Only `critical` makes this channel a pager; every
// other threshold (warning, info, unset) leaves it a feed whose alerts may
// never spend the page reserve. Deliberately narrow — see pushbudget.go.
func (n *Ntfy) WithPagePolicy(minSeverity string) *Ntfy {
	n.pager = strings.EqualFold(strings.TrimSpace(minSeverity), "critical")
	return n
}

// Server is the configured push server (normalized to its host by
// PushServerKey when it is used as a budget/metric key).
func (n *Ntfy) Server() string { return n.server }

// Pages implements PageClassifier: true when this alert is a PAGE on the
// product side — severity `critical` on a channel configured as a pager. This
// single definition decides BOTH whether the alert may spend the shared page
// reserve and whether it earns the one bounded retry against a 429; nothing
// else widens it.
func (n *Ntfy) Pages(a models.Alert) bool {
	return n.pager && strings.EqualFold(strings.TrimSpace(a.Severity), "critical")
}

// ntfy's priority ladder (1 min … 5 max). Exported so a caller composing its own
// push does not re-derive the ladder from a magic string.
const (
	NtfyPriorityMin     = "1"
	NtfyPriorityLow     = "2"
	NtfyPriorityDefault = "3"
	NtfyPriorityHigh    = "4"
	NtfyPriorityMax     = "5"
)

// Wire bounds (§9: all IO bounded). ntfy itself caps a message at 4 KiB and a
// header at far less; truncating here keeps a pathological annotation from
// turning into a rejected request the operator never sees.
const (
	maxNtfyTitle = 200
	maxNtfyTags  = 120
	maxNtfyBody  = 4096
)

// NtfyPush is ONE already-composed push. Every field is treated as untrusted
// text (§3): the title and tags ride HTTP headers, so they are sanitized to
// printable ASCII before they can inject a header, and the priority is
// validated against the ladder above rather than forwarded verbatim.
type NtfyPush struct {
	Title    string
	Body     string
	Priority string
	Tags     string
	// Page marks a push that may spend the shared budget's PAGE RESERVE. Set
	// by the composer, never by anything on the wire: on the product side it is
	// Ntfy.Pages, on the host route it is the server-controlled `tier` label.
	Page bool
}

func (n *Ntfy) Name() string { return "ntfy" }

func (n *Ntfy) Send(a models.Alert) error {
	return n.Push(NtfyPush{
		Title:    fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), a.Rule),
		Body:     smsBody(a),
		Priority: ntfyPriority(a.Severity),
		Tags:     "rotating_light",
		Page:     n.Pages(a),
	})
}

// Push publishes a composed message to the configured topic.
//
// The SHARED budget (pushbudget.go) is taken FIRST, before any request is
// built: the whole point of the guard is that the request is never made, and a
// refusal must not look like a server error. A nil budget always allows.
func (n *Ntfy) Push(p NtfyPush) error {
	if n.topic == "" {
		return errors.New("ntfy: no topic configured")
	}
	if !n.budget.Take(p.Page) {
		return ErrPushBudgetExhausted
	}
	body := strings.TrimSpace(p.Body)
	if len(body) > maxNtfyBody {
		body = body[:maxNtfyBody]
	}
	if body == "" {
		// ntfy renders an empty body as the topic name — which would put the
		// topic (a credential) on the operator's lock screen.
		body = "(no detail)"
	}
	req, err := http.NewRequest(http.MethodPost, n.server+"/"+n.topic, strings.NewReader(body))
	if err != nil {
		return errors.New("ntfy: could not build the request")
	}
	if title := ntfyHeaderText(p.Title, maxNtfyTitle); title != "" {
		req.Header.Set("Title", title)
	}
	req.Header.Set("Priority", ntfyValidPriority(p.Priority))
	if tags := ntfyHeaderText(p.Tags, maxNtfyTags); tags != "" {
		req.Header.Set("Tags", tags)
	}
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy: request failed: %s", n.scrub(err))
	}
	defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on close failure
	if resp.StatusCode >= 300 {
		return &NtfyStatusError{Status: resp.StatusCode, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	}
	return nil
}

// NtfyStatusError is a non-2xx answer from the ntfy server, carried as a TYPE
// rather than a formatted string so a caller with a retry policy can tell
// "slow down" from "you are wrong" without parsing the message.
//
// This exists because of a live failure (2026-09-03 ~04:00 UTC): ntfy.sh's free
// public server rate-limits per topic/IP, the platform self-health route was
// pushing every chronic warning individually, and the resulting `status 429`
// storm meant a real PAGE could be refused behind a warning's budget. The
// route's answer is a warning digest plus a retry with backoff, and both need
// the status code and the server's own Retry-After, not a string.
//
// Error() keeps the exact wording the previous fmt.Errorf produced, so log
// lines and any operator grep for "ntfy: status 429" still match — and, like
// every other error out of this file, it NEVER contains the topic (§8: a topic
// is a credential).
type NtfyStatusError struct {
	// Status is the HTTP status the server answered with.
	Status int
	// RetryAfter is the server's own Retry-After, normalized to a duration.
	// Zero means the server did not say — the caller picks its own backoff.
	RetryAfter time.Duration
}

func (e *NtfyStatusError) Error() string { return fmt.Sprintf("ntfy: status %d", e.Status) }

// RateLimited reports a refusal for BUDGET reasons rather than a fault. It is
// the one failure a caller must not answer by pushing harder.
func (e *NtfyStatusError) RateLimited() bool { return e.Status == http.StatusTooManyRequests }

// Retryable reports whether re-sending the SAME message can succeed. 429 and
// 5xx are transient (budget / server-side); every other 4xx is a statement
// about the request itself (bad token, unknown topic, oversize header) and
// retrying it only burns the rate budget the 429 case needs.
func (e *NtfyStatusError) Retryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// maxRetryAfter bounds what a server can make us wait. Retry-After is remote
// input (§3: never trust upstream), and an hour-long value from a hostile or
// misconfigured server would park a page-tier push indefinitely.
const maxRetryAfter = 2 * time.Minute

// parseRetryAfter reads both RFC7231 spellings — delta-seconds and HTTP-date —
// and clamps the result. An unparseable or negative value yields 0, which the
// caller reads as "the server did not say".
func parseRetryAfter(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		if secs <= 0 {
			return 0
		}
		return capRetryAfter(time.Duration(secs) * time.Second)
	}
	if t, err := http.ParseTime(raw); err == nil {
		if d := time.Until(t); d > 0 {
			return capRetryAfter(d)
		}
	}
	return 0
}

func capRetryAfter(d time.Duration) time.Duration {
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

// scrub renders a transport error WITHOUT the request URL. A *url.Error's
// Error() embeds the URL, and the URL contains the topic — knowing an ntfy
// topic is enough to read every alert published to it and to publish forgeries,
// so a topic is a credential and must never reach a log line (§8: sanitize all
// logs). Callers log what this returns.
func (n *Ntfy) scrub(err error) string {
	msg := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		msg = ue.Op + ": " + ue.Err.Error()
	}
	if n.topic != "" {
		msg = strings.ReplaceAll(msg, n.topic, "<topic>")
	}
	return msg
}

// ntfyHeaderText makes untrusted text safe to carry in an HTTP header: CR/LF
// (header injection) and every other control or non-ASCII byte collapse to a
// space, runs of spaces collapse to one, and the result is bounded. ntfy wants
// RFC2047 encoding for non-ASCII titles; we do not send any.
func ntfyHeaderText(s string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			r = ' '
		}
		if r == ' ' {
			if space || b.Len() == 0 {
				continue
			}
			space = true
		} else {
			space = false
		}
		b.WriteRune(r)
		if b.Len() >= max {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// ntfyValidPriority forwards only a value on the ladder. An unknown or empty
// priority becomes the default — never max, so a composition bug cannot escalate
// itself onto someone's phone at 3am.
func ntfyValidPriority(p string) string {
	switch strings.TrimSpace(p) {
	case NtfyPriorityMin, NtfyPriorityLow, NtfyPriorityDefault, NtfyPriorityHigh, NtfyPriorityMax:
		return strings.TrimSpace(p)
	default:
		return NtfyPriorityDefault
	}
}

func ntfyPriority(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return NtfyPriorityMax
	case "error":
		return NtfyPriorityHigh
	case "warning":
		return NtfyPriorityDefault
	default:
		return NtfyPriorityLow
	}
}
