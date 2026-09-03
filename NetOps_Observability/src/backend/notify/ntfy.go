package notify

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
}

func NewNtfy(server, topic, token string) *Ntfy {
	if server == "" {
		server = "https://ntfy.sh"
	}
	return &Ntfy{
		server: strings.TrimRight(server, "/"),
		topic:  topic,
		token:  token,
		client: safehttp.Client(10 * time.Second),
	}
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
}

func (n *Ntfy) Name() string { return "ntfy" }

func (n *Ntfy) Send(a models.Alert) error {
	return n.Push(NtfyPush{
		Title:    fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), a.Rule),
		Body:     smsBody(a),
		Priority: ntfyPriority(a.Severity),
		Tags:     "rotating_light",
	})
}

// Push publishes a composed message to the configured topic.
func (n *Ntfy) Push(p NtfyPush) error {
	if n.topic == "" {
		return errors.New("ntfy: no topic configured")
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
		return fmt.Errorf("ntfy: status %d", resp.StatusCode)
	}
	return nil
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
