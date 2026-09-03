package notify

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/models"
)

// captured is one request the fake ntfy server received.
type captured struct {
	path     string
	title    string
	priority string
	tags     string
	auth     string
	body     string
}

func fakeNtfy(t *testing.T, status int) (*httptest.Server, *[]captured) {
	t.Helper()
	var got []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, captured{
			path:     r.URL.Path,
			title:    r.Header.Get("Title"),
			priority: r.Header.Get("Priority"),
			tags:     r.Header.Get("Tags"),
			auth:     r.Header.Get("Authorization"),
			body:     string(b),
		})
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

// Push is the composed-message path used by the platform self-health route. It
// must ride the SAME client and the SAME request shape as Send.
func TestNtfyPushComposesTheRequest(t *testing.T) {
	srv, got := fakeNtfy(t, http.StatusOK)
	n := NewNtfy(srv.URL, "host-mon-topic", "tok")
	err := n.Push(NtfyPush{
		Title:    "[PAGE] CorrelationConsumerDead: consumer group empty",
		Body:     "detail",
		Priority: NtfyPriorityHigh,
		Tags:     "rotating_light",
	})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(*got) != 1 {
		t.Fatalf("requests = %d, want 1", len(*got))
	}
	c := (*got)[0]
	if c.path != "/host-mon-topic" {
		t.Errorf("path = %q", c.path)
	}
	if c.title != "[PAGE] CorrelationConsumerDead: consumer group empty" {
		t.Errorf("Title = %q", c.title)
	}
	if c.priority != NtfyPriorityHigh {
		t.Errorf("Priority = %q, want %q", c.priority, NtfyPriorityHigh)
	}
	if c.tags != "rotating_light" || c.body != "detail" || c.auth != "Bearer tok" {
		t.Errorf("unexpected request: %+v", c)
	}
}

// A title is an HTTP HEADER. CR/LF in it would inject headers; ntfy also
// requires ASCII. Both are neutralised at the one place that writes the wire.
func TestNtfyPushSanitizesTheHeaderText(t *testing.T) {
	srv, got := fakeNtfy(t, http.StatusOK)
	n := NewNtfy(srv.URL, "topic", "")
	if err := n.Push(NtfyPush{
		Title: "boom\r\nX-Injected: yes\ttab énd",
		Body:  "b",
	}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	c := (*got)[0]
	if strings.ContainsAny(c.title, "\r\n") {
		t.Fatalf("CR/LF survived into a header value: %q", c.title)
	}
	if c.title != "boom X-Injected: yes tab nd" {
		t.Errorf("Title = %q", c.title)
	}
}

// An unknown priority must fall back to DEFAULT, never to max: a composition
// bug must not be able to escalate itself onto someone's phone.
func TestNtfyPushRejectsAnUnknownPriority(t *testing.T) {
	srv, got := fakeNtfy(t, http.StatusOK)
	n := NewNtfy(srv.URL, "topic", "")
	for _, p := range []string{"", "9", "urgent", "-1"} {
		if err := n.Push(NtfyPush{Body: "b", Priority: p}); err != nil {
			t.Fatalf("Push(%q): %v", p, err)
		}
	}
	for i, c := range *got {
		if c.priority != NtfyPriorityDefault {
			t.Errorf("request %d: Priority = %q, want %q", i, c.priority, NtfyPriorityDefault)
		}
	}
}

// An empty body would make ntfy render the TOPIC as the message text — putting
// a credential on the lock screen.
func TestNtfyPushNeverSendsAnEmptyBody(t *testing.T) {
	srv, got := fakeNtfy(t, http.StatusOK)
	if err := NewNtfy(srv.URL, "topic", "").Push(NtfyPush{Title: "t"}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if b := (*got)[0].body; b == "" || strings.Contains(b, "topic") {
		t.Fatalf("body = %q — must be non-empty and must not be the topic", b)
	}
}

// Send (the product/tenant path) keeps its severity ladder and now rides Push.
func TestNtfySendMapsSeverityToPriority(t *testing.T) {
	srv, got := fakeNtfy(t, http.StatusOK)
	n := NewNtfy(srv.URL, "topic", "")
	for _, tc := range []struct{ sev, want string }{
		{"critical", NtfyPriorityMax},
		{"error", NtfyPriorityHigh},
		{"warning", NtfyPriorityDefault},
		{"info", NtfyPriorityLow},
	} {
		if err := n.Send(models.Alert{Rule: "LinkDown", Severity: tc.sev, Summary: "eth0 down"}); err != nil {
			t.Fatalf("Send(%s): %v", tc.sev, err)
		}
		c := (*got)[len(*got)-1]
		if c.priority != tc.want {
			t.Errorf("severity %s: Priority = %q, want %q", tc.sev, c.priority, tc.want)
		}
		if !strings.Contains(c.title, "LinkDown") || !strings.Contains(c.body, "eth0 down") {
			t.Errorf("severity %s: unexpected request %+v", tc.sev, c)
		}
	}
}

func TestNtfyUnconfiguredTopicIsAnError(t *testing.T) {
	if err := NewNtfy("https://ntfy.sh", "", "").Send(models.Alert{Severity: "critical"}); err == nil {
		t.Fatal("expected an error when no topic is configured")
	}
}

func TestNtfyNonSuccessStatusIsReported(t *testing.T) {
	srv, _ := fakeNtfy(t, http.StatusForbidden)
	err := NewNtfy(srv.URL, "topic", "").Push(NtfyPush{Body: "b"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want a 403", err)
	}
}

// A TOPIC IS A CREDENTIAL: anyone holding it can read every alert published to
// it and publish forgeries. A transport error's default rendering embeds the
// request URL — and therefore the topic — and the caller LOGS that error.
func TestNtfyTransportErrorNeverLeaksTheTopic(t *testing.T) {
	srv, _ := fakeNtfy(t, http.StatusOK)
	addr := srv.URL
	srv.Close() // nothing is listening now: the next request fails at connect
	err := NewNtfy(addr, "super-secret-topic", "").Push(NtfyPush{Body: "b"})
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "super-secret-topic") {
		t.Fatalf("the topic leaked into an error that gets logged: %v", err)
	}
}
