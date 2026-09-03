package pipedebug

import (
	"strings"
	"testing"
	"time"
)

// ── redaction ───────────────────────────────────────────────────────────────

func TestRedactionReusesTheSharedDeviceOutputPass(t *testing.T) {
	cases := map[string]string{
		"snmp-server community pubS3cret RO":            "pubS3cret",
		"username admin password Sup3rSecret":           "Sup3rSecret",
		"enable secret 5 $1$abc$xyz":                    "$1$abc$xyz",
		"ip ospf message-digest-key 1 md5 ospfKey123":   "ospfKey123",
		"crypto isakmp key preSharedThing address 1.2.": "preSharedThing",
	}
	for in, secret := range cases {
		got := RedactString(in)
		if strings.Contains(got, secret) {
			t.Errorf("RedactString(%q) leaked %q: %q", in, secret, got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("RedactString(%q) did not mark the redaction: %q", in, got)
		}
	}
}

// The debugger captures HTTP-shaped container logs, which device output never
// contains — so it adds this one class on top of the shared pass.
func TestBearerAndTokenValuesAreStripped(t *testing.T) {
	cases := []struct{ in, secret string }{
		{`{"header":"Authorization: Bearer eyJhbGci.PAYLOAD.sig"}`, "eyJhbGci.PAYLOAD.sig"},
		{"GET /x?access_token=abc123def&y=1", "abc123def"},
		{"x-api-key: sk-live-9999", "sk-live-9999"},
		{"Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
	}
	for _, c := range cases {
		got := RedactString(c.in)
		if strings.Contains(got, c.secret) {
			t.Errorf("RedactString(%q) leaked %q: %q", c.in, c.secret, got)
		}
	}
}

func TestRedactFieldsRecursesAndDoesNotMutateTheInput(t *testing.T) {
	in := map[string]any{
		"msg":    "snmp-server community leakMe RO",
		"nested": map[string]any{"cmd": "username u password leakMe2"},
		"list":   []any{"enable secret leakMe3"},
		"strs":   []string{"pre-shared-key leakMe4"},
		"count":  42,
		"tenant": "t_keepme",
	}
	out := RedactFields(in)
	if in["msg"] != "snmp-server community leakMe RO" {
		t.Error("RedactFields mutated its input")
	}
	flat := flatten(out)
	for _, secret := range []string{"leakMe ", "leakMe2", "leakMe3", "leakMe4"} {
		if strings.Contains(flat, secret) {
			t.Errorf("RedactFields leaked %q: %s", secret, flat)
		}
	}
	if out["count"] != 42 {
		t.Error("a numeric leaf was rewritten — redaction must not corrupt evidence")
	}
	if !strings.Contains(flat, "t_keepme") {
		t.Error("the tenant id was redacted; design §5 keeps tenant ids for support")
	}
}

func flatten(v any) string {
	switch t := v.(type) {
	case map[string]any:
		var b strings.Builder
		for k, val := range t {
			b.WriteString(k + "=" + flatten(val) + " ")
		}
		return b.String()
	case []any:
		var b strings.Builder
		for _, e := range t {
			b.WriteString(flatten(e) + " ")
		}
		return b.String()
	case []string:
		return strings.Join(t, " ")
	default:
		return strings.TrimSpace(strings.Join([]string{}, "") + toStr(t))
	}
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// ── the API's marker ring ───────────────────────────────────────────────────

func TestMarkerIsFoundInTheMessageOrAField(t *testing.T) {
	m := "01j9abcdefghjkmnpqrstvwxyz"
	if got := MarkerIn("probe cx_debug="+m+" done", nil); got != m {
		t.Errorf("marker not found in a message: %q", got)
	}
	if got := MarkerIn("nothing here", map[string]any{"marker": strings.ToUpper(m)}); got != m {
		t.Errorf("marker not found (and normalised) in a field: %q", got)
	}
	if got := MarkerIn("nothing", map[string]any{"path": "/api/debug/stage/api?marker=" + m}); got != "" {
		t.Errorf("a bare marker in an unrelated field must not be picked up without the cx_debug= tag: %q", got)
	}
	if got := MarkerIn("cx_debug=tooshort", nil); got != "" {
		t.Errorf("a malformed marker was accepted: %q", got)
	}
	if got := MarkerIn("an ordinary log line", nil); got != "" {
		t.Errorf("an untagged line produced a marker: %q", got)
	}
}

// §9: a debug facility must not be the memory leak that takes the API down.
func TestRingIsBoundedGloballyAndPerMarker(t *testing.T) {
	r := NewRing()
	m := "01j9abcdefghjkmnpqrstvwxyz"
	for i := 0; i < ringPerMarker*3; i++ {
		r.Append(m, RingLine{Msg: "line"})
	}
	if got := len(r.Lines(m)); got > ringPerMarker {
		t.Errorf("per-marker bound broken: %d lines retained, cap %d", got, ringPerMarker)
	}
	if r.Len() > RingCapacity {
		t.Errorf("global bound broken: %d lines, cap %d", r.Len(), RingCapacity)
	}
}

func TestRingBoundsTheNumberOfMarkersAndKeepsAcceptingNewOnes(t *testing.T) {
	r := NewRing()
	base := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	var last string
	for i := 0; i < ringMaxMarkers*2; i++ {
		last = NewMarker(base.Add(time.Duration(i) * time.Millisecond))
		r.Append(last, RingLine{Msg: "x"})
	}
	if len(r.Lines(last)) == 0 {
		t.Error("the newest trace's line was evicted — a full ring must drop the OLDEST marker, not refuse the new one")
	}
	if r.Len() > RingCapacity {
		t.Errorf("global bound broken after marker eviction: %d", r.Len())
	}
}

func TestRingRedactsOnTheWayIn(t *testing.T) {
	r := NewRing()
	m := "01j9abcdefghjkmnpqrstvwxyz"
	r.Append(m, RingLine{Msg: "snmp-server community ringLeak RO",
		Fields: map[string]any{"auth": "Authorization: Bearer ringTok"}})
	lines := r.Lines(m)
	if len(lines) != 1 {
		t.Fatalf("want 1 line, got %d", len(lines))
	}
	if strings.Contains(lines[0].Msg, "ringLeak") {
		t.Error("the ring retained an unredacted secret in memory")
	}
	if s, _ := lines[0].Fields["auth"].(string); strings.Contains(s, "ringTok") {
		t.Error("the ring retained an unredacted bearer token in memory")
	}
}

func TestRingIgnoresAnInvalidMarkerAndANilReceiver(t *testing.T) {
	var nilRing *Ring
	nilRing.Append("01j9abcdefghjkmnpqrstvwxyz", RingLine{Msg: "x"}) // must not panic
	if nilRing.Lines("01j9abcdefghjkmnpqrstvwxyz") != nil || nilRing.Len() != 0 {
		t.Error("a nil ring must behave as empty")
	}
	r := NewRing()
	r.Append("not-a-marker", RingLine{Msg: "x"})
	if r.Len() != 0 {
		t.Error("the ring retained a line under an invalid marker")
	}
}
