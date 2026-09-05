package ticketing

// attach_common.go — small helpers shared by the attach transports.

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// retryAfterOr reads a provider's Retry-After (delta-seconds form) and falls
// back to def. Values outside (0, 1h] are ignored: a hostile or broken header
// must not park an interactive call.
func retryAfterOr(resp *http.Response, def time.Duration) time.Duration {
	if resp == nil {
		return def
	}
	if n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && n > 0 && n <= 3600 {
		return time.Duration(n) * time.Second
	}
	return def
}

// sanitizeFileName reduces an attachment name to a safe, portable form: no path
// separators, no control characters, bounded length. Every transport composes
// the name into a URL, a MIME header or an object key, so it is normalized once
// here rather than trusted at each boundary (§3: validate at every boundary).
func sanitizeFileName(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f:
			// drop control characters (header injection, log forging)
		case r == '"' || r == '\r' || r == '\n':
			// drop MIME-header metacharacters
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	out = strings.TrimLeft(out, ".")
	if out == "" {
		return "bundle.zip"
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}
