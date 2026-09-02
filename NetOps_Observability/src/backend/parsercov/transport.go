package parsercov

// transport.go — the two small constructors package backend wires into Deps,
// plus the one response-read cap every path shares.
//
// They live HERE, not in main, so the registration hunk stays three lines and
// so the bounds are unit-tested next to the code that relies on them. Neither
// reads the environment or dials anything on its own: the client and the
// configured strings are handed in.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// EnvMaxLines is the environment variable bounding one mining run's scan.
const EnvMaxLines = "PARSERCOV_MAX_LINES"

// EnvReplicaURLs optionally names the correlation replicas explicitly, as a
// comma-separated list of base URLs.
//
// WHY IT EXISTS. Parser counters are PER PROCESS: each `--scale correlation=N`
// replica owns a disjoint slice of tenants and keeps its own totals. The
// service name round-robins, so one scrape samples one replica. Naming the
// replicas is the only way to sum them — and it is configuration, not
// discovery, because the endpoints are TLS-verified BY NAME on the hardened
// deployment (CORRELATION_URL=https://correlation:8443): addressing a replica
// by its resolved IP would fail certificate verification, so DNS fan-out is not
// a safe substitute and is deliberately not attempted.
//
// Unset is the correct configuration for the default single-replica stack: the
// list falls back to CORRELATION_URL, and the reported counters are that
// process's, which is all there is.
const EnvReplicaURLs = "CORRELATION_REPLICA_URLS"

// maxReplicaResponseBytes bounds one /healthz or /metrics read. The response
// size is chosen by the peer, not by us (audit F-27): an unbounded io.ReadAll
// of a peer's body is an OOM in the process that also serves the API.
const maxReplicaResponseBytes = 8 << 20

// ReplicaList resolves the replica base URLs from configuration. `explicit` is
// the raw EnvReplicaURLs value (comma-separated, may be empty); `base` is
// CORRELATION_URL. Entries are trimmed; empties are dropped; an empty result
// means nothing is configured and the stats route answers 503 rather than
// scraping a guessed endpoint.
func ReplicaList(base, explicit string) []string {
	out := make([]string, 0, 4)
	for _, part := range strings.Split(explicit, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, strings.TrimRight(p, "/"))
		}
	}
	if len(out) > 0 {
		return out
	}
	if b := strings.TrimSpace(base); b != "" {
		return []string{strings.TrimRight(b, "/")}
	}
	return nil
}

// NewFetcher builds Deps.Fetch over an http.Client (package backend passes
// backendHTTPClient, which carries the internal-mTLS transport). The returned
// function bounds the response read and refuses a non-2xx status rather than
// handing back an error page as if it were data.
func NewFetcher(client *http.Client) func(ctx context.Context, url string) ([]byte, error) {
	return func(ctx context.Context, url string) ([]byte, error) {
		if client == nil {
			return nil, errors.New("no HTTP client configured")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json, text/plain")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := readLimited(resp.Body, maxReplicaResponseBytes)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("correlation replica status %d", resp.StatusCode)
		}
		return body, nil
	}
}

// readCapped reads an OpenSearch response under the shared cap.
func readCapped(resp *http.Response) ([]byte, error) {
	return readLimited(resp.Body, maxOSResponse)
}

// readLimited reads at most `max` bytes and treats hitting the cap exactly as a
// FAILURE, not a truncation: a silently clipped JSON body decodes to a
// plausible-looking partial answer, which is worse than an error.
func readLimited(r io.Reader, max int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, max))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) >= max {
		return nil, fmt.Errorf("response exceeded %d bytes — refusing a truncated body", max)
	}
	return body, nil
}
