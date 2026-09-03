package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/pipedebug"
)

// ── bundle ──────────────────────────────────────────────────────────────────

func seedSession(t *testing.T, root string, when time.Time, marker string) string {
	t.Helper()
	sess, err := pipedebug.NewSession(root, "trace", "", when, pipedebug.Manifest{Actor: "unit"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.SetMarker(marker); err != nil {
		t.Fatal(err)
	}
	if err := sess.Line(pipedebug.StageAPI, "info", "hello", nil); err != nil {
		t.Fatal(err)
	}
	if err := sess.EnsureAllModules(func(pipedebug.Stage) string { return "not collected in this test" }); err != nil {
		t.Fatal(err)
	}
	if err := sess.WriteSummary("summary"); err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(when); err != nil {
		t.Fatal(err)
	}
	return sess.Dir()
}

// PATH is emptied so LookPath("zstd") fails and the stdlib gzip fallback runs —
// the codec must be REPORTED, never implied by a file name that lies.
func TestBundleFallsBackToGzipAndSaysSo(t *testing.T) {
	t.Setenv("PATH", "")
	root := filepath.Join(t.TempDir(), "debug")
	seedSession(t, root, time.Date(2026, 9, 4, 11, 0, 0, 0, time.UTC), "01j9abcdefghjkmnpqrstvwxyz")

	var out bytes.Buffer
	if code, err := RunBundle(context.Background(), BundleOptions{Last: 1, Root: root}, &out); err != nil || code != 0 {
		t.Fatalf("RunBundle: %v (code %d)", err, code)
	}
	if !strings.Contains(out.String(), "gzip") {
		t.Errorf("the codec was not reported: %s", out.String())
	}
	matches, err := filepath.Glob(filepath.Join(root, "*.tar.gz"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("no .tar.gz produced: %v %v", matches, err)
	}
	if left, _ := filepath.Glob(filepath.Join(root, "*.tar")); len(left) != 0 {
		t.Errorf("the uncompressed tar was left behind: %v", left)
	}
}

func TestBundleCarriesSHA256SUMSThatVerify(t *testing.T) {
	t.Setenv("PATH", "")
	root := filepath.Join(t.TempDir(), "debug")
	seedSession(t, root, time.Date(2026, 9, 4, 11, 0, 0, 0, time.UTC), "01j9abcdefghjkmnpqrstvwxyz")
	var out bytes.Buffer
	if _, err := RunBundle(context.Background(), BundleOptions{Last: 1, Root: root}, &out); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(root, "*.tar.gz"))
	f, err := os.Open(matches[0]) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	members := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		members[h.Name] = data
	}
	sums, ok := members["SHA256SUMS"]
	if !ok {
		t.Fatal("the bundle carries no SHA256SUMS")
	}
	if _, ok := members["BUNDLE-README.txt"]; !ok {
		t.Error("the bundle carries no README naming the redaction pass")
	}
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		want, name, found := strings.Cut(line, "  ")
		if !found {
			t.Fatalf("malformed SHA256SUMS line: %q", line)
		}
		data, ok := members[name]
		if !ok {
			t.Errorf("SHA256SUMS names %q, which is not in the archive", name)
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != want {
			t.Errorf("checksum mismatch for %s", name)
		}
		checked++
	}
	if checked < 12 {
		t.Errorf("only %d members checksummed — a session has 13 files", checked)
	}
	// Every module file of the §3 layout must be in the bundle.
	for _, st := range pipedebug.Stages {
		found := false
		for name := range members {
			if strings.HasSuffix(name, "/"+st.LogFile()) {
				found = true
			}
		}
		if !found {
			t.Errorf("the bundle is missing %s", st.LogFile())
		}
	}
}

func TestBundleLastNPicksTheNewestSessions(t *testing.T) {
	t.Setenv("PATH", "")
	root := filepath.Join(t.TempDir(), "debug")
	seedSession(t, root, time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC), "01j9abcdefghjkmnpqrstvwxyz")
	newest := seedSession(t, root, time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC), "01j9abcdefghjkmnpqrstvwxzz")
	var out bytes.Buffer
	if _, err := RunBundle(context.Background(), BundleOptions{Last: 1, Root: root}, &out); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(root, "*.tar.gz"))
	data, err := os.ReadFile(matches[0]) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	sawNewest := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(h.Name, filepath.Base(newest)+"/") {
			sawNewest = true
		}
	}
	if !sawNewest {
		t.Error("--last 1 did not select the newest session")
	}
}

func TestBundleRefusesAnEmptyRoot(t *testing.T) {
	var out bytes.Buffer
	if _, err := RunBundle(context.Background(), BundleOptions{Last: 1, Root: filepath.Join(t.TempDir(), "nope")}, &out); err == nil {
		t.Error("bundling a nonexistent debug root succeeded")
	}
}

// ── client ──────────────────────────────────────────────────────────────────

func TestLoadEnvCredentialsReadsOnlyWhatItNeeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(strings.Join([]string{
		"# a comment",
		"BASE_PORT=8123",
		"ADMIN_USERNAME=admin",
		"ADMIN_INITIAL_PASSWORD=pw with = signs",
		"JWT_SECRET=should-not-be-read",
		"malformed line",
	}, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	got := LoadEnvCredentials(path)
	if got.Base != "http://localhost:8123" || got.User != "admin" || got.Password != "pw with = signs" {
		t.Errorf("credentials not parsed: %+v", got)
	}
	// A missing file is not an error — the operator may be passing --token.
	if c := LoadEnvCredentials(filepath.Join(dir, "absent")); c.User != "" || c.Base != "" {
		t.Errorf("a missing .env produced credentials: %+v", c)
	}
}

func TestNewClientRefusesWithNoBaseOrNoCredentials(t *testing.T) {
	ctx := context.Background()
	if _, err := NewClient(ctx, Credentials{}, time.Second); err == nil {
		t.Error("a client was built with no API base URL")
	}
	if _, err := NewClient(ctx, Credentials{Base: "http://x"}, time.Second); err == nil {
		t.Error("a client was built with neither a token nor credentials")
	}
}

// A failed login must not echo the response body: it is the one place a
// credential could be reflected into a terminal or a log (§8).
func TestFailedLoginDoesNotEchoTheResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad password: hunter2"}`))
	}))
	defer srv.Close()
	_, err := NewClient(context.Background(), Credentials{Base: srv.URL, User: "admin", Password: "hunter2"}, 5*time.Second)
	if err == nil {
		t.Fatal("a 401 login was accepted")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("the login failure echoed a credential: %v", err)
	}
}

func TestClientSendsTheBearerAndNeverLogsIt(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			_, _ = w.Write([]byte(`{"token":"tok-abc"}`))
		default:
			gotAuth = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`{"marker":"01j9abcdefghjkmnpqrstvwxyz","kind":"syslog","injected":true,"ttl_seconds":60,"synthetic":true}`))
		}
	}))
	defer srv.Close()
	cl, err := NewClient(context.Background(), Credentials{Base: srv.URL, User: "admin", Password: "pw"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if cl.User() != "admin" {
		t.Errorf("User() = %q", cl.User())
	}
	rec, err := cl.StartTrace(context.Background(), pipedebug.KindSyslog, "spine1", "t1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok-abc" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if rec.Marker != "01j9abcdefghjkmnpqrstvwxyz" || !rec.Injected {
		t.Errorf("receipt not decoded: %+v", rec)
	}
	// The token must not be reachable through any exported surface: the Client
	// has no exported field at all, and the two accessors it does expose return
	// the base URL and the username, never the credential.
	rt := reflect.TypeOf(*cl)
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).IsExported() {
			t.Errorf("Client exports field %q — a bearer token must not be reachable or serialisable", rt.Field(i).Name)
		}
	}
	if strings.Contains(cl.Base()+cl.User(), "tok-abc") {
		t.Error("an accessor leaked the bearer token")
	}
}

func TestTraceStatusValidatesTheMarkerBeforeDialling(t *testing.T) {
	cl, err := NewClient(context.Background(), Credentials{Base: "http://127.0.0.1:1", Token: "t"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.TraceStatus(context.Background(), "not-a-marker"); err == nil {
		t.Error("a malformed marker was sent to the API")
	}
}

func TestSetLogLevelClampsTheWindowBeforeSendingIt(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"module":"api","applied":true,"level":"debug"}`))
	}))
	defer srv.Close()
	cl, err := NewClient(context.Background(), Credentials{Base: srv.URL, Token: "t"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.SetLogLevel(context.Background(), pipedebug.ModuleAPI, pipedebug.LevelDebug, 99*time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, _ := body["for_seconds"].(float64); int(got) != int(pipedebug.MaxWindow.Seconds()) {
		t.Errorf("for_seconds = %v, want the %v cap", got, pipedebug.MaxWindow)
	}
}
