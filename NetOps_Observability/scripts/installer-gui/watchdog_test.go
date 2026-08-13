// POST /api/watchdog tests (design §8, privileged op #3): session gate,
// server-side validation mirroring install-watchdog.sh, install-result gating,
// fixed argv assembly (I1), password stdin + zeroing (H3), secret-token
// scrubbing in logs (§8), state flag, failure reporting, single-flight with
// the existing run guard.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const wdAppURL = "https://10.0.0.7:8000"

// setInstalledResult puts the server in the "install succeeded" state the
// watchdog endpoint requires.
func setInstalledResult(s *server) {
	s.st.mu.Lock()
	s.st.result = &Result{Status: "ok", URL: wdAppURL, AdminUser: "admin"}
	s.st.mu.Unlock()
}

func watchdogState(t *testing.T, c *http.Client, url string) bool {
	t.Helper()
	res, err := c.Get(url + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var st struct {
		WatchdogInstalled bool `json:"watchdog_installed"`
	}
	if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	return st.WatchdogInstalled
}

func TestWatchdogSessionGate(t *testing.T) {
	_, ts := newTestServer(t, &fakeRunner{})
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/watchdog",
		strings.NewReader(`{"password":"pw","ntfy_topic":"ops"}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ts.Client().Do(req) // no session cookie, no token
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("watchdog without session: got %d, want 403", res.StatusCode)
	}
}

func TestWatchdogValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // substring the 400 error must contain (field name)
	}{
		{"empty body", `{}`, "password"},
		{"missing password", `{"ntfy_topic":"ops-alerts"}`, "password"},
		{"bad topic chars", `{"password":"pw","ntfy_topic":"bad topic!"}`, "ntfy_topic"},
		{"topic too long", `{"password":"pw","ntfy_topic":"` + strings.Repeat("a", 65) + `"}`, "ntfy_topic"},
		{"bad ntfy_server scheme", `{"password":"pw","ntfy_topic":"ops","ntfy_server":"http://ntfy.example.com/ops"}`, "ntfy_server"},
		{"ntfy_server unsafe chars", `{"password":"pw","ntfy_topic":"ops","ntfy_server":"https://ntfy.example.com/ops?x=1"}`, "ntfy_server"},
		{"ntfy_token too short", `{"password":"pw","ntfy_topic":"ops","ntfy_token":"short"}`, "ntfy_token"},
		{"ntfy_token bad chars", `{"password":"pw","ntfy_topic":"ops","ntfy_token":"bad token!!"}`, "ntfy_token"},
		{"bad email", `{"password":"pw","email":"not-an-email"}`, "email"},
		{"email too long", `{"password":"pw","email":"` + strings.Repeat("a", 250) + `@x.co"}`, "email"},
		{"hc not https", `{"password":"pw","hc_url":"http://hc-ping.com/uuid-1"}`, "hc_url"},
		{"hc no path", `{"password":"pw","hc_url":"https://hc-ping.com"}`, "hc_url"},
		{"hc unsafe chars", `{"password":"pw","hc_url":"https://hc-ping.com/uuid;reboot"}`, "hc_url"},
		{"hc too long", `{"password":"pw","hc_url":"https://hc-ping.com/` + strings.Repeat("a", 200) + `"}`, "hc_url"},
		{"bad webhook_url", `{"password":"pw","webhook_url":"https://hooks.example.com/$(x)"}`, "webhook_url"},
		{"webhook_token bad chars", `{"password":"pw","webhook_url":"https://hooks.example.com/T0/B0","webhook_token":"has spaces!"}`, "webhook_token"},
		{"webhook_token too long", `{"password":"pw","webhook_url":"https://hooks.example.com/T0/B0","webhook_token":"` + strings.Repeat("t", 257) + `"}`, "webhook_token"},
		{"no channel at all", `{"password":"pw"}`, "at least one"},
		{"token only is not a channel", `{"password":"pw","ntfy_token":"tok=12345678"}`, "at least one"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRunner{}
			s, ts := newTestServer(t, fr)
			setInstalledResult(s) // prove these are 400s, not the 409 gate
			c := sessionClient(t, ts)
			res := postJSON(t, c, ts.URL+"/api/watchdog", tc.body, nil)
			defer res.Body.Close()
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("got %d, want 400", res.StatusCode)
			}
			var out struct{ Error string }
			if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.Error, tc.want) {
				t.Fatalf("error %q does not name %q", out.Error, tc.want)
			}
			if fr.calls() != 0 {
				t.Fatal("a rejected request must never spawn sudo")
			}
		})
	}
}

func TestWatchdogRequiresInstallResult(t *testing.T) {
	fr := &fakeRunner{}
	s, ts := newTestServer(t, fr)
	c := sessionClient(t, ts)
	body := `{"password":"pw","ntfy_topic":"ops-alerts"}`

	// No install result at all → 409.
	res := postJSON(t, c, ts.URL+"/api/watchdog", body, nil)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("no result: got %d, want 409", res.StatusCode)
	}
	var out struct{ Error string }
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if !strings.Contains(out.Error, "install first") {
		t.Fatalf("409 body %q should say to install first", out.Error)
	}

	// A FAILED install result is not good enough either.
	s.st.mu.Lock()
	s.st.result = &Result{Status: "fail", URL: wdAppURL}
	s.st.mu.Unlock()
	res = postJSON(t, c, ts.URL+"/api/watchdog", body, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("failed result: got %d, want 409", res.StatusCode)
	}
	if fr.calls() != 0 {
		t.Fatal("watchdog must not run without a successful install result")
	}
}

func TestWatchdogArgvAssembly(t *testing.T) {
	base := []string{"sudo", "-k", "-S", "-p", "", "bash", "./scripts/install-watchdog.sh", "--app-url", wdAppURL}
	cases := []struct {
		name string
		req  watchdogReq
		want []string
	}{
		{"topic only", watchdogReq{NtfyTopic: "ops-alerts"},
			append(append([]string{}, base...), "--topic", "ops-alerts")},
		{"email only", watchdogReq{Email: "noc@example.com"},
			append(append([]string{}, base...), "--email", "noc@example.com")},
		{"hc only", watchdogReq{HCURL: "https://hc-ping.com/uuid-1"},
			append(append([]string{}, base...), "--hc-url", "https://hc-ping.com/uuid-1")},
		{"webhook only", watchdogReq{WebhookURL: "https://hooks.example.com/T0/B0"},
			append(append([]string{}, base...), "--webhook-url", "https://hooks.example.com/T0/B0")},
		{"all fields", watchdogReq{
			NtfyTopic: "ops-alerts", NtfyServer: "https://ntfy.example.com/ops", NtfyToken: "nt_secret=1234",
			Email: "noc@example.com", HCURL: "https://hc-ping.com/uuid-1",
			WebhookURL: "https://hooks.example.com/T0/B0", WebhookToken: "wh_secret=5678",
		},
			append(append([]string{}, base...),
				"--topic", "ops-alerts",
				"--ntfy-server", "https://ntfy.example.com/ops",
				"--ntfy-token", "nt_secret=1234",
				"--email", "noc@example.com",
				"--hc-url", "https://hc-ping.com/uuid-1",
				"--webhook-url", "https://hooks.example.com/T0/B0",
				"--webhook-token", "wh_secret=5678")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := watchdogArgv("./scripts/install-watchdog.sh", wdAppURL, &tc.req)
			if strings.Join(got, "\x1f") != strings.Join(tc.want, "\x1f") {
				t.Fatalf("argv = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestScrubArgv(t *testing.T) {
	in := []string{"sudo", "--ntfy-token", "nt_secret=1234", "--topic", "ops", "--webhook-token", "wh_secret=5678"}
	got := scrubArgv(in)
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "nt_secret=1234") || strings.Contains(joined, "wh_secret=5678") {
		t.Fatalf("scrubArgv leaked a token: %q", joined)
	}
	if got[2] != "<secret>" || got[6] != "<secret>" || got[3] != "--topic" || got[4] != "ops" {
		t.Fatalf("scrubArgv = %q", got)
	}
	// The original argv (which the child receives) must be untouched.
	if in[2] != "nt_secret=1234" || in[6] != "wh_secret=5678" {
		t.Fatalf("scrubArgv mutated its input: %q", in)
	}
}

func TestWatchdogEndToEndSuccess(t *testing.T) {
	fr := &fakeRunner{out: "watchdog cron installed\n"}
	s, ts := newTestServer(t, fr)
	setInstalledResult(s)
	c := sessionClient(t, ts)

	body := `{"password":"hunter2","ntfy_topic":"ops-alerts","ntfy_server":"https://ntfy.example.com/ops",` +
		`"ntfy_token":"nt_secret_token=1","email":"noc@example.com","hc_url":"https://hc-ping.com/uuid-1",` +
		`"webhook_url":"https://hooks.example.com/T0/B0","webhook_token":"wh_secret_token=2"}`
	res := postJSON(t, c, ts.URL+"/api/watchdog", body, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("got %d (%s), want 200", res.StatusCode, b)
	}
	var out struct {
		WatchdogInstalled bool `json:"watchdog_installed"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.WatchdogInstalled {
		t.Fatal("response missing watchdog_installed:true")
	}

	// Exact fixed argv (I1) — every value a discrete element, fixed order.
	// The script path is rootDir-resolved by the server (bundle/source-tree
	// dual layout) — in this fixture that is <bundle>/scripts/install-watchdog.sh.
	want := []string{
		"sudo", "-k", "-S", "-p", "", "bash", filepath.Join(s.bundle, "scripts", "install-watchdog.sh"),
		"--app-url", wdAppURL,
		"--topic", "ops-alerts",
		"--ntfy-server", "https://ntfy.example.com/ops",
		"--ntfy-token", "nt_secret_token=1",
		"--email", "noc@example.com",
		"--hc-url", "https://hc-ping.com/uuid-1",
		"--webhook-url", "https://hooks.example.com/T0/B0",
		"--webhook-token", "wh_secret_token=2",
	}
	if got := fr.argv(0); strings.Join(got, "\x1f") != strings.Join(want, "\x1f") {
		t.Fatalf("argv = %q, want %q", got, want)
	}

	// The sudo password reached stdin, newline-terminated (H3).
	fr.mu.Lock()
	stdin := string(fr.stdins[0])
	fr.mu.Unlock()
	if stdin != "hunter2\n" {
		t.Fatalf("sudo stdin = %q, want password + newline", stdin)
	}

	// /api/state surfaces the flag.
	if !watchdogState(t, c, ts.URL) {
		t.Fatal("watchdog_installed not surfaced in /api/state after success")
	}

	// §8: the secret tokens must never reach the log ring or the SSE event
	// history — the scrubbed command line must be there instead.
	s.st.logMu.Lock()
	logged := strings.Join(s.st.logBuf, "\n") + "\n" + strings.Join(s.st.events, "\n")
	s.st.logMu.Unlock()
	for _, secret := range []string{"nt_secret_token=1", "wh_secret_token=2", "hunter2"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("secret %q leaked into the log/SSE stream", secret)
		}
	}
	if !strings.Contains(logged, "--ntfy-token <secret>") || !strings.Contains(logged, "--webhook-token <secret>") {
		t.Fatalf("scrubbed command line missing from the log:\n%s", logged)
	}
}

func TestWatchdogPasswordStdinZeroed(t *testing.T) {
	// A runner that honors the execRunner contract for stdin: it delivers the
	// buffer via writeSecret (which zeroes it) and keeps the original slice so
	// the test can prove the plaintext is gone after the request completes.
	var raw []byte
	var sink bytes.Buffer
	rn := runnerFunc(func(dir string, stdin []byte, extraEnv []string, argv ...string) (io.ReadCloser, error) {
		raw = stdin
		if err := writeSecret(nopWriteCloser{&sink}, stdin); err != nil {
			return nil, err
		}
		pr, pw := io.Pipe()
		go func() {
			_, _ = io.WriteString(pw, "ok\n")
			_ = pw.Close()
		}()
		return pr, nil
	})
	s, ts := newTestServer(t, rn)
	setInstalledResult(s)
	c := sessionClient(t, ts)

	res := postJSON(t, c, ts.URL+"/api/watchdog", `{"password":"hunter2","ntfy_topic":"ops"}`, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", res.StatusCode)
	}
	if sink.String() != "hunter2\n" {
		t.Fatalf("sudo stdin got %q, want password + newline", sink.String())
	}
	if len(raw) == 0 {
		t.Fatal("runner never received the password buffer")
	}
	for i, b := range raw {
		if b != 0 {
			t.Fatalf("password buffer byte %d not zeroed after the request: %v", i, raw)
		}
	}
}

func TestWatchdogFailureReportsLastLine(t *testing.T) {
	fr := &fakeRunner{out: "writing stack-watchdog.env\ncrontab: permission denied\n", fail: true}
	s, ts := newTestServer(t, fr)
	setInstalledResult(s)
	c := sessionClient(t, ts)

	res := postJSON(t, c, ts.URL+"/api/watchdog", `{"password":"pw","ntfy_topic":"ops"}`, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500", res.StatusCode)
	}
	var out struct{ Error string }
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Error, "crontab: permission denied") {
		t.Fatalf("error %q does not carry the last output line", out.Error)
	}
	if watchdogState(t, c, ts.URL) {
		t.Fatal("watchdog_installed must stay false after a failed run")
	}
}

func TestWatchdogConflictWhileInstallRunning(t *testing.T) {
	pr, pw := io.Pipe()
	blocking := runnerFunc(func(dir string, stdin []byte, extraEnv []string, argv ...string) (io.ReadCloser, error) {
		return pr, nil
	})
	s, ts := newTestServer(t, blocking)
	setInstalledResult(s) // even with a prior success, a running job wins
	c := sessionClient(t, ts)

	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	waitPhase(t, s, PhaseInstalling)

	res = postJSON(t, c, ts.URL+"/api/watchdog", `{"password":"pw","ntfy_topic":"ops"}`, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("watchdog during install: got %d, want 409", res.StatusCode)
	}
	var out struct{ Error string }
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Error, "another job") {
		t.Fatalf("409 body %q should name the running job", out.Error)
	}
	_ = pw.Close()
	waitPhase(t, s, PhaseInstalled)
}

func TestInstallConflictWhileWatchdogRunning(t *testing.T) {
	pr, pw := io.Pipe()
	blocking := runnerFunc(func(dir string, stdin []byte, extraEnv []string, argv ...string) (io.ReadCloser, error) {
		return pr, nil
	})
	s, ts := newTestServer(t, blocking)
	setInstalledResult(s)
	c := sessionClient(t, ts)

	codeCh := make(chan int, 1)
	go func() {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/watchdog",
			strings.NewReader(`{"password":"pw","ntfy_topic":"ops"}`))
		if err != nil {
			codeCh <- -1
			return
		}
		req.Header.Set("Content-Type", "application/json")
		wres, err := c.Do(req)
		if err != nil {
			codeCh <- -1
			return
		}
		wres.Body.Close()
		codeCh <- wres.StatusCode
	}()

	// Wait until the synchronous watchdog op holds the run guard.
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.st.mu.Lock()
		busy := s.st.watchdogBusy
		s.st.mu.Unlock()
		if busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watchdog op never acquired the run guard")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// An install (new idempotency key) must be refused while it runs.
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "kX"})
	res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("install during watchdog: got %d, want 409", res.StatusCode)
	}
	// So must a check (runPhase-level guard).
	res = postJSON(t, c, ts.URL+"/api/run/check", "{}", nil)
	var started struct{ Started bool }
	if err := json.NewDecoder(res.Body).Decode(&started); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if started.Started {
		t.Fatal("check started while the watchdog op was running")
	}

	_ = pw.Close() // release the watchdog script → success
	if code := <-codeCh; code != http.StatusOK {
		t.Fatalf("watchdog op finished with %d, want 200", code)
	}
	if !watchdogState(t, c, ts.URL) {
		t.Fatal("watchdog_installed not set after the released run succeeded")
	}
}
