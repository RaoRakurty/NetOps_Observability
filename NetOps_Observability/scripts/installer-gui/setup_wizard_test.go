// Tests for the management-address / transport-choice surface added for the
// customer install package (tracker 266): the address list the shell offers,
// the certificate SANs that must cover whatever address was picked, the HTTPS
// default and its explicit HTTP opt-out, the routing table, and the two new
// Settings fields (administrator name, application-state backend) on the round
// trip UI -> profile -> validated argv.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- management address list ------------------------------------------------

func TestPrintIPsIsTabSeparatedAndParsable(t *testing.T) {
	var buf bytes.Buffer
	printIPs(&buf)
	// A machine with no non-loopback IPv4 prints nothing; that is a valid
	// answer and install-correlix.sh falls back to loopback. Everything that
	// IS printed must be a parsable "iface\tipv4" pair, because the shell
	// splits on exactly that.
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			t.Fatalf("line %q: want iface<TAB>ip, got %d fields", line, len(parts))
		}
		if parts[0] == "" {
			t.Fatalf("line %q: empty interface name", line)
		}
		ip := net.ParseIP(parts[1])
		if ip == nil || ip.To4() == nil {
			t.Fatalf("line %q: %q is not an IPv4 address", line, parts[1])
		}
		if ip.IsLoopback() {
			t.Fatalf("line %q: loopback must never be offered as a management address", line)
		}
	}
}

func TestHostIPv4sExcludesLoopbackAndLinkLocal(t *testing.T) {
	for _, a := range hostIPv4s() {
		ip := net.ParseIP(a.IP)
		if ip == nil {
			t.Fatalf("iface %s: unparsable address %q", a.Iface, a.IP)
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			t.Fatalf("iface %s: %s must not be offered", a.Iface, a.IP)
		}
	}
	// lanIP is the default the installer proposes: it must agree with the list.
	if got, list := lanIP(), hostIPv4s(); len(list) > 0 && got != list[0].IP {
		t.Fatalf("lanIP()=%q but the first offered address is %q", got, list[0].IP)
	}
}

// --- listen address ---------------------------------------------------------

func TestListenAddrBindsWhatWasAskedFor(t *testing.T) {
	cases := []struct {
		name   string
		addr   string
		remote bool
		want   string
	}{
		{"default is loopback", ":8800", false, "127.0.0.1:8800"},
		{"remote opens every interface", ":8800", true, "0.0.0.0:8800"},
		{"an explicit management IP wins over both", "10.20.30.40:8800", false, "10.20.30.40:8800"},
		{"an explicit management IP is not widened by remote", "10.20.30.40:8800", true, "10.20.30.40:8800"},
		{"a malformed address falls back to the default port", "nonsense", false, "127.0.0.1:8800"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := listenAddr(tc.addr, tc.remote); got != tc.want {
				t.Fatalf("listenAddr(%q, %v) = %q, want %q", tc.addr, tc.remote, got, tc.want)
			}
		})
	}
}

// --- TLS: the default, and what the certificate has to cover ----------------

func TestMintCertCoversTheChosenManagementAddress(t *testing.T) {
	cert, fp, err := mintCert([]string{"localhost", "127.0.0.1", "appliance-1", "10.20.30.40"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("minted certificate has no parsed leaf")
	}
	if err := leaf.VerifyHostname("10.20.30.40"); err != nil {
		t.Fatalf("certificate is not valid for the chosen management IP: %v", err)
	}
	if err := leaf.VerifyHostname("appliance-1"); err != nil {
		t.Fatalf("certificate is not valid for the hostname: %v", err)
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Fatalf("certificate is not valid for localhost: %v", err)
	}
	// The fingerprint is what the operator compares in the browser warning, so
	// it has to be the browser's rendering: 32 colon-separated uppercase pairs.
	parts := strings.Split(fp, ":")
	if len(parts) != 32 {
		t.Fatalf("fingerprint %q has %d octets, want 32", fp, len(parts))
	}
	if fp != strings.ToUpper(fp) {
		t.Fatalf("fingerprint %q is not uppercase", fp)
	}
}

func TestSessionCookieIsSecureByDefaultAndOnlyRelaxedForHTTP(t *testing.T) {
	// Default posture: TLS, so the session cookie must carry Secure.
	_, ts := newTestServer(t, &fakeRunner{})
	res, err := ts.Client().Get(ts.URL + "/api/state?t=tok123")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	var got *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "cx_setup" {
			got = c
		}
	}
	if got == nil {
		t.Fatal("no cx_setup cookie was issued")
	}
	if !got.Secure {
		t.Fatal("the session cookie must be Secure whenever the server serves TLS")
	}
	if !got.HttpOnly || got.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie lost a hardening attribute: HttpOnly=%v SameSite=%v", got.HttpOnly, got.SameSite)
	}

	// Explicit --http opt-out: Secure would make the cookie unusable, so it is
	// dropped — and ONLY then.
	s2, ts2 := newTestServer(t, &fakeRunner{})
	s2.secureCookie = false
	res2, err := ts2.Client().Get(ts2.URL + "/api/state?t=tok123")
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	for _, c := range res2.Cookies() {
		if c.Name == "cx_setup" && c.Secure {
			t.Fatal("--http mode still stamped Secure — the wizard could not hold a session")
		}
	}
}

func TestSudoPasswordStaysTLSOnly(t *testing.T) {
	// H3 does not move for --http: the prepare route refuses a cleartext
	// arrival, which is exactly what the launch banner warns about.
	s, _ := newTestServer(t, &fakeRunner{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/run/prepare", strings.NewReader(`{"password":"x"}`))
	req.TLS = nil // a plaintext arrival
	s.apiPrepare(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cleartext sudo POST: got %d, want 403", rec.Code)
	}
}

// --- routing ----------------------------------------------------------------

func TestEveryRouteIsBehindTheSessionGate(t *testing.T) {
	_, ts := newTestServer(t, &fakeRunner{})
	// No token, no cookie: every route must refuse. A route that answers here
	// is a route someone can drive without the printed token.
	for _, r := range []struct{ method, path string }{
		{"GET", "/"},
		{"GET", "/api/state"},
		{"GET", "/api/facts"},
		{"GET", "/api/stream"},
		{"GET", "/api/support-bundle"},
		{"POST", "/api/run/check"},
		{"POST", "/api/run/prepare"},
		{"POST", "/api/run/install"},
		{"POST", "/api/watchdog"},
		{"POST", "/api/done"},
	} {
		req, err := http.NewRequest(r.method, ts.URL+r.path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", r.method, r.path, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s without a token: got %d, want 403", r.method, r.path, res.StatusCode)
		}
	}
}

func TestUnknownPathIsNotFound(t *testing.T) {
	_, ts := newTestServer(t, &fakeRunner{})
	c := sessionClient(t, ts)
	res, err := c.Get(ts.URL + "/api/nope")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown route: got %d, want 404", res.StatusCode)
	}
}

// --- Settings: administrator name + application-state backend ---------------

func TestProfileValidatesTheAdministratorName(t *testing.T) {
	base := func(user string) string {
		return `{"version":1,"port":8000,"tls":"yes","admin_user":"` + user + `"}`
	}
	for _, ok := range []string{"admin", "net-ops", "cx.admin", "a_b9"} {
		var p Profile
		if err := decodeProfile(strings.NewReader(base(ok)), &p); err != nil {
			t.Fatalf("admin_user %q should be accepted: %v", ok, err)
		}
		if p.AdminUser != ok {
			t.Fatalf("admin_user round trip: got %q, want %q", p.AdminUser, ok)
		}
	}
	for _, bad := range []string{"ad", "Admin", "9admin", "admin;rm -rf /", "admin user", strings.Repeat("a", 33)} {
		var p Profile
		if err := decodeProfile(strings.NewReader(base(bad)), &p); err == nil {
			t.Fatalf("admin_user %q must be refused", bad)
		}
	}
}

func TestProfileStoreBackendDefaultsToPostgresAndRefusesAnythingElse(t *testing.T) {
	var p Profile
	// Omitted: the field stays empty and install-correlix.sh applies the
	// PostgreSQL default (tracker 245) — the GUI never has to restate it.
	if err := decodeProfile(strings.NewReader(`{"version":1,"port":8000,"tls":"yes"}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.StoreBackend != "" {
		t.Fatalf("omitted store_backend should stay empty, got %q", p.StoreBackend)
	}
	for _, ok := range []string{"postgres", "file"} {
		var q Profile
		body := `{"version":1,"port":8000,"tls":"yes","store_backend":"` + ok + `"}`
		if err := decodeProfile(strings.NewReader(body), &q); err != nil {
			t.Fatalf("store_backend %q should be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"memory", "mysql", "POSTGRES", ""} {
		var q Profile
		body := `{"version":1,"port":8000,"tls":"yes","store_backend":"` + bad + `"}`
		if err := decodeProfile(strings.NewReader(body), &q); err == nil && bad != "" {
			t.Fatalf("store_backend %q must be refused", bad)
		}
	}
}

// --- argv: no request data may ever reach a shell line ----------------------

func TestInstallArgvIsFixedAndRefusesAnUnsafeConfigPath(t *testing.T) {
	argv, err := installArgv(false, "/opt/correlix/correlix-profile-123.json")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bash", "./install-correlix.sh", "install", "--config", "/opt/correlix/correlix-profile-123.json"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv = %q, want %q", argv, want)
		}
	}
	// The sg form embeds the path in a command string, so a path with shell
	// punctuation or a traversal must be refused rather than quoted.
	for _, bad := range []string{"/tmp/a;rm -rf /", "/tmp/$(id)", "/tmp/../etc/passwd", "/tmp/a b.json"} {
		if _, err := installArgv(true, bad); err == nil {
			t.Fatalf("installArgv(sg, %q) must refuse", bad)
		}
	}
	if _, err := installArgv(true, "/opt/correlix/correlix-profile-123.json"); err != nil {
		t.Fatalf("a server-generated temp path must be accepted under sg: %v", err)
	}
}

// --- the wizard walk (Go-driven smoke test) ---------------------------------

// TestWizardWalk drives the whole wizard the way a browser does — token
// exchange, facts, preflight, install with a validated profile, done — against
// a fake installer command, and asserts what each step produced.
func TestWizardWalk(t *testing.T) {
	fr := &fakeRunner{out: "  PASS docker engine\n  PASS compose v2\n"}
	s, ts := newTestServer(t, fr)
	c := sessionClient(t, ts)

	// 1. the page itself
	res, err := c.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("wizard page: got %d, want 200", res.StatusCode)
	}

	// 2. facts (the Welcome screen's host summary)
	res, err = c.Get(ts.URL + "/api/facts")
	if err != nil {
		t.Fatal(err)
	}
	var facts map[string]any
	if err := json.NewDecoder(res.Body).Decode(&facts); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if _, ok := facts["docker"]; !ok {
		t.Fatalf("facts payload has no docker section: %v", facts)
	}

	// 3. preflight
	res = postJSON(t, c, ts.URL+"/api/run/check", "{}", nil)
	res.Body.Close()
	waitPhase(t, s, PhaseReady)
	res, err = c.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Phase      string `json:"phase"`
		CheckItems []struct {
			OK   bool   `json:"ok"`
			Text string `json:"text"`
		} `json:"check_items"`
	}
	if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if st.Phase != string(PhaseReady) {
		t.Fatalf("after preflight: phase %q, want %q", st.Phase, PhaseReady)
	}
	if len(st.CheckItems) != 2 || !st.CheckItems[0].OK {
		t.Fatalf("preflight items not surfaced: %+v", st.CheckItems)
	}

	// 4. install, with everything the Settings screen collects
	fr2 := &fakeRunner{out: `@CX@ {"kind":"stage","id":"env","title":"Environment","status":"ok"}` + "\n" +
		`@CX@ {"kind":"result","status":"ok","url":"http://10.20.30.40:8000","admin_user":"netops"}` + "\n"}
	s.run = fr2
	body := `{"version":1,"port":8000,"tls":"yes","admin_user":"netops","store_backend":"postgres",` +
		`"retention_profile":"production","addons":["self-monitoring"],"sizing":{"profile":"auto"}}`
	res = postJSON(t, c, ts.URL+"/api/run/install", body, map[string]string{"Idempotency-Key": "walk-1"})
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		t.Fatalf("install POST: got %d (%s)", res.StatusCode, b)
	}
	res.Body.Close()
	waitPhase(t, s, PhaseInstalled)

	argv := fr2.argv(-1)
	if len(argv) < 5 || argv[0] != "bash" || argv[2] != "install" || argv[3] != "--config" {
		t.Fatalf("install argv is not the fixed form: %q", argv)
	}

	// 5. done — acknowledging the success screen arms the auto-stop
	res = postJSON(t, c, ts.URL+"/api/done", "{}", nil)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("done: got %d, want 200", res.StatusCode)
	}
}

// TestWizardWalkAgainstRealScripts is the end-to-end smoke test: a real
// TLS listener on 127.0.0.1, the REAL execRunner, and stub prepare-host.sh /
// install-correlix.sh standing in for the installer. It proves the parts the
// fake runner cannot: that the server actually execs a bundle's scripts, parses
// their PASS/FIX lines and `@CX@` markers, and reaches the Done screen.
func TestWizardWalkAgainstRealScripts(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	bundle := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write("prepare-host.sh", "#!/usr/bin/env bash\nset -euo pipefail\necho '  PASS docker engine 27.1'\necho '  PASS compose v2'\necho '  PASS vm.max_map_count'\n")
	// The stub install command echoes the same marker contract install.py and
	// install-correlix.sh emit, and records the argv it was handed.
	write("install-correlix.sh", "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/argv.txt\"\n"+
		"echo '@CX@ {\"kind\":\"stage\",\"id\":\"env\",\"title\":\"Environment generated\",\"status\":\"ok\"}'\n"+
		"echo '@CX@ {\"kind\":\"result\",\"status\":\"ok\",\"url\":\"http://127.0.0.1:8000\",\"admin_user\":\"netops\"}'\n")

	s := newServer(bundle, "walktok", execRunner{})
	s.fsRoot = t.TempDir()
	s.probePort = func(int) bool { return true }
	s.statfs = func(string) (uint64, error) { return 40 << 30, nil }
	s.shutdownFn = func(string) {}
	s.afterFunc = func(time.Duration, func()) *time.Timer { return time.NewTimer(time.Hour) }

	cert, _, err := mintCert([]string{"localhost", "127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           s.handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	base := "https://" + ln.Addr().String()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	// The self-signed certificate is the point of the deployment, so the test
	// client pins THIS certificate instead of disabling verification.
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	c := &http.Client{
		Jar:     jar,
		Timeout: 20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12,
		}},
	}

	// Welcome: the token in the URL is exchanged for the session cookie.
	res, err := c.Get(base + "/?t=walktok")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("wizard page: got %d, want 200", res.StatusCode)
	}
	if !bytes.Contains(page, []byte("Correlix Setup")) {
		t.Fatal("the served page is not the wizard")
	}

	// Preflight.
	res = postJSON(t, c, base+"/api/run/check", "{}", nil)
	res.Body.Close()
	waitPhase(t, s, PhaseReady)

	// Install, carrying everything the Settings screen collects.
	body := `{"version":1,"port":8000,"tls":"yes","admin_user":"netops","store_backend":"postgres",` +
		`"retention_profile":"production","sizing":{"profile":"auto"}}`
	res = postJSON(t, c, base+"/api/run/install", body, map[string]string{"Idempotency-Key": "e2e-1"})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("install POST: got %d", res.StatusCode)
	}
	waitPhase(t, s, PhaseInstalled)

	argv, err := os.ReadFile(filepath.Join(bundle, "argv.txt"))
	if err != nil {
		t.Fatalf("the stub installer was never executed: %v", err)
	}
	lines := strings.Fields(string(argv))
	if len(lines) != 3 || lines[0] != "install" || lines[1] != "--config" {
		t.Fatalf("stub installer argv = %q, want [install --config <path>]", lines)
	}
	if !strings.HasSuffix(lines[2], ".json") || !strings.Contains(lines[2], "correlix-profile-") {
		t.Fatalf("config path %q is not a server-generated profile temp file", lines[2])
	}

	// Done: the result the success screen renders.
	res, err = c.Get(base + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Phase  string `json:"phase"`
		Result struct {
			URL       string `json:"url"`
			AdminUser string `json:"admin_user"`
		} `json:"result"`
	}
	if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if st.Phase != string(PhaseInstalled) {
		t.Fatalf("final phase %q, want %q", st.Phase, PhaseInstalled)
	}
	if st.Result.URL == "" || st.Result.AdminUser != "netops" {
		t.Fatalf("success screen data is wrong: %+v", st.Result)
	}
}
