// P1 hardening + P2 API tests: TLS mint/fingerprint, bind selection,
// single-session, idle timeout, idempotency, facts, profile validation,
// @CX@ marker parsing, sg-docker decision, support-bundle redaction,
// sudo-password zeroing, auto-shutdown scheduling.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mapRunner answers each exact argv with a canned output; unknown commands
// fail like a missing binary would.
type mapRunner struct {
	m map[string]string
}

func (m mapRunner) start(dir string, stdin []byte, extraEnv []string, argv ...string) (io.ReadCloser, error) {
	out, ok := m.m[strings.Join(argv, " ")]
	if !ok {
		return nil, fmt.Errorf("exec: %q: executable file not found", argv[0])
	}
	pr, pw := io.Pipe()
	go func() {
		_, _ = io.WriteString(pw, out)
		_ = pw.Close()
	}()
	return pr, nil
}

// --- P1: TLS ---------------------------------------------------------------

var fingerprintRE = regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`)

func TestMintCertFingerprintAndTLSServing(t *testing.T) {
	cert, fp, err := mintCert([]string{"localhost", "127.0.0.1", "testhost"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprintRE.MatchString(fp) {
		t.Fatalf("fingerprint %q is not colon-separated uppercase SHA-256 hex", fp)
	}
	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("minted cert has no parsed leaf")
	}
	if len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != "localhost" || leaf.DNSNames[1] != "testhost" {
		t.Fatalf("DNS SANs = %v, want [localhost testhost]", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("IP SANs = %v, want [127.0.0.1]", leaf.IPAddresses)
	}
	if leaf.NotAfter.Before(time.Now().AddDate(0, 11, 0)) {
		t.Fatalf("cert lifetime too short: NotAfter=%v", leaf.NotAfter)
	}

	// A real handshake must present exactly this cert.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.(*tls.Conn).Handshake()
		_ = c.Close()
	}()
	// #nosec G402 — the test pins the certificate by fingerprint instead of PKI.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := conn.ConnectionState().PeerCertificates[0]
	if got := certFingerprint(peer.Raw); got != fp {
		t.Fatalf("served cert fingerprint %q != minted %q", got, fp)
	}
}

func TestListenAddr(t *testing.T) {
	cases := []struct {
		addr   string
		remote bool
		want   string
	}{
		{":8800", false, "127.0.0.1:8800"},
		{":8800", true, "0.0.0.0:8800"},
		{":9999", false, "127.0.0.1:9999"},
		{"10.0.0.5:9000", false, "10.0.0.5:9000"},
		{"10.0.0.5:9000", true, "10.0.0.5:9000"},
		{"garbage", false, "127.0.0.1:8800"},
	}
	for _, c := range cases {
		if got := listenAddr(c.addr, c.remote); got != c.want {
			t.Errorf("listenAddr(%q, %v) = %q, want %q", c.addr, c.remote, got, c.want)
		}
	}
}

// --- P1: sessions ----------------------------------------------------------

func TestSingleSessionConflict(t *testing.T) {
	_, ts := newTestServer(t, &fakeRunner{})
	_ = sessionClient(t, ts) // first session lives

	// Second token exchange (fresh browser, no cookie) while the first
	// session is alive must be refused with 409 and a clear message.
	res, err := ts.Client().Get(ts.URL + "/api/state?t=tok123")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("second token exchange: got %d, want 409", res.StatusCode)
	}
	var out struct{ Error string }
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Error, "session") {
		t.Fatalf("409 body should explain the session conflict, got %q", out.Error)
	}
}

func TestIdleTimeoutExpiry(t *testing.T) {
	s, ts := newTestServer(t, &fakeRunner{})
	var cmu sync.Mutex
	cur := time.Now()
	s.now = func() time.Time {
		cmu.Lock()
		defer cmu.Unlock()
		return cur
	}
	advance := func(d time.Duration) {
		cmu.Lock()
		cur = cur.Add(d)
		cmu.Unlock()
	}

	c1 := sessionClient(t, ts)

	// Within the idle window the cookie keeps working (and slides it).
	advance(10 * time.Minute)
	res, err := c1.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("within idle window: got %d, want 200", res.StatusCode)
	}

	// 16 idle minutes later the session is dead: cookie → 403.
	advance(16 * time.Minute)
	res, err = c1.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("after idle expiry: got %d, want 403", res.StatusCode)
	}

	// The token becomes exchangeable again once the session died.
	_ = sessionClient(t, ts)
}

// --- P1: auto-shutdown scheduling ------------------------------------------

func TestShutdownScheduling(t *testing.T) {
	fr := &fakeRunner{out: "install done\n"}
	s, ts := newTestServer(t, fr)
	var mu sync.Mutex
	var durs []time.Duration
	s.afterFunc = func(d time.Duration, f func()) *time.Timer {
		mu.Lock()
		durs = append(durs, d)
		mu.Unlock()
		return time.NewTimer(time.Hour)
	}
	c := sessionClient(t, ts)

	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	waitPhase(t, s, PhaseInstalled)
	mu.Lock()
	got := append([]time.Duration(nil), durs...)
	mu.Unlock()
	if len(got) != 1 || got[0] != resultShutdown {
		t.Fatalf("after install result: scheduled %v, want [%v]", got, resultShutdown)
	}

	res = postJSON(t, c, ts.URL+"/api/done", "", nil)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/api/done: got %d, want 200", res.StatusCode)
	}
	mu.Lock()
	got = append([]time.Duration(nil), durs...)
	mu.Unlock()
	if len(got) != 2 || got[1] != ackShutdownDelay {
		t.Fatalf("after /api/done: scheduled %v, want ack delay %v last", got, ackShutdownDelay)
	}
}

// --- P1: security headers --------------------------------------------------

func TestSecurityHeaders(t *testing.T) {
	_, ts := newTestServer(t, &fakeRunner{})
	c := sessionClient(t, ts)

	res, err := c.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	csp := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("API CSP = %q, want default-src 'none' + frame-ancestors 'none'", csp)
	}

	res, err = c.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	csp = res.Header.Get("Content-Security-Policy")
	for _, need := range []string{"style-src 'unsafe-inline'", "script-src 'unsafe-inline'", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, need) {
			t.Errorf("page CSP %q missing %q", csp, need)
		}
	}
}

// --- P2: idempotency -------------------------------------------------------

func TestIdempotencyKeySemantics(t *testing.T) {
	fr := &fakeRunner{out: "done\n"}
	s, ts := newTestServer(t, fr)
	c := sessionClient(t, ts)

	// Missing key → 400.
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("install without Idempotency-Key: got %d, want 400", res.StatusCode)
	}

	res = postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first install: got %d, want 200", res.StatusCode)
	}
	waitPhase(t, s, PhaseInstalled)

	// Repeating the same key after the job exists → 200 {"job":"existing"},
	// and no second child is spawned (browser-retry safety).
	calls := fr.calls()
	res = postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	var out struct{ Job string }
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || out.Job != "existing" {
		t.Fatalf("repeat key: got %d %+v, want 200 job=existing", res.StatusCode, out)
	}
	if fr.calls() != calls {
		t.Fatal("repeat idempotency key spawned a second install")
	}

	// A NEW key after the previous job finished is a legitimate retry.
	res = postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k2"})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("new key after completion: got %d, want 200", res.StatusCode)
	}
	waitPhase(t, s, PhaseInstalled)
}

// --- P2: facts -------------------------------------------------------------

func TestFactsEndpointShape(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	fr := mapRunner{m: map[string]string{
		"docker --version":       "Docker version 27.1.1, build 6312585\n",
		"docker compose version": "Docker Compose version v2.27.0\n",
		"docker info":            "lots of daemon info\n",
		"timedatectl show -p NTPSynchronized --value": "yes\n",
	}}
	s, ts := newTestServer(t, fr)
	writeFixture(t, filepath.Join(s.fsRoot, "etc", "os-release"),
		"ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n")
	writeFixture(t, filepath.Join(s.fsRoot, "proc", "meminfo"),
		"MemTotal:       16384000 kB\nMemFree:         1024 kB\n")
	writeFixture(t, filepath.Join(s.fsRoot, "etc", "group"),
		"root:x:0:\ndocker:x:989:"+u.Username+"\n")
	writeFixture(t, filepath.Join(s.bundle, "MANIFEST"),
		"product:  Correlix (NetOps Observability)\nversion:  2026.08.0\ngit_sha:  abc\n")
	c := sessionClient(t, ts)

	res, err := c.Get(ts.URL + "/api/facts")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("facts: got %d, want 200", res.StatusCode)
	}
	var f map[string]any
	if err := json.NewDecoder(res.Body).Decode(&f); err != nil {
		t.Fatal(err)
	}

	if f["os_id"] != "ubuntu" || f["os_supported"] != true {
		t.Errorf("os facts wrong: id=%v supported=%v", f["os_id"], f["os_supported"])
	}
	if f["os_pretty"] != "Ubuntu 24.04.1 LTS" {
		t.Errorf("os_pretty = %v", f["os_pretty"])
	}
	if f["mem_bytes"] != float64(16384000*1024) {
		t.Errorf("mem_bytes = %v, want %d", f["mem_bytes"], 16384000*1024)
	}
	if f["disk_free_bytes"] != float64(1<<30) {
		t.Errorf("disk_free_bytes = %v, want %d", f["disk_free_bytes"], 1<<30)
	}
	if f["cpus"].(float64) < 1 {
		t.Errorf("cpus = %v", f["cpus"])
	}
	docker := f["docker"].(map[string]any)
	if docker["present"] != true || docker["version"] != "27.1.1" || docker["compose_v2"] != true || docker["daemon_ok"] != true {
		t.Errorf("docker facts wrong: %+v", docker)
	}
	if f["user_in_docker_group"] != true {
		t.Error("user_in_docker_group should be true (listed in /etc/group)")
	}
	if f["time_sync"] != true {
		t.Error("time_sync should be true (timedatectl said yes)")
	}
	ports := f["ports"].(map[string]any)
	stack := ports["stack"].(map[string]any)
	if stack["port"] != float64(8000) || stack["free"] != true {
		t.Errorf("ports.stack = %+v", stack)
	}
	setup := ports["setup"].(map[string]any)
	if setup["port"] != float64(8800) {
		t.Errorf("ports.setup = %+v", setup)
	}
	if _, has := setup["free"]; has {
		t.Errorf("ports.setup must not carry a free flag (contract), got %+v", setup)
	}
	bundle := f["bundle"].(map[string]any)
	if bundle["version"] != "2026.08.0" || bundle["source_tree"] != false {
		t.Errorf("bundle facts wrong: %+v", bundle)
	}
	if _, has := f["sizing"]; has {
		t.Error("sizing must be omitted when the planner is absent")
	}

	// facts_hash is now exposed via /api/state.
	res2, err := c.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	var st map[string]any
	if err := json.NewDecoder(res2.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if h, _ := st["facts_hash"].(string); len(h) != 64 {
		t.Errorf("facts_hash = %v, want 64 hex chars", st["facts_hash"])
	}
}

func TestFactsSizingBlock(t *testing.T) {
	s := newServer(t.TempDir(), "tok", nil)
	planner := filepath.Join(s.bundle, "resource_planner.py")
	writeFixture(t, planner, "# fake planner\n")
	s.run = mapRunner{m: map[string]string{
		"python3 " + planner + " --detect-json": `{"suggested_profile":"small","mem_gib":16,"profiles":["demo","small","medium","large"]}` + "\n",
	}}
	raw := s.sizingNow()
	if raw == nil {
		t.Fatal("sizing block missing despite a working planner")
	}
	var sz map[string]any
	if err := json.Unmarshal(raw, &sz); err != nil {
		t.Fatal(err)
	}
	if sz["suggested_profile"] != "small" || sz["mem_gib"] != float64(16) {
		t.Fatalf("sizing = %+v", sz)
	}

	// Any planner failure omits the block.
	s.run = mapRunner{m: map[string]string{}}
	if s.sizingNow() != nil {
		t.Fatal("sizing must be omitted when the planner fails")
	}
}

// --- P2: profile validation ------------------------------------------------

func TestProfileValidation(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string // "" = valid
	}{
		{"valid minimal", `{"version":1,"port":8000,"tls":"no"}`, ""},
		{"valid full", `{"version":1,"port":8443,"tls":"yes","retention_profile":"production",
			"addons":["log-search-ui","self-monitoring"],
			"external_kafka":{"broker_urls":"k1.example:9092, k2.example:9092"},
			"discovery":{"enabled":true,"cidrs":["10.70.0.0/16","192.168.1.0/24"]},
			"sizing":{"profile":"auto"}}`, ""},
		{"null external_kafka", `{"version":1,"port":8000,"tls":"no","external_kafka":null}`, ""},
		{"unknown field", `{"version":1,"port":8000,"tls":"no","bogus":true}`, "bogus"},
		{"unknown nested field", `{"version":1,"port":8000,"tls":"no","discovery":{"enabled":false,"surprise":1}}`, "surprise"},
		{"bad version", `{"version":2,"port":8000,"tls":"no"}`, "version"},
		{"port zero", `{"version":1,"port":0,"tls":"no"}`, "port"},
		{"port too big", `{"version":1,"port":70000,"tls":"no"}`, "port"},
		{"bad tls", `{"version":1,"port":8000,"tls":"maybe"}`, "tls"},
		{"bad retention", `{"version":1,"port":8000,"tls":"no","retention_profile":"forever"}`, "retention_profile"},
		{"bad addon", `{"version":1,"port":8000,"tls":"no","addons":["bitcoin-miner"]}`, "addons"},
		{"bad cidr", `{"version":1,"port":8000,"tls":"no","discovery":{"enabled":true,"cidrs":["10.0.0.0/33"]}}`, "discovery.cidrs"},
		{"cidr not a prefix", `{"version":1,"port":8000,"tls":"no","discovery":{"enabled":true,"cidrs":["10.0.0.5"]}}`, "discovery.cidrs"},
		{"discovery enabled without cidrs", `{"version":1,"port":8000,"tls":"no","discovery":{"enabled":true}}`, "discovery.cidrs"},
		{"bad broker", `{"version":1,"port":8000,"tls":"no","external_kafka":{"broker_urls":"nohostport"}}`, "broker_urls"},
		{"bad broker port", `{"version":1,"port":8000,"tls":"no","external_kafka":{"broker_urls":"h:99999"}}`, "broker_urls"},
		{"bad sizing", `{"version":1,"port":8000,"tls":"no","sizing":{"profile":"gigantic"}}`, "sizing.profile"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var p Profile
			err := decodeProfile(strings.NewReader(c.body), &p)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error naming %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q does not name the field %q", err, c.wantErr)
			}
		})
	}
}

func TestInstallRejectsBadProfileHTTP(t *testing.T) {
	fr := &fakeRunner{}
	_, ts := newTestServer(t, fr)
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/install",
		`{"version":1,"port":8000,"tls":"no","bogus":1}`, map[string]string{"Idempotency-Key": "k1"})
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad profile: got %d, want 400", res.StatusCode)
	}
	var out struct{ Error string }
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Error, "bogus") {
		t.Fatalf("400 body %q does not name the offending field", out.Error)
	}
	if fr.calls() != 0 {
		t.Fatal("a rejected profile must never spawn the engine")
	}
}

// --- P2: @CX@ marker parsing + SSE forwarding -------------------------------

func TestMarkerParsingAndSSE(t *testing.T) {
	stageStart := `{"kind":"stage","id":"env","title":"generating environment","status":"start"}`
	stageOK := `{"kind":"stage","id":"env","title":"generating environment","status":"ok"}`
	result := `{"kind":"result","status":"ok","url":"https://10.0.0.7:8000","admin_user":"admin"}`
	fr := &fakeRunner{out: "Starting engine\n@CX@ " + stageStart + "\n@CX@ " + stageOK + "\n@CX@ " + result + "\n"}
	s, ts := newTestServer(t, fr)
	// The generated .env is where the Go side reads the credentials from.
	writeFixture(t, filepath.Join(s.bundle, "deployment", "docker", ".env"),
		"ADMIN_USERNAME=admin\nADMIN_INITIAL_PASSWORD=envPW9\n")
	c := sessionClient(t, ts)

	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	waitPhase(t, s, PhaseInstalled)

	s.st.mu.Lock()
	stages := append([]Stage(nil), s.st.stages...)
	r := s.st.result
	s.st.mu.Unlock()
	if len(stages) != 1 || stages[0].ID != "env" || stages[0].Status != "ok" || stages[0].Title != "generating environment" {
		t.Fatalf("stages = %+v, want one env stage upserted to ok", stages)
	}
	if r == nil || r.Status != "ok" || r.URL != "https://10.0.0.7:8000" {
		t.Fatalf("result = %+v", r)
	}

	// /api/state carries stages + result with the .env password.
	res2, err := c.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Stages []Stage `json:"stages"`
		Result struct {
			URL           string `json:"url"`
			AdminUser     string `json:"admin_user"`
			AdminPassword string `json:"admin_password"`
		} `json:"result"`
	}
	if err := json.NewDecoder(res2.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if len(st.Stages) != 1 || st.Result.URL != "https://10.0.0.7:8000" ||
		st.Result.AdminUser != "admin" || st.Result.AdminPassword != "envPW9" {
		t.Fatalf("state stages/result wrong: %+v", st)
	}

	// SSE must replay the marker payloads as-is and wrap plain lines as log events.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	sres, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer sres.Body.Close()
	wantData := map[string]bool{
		stageStart: false,
		result:     false,
		`{"kind":"log","line":"Starting engine"}`: false,
	}
	found := 0
	sc := bufio.NewScanner(sres.Body)
	for sc.Scan() && found < len(wantData) {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		if seen, tracked := wantData[data]; tracked && !seen {
			wantData[data] = true
			found++
		}
	}
	for line, seen := range wantData {
		if !seen {
			t.Errorf("SSE never delivered %q", line)
		}
	}
}

func TestMarkerResultFailFailsInstall(t *testing.T) {
	fr := &fakeRunner{out: "@CX@ {\"kind\":\"stage\",\"id\":\"up-a\",\"title\":\"starting\",\"status\":\"fail\",\"message\":\"compose up failed\"}\n" +
		"@CX@ {\"kind\":\"result\",\"status\":\"fail\"}\n"}
	s, ts := newTestServer(t, fr)
	c := sessionClient(t, ts)
	res := postJSON(t, c, ts.URL+"/api/run/install", minimalProfile, map[string]string{"Idempotency-Key": "k1"})
	res.Body.Close()
	waitPhase(t, s, PhaseError)

	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if s.st.result == nil || s.st.result.Status != "fail" {
		t.Fatalf("result = %+v, want fail", s.st.result)
	}
	if len(s.st.stages) != 1 || s.st.stages[0].Message != "compose up failed" {
		t.Fatalf("stages = %+v", s.st.stages)
	}
}

// --- P2: sg-docker decision -------------------------------------------------

func TestNeedSGDocker(t *testing.T) {
	cases := []struct {
		proc, etc, want bool
	}{
		{true, true, false},   // process already has the group
		{true, false, false},  // has it (stale /etc/group is irrelevant)
		{false, true, true},   // the chicken-and-egg window → sg
		{false, false, false}, // not in the group at all: plain spawn, engine fails loudly
	}
	for _, c := range cases {
		if got := needSGDocker(c.proc, c.etc); got != c.want {
			t.Errorf("needSGDocker(proc=%v, etc=%v) = %v, want %v", c.proc, c.etc, got, c.want)
		}
	}
}

func TestDockerGroupFacts(t *testing.T) {
	group := "root:x:0:\ndocker:x:989:alice,bob\nusers:x:100:alice\n"
	listed, member := dockerGroupFacts(group, "bob", []int{4, 100})
	if !listed || member {
		t.Fatalf("bob: listed=%v member=%v, want listed only", listed, member)
	}
	listed, member = dockerGroupFacts(group, "carol", []int{989})
	if listed || !member {
		t.Fatalf("carol: listed=%v member=%v, want member only", listed, member)
	}
	listed, member = dockerGroupFacts("nogroups\n", "alice", []int{989})
	if listed || member {
		t.Fatal("no docker line must mean no membership")
	}
}

func TestInstallArgv(t *testing.T) {
	argv, err := installArgv(false, "/bundle/correlix-profile-123.json")
	if err != nil {
		t.Fatal(err)
	}
	want := "bash ./install-correlix.sh install --config /bundle/correlix-profile-123.json"
	if strings.Join(argv, " ") != want {
		t.Fatalf("plain argv = %q", argv)
	}

	argv, err = installArgv(true, "/bundle/correlix-profile-123.json")
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != "sg" || argv[1] != "docker" || argv[2] != "-c" ||
		argv[3] != "bash ./install-correlix.sh install --config /bundle/correlix-profile-123.json" {
		t.Fatalf("sg argv = %q", argv)
	}

	// The sg form embeds the path in a shell string — anything that is not a
	// plain server-generated temp path must be refused (I1).
	for _, bad := range []string{
		"/bundle/x; rm -rf /",
		"/bundle/$(reboot).json",
		"/bundle/a b.json",
		"/bundle/../../etc/passwd",
		"/bundle/pro`file`.json",
		"/bundle/pro'file.json",
	} {
		if _, err := installArgv(true, bad); err == nil {
			t.Errorf("installArgv(sg, %q) accepted an unsafe path", bad)
		}
	}
}

// --- P2: support bundle redaction -------------------------------------------

func TestRedactEnv(t *testing.T) {
	in := strings.Join([]string{
		"# comment with PASSWORD=visible stays a comment",
		"ADMIN_INITIAL_PASSWORD=topsecret1",
		"API_SECRET=topsecret2",
		"AUTH_TOKEN=topsecret3",
		"ENCRYPTION_KEY=topsecret4",
		"lowercase_password=topsecret5",
		"BASE_PORT=8000",
		"EMPTY_SECRET=",
		"COMPOSE_PROFILES=embedded-bus",
	}, "\n")
	out := redactEnv(in)
	if strings.Contains(out, "topsecret") {
		t.Fatalf("redaction leaked a secret:\n%s", out)
	}
	for _, want := range []string{
		"ADMIN_INITIAL_PASSWORD=<set>",
		"API_SECRET=<set>",
		"AUTH_TOKEN=<set>",
		"ENCRYPTION_KEY=<set>",
		"lowercase_password=<set>",
		"BASE_PORT=8000",
		"COMPOSE_PROFILES=embedded-bus",
		"# comment with PASSWORD=visible stays a comment",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("redacted env missing %q:\n%s", want, out)
		}
	}
}

func TestSupportBundleRedactsAndDegradesSansDocker(t *testing.T) {
	// docker captures fail (fail=true) → bundle must degrade gracefully.
	fr := &fakeRunner{out: "", fail: true}
	s, ts := newTestServer(t, fr)
	root := filepath.Join(s.bundle, "NetOps_Observability")
	writeFixture(t, filepath.Join(root, "deployment", "docker", "docker-compose.yml"), "services: {}\n")
	writeFixture(t, filepath.Join(root, "deployment", "docker", ".env"), strings.Join([]string{
		"ADMIN_USERNAME=admin",
		"ADMIN_INITIAL_PASSWORD=topsecret1",
		"API_SECRET=topsecret2",
		"AUTH_TOKEN=topsecret3",
		"ENCRYPTION_KEY=topsecret4",
		"BASE_PORT=8000",
	}, "\n")+"\n")
	writeFixture(t, filepath.Join(s.bundle, "MANIFEST"), "version:  2026.08.0\n")
	c := sessionClient(t, ts)

	res, err := c.Get(ts.URL + "/api/support-bundle")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("support bundle: got %d, want 200", res.StatusCode)
	}
	if got := res.Header.Get("Content-Type"); got != "application/gzip" {
		t.Errorf("Content-Type = %q", got)
	}

	gz, err := gzip.NewReader(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	files := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[hdr.Name] = string(b)
	}

	for _, want := range []string{"env.redacted", "prepare-check.txt", "facts.json", "stages.json", "MANIFEST"} {
		if _, ok := files[want]; !ok {
			t.Errorf("bundle missing %s (has %v)", want, keys(files))
		}
	}
	if _, ok := files["compose-ps.txt"]; ok {
		t.Error("compose-ps.txt must be skipped when docker is absent")
	}
	env := files["env.redacted"]
	for _, want := range []string{"ADMIN_INITIAL_PASSWORD=<set>", "API_SECRET=<set>", "AUTH_TOKEN=<set>", "ENCRYPTION_KEY=<set>", "BASE_PORT=8000"} {
		if !strings.Contains(env, want) {
			t.Errorf("env.redacted missing %q:\n%s", want, env)
		}
	}
	for name, content := range files {
		if strings.Contains(content, "topsecret") {
			t.Errorf("secret leaked into bundle member %s", name)
		}
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestFailedServices(t *testing.T) {
	psJSON := `{"Service":"api","State":"running","Health":"healthy","ExitCode":0}
{"Service":"kafka","State":"exited","Health":"","ExitCode":1}
{"Service":"vector","State":"running","Health":"unhealthy","ExitCode":0}
{"Service":"seal","State":"exited","Health":"","ExitCode":0}
{"Service":"bad;svc","State":"dead","Health":"","ExitCode":1}
`
	got := failedServices(psJSON)
	want := []string{"kafka", "vector"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("failedServices = %v, want %v (exit-0 one-shots and unsafe names excluded)", got, want)
	}
}

// --- P1: sudo password zeroing ----------------------------------------------

type nopWriteCloser struct{ *bytes.Buffer }

func (nopWriteCloser) Close() error { return nil }

func TestWriteSecretZeroesBuffer(t *testing.T) {
	secret := []byte("hunter2\n")
	var sink bytes.Buffer
	if err := writeSecret(nopWriteCloser{&sink}, secret); err != nil {
		t.Fatal(err)
	}
	if sink.String() != "hunter2\n" {
		t.Fatalf("child stdin got %q", sink.String())
	}
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("secret buffer byte %d not zeroed after write: %v", i, secret)
		}
	}
}

type failWriteCloser struct{}

func (failWriteCloser) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (failWriteCloser) Close() error              { return nil }

func TestWriteSecretZeroesEvenOnWriteError(t *testing.T) {
	secret := []byte("hunter2\n")
	if err := writeSecret(failWriteCloser{}, secret); err == nil {
		t.Fatal("want write error to propagate")
	}
	for _, b := range secret {
		if b != 0 {
			t.Fatal("secret buffer must be zeroed even when the write fails")
		}
	}
}
