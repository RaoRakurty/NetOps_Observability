// Command mock-nms is a tiny, stdlib-only stand-in for a Cisco Catalyst SD-WAN
// Manager (vManage) REST API, used to exercise Correlix's NMS vendor-controller
// integration cycle (#95) end-to-end on the live stack WITHOUT a real
// controller. It is a TEST FIXTURE — never a production dependency:
//
//   - Off by default (compose profile "mock-nms"); the stack never starts it
//     unless explicitly asked.
//   - It implements only the endpoints the vmanage connector actually drives:
//       POST /jwt/login                        (username/password → JWT)
//       GET  /dataservice/alarms               (BFD/tunnel alarms → events+states)
//       GET  /dataservice/statistics/approute  (latency/jitter/loss/QoE → metrics)
//       GET  /dataservice/device               (+ the other streams: empty data)
//     plus non-vManage GET /inspect (watch what was served) and GET /healthz.
//
// Faithful behaviours that matter for the runtime's correctness:
//   - Wrong credentials → 401 on login; a poll without the Bearer → 401, so the
//     re-auth path is exercised against a real network peer.
//   - The BFD session FLAPS on a timer (down ≈90s, up ≈90s, new alarm uuid per
//     transition): every phase change produces a fresh controller event and a
//     state transition (flap_count grows in controller_state_current), while
//     repeated polls inside a phase are DEDUPED by the pipeline (same uuid).
//   - Approute metrics jitter smoothly (sinusoid + noise), with loss following
//     the BFD-down phase on the mpls tunnel — so the metric lane visibly
//     corroborates the event lane, the whole point of controller intelligence.
//
// Zero deps, builds offline (CLAUDE.md §6 stdlib-only).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type state struct {
	mu      sync.Mutex
	token   string
	logins  int
	polls   int
	unauth  int
	started time.Time
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func randToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "mock-jwt-fallback"
	}
	return "mock-jwt-" + hex.EncodeToString(b)
}

// flapPeriod is one full down+up cycle; the BFD session is DOWN for the first
// half and UP for the second. Keyed to wall-clock so restarts don't reset phase.
const flapHalf = 90 * time.Second

// bfdDown reports the current phase and a stable per-phase id (the alarm uuid
// changes only on transition, so steady-state polls dedupe).
func bfdDown(now time.Time) (down bool, phaseID int64) {
	phase := now.Unix() / int64(flapHalf.Seconds())
	return phase%2 == 0, phase
}

func main() {
	addr := envOr("MOCK_NMS_ADDR", ":8091")
	user := envOr("MOCK_NMS_USER", "correlix")
	pass := envOr("MOCK_NMS_PASSWORD", "correlix-mock-secret")

	st := &state{started: time.Now()}

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok"})
	})

	mux.HandleFunc("/inspect", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		down, phase := bfdDown(time.Now())
		writeJSON(w, 200, map[string]any{
			"logins": st.logins, "polls": st.polls, "unauthorized": st.unauth,
			"bfd_down": down, "flap_phase": phase,
			"uptime_s": int(time.Since(st.started).Seconds()),
		})
	})

	mux.HandleFunc("/jwt/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body); err != nil ||
			body.Username != user || body.Password != pass {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		st.mu.Lock()
		st.logins++
		st.token = randToken()
		tok := st.token
		st.mu.Unlock()
		writeJSON(w, 200, map[string]string{"token": tok})
	})

	// authed wraps a /dataservice handler with the Bearer check.
	authed := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			st.mu.Lock()
			tok := st.token
			st.polls++
			st.mu.Unlock()
			if tok == "" || r.Header.Get("Authorization") != "Bearer "+tok {
				st.mu.Lock()
				st.unauth++
				st.mu.Unlock()
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fn(w, r)
		}
	}

	mux.HandleFunc("/dataservice/alarms", authed(func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now()
		down, phase := bfdDown(now)
		nowMS := now.UnixMilli()
		phaseStartMS := phase * flapHalf.Milliseconds()
		alarm := map[string]any{
			// uuid stable within a phase → pipeline dedupes steady-state polls;
			// new uuid on each transition → a fresh flap event every phase.
			"uuid":              "mock-bfd-" + itoa(phase),
			"eventname":         "bfd-state-change",
			"type":              "bfd_tloc_down",
			"rule_name_display": "BFD Session Down",
			"component":         "BFD",
			"severity":          "Critical",
			"severity_number":   1,
			"entry_time":        phaseStartMS,
			"system_ip":         "10.1.1.1",
			"host_name":         "vEdge-Branch-1",
			"site_id":           "100",
			"active":            down, // active=false ⇒ cleared ⇒ state recovers
			"acknowledged":      false,
			"values": []map[string]any{{
				"system-ip": "10.1.1.1", "local-color": "mpls", "remote-color": "biz-internet",
				"src-ip": "192.0.2.1", "dst-ip": "198.51.100.7", "proto": "ipsec",
			}},
		}
		// A second, steadier device so the UI shows more than one entity.
		tunnel := map[string]any{
			"uuid": "mock-tunnel-baseline", "eventname": "tunnel-state-change",
			"type": "tunnel_up", "rule_name_display": "Tunnel Up", "component": "Tunnel",
			"severity": "Medium", "severity_number": 3, "entry_time": nowMS - 3600_000,
			"system_ip": "10.2.2.2", "host_name": "vEdge-DC-1", "site_id": "200",
			"active": false, "acknowledged": true,
		}
		writeJSON(w, 200, map[string]any{"data": []any{alarm, tunnel}})
	}))

	mux.HandleFunc("/dataservice/statistics/approute", authed(func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now()
		down, _ := bfdDown(now)
		t := float64(now.Unix())
		nowMS := now.UnixMilli()
		mk := func(name, local, remote, lcolor, rcolor, site string, base, spread float64, lossy bool) map[string]any {
			lat := base + spread*math.Sin(t/97.0) + 1.5*math.Sin(t/13.0)
			jit := 2.0 + 1.2*math.Sin(t/31.0+2)
			loss := 0.1 + 0.1*math.Sin(t/59.0+1)
			qoe := 9.5 - loss
			if lossy && down {
				loss = 22.0 + 6*math.Sin(t/7.0) // BFD-down phase: mpls path bleeds
				lat = base + 80 + 20*math.Sin(t/11.0)
				qoe = 2.1
			}
			return map[string]any{
				"vdevice_name": "vEdge-Branch-1", "local_system_ip": local, "remote_system_ip": remote,
				"local_color": lcolor, "remote_color": rcolor, "site_id": site, "name": name,
				"latency": round1(lat), "jitter": round1(jit), "loss_percentage": round1(loss),
				"vqoe_score": round1(qoe), "entry_time": nowMS,
			}
		}
		writeJSON(w, 200, map[string]any{"data": []any{
			mk("10.1.1.1:mpls-10.2.2.2:mpls", "10.1.1.1", "10.2.2.2", "mpls", "mpls", "100", 12, 3, true),
			mk("10.1.1.1:biz-internet-10.2.2.2:biz-internet", "10.1.1.1", "10.2.2.2", "biz-internet", "biz-internet", "100", 28, 6, false),
			mk("10.1.1.1:mpls-10.3.3.3:mpls", "10.1.1.1", "10.3.3.3", "mpls", "mpls", "100", 45, 8, false),
			mk("10.1.1.1:biz-internet-10.3.3.3:biz-internet", "10.1.1.1", "10.3.3.3", "biz-internet", "biz-internet", "100", 61, 10, false),
		}})
	}))

	// Remaining vmanage streams: valid-but-empty payloads (the connector
	// tolerates quiet streams; they exist so every configured stream 200s).
	for _, p := range []string{
		"/dataservice/device", "/dataservice/event",
		"/dataservice/device/tunnel/statistics",
		"/dataservice/device/control/connections",
		"/dataservice/device/bfd/sessions",
	} {
		mux.HandleFunc(p, authed(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{"data": []any{}})
		}))
	}

	srv := &http.Server{
		Addr: addr, Handler: mux,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
	}
	log.Printf("mock-nms (vManage stand-in) listening on %s (user=%s)", addr, user)
	log.Fatal(srv.ListenAndServe())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b strings.Builder
	var digits []byte
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	if neg {
		b.WriteByte('-')
	}
	for i := len(digits) - 1; i >= 0; i-- {
		b.WriteByte(digits[i])
	}
	return b.String()
}
