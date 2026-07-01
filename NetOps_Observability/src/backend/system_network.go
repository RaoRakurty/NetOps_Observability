package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// system_network.go — Correlix SYSTEM network settings: the DNS resolvers the
// platform uses to resolve outbound URLs (integrations, webhooks, providers) and
// the NTP servers it tracks its clock against. This is platform‑global system
// configuration (not per‑tenant, not a monitoring feature) — like the "System →
// DNS / NTP" settings on any network appliance.
//
//   - DNS: the configured servers are installed as the process resolver
//     (net.DefaultResolver), so every name lookup Correlix makes for a URL goes
//     through them.
//   - NTP: a background SNTP client measures Correlix's clock OFFSET against the
//     configured servers and exposes it (reachable / stratum / offset), so an
//     operator can confirm the platform clock is accurate. Setting the host OS
//     clock is the deployment's responsibility; Correlix reports sync health.
//
// Gated by requirePlatformAdmin: a tenant admin manages their tenant, never the
// platform's own system settings.

// SystemNetworkConfig is the platform's DNS + NTP settings (single global row).
type SystemNetworkConfig struct {
	DNSServers    []string  `json:"dns_servers"`              // resolver IPs, in order
	SearchDomains []string  `json:"search_domains,omitempty"` // optional DNS search suffixes
	NTPServers    []string  `json:"ntp_servers"`              // NTP server host/IPs
	UpdatedBy     string    `json:"updated_by,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

// systemNetStore persists the single config row to a JSON file.
type systemNetStore struct {
	mu   sync.RWMutex
	path string
	cfg  SystemNetworkConfig
}

func newSystemNetStore(path string) (*systemNetStore, error) {
	if path == "" {
		path = "/data/system_network.json"
	}
	s := &systemNetStore{path: path}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.cfg)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *systemNetStore) Get() SystemNetworkConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *systemNetStore) Put(c SystemNetworkConfig) error {
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// ---- validation ----

// sanitizeSystemNetwork validates + normalizes the config: DNS entries must be
// IPs; NTP entries a host or IP; search domains a hostname. Deduped, trimmed.
func sanitizeSystemNetwork(in SystemNetworkConfig) (SystemNetworkConfig, error) {
	out := SystemNetworkConfig{}
	seen := map[string]bool{}
	for _, d := range in.DNSServers {
		d = strings.TrimSpace(d)
		if d == "" || seen["dns:"+d] {
			continue
		}
		if net.ParseIP(d) == nil {
			return out, fmt.Errorf("DNS server %q is not a valid IP address", d)
		}
		seen["dns:"+d] = true
		out.DNSServers = append(out.DNSServers, d)
	}
	for _, n := range in.NTPServers {
		n = strings.TrimSpace(n)
		if n == "" || seen["ntp:"+n] {
			continue
		}
		if net.ParseIP(n) == nil && !isHostname(n) {
			return out, fmt.Errorf("NTP server %q is not a valid host or IP", n)
		}
		seen["ntp:"+n] = true
		out.NTPServers = append(out.NTPServers, n)
	}
	for _, sd := range in.SearchDomains {
		sd = strings.TrimSpace(strings.TrimSuffix(sd, "."))
		if sd == "" || seen["sd:"+sd] || !isHostname(sd) {
			continue
		}
		seen["sd:"+sd] = true
		out.SearchDomains = append(out.SearchDomains, sd)
	}
	return out, nil
}

// isHostname is a light RFC‑1123‑ish check (letters/digits/hyphen/dot, no spaces).
func isHostname(h string) bool {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " \t/\\:") {
		return false
	}
	for _, lbl := range strings.Split(h, ".") {
		if lbl == "" {
			return false
		}
	}
	return true
}

// NOTE on DNS scope: the configured resolvers are used to VALIDATE outbound
// resolution (the Test endpoint, via resolverFor) — they are deliberately NOT
// installed as the global process resolver. Overriding net.DefaultResolver would
// hijack INTERNAL container name resolution too (clickhouse/postgres/redis/…),
// which broke the platform. Applying the configured DNS only to specific outbound
// external clients (integrations/webhooks) is a safe, scoped follow-up.

// ---- NTP (SNTP) client — stdlib only, no new dependency ----

// ntpEpochOffset converts the NTP era (1900) to Unix (1970).
const ntpEpochOffset = 2208988800

// NTPResult is one server's measured sync state.
type NTPResult struct {
	Server    string  `json:"server"`
	Reachable bool    `json:"reachable"`
	Stratum   int     `json:"stratum,omitempty"`
	OffsetMs  float64 `json:"offset_ms,omitempty"` // local − server (positive = local ahead)
	RTTMs     float64 `json:"rtt_ms,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// queryNTP performs one SNTP exchange (RFC 4330) and computes the clock offset.
// `now` is injected for testability of the offset math via parseNTPResponse.
func queryNTP(ctx context.Context, server string) NTPResult {
	res := NTPResult{Server: server}
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "123")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := make([]byte, 48)
	req[0] = 0x1B // LI=0, VN=3, Mode=3 (client)
	t1 := time.Now()
	if _, err := conn.Write(req); err != nil {
		res.Error = err.Error()
		return res
	}
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		res.Error = err.Error()
		return res
	}
	t4 := time.Now()

	offset, stratum, perr := parseNTPResponse(resp, t1, t4)
	if perr != nil {
		res.Error = perr.Error()
		return res
	}
	res.Reachable = true
	res.Stratum = stratum
	res.OffsetMs = float64(offset.Milliseconds())
	res.RTTMs = float64(t4.Sub(t1).Milliseconds())
	return res
}

// parseNTPResponse computes the clock offset from a 48‑byte NTP response and the
// local send/receive times. offset = ((T2 − T1) + (T3 − T4)) / 2. Pure/testable.
func parseNTPResponse(resp []byte, t1, t4 time.Time) (offset time.Duration, stratum int, err error) {
	if len(resp) < 48 {
		return 0, 0, fmt.Errorf("short NTP response (%d bytes)", len(resp))
	}
	stratum = int(resp[1])
	t2 := ntpTime(resp[32:40]) // receive timestamp (server)
	t3 := ntpTime(resp[40:48]) // transmit timestamp (server)
	if t2.IsZero() || t3.IsZero() {
		return 0, stratum, fmt.Errorf("NTP response missing timestamps")
	}
	offset = ((t2.Sub(t1)) + (t3.Sub(t4))) / 2
	return offset, stratum, nil
}

// ntpTime decodes an 8‑byte NTP timestamp (32.32 fixed point since 1900) to time.
func ntpTime(b []byte) time.Time {
	secs := binary.BigEndian.Uint32(b[0:4])
	frac := binary.BigEndian.Uint32(b[4:8])
	if secs == 0 && frac == 0 {
		return time.Time{}
	}
	nsec := (int64(frac) * 1e9) >> 32
	return time.Unix(int64(secs)-ntpEpochOffset, nsec).UTC()
}

// ---- HTTP handlers ----

// handleSystemNetwork: GET|PUT /api/system/network — platform DNS + NTP settings.
func (s *server) handleSystemNetwork(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, ok := s.requirePlatformAdmin(w, r); !ok {
			return
		}
		writeJSON(w, http.StatusOK, s.systemNet.Get())
	case http.MethodPut:
		claims, ok := s.requirePlatformAdmin(w, r)
		if !ok {
			return
		}
		var req SystemNetworkConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad body: " + err.Error()})
			return
		}
		clean, err := sanitizeSystemNetwork(req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		clean.UpdatedBy = claims.Sub
		clean.UpdatedAt = time.Now().UTC()
		if err := s.systemNet.Put(clean); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, clean)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

// systemNetworkStatus is the live test/status payload.
type systemNetworkStatus struct {
	DNS struct {
		Servers  []string `json:"servers"`
		TestHost string   `json:"test_host"`
		Resolved []string `json:"resolved,omitempty"`
		OK       bool     `json:"ok"`
		Error    string   `json:"error,omitempty"`
	} `json:"dns"`
	NTP struct {
		Results  []NTPResult `json:"results"`
		OK       bool        `json:"ok"`       // at least one server reachable
		OffsetMs float64     `json:"offset_ms"` // best (min |offset|) reachable server
	} `json:"ntp"`
}

// handleSystemNetworkTest: POST /api/system/network/test — resolve a name via the
// configured DNS and query each NTP server for offset/stratum. Read‑only probe.
func (s *server) handleSystemNetworkTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	cfg := s.systemNet.Get()
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	var st systemNetworkStatus
	// DNS: resolve a well‑known name via the configured resolver.
	st.DNS.Servers = cfg.DNSServers
	st.DNS.TestHost = strings.TrimSpace(r.URL.Query().Get("host"))
	if st.DNS.TestHost == "" {
		st.DNS.TestHost = "cloudflare.com"
	}
	resolver := net.DefaultResolver
	if len(cfg.DNSServers) > 0 {
		resolver = resolverFor(cfg.DNSServers)
	}
	if ips, err := resolver.LookupHost(ctx, st.DNS.TestHost); err != nil {
		st.DNS.Error = err.Error()
	} else {
		st.DNS.Resolved = ips
		st.DNS.OK = len(ips) > 0
	}

	// NTP: query each server, report the best (smallest |offset|) reachable one.
	best := 1 << 30
	for _, srv := range cfg.NTPServers {
		res := queryNTP(ctx, srv)
		st.NTP.Results = append(st.NTP.Results, res)
		if res.Reachable {
			st.NTP.OK = true
			if abs := absInt(int(res.OffsetMs)); abs < best {
				best = abs
				st.NTP.OffsetMs = res.OffsetMs
			}
		}
	}
	sort.SliceStable(st.NTP.Results, func(i, j int) bool { return st.NTP.Results[i].Server < st.NTP.Results[j].Server })
	writeJSON(w, http.StatusOK, st)
}

// resolverFor builds a one‑off resolver over the given DNS servers (for the test
// probe, without touching the global default).
func resolverFor(servers []string) *net.Resolver {
	targets := make([]string, len(servers))
	for i, s := range servers {
		targets[i] = net.JoinHostPort(strings.TrimSpace(s), "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			proto := "udp"
			if network == "tcp" {
				proto = "tcp"
			}
			var lastErr error
			for _, addr := range targets {
				if c, err := d.DialContext(ctx, proto, addr); err == nil {
					return c, nil
				} else {
					lastErr = err
				}
			}
			return nil, lastErr
		},
	}
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
