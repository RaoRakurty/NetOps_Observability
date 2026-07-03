package collectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"
)

// unifi.go — Ubiquiti UniFi controller connector. Ubiquiti device health lives
// in the UniFi/EdgeMax CONTROLLER API, not device SNMP (which is why the SNMP
// `ubiquiti` profile is registered-only). This connector logs into the
// controller, pulls the device stat set, and normalizes it to VM series keyed
// by device — the same emit path every other collector uses.
//
// SCOPE (owner hold): this is the controller DATA-ACQUISITION plumbing +
// device-level health (client count, state, cpu/mem, uptime, satisfaction,
// uplink). The wireless-specific metric family (per-radio channel utilization,
// SSID/band breakdown, AP signatures, wireless UI) is DEFERRED to the owner's
// wireless-AP design — this connector deliberately stops at device-level
// monitoring so it doesn't pre-empt that design.
//
// TESTABILITY: the login + fetch need a live controller (none in the lab), so
// they are not CI-covered. The RISK — parsing the controller JSON into
// normalized series — is pure and unit-tested (normalizeUniFiDevices).

// UniFiConfig is the connector configuration (env-driven, like the other
// collectors; the password is a secret reference resolved by the caller).
type UniFiConfig struct {
	BaseURL  string // https://unifi.example.com:8443  or a UniFi OS console URL
	Site     string // controller site id (default "default")
	Username string
	Password string
	UnifiOS  bool // true → UniFi OS (/api/auth/login + /proxy/network prefix)
}

// unifiConfigFromEnv reads the connector config. FEATURE_UNIFI gates the whole
// connector; empty BaseURL/creds → disabled.
func unifiConfigFromEnv() (UniFiConfig, bool) {
	if os.Getenv("FEATURE_UNIFI") != "true" {
		return UniFiConfig{}, false
	}
	c := UniFiConfig{
		BaseURL:  strings.TrimRight(os.Getenv("UNIFI_URL"), "/"),
		Site:     envOrDefault("UNIFI_SITE", "default"),
		Username: os.Getenv("UNIFI_USER"),
		Password: os.Getenv("UNIFI_PASSWORD"),
		UnifiOS:  os.Getenv("UNIFI_OS") == "true",
	}
	if c.BaseURL == "" || c.Username == "" || c.Password == "" {
		return UniFiConfig{}, false
	}
	return c, true
}

func envOrDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// unifiDevice is the subset of a UniFi /stat/device record we normalize. The
// controller returns many more fields; we take the device-level health only
// (radio_table_stats etc. are wireless-specific — deferred).
type unifiDevice struct {
	Name         string  `json:"name"`
	Model        string  `json:"model"`
	Type         string  `json:"type"` // uap | usw | ugw | udm
	State        int     `json:"state"`
	NumSta       int     `json:"num_sta"`
	Uptime       int64   `json:"uptime"`
	Satisfaction int     `json:"satisfaction"`
	SystemStats  struct {
		CPU string `json:"cpu"`
		Mem string `json:"mem"`
	} `json:"system-stats"`
}

// normalizeUniFiDevices parses a /stat/device response body and emits normalized
// VM series. Pure + unit-tested. Cardinality law: device + model + type labels
// only (no serials/MACs). Metric names are device_unifi_* (device-level, not
// wireless-family — that awaits the wireless design).
func normalizeUniFiDevices(body []byte, tsMillis int64) ([]string, error) {
	var resp struct {
		Data []unifiDevice `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	var lines []string
	for _, d := range resp.Data {
		name := sanitizeLabel(d.Name)
		if name == "" {
			continue
		}
		lbl := fmt.Sprintf("device=%q,model=%q,type=%q", name, sanitizeLabel(d.Model), sanitizeLabel(d.Type))
		lines = append(lines,
			fmt.Sprintf("device_unifi_state{%s} %d %d", lbl, d.State, tsMillis),
			fmt.Sprintf("device_unifi_clients{%s} %d %d", lbl, d.NumSta, tsMillis),
			fmt.Sprintf("device_unifi_uptime_seconds{%s} %d %d", lbl, d.Uptime, tsMillis),
		)
		if d.Satisfaction >= 0 && d.Satisfaction <= 100 {
			lines = append(lines, fmt.Sprintf("device_unifi_satisfaction_pct{%s} %d %d", lbl, d.Satisfaction, tsMillis))
		}
		if cpu := parseNum(d.SystemStats.CPU); cpu >= 0 {
			lines = append(lines, fmt.Sprintf("device_unifi_cpu_pct{%s} %g %d", lbl, cpu, tsMillis))
		}
		if mem := parseNum(d.SystemStats.Mem); mem >= 0 {
			lines = append(lines, fmt.Sprintf("device_unifi_mem_pct{%s} %g %d", lbl, mem, tsMillis))
		}
	}
	return lines, nil
}

// parseNum parses a UniFi numeric-string field ("cpu":"3.4"); -1 if absent/bad.
func parseNum(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return -1
	}
	var f float64
	if _, err := fmt.Sscanf(s, "%g", &f); err != nil {
		return -1
	}
	return f
}

// unifiClient carries auth cookies across controller calls.
type unifiClient struct {
	cfg  UniFiConfig
	http *http.Client
}

func newUniFiClient(cfg UniFiConfig) (*unifiClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	// System trust store (no InsecureSkipVerify — TLS policy). A lab controller
	// with a self-signed cert must have its CA added to the trust store.
	return &unifiClient{cfg: cfg, http: &http.Client{Jar: jar, Timeout: 20 * time.Second}}, nil
}

// login authenticates against the controller (UniFi OS vs legacy path).
func (c *unifiClient) login(ctx context.Context) error {
	path := "/api/login"
	if c.cfg.UnifiOS {
		path = "/api/auth/login"
	}
	body, _ := json.Marshal(map[string]string{"username": c.cfg.Username, "password": c.cfg.Password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unifi login: status %d", resp.StatusCode)
	}
	return nil
}

// fetchDevices returns the raw /stat/device body (normalized by the pure fn).
func (c *unifiClient) fetchDevices(ctx context.Context) ([]byte, error) {
	prefix := ""
	if c.cfg.UnifiOS {
		prefix = "/proxy/network"
	}
	url := fmt.Sprintf("%s%s/api/s/%s/stat/device", c.cfg.BaseURL, prefix, c.cfg.Site)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unifi devices: status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// CollectUniFi runs one controller poll (login → fetch → normalize → emit).
// Best-effort; disabled unless FEATURE_UNIFI + config present.
func CollectUniFi(ctx context.Context) {
	cfg, ok := unifiConfigFromEnv()
	if !ok {
		return
	}
	c, err := newUniFiClient(cfg)
	if err != nil {
		return
	}
	if err := c.login(ctx); err != nil {
		return
	}
	body, err := c.fetchDevices(ctx)
	if err != nil {
		return
	}
	lines, err := normalizeUniFiDevices(body, time.Now().UnixMilli())
	if err != nil || len(lines) == 0 {
		return
	}
	emitMetrics(ctx, strings.Join(lines, "\n"))
}

// ── Collector wrapper (pool integration) ──────────────────────────────────────

type unifiCollector struct {
	interval time.Duration
	status   Status
}

// NewUniFi builds the UniFi controller collector (discovery-kind; the Collectors
// tab groups it with the other feature collectors).
func NewUniFi() Collector {
	return &unifiCollector{interval: 60 * time.Second, status: Status{Name: "unifi", Kind: "discovery"}}
}

func (u *unifiCollector) Name() string   { return "unifi" }
func (u *unifiCollector) Status() Status  { return u.status }

func (u *unifiCollector) Run(ctx context.Context) error {
	t := time.NewTicker(u.interval)
	defer t.Stop()
	CollectUniFi(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			CollectUniFi(ctx)
		}
	}
}
