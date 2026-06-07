package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// DiscoverySource is the contract every discovery plugin (Netbox, SNMP
// scan, static YAML, future Kubernetes/CMDB integrations) must satisfy.
type DiscoverySource interface {
	Name() string
	Poll(ctx context.Context) ([]models.Device, error)
	Interval() time.Duration
}

// DiscoveryAggregator multiplexes multiple sources, caches their output,
// and resolves conflicts when the same device id is reported by more
// than one source. Source precedence is registration order — first
// registered wins on conflict.
type DiscoveryAggregator struct {
	mu      sync.RWMutex
	sources []DiscoverySource
	cache   map[string]models.Device
	refresh chan struct{}
	stats   map[string]sourceStats
	// detected holds vendors learned via SNMP sysObjectID detection, keyed by
	// device id. Re-applied on every source poll so a re-poll (which rebuilds
	// the cache entry from the source) doesn't wipe a detected vendor.
	detected map[string]string
}

type sourceStats struct {
	LastPoll  time.Time `json:"last_poll"`
	LastError string    `json:"last_error,omitempty"`
	Devices   int       `json:"devices"`
}

func NewDiscoveryAggregator() *DiscoveryAggregator {
	return &DiscoveryAggregator{
		cache:    make(map[string]models.Device),
		refresh:  make(chan struct{}, 1),
		stats:    make(map[string]sourceStats),
		detected: make(map[string]string),
	}
}

func (a *DiscoveryAggregator) Register(s DiscoverySource) {
	if s == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sources = append(a.sources, s)
}

func (a *DiscoveryAggregator) Start(ctx context.Context) {
	a.mu.RLock()
	sources := make([]DiscoverySource, len(a.sources))
	copy(sources, a.sources)
	a.mu.RUnlock()
	for _, src := range sources {
		go a.pollLoop(ctx, src)
	}
	if os.Getenv("ENABLE_VENDOR_DETECTION") == "true" {
		go a.vendorLoop(ctx)
	}
}

// vendorLoop periodically fills in the vendor of any inventory device that
// doesn't have one yet, via SNMP sysObjectID detection — the authoritative
// signal (LibreNMS/Observium all lead with it). Devices whose source
// already supplies a vendor (Netbox, static YAML) are left untouched.
func (a *DiscoveryAggregator) vendorLoop(ctx context.Context) {
	community := os.Getenv("SNMP_COMMUNITY")
	if community == "" {
		community = "public"
	}
	a.enrichVendors(ctx, community)
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.enrichVendors(ctx, community)
		}
	}
}

func (a *DiscoveryAggregator) enrichVendors(ctx context.Context, community string) {
	// Snapshot the devices still needing detection (don't hold the lock during
	// the SNMP round-trips).
	type todo struct{ id, addr string }
	a.mu.RLock()
	var pending []todo
	for id, d := range a.cache {
		if d.Address == "" || d.Vendor != "" {
			continue
		}
		if _, done := a.detected[id]; done {
			continue
		}
		pending = append(pending, todo{id, d.Address})
	}
	a.mu.RUnlock()

	for _, p := range pending {
		dctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		vendor, descr := collectors.DetectVendor(dctx, p.addr, community)
		cancel()
		if vendor == "" {
			continue // leave it for a later cycle (negative result not cached)
		}
		a.mu.Lock()
		a.detected[p.id] = vendor
		if d, ok := a.cache[p.id]; ok && d.Vendor == "" {
			d.Vendor = vendor
			if d.OS == "" && descr != "" {
				d.OS = truncateDescr(descr)
			}
			a.cache[p.id] = d
		}
		a.mu.Unlock()
	}
}

// truncateDescr keeps sysDescr short enough for the inventory's OS column.
func truncateDescr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

func (a *DiscoveryAggregator) pollLoop(ctx context.Context, src DiscoverySource) {
	interval := src.Interval()
	if interval <= 0 {
		interval = 60 * time.Second
	}
	a.pollOnce(ctx, src)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.pollOnce(ctx, src)
		case <-a.refresh:
			a.pollOnce(ctx, src)
		}
	}
}

func (a *DiscoveryAggregator) pollOnce(ctx context.Context, src DiscoverySource) {
	devices, err := src.Poll(ctx)
	stat := sourceStats{LastPoll: time.Now().UTC(), Devices: len(devices)}
	if err != nil {
		stat.LastError = err.Error()
		log.Printf("discovery source %s poll error: %v", src.Name(), err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats[src.Name()] = stat
	for _, d := range devices {
		existing, ok := a.cache[d.ID]
		if ok && existing.Source != src.Name() {
			continue // higher-precedence source already won this id
		}
		d.Source = src.Name()
		d.LastSeen = time.Now().UTC()
		if d.Vendor == "" {
			if v, ok := a.detected[d.ID]; ok {
				d.Vendor = v
			}
		}
		a.cache[d.ID] = d
	}
}

func (a *DiscoveryAggregator) RefreshNow() {
	select {
	case a.refresh <- struct{}{}:
	default:
	}
}

func (a *DiscoveryAggregator) Devices() []models.Device {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]models.Device, 0, len(a.cache))
	for _, d := range a.cache {
		out = append(out, d)
	}
	return out
}

func (a *DiscoveryAggregator) Get(id string) (models.Device, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	d, ok := a.cache[id]
	return d, ok
}

func (a *DiscoveryAggregator) Upsert(d models.Device) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if d.Source == "" {
		d.Source = "manual"
	}
	d.LastSeen = time.Now().UTC()
	a.cache[d.ID] = d
}

func (a *DiscoveryAggregator) Delete(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.cache, id)
}

func (a *DiscoveryAggregator) Health() map[string]sourceStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make(map[string]sourceStats, len(a.stats))
	for k, v := range a.stats {
		out[k] = v
	}
	return out
}

// =============================================================================
// Static source — reads a small YAML file off disk.
// =============================================================================

type StaticSource struct {
	path string
}

func NewStaticSource(path string) *StaticSource {
	if path == "" {
		path = "/config/devices.yaml"
	}
	return &StaticSource{path: path}
}

func (s *StaticSource) Name() string            { return "static" }
func (s *StaticSource) Interval() time.Duration { return 60 * time.Second }
func (s *StaticSource) Poll(_ context.Context) ([]models.Device, error) {
	return ParseStaticDevices(s.path)
}

// ParseStaticDevices reads a YAML file shaped like:
//
//	devices:
//	  core-router-01:
//	    address: 10.0.0.1
//	    preferred_protocol: snmp
//	    credential_ref: corp-snmp
//	    labels:
//	      site: hq
//
// We accept this narrow shape only — the parser is hand-rolled to keep
// the build dependency-free. Swap for `gopkg.in/yaml.v3` when you need
// anchors, multi-doc, or arbitrary nesting.
func ParseStaticDevices(path string) ([]models.Device, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return parseStaticDevicesYAML(string(b))
}

func parseStaticDevicesYAML(s string) ([]models.Device, error) {
	var devices []models.Device
	var cur *models.Device
	inDevices := false
	inLabels := false
	labelIndent := -1

	flush := func() {
		if cur != nil && cur.ID != "" {
			devices = append(devices, *cur)
		}
		cur = nil
		inLabels = false
		labelIndent = -1
	}

	for _, raw := range strings.Split(s, "\n") {
		line := raw
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		trim := strings.TrimRight(line, " \t\r")
		if strings.TrimSpace(trim) == "" {
			continue
		}
		indent := indentOf(trim)
		body := strings.TrimSpace(trim)

		// Top-level
		if indent == 0 {
			flush()
			inDevices = body == "devices:"
			continue
		}
		if !inDevices {
			continue
		}
		// Device key: 2-space indented "name:"
		if indent == 2 && strings.HasSuffix(body, ":") {
			flush()
			cur = &models.Device{ID: strings.TrimSuffix(body, ":"), Name: strings.TrimSuffix(body, ":")}
			continue
		}
		if cur == nil {
			continue
		}
		// Inside labels block
		if inLabels && indent > labelIndent {
			if k, v, ok := splitKV(body); ok {
				if cur.Labels == nil {
					cur.Labels = map[string]string{}
				}
				cur.Labels[k] = unquoteValue(v)
			}
			continue
		}
		inLabels = false
		// Device fields
		switch {
		case strings.HasPrefix(body, "address:"):
			cur.Address = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "address:")))
		case strings.HasPrefix(body, "preferred_protocol:"):
			cur.PreferredProtocol = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "preferred_protocol:")))
		case strings.HasPrefix(body, "credential_ref:"):
			cur.CredentialRef = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "credential_ref:")))
		case strings.HasPrefix(body, "vendor:"):
			cur.Vendor = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "vendor:")))
		case strings.HasPrefix(body, "model:"):
			cur.Model = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "model:")))
		case strings.HasPrefix(body, "os:"):
			cur.OS = unquoteValue(strings.TrimSpace(strings.TrimPrefix(body, "os:")))
		case body == "labels:":
			inLabels = true
			labelIndent = indent
		}
	}
	flush()
	return devices, nil
}

func indentOf(s string) int {
	n := 0
	for _, c := range s {
		if c == ' ' {
			n++
		} else if c == '\t' {
			n += 2
		} else {
			break
		}
	}
	return n
}

func splitKV(s string) (string, string, bool) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}

func unquoteValue(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// =============================================================================
// SNMP source — real implementation lives in Telegraf now (SNMP polling
// is its job, not ours). Keep this stub for the diagram completeness;
// it never returns devices.
// =============================================================================

type SNMPSource struct {
	cidrRanges []string
}

func NewSNMPSource(cidrs string) *SNMPSource {
	ranges := strings.Split(cidrs, ",")
	clean := ranges[:0]
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if r != "" {
			clean = append(clean, r)
		}
	}
	return &SNMPSource{cidrRanges: clean}
}

func (s *SNMPSource) Name() string                                    { return "snmp" }
func (s *SNMPSource) Interval() time.Duration                         { return 5 * time.Minute }
func (s *SNMPSource) Poll(_ context.Context) ([]models.Device, error) { return nil, nil }

// =============================================================================
// Netbox source — real HTTP client.
// =============================================================================

type NetboxSource struct {
	url    string
	token  string
	client *http.Client
}

func NewNetboxSource(rawURL, token string) *NetboxSource {
	return &NetboxSource{
		url:    strings.TrimRight(rawURL, "/"),
		token:  token,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (n *NetboxSource) Name() string            { return "netbox" }
func (n *NetboxSource) Interval() time.Duration { return 60 * time.Second }

// netboxDevice is the subset of /dcim/devices/ we care about.
type netboxDevice struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	PrimaryIP *struct {
		Address string `json:"address"`
	} `json:"primary_ip"`
	DeviceType *struct {
		Manufacturer *struct {
			Name string `json:"name"`
		} `json:"manufacturer"`
		Model string `json:"model"`
	} `json:"device_type"`
	Platform *struct {
		Name string `json:"name"`
	} `json:"platform"`
	Site *struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"site"`
	Tags []struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"tags"`
}

type netboxResp struct {
	Count   int            `json:"count"`
	Next    *string        `json:"next"`
	Results []netboxDevice `json:"results"`
}

func (n *NetboxSource) Poll(ctx context.Context) ([]models.Device, error) {
	if n.url == "" || n.token == "" {
		return nil, errors.New("netbox not configured")
	}

	// SR-023: the API token rides in the Authorization header on EVERY request,
	// including the upstream-supplied `next` pagination URL. A compromised or
	// MITM'd Netbox could point `next` at an attacker host and harvest the token
	// (and SSRF the backend). Pin pagination to the configured instance's host.
	base, err := url.Parse(n.url)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("netbox: invalid NETBOX_URL %q: %w", n.url, err)
	}

	// Page through /dcim/devices/?limit=200.
	next := n.url + "/api/dcim/devices/?limit=200"
	var out []models.Device
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("Authorization", "Token "+n.token)
		req.Header.Set("Accept", "application/json")

		resp, err := n.client.Do(req)
		if err != nil {
			return out, err
		}
		if resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return out, fmt.Errorf("netbox %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var page netboxResp
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return out, err
		}
		resp.Body.Close()

		for _, d := range page.Results {
			dev := models.Device{
				ID:     fmt.Sprintf("netbox-%d", d.ID),
				Name:   d.Name,
				Labels: map[string]string{},
			}
			if d.PrimaryIP != nil && d.PrimaryIP.Address != "" {
				// "10.0.0.1/24" → "10.0.0.1"
				addr := d.PrimaryIP.Address
				if i := strings.Index(addr, "/"); i > 0 {
					addr = addr[:i]
				}
				dev.Address = addr
			}
			if d.DeviceType != nil {
				dev.Model = d.DeviceType.Model
				if d.DeviceType.Manufacturer != nil {
					dev.Vendor = d.DeviceType.Manufacturer.Name
				}
			}
			if d.Platform != nil {
				dev.OS = d.Platform.Name
			}
			if d.Site != nil {
				dev.Labels["site"] = d.Site.Slug
			}
			for _, t := range d.Tags {
				dev.Labels["tag_"+t.Slug] = "true"
			}
			out = append(out, dev)
		}

		// Advance to the next page only if Netbox supplied an absolute URL on the
		// SAME host as the configured instance (SR-023) — never follow a
		// cross-host `next` (it would leak the token / SSRF).
		next = ""
		if page.Next != nil && *page.Next != "" {
			nu, perr := url.Parse(*page.Next)
			switch {
			case perr != nil || (nu.Scheme != "http" && nu.Scheme != "https"):
				logWarn("discovery", "netbox: ignoring malformed pagination URL", nil)
			case !strings.EqualFold(nu.Host, base.Host):
				logWarn("discovery", "netbox: ignoring cross-host pagination URL", map[string]any{"got": nu.Host, "want": base.Host})
			default:
				next = *page.Next
			}
		}
	}

	return out, nil
}

// Quiet unused-import lint if url is ever removed; keeps it stable.
var _ = url.Parse
