package selfheal

// self_heal.go — appliance self-health guard (customer-grade, in-product).
//
// A full appliance disk flips OpenSearch indices read_only_allow_delete at the
// 95% flood watermark, and OpenSearch NEVER clears the block itself: disk
// recovers, ingest stays silently dead until an operator who knows the trick
// clears it by hand. That is a §10 no-silent-failures violation waiting at
// every customer site (it cost this project a full log outage once, and again
// on 2026-07-14). This guard runs INSIDE the api so a customer deployment
// needs zero host-side setup:
//
//   watch  — appliance disk usage (the api's own /data bind mount is on the
//            appliance filesystem) + OpenSearch read-only index blocks
//   heal   — clear the blocks automatically once disk is back under the safe
//            watermark (never while the disk is still hot)
//   tell   — page the operator through the EXISTING platform self-health lane
//            (layer=stack → the customer's configured channels; notify/
//            platform_scope.go keeps it off tenant lanes), and expose the
//            state on the Stack health surface — a heal is an event, never
//            silent housekeeping
//
// The complementary ALERTING half already ships: rules.yaml HostDiskAlmostFull
// (layer=host) pages before the cliff. This is the after-the-cliff recovery.
//
// Config: SELF_HEAL=false disables the HEAL action (watching + surfacing stay
// on — visibility is never optional); SELF_HEAL_CLEAR_PCT (default 90) is the
// disk ceiling above which blocks are left in place.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

type Snapshot struct {
	Enabled        bool     `json:"enabled"`
	DiskPct        int      `json:"disk_pct"` // -1 = not measurable
	DiskPath       string   `json:"disk_path"`
	BlockedIndices int      `json:"blocked_indices"`
	BlockedSample  []string `json:"blocked_sample,omitempty"` // first few names
	LastCheck      string   `json:"last_check,omitempty"`
	LastHeal       string   `json:"last_heal,omitempty"`
	LastHealCount  int      `json:"last_heal_count,omitempty"`
	LastHealResult string   `json:"last_heal_result,omitempty"` // healed | failed
}

type Healer struct {
	cfg      Config
	notifier *notify.Dispatcher
	osURL    string
	diskPath string
	clearPct int
	enabled  bool
	interval time.Duration

	// diskPctFn measures the filesystem holding diskPath. Injectable so a test
	// can drive the heal decision deterministically instead of reading the real
	// host disk — the previous test used t.TempDir() and passed or failed purely
	// on whatever the host's /tmp happened to be, which made a merge-blocking
	// test flaky (it failed at 91% host usage, which is a genuine disk problem,
	// not a code fault). nil means "use the real diskUsedPct".
	diskPctFn func(string) int

	mu    sync.Mutex
	state Snapshot
}

// measureDisk returns the disk usage percent, via the injected function when a
// test set one, else the real filesystem measurement.
func (h *Healer) measureDisk() int {
	if h.diskPctFn != nil {
		return h.diskPctFn(h.diskPath)
	}
	return diskUsedPct(h.diskPath)
}

// Config carries the healer's knobs (env reads live in the integrator).
type Config struct {
	OSURL    string // OpenSearch base URL
	DiskPath string // filesystem to measure
	ClearPct int    // heal only below this used%% (hysteresis)
	Enabled  bool
	HTTP     func(timeout time.Duration) *http.Client // platform mTLS-aware client
	Infof    func(component, msg string, fields map[string]any)
	Errorf   func(component, msg string, fields map[string]any)
}

func NewHealer(notifier *notify.Dispatcher, cfg Config) *Healer {
	if cfg.ClearPct <= 0 || cfg.ClearPct >= 100 {
		cfg.ClearPct = 90
	}
	if cfg.HTTP == nil {
		cfg.HTTP = func(timeout time.Duration) *http.Client { return &http.Client{Timeout: timeout} }
	}
	if cfg.Infof == nil {
		cfg.Infof = func(string, string, map[string]any) {}
	}
	if cfg.Errorf == nil {
		cfg.Errorf = func(string, string, map[string]any) {}
	}
	return &Healer{
		notifier: notifier,
		cfg:      cfg,
		osURL:    strings.TrimRight(cfg.OSURL, "/"),
		diskPath: cfg.DiskPath,
		clearPct: cfg.ClearPct,
		enabled:  cfg.Enabled,
		interval: time.Minute,
	}
}

// diskUsedPct measures the filesystem holding path, the same way df does
// (used vs used+available-to-unprivileged). -1 = not measurable — an honest
// unknown, never treated as healthy.
func diskUsedPct(path string) int {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return -1
	}
	used := st.Blocks - st.Bfree
	total := used + st.Bavail
	if total == 0 {
		return -1
	}
	return int(used * 100 / total)
}

// shouldHeal is the ONE decision rule (unit-tested): heal only when there is
// something to heal AND the disk is verifiably back under the safe watermark.
// An unmeasurable disk (-1) never heals — we won't unlock indices blind.
func shouldHeal(diskPct, clearPct, blocked int) bool {
	return blocked > 0 && diskPct >= 0 && diskPct < clearPct
}

// osBlockedIndices lists indices carrying read_only_allow_delete=true.
func (h *Healer) osBlockedIndices(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		h.osURL+"/_all/_settings/index.blocks.read_only_allow_delete", nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.cfg.HTTP(8 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on close failure
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opensearch settings read: status %d", resp.StatusCode)
	}
	return parseBlockedIndices(body)
}

// parseBlockedIndices is the pure parser (unit-tested): OS returns
// {"<index>":{"settings":{"index":{"blocks":{"read_only_allow_delete":"true"}}}}}
// for each index carrying the block, {} when none.
func parseBlockedIndices(body []byte) ([]string, error) {
	var raw map[string]struct {
		Settings struct {
			Index struct {
				Blocks struct {
					ReadOnlyAllowDelete string `json:"read_only_allow_delete"`
				} `json:"blocks"`
			} `json:"index"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	var out []string
	for idx, v := range raw {
		if v.Settings.Index.Blocks.ReadOnlyAllowDelete == "true" {
			out = append(out, idx)
		}
	}
	return out, nil
}

func (h *Healer) clearBlocks(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, h.osURL+"/_all/_settings",
		strings.NewReader(`{"index.blocks.read_only_allow_delete": null}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.cfg.HTTP(15 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on close failure
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("opensearch unblock: status %d", resp.StatusCode)
	}
	return nil
}

// alert pages the operator through the platform self-health lane. layer=stack
// is the typed marker notify.PlatformScopeFilter allowlists onto the global
// channels — and keeps this OFF every tenant lane (it is platform plumbing).
func (h *Healer) alert(severity, summary, detail string) {
	if h.notifier == nil {
		return
	}
	h.notifier.Dispatch(models.Alert{
		ID:          "self-heal-" + strconv.FormatInt(time.Now().Unix(), 10),
		Rule:        "StackIngestSelfHeal",
		Severity:    severity,
		Summary:     summary,
		Description: detail,
		Labels:      map[string]string{"layer": "stack", "component": "opensearch"},
		FiredAt:     time.Now().UTC(),
	})
}

// CurrentSnapshot reports the last cycle for /api/stack/health.
func (h *Healer) CurrentSnapshot() Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// run is the 1-minute guard loop. Healing fires at most once per episode: the
// action itself is the edge (blocks exist → cleared); a failed heal re-tries
// next tick but only re-alerts when the failure is new.
// Run is the healer loop (integrator worker entrypoint).
func (h *Healer) Run(ctx context.Context) {
	lastFailAlert := time.Time{}
	t := time.NewTicker(h.interval)
	defer t.Stop()
	for {
		diskPct := h.measureDisk()
		blocked, err := h.osBlockedIndices(ctx)
		h.mu.Lock()
		h.state.Enabled = h.enabled
		h.state.DiskPct = diskPct
		h.state.DiskPath = h.diskPath
		h.state.LastCheck = time.Now().UTC().Format(time.RFC3339)
		if err == nil {
			h.state.BlockedIndices = len(blocked)
			sample := blocked
			if len(sample) > 5 {
				sample = sample[:5]
			}
			h.state.BlockedSample = sample
		}
		h.mu.Unlock()

		if err == nil && h.enabled && shouldHeal(diskPct, h.clearPct, len(blocked)) {
			healErr := h.clearBlocks(ctx)
			h.mu.Lock()
			h.state.LastHeal = time.Now().UTC().Format(time.RFC3339)
			h.state.LastHealCount = len(blocked)
			if healErr == nil {
				h.state.LastHealResult = "healed"
				h.state.BlockedIndices = 0
				h.state.BlockedSample = nil
			} else {
				h.state.LastHealResult = "failed"
			}
			h.mu.Unlock()
			if healErr == nil {
				h.cfg.Infof("self_heal", "cleared read-only blocks", map[string]any{"indices": len(blocked), "disk_pct": diskPct})
				h.alert("warning",
					fmt.Sprintf("Ingest self-healed: cleared read-only blocks on %d indices", len(blocked)),
					fmt.Sprintf("The search store had flipped %d indices read-only during disk pressure; disk is back at %d%% so the platform cleared the blocks and log ingestion has resumed. Investigate what filled the disk.", len(blocked), diskPct))
			} else if time.Since(lastFailAlert) > time.Hour {
				lastFailAlert = time.Now()
				h.cfg.Errorf("self_heal", "unblock failed", map[string]any{"error": healErr.Error()})
				h.alert("critical",
					fmt.Sprintf("Ingest self-heal FAILED: %d indices remain read-only", len(blocked)),
					"The search store has read-only index blocks and the automatic clear failed — log ingestion is dead until cleared. Error: "+healErr.Error())
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
