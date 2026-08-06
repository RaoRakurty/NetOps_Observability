package secobs

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// inventory.go reads docs/security/transport-inventory.yaml — the SEC-001
// declared-transport ledger. The file's content is JSON (deliberately: valid
// YAML 1.2, parseable by the stdlib here and by the stdlib-only preflight), so
// encoding/json is the whole parser.
//
// The runtime copy rides in the api image (Dockerfile.backend COPYs it;
// TRANSPORT_INVENTORY_PATH overrides for tests and unusual layouts). A missing
// or malformed inventory is a loud error: posture built on a silently absent
// declaration table would report "nothing declared" as "nothing exposed".

// EdgeSide is one of an edge's declared states (current / security_profile /
// target).
type EdgeSide struct {
	Transport string `json:"transport"`
	Authn     string `json:"authn,omitempty"`
	Authz     string `json:"authz,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

// Exception is a declared, owner-accepted plaintext end state (the honesty
// mechanism: accepted plaintext must carry an owner and an accepted date so it
// can age visibly instead of silently).
type Exception struct {
	Owner    string `json:"owner"`
	Accepted string `json:"accepted"` // YYYY-MM-DD, the last review date
	Reason   string `json:"reason"`
}

// AcceptedTime parses the accepted date. An exception with an unparseable date
// is an inventory bug and surfaces as an error, never as age zero.
func (e Exception) AcceptedTime() (time.Time, error) {
	t, err := time.Parse("2006-01-02", e.Accepted)
	if err != nil {
		return time.Time{}, fmt.Errorf("exception accepted date %q: %w", e.Accepted, err)
	}
	return t, nil
}

// Edge is one hop of the transport inventory.
type Edge struct {
	ID          string   `json:"id"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Channel     string   `json:"channel"`
	Protocol    string   `json:"protocol"`
	Port        int      `json:"port"`
	Current     EdgeSide `json:"current"`
	// SecurityProfile is nil on edges whose state does not change when the TLS
	// profile is enabled (14 of 33 at the time of writing) — Current applies.
	SecurityProfile *EdgeSide  `json:"security_profile,omitempty"`
	Target          EdgeSide   `json:"target"`
	TrustDomain     string     `json:"trust_domain"`
	OwningEpic      string     `json:"owning_epic"`
	Priority        string     `json:"priority"`
	Evidence        []string   `json:"evidence"`
	Exception       *Exception `json:"exception,omitempty"`
}

// DeclaredTier is the edge's declared transport once the TLS profile is on:
// the security_profile state when present, else the current state.
func (e Edge) DeclaredTier() string {
	if e.SecurityProfile != nil {
		return e.SecurityProfile.Transport
	}
	return e.Current.Transport
}

// Inventory is the parsed file.
type Inventory struct {
	SchemaVersion int      `json:"schema_version"`
	Updated       string   `json:"updated"`
	ExternalPeers []string `json:"external_peers"`
	Edges         []Edge   `json:"edges"`
}

// LoadInventory reads and validates the inventory at path.
func LoadInventory(path string) (*Inventory, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured TRANSPORT_INVENTORY_PATH / image-baked constant, not user input
	if err != nil {
		return nil, fmt.Errorf("transport inventory: %w", err)
	}
	var inv Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		return nil, fmt.Errorf("transport inventory %s: %w", path, err)
	}
	if inv.SchemaVersion != 1 {
		return nil, fmt.Errorf("transport inventory %s: unsupported schema_version %d", path, inv.SchemaVersion)
	}
	if len(inv.Edges) == 0 {
		return nil, fmt.Errorf("transport inventory %s: no edges", path)
	}
	seen := make(map[string]bool, len(inv.Edges))
	for _, e := range inv.Edges {
		if e.ID == "" || e.Source == "" || e.Destination == "" || e.Channel == "" {
			return nil, fmt.Errorf("transport inventory %s: edge %+q missing id/source/destination/channel", path, e.ID)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("transport inventory %s: duplicate edge id %q", path, e.ID)
		}
		seen[e.ID] = true
		if e.Exception != nil {
			if e.Exception.Owner == "" || e.Exception.Reason == "" {
				return nil, fmt.Errorf("transport inventory %s: edge %q exception must carry owner and reason", path, e.ID)
			}
			if _, err := e.Exception.AcceptedTime(); err != nil {
				return nil, fmt.Errorf("transport inventory %s: edge %q: %w", path, e.ID, err)
			}
		}
	}
	return &inv, nil
}

// DeclaredTierCensus counts edges by declared tier, sorted by tier name for a
// stable metric emission order.
func (inv *Inventory) DeclaredTierCensus() []TierCount {
	c := map[string]int{}
	for _, e := range inv.Edges {
		c[e.DeclaredTier()]++
	}
	out := make([]TierCount, 0, len(c))
	for tier, n := range c {
		out = append(out, TierCount{Tier: tier, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tier < out[j].Tier })
	return out
}

// TierCount is one row of the declared-tier census.
type TierCount struct {
	Tier  string
	Count int
}

// Exceptions returns every edge carrying a declared exception, sorted by edge
// id for stable emission and rendering order.
func (inv *Inventory) Exceptions() []Edge {
	var out []Edge
	for _, e := range inv.Edges {
		if e.Exception != nil {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
