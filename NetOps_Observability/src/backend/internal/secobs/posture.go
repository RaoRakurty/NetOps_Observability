package secobs

import (
	"fmt"
	"strings"
	"time"
)

// posture.go assembles the SEC-021.1 read-only transport posture: the declared
// state of every hop (transport inventory) joined with the observed state (the
// SEC-019.1 served-certificate probe). Pure functions over injected data — the
// HTTP handler supplies the probe snapshot, so this package depends on neither
// tlsprobe nor the server.
//
// Honesty rules (HLD §6.6 / backlog C4): a hop with no probe coverage reports
// "not probed", never "secure"; a device lane that is unauthenticated says so
// with its declared reason; drift is computed only where an observation exists.

// ProbeObservation is one endpoint's served-certificate state, mapped by the
// caller from the tlsprobe result set.
type ProbeObservation struct {
	OK        bool      `json:"probe_ok"`
	NotAfter  time.Time `json:"cert_not_after"`
	CheckedAt time.Time `json:"last_checked"`
}

// PostureRow is one edge of the posture table: declared on the left, observed
// on the right, drift when the two disagree.
type PostureRow struct {
	Edge         string `json:"edge"`
	Source       string `json:"source"`
	Destination  string `json:"destination"`
	Channel      string `json:"channel"`
	Protocol     string `json:"protocol"`
	Port         int    `json:"port,omitempty"`
	TrustDomain  string `json:"trust_domain"`
	OwningEpic   string `json:"owning_epic"`
	CurrentTier  string `json:"current_tier"`  // base compose (fresh install)
	DeclaredTier string `json:"declared_tier"` // with the TLS profile enabled
	TargetTier   string `json:"target_tier"`   // agreed v1 end state
	// Identity is the destination's SPIFFE id when it holds a workload
	// identity (stamped by the caller, which knows the trust domain); "" for
	// external peers and exempt services.
	Identity string `json:"identity,omitempty"`
	// Observed is nil when no probe watches this edge's destination — rendered
	// as "not probed", never assumed green.
	Observed *ProbeObservation `json:"observed,omitempty"`
	// Drift is "" when declared and observed agree (or no observation exists).
	Drift string `json:"drift,omitempty"`
	// Exception + AgeDays surface declared plaintext with its owner and age.
	Exception *Exception `json:"exception,omitempty"`
	AgeDays   int        `json:"exception_age_days,omitempty"`
}

// tierExpectsTLS reports whether a declared tier means "a certificate is
// served on this hop". Tier names are the inventory's vocabulary: anything
// containing "tls" (tls, mtls, tls-via-vmauth, tls-verify-full, …) except the
// explicit plaintext markers.
func tierExpectsTLS(tier string) bool {
	t := strings.ToLower(tier)
	return strings.Contains(t, "tls") && !strings.Contains(t, "plaintext")
}

// BuildPosture joins the inventory with the probe snapshot. probes is keyed by
// the tlsprobe endpoint name ("postgres:5432"); an edge matches when its
// destination:port equals the key. now drives exception ageing; nil = time.Now.
func BuildPosture(inv *Inventory, probes map[string]ProbeObservation, now func() time.Time) []PostureRow {
	if now == nil {
		now = time.Now
	}
	if inv == nil {
		return nil
	}
	rows := make([]PostureRow, 0, len(inv.Edges))
	for _, e := range inv.Edges {
		row := PostureRow{
			Edge:         e.ID,
			Source:       e.Source,
			Destination:  e.Destination,
			Channel:      e.Channel,
			Protocol:     e.Protocol,
			Port:         e.Port,
			TrustDomain:  e.TrustDomain,
			OwningEpic:   e.OwningEpic,
			CurrentTier:  e.Current.Transport,
			DeclaredTier: e.DeclaredTier(),
			TargetTier:   e.Target.Transport,
			Exception:    e.Exception,
		}
		if e.Exception != nil {
			if at, err := e.Exception.AcceptedTime(); err == nil {
				row.AgeDays = int(now().Sub(at).Hours() / 24)
			}
		}
		if e.Port != 0 {
			key := fmt.Sprintf("%s:%d", e.Destination, e.Port)
			if obs, found := probes[key]; found {
				o := obs
				row.Observed = &o
				switch {
				case tierExpectsTLS(row.DeclaredTier) && !obs.OK:
					row.Drift = "declared " + row.DeclaredTier + " but no certificate observed on the wire"
				case tierExpectsTLS(row.DeclaredTier) && !obs.NotAfter.IsZero() && obs.NotAfter.Before(now()):
					row.Drift = "served certificate is EXPIRED"
				case !tierExpectsTLS(row.DeclaredTier) && obs.OK:
					// The good direction of drift — enforcement ran ahead of
					// the declaration. Surfaced so the inventory gets updated.
					row.Drift = "certificate observed on an edge declared " + row.DeclaredTier
				}
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// DeviceLaneRows filters the posture to the device trust domain — the lanes a
// tenant's devices ride. This is the tenant-visible slice: platform-internal
// hops (workload/operator/public domains) are deliberately absent.
func DeviceLaneRows(rows []PostureRow) []PostureRow {
	var out []PostureRow
	for _, r := range rows {
		if r.TrustDomain == "device" {
			out = append(out, r)
		}
	}
	return out
}

// PostureTable renders rows for the exportable report: fixed header, one line
// per edge, observation and drift verbalized. Cell text only — no markup.
func PostureTable(rows []PostureRow, now func() time.Time) (header []string, cells [][]string) {
	if now == nil {
		now = time.Now
	}
	header = []string{"Edge", "Channel", "Declared", "Target", "Peer identity", "Observed", "Cert expires", "Drift / exception"}
	for _, r := range rows {
		observed := "not probed"
		expiry := "—"
		if r.Observed != nil {
			if r.Observed.OK {
				observed = "certificate served"
				expiry = fmt.Sprintf("%.1fd", r.Observed.NotAfter.Sub(now()).Hours()/24)
			} else {
				observed = "NO certificate"
			}
		}
		note := r.Drift
		if r.Exception != nil {
			exc := fmt.Sprintf("declared exception (owner %s, accepted %s, %dd ago): %s",
				r.Exception.Owner, r.Exception.Accepted, r.AgeDays, r.Exception.Reason)
			if note != "" {
				note += "; " + exc
			} else {
				note = exc
			}
		}
		identity := r.Identity
		if identity == "" {
			identity = "—"
		}
		cells = append(cells, []string{
			r.Edge, r.Channel, r.DeclaredTier, r.TargetTier, identity, observed, expiry, note,
		})
	}
	return header, cells
}
