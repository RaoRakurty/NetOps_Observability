package appid

import "time"

// scope.go — #81 Fusion Layer §A ScopeResolver. Determines WHAT an observation's
// identity decision applies to, and how strong that binding is. Exact session is
// strongest; destination-only is weakest. Pure + separately testable.

// ScopeMatch is the kind of binding an observation carries (strongest→weakest).
type ScopeMatch string

const (
	ScopeSession  ScopeMatch = "session"  // exact session_id (strongest)
	ScopeFlow     ScopeMatch = "flow"     // 5-tuple + time window
	ScopeWorkload ScopeMatch = "workload" // endpoint/workload-bound
	ScopeUser     ScopeMatch = "user"     // user-bound
	ScopeDomain   ScopeMatch = "domain"   // destination domain
	ScopeDstIP    ScopeMatch = "dst_ip"   // destination IP
	ScopeProvider ScopeMatch = "provider" // provider / ASN
	ScopePort     ScopeMatch = "port"     // port/protocol (weakest)
	ScopeNone     ScopeMatch = "none"
)

// strength is the §A scope-strength order (8 strongest … 1 weakest).
func (m ScopeMatch) strength() int {
	switch m {
	case ScopeSession:
		return 8
	case ScopeFlow:
		return 7
	case ScopeWorkload:
		return 6
	case ScopeUser:
		return 5
	case ScopeDomain:
		return 4
	case ScopeDstIP:
		return 3
	case ScopeProvider:
		return 2
	case ScopePort:
		return 1
	default:
		return 0
	}
}

// exact reports whether the scope identifies a single session/flow (vs coarser).
func (m ScopeMatch) exact() bool { return m == ScopeSession || m == ScopeFlow }

// ScopeResolution is the ScopeResolver output (§A).
type ScopeResolution struct {
	Type      ScopeMatch    `json:"type"`
	Key       string        `json:"key"`
	Window    time.Duration `json:"window"`
	Strength  int           `json:"strength"`
	Ambiguity []string      `json:"ambiguity,omitempty"` // nat_collapsed | shared_cdn | dst_only | ...
}

const defaultFlowWindow = 2 * time.Minute

// ResolveScope derives the scope of one observation. The binding is chosen from the
// strongest identifier the observation carries.
func ResolveScope(o ApplicationObservation) ScopeResolution {
	var amb []string
	switch {
	case o.SessionID != "":
		return ScopeResolution{Type: ScopeSession, Key: o.SessionID, Strength: ScopeSession.strength()}
	case o.FlowID != "":
		return ScopeResolution{Type: ScopeFlow, Key: o.FlowID, Window: defaultFlowWindow, Strength: ScopeFlow.strength()}
	case o.Workload != "":
		return ScopeResolution{Type: ScopeWorkload, Key: o.Workload, Strength: ScopeWorkload.strength()}
	case o.User != "":
		return ScopeResolution{Type: ScopeUser, Key: o.User, Strength: ScopeUser.strength()}
	}
	// destination-only bindings — flag the ambiguity the guardrails act on.
	amb = append(amb, "dst_only")
	switch o.Source {
	case SrcDNS, SrcSNI:
		return ScopeResolution{Type: ScopeDomain, Key: o.DstIP, Strength: ScopeDomain.strength(), Ambiguity: amb}
	case SrcIPCatalog:
		return ScopeResolution{Type: ScopeDstIP, Key: o.DstIP, Strength: ScopeDstIP.strength(), Ambiguity: amb}
	case SrcASN:
		return ScopeResolution{Type: ScopeProvider, Key: o.DstIP, Strength: ScopeProvider.strength(), Ambiguity: amb}
	case SrcPort:
		return ScopeResolution{Type: ScopePort, Key: itoa(o.DstPort), Strength: ScopePort.strength(), Ambiguity: amb}
	default:
		if o.DstIP != "" {
			return ScopeResolution{Type: ScopeDstIP, Key: o.DstIP, Strength: ScopeDstIP.strength(), Ambiguity: amb}
		}
		return ScopeResolution{Type: ScopeNone, Strength: 0, Ambiguity: amb}
	}
}

func itoa(n int) string {
	if n == 0 {
		return ""
	}
	// small positive ints only (ports) — avoid strconv import churn.
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
