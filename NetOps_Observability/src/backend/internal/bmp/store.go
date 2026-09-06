// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// store.go — the in-memory, tenant-keyed, BOUNDED record of what arrived.
//
// Two invariants hold this file together:
//
//  1. TENANCY IS STRUCTURAL. Every session carries the tenant stamped from the
//     resolved inventory device at connect time, and there is NO method that
//     lists sessions or updates without a (tenant, cross) pair. The store
//     itself is the filter (§3a rule 4), so a handler cannot forget to apply
//     one — the only way to read is to say who you are, and a caller with no
//     tenant and no cross-tenant grant reads NOTHING.
//
//  2. MEMORY IS BOUNDED IN EVERY DIRECTION. Sessions are capped
//     (MaxSessionRecords, evicting the oldest CLOSED record and never a live
//     one); updates are a fixed-size ring per session (MaxUpdatesPerSession,
//     drop-oldest with a counter); peers per session are capped. Nothing here
//     grows with what a router chooses to send.

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxPeersPerSession caps the peer table one session may build. A router
// monitoring thousands of BGP peers is legitimate; an unbounded map driven by
// a hostile peer-address field is not.
const maxPeersPerSession = 1024

// Store errors.
var (
	// ErrAtCapacity means the receiver is already holding its maximum number of
	// sessions and none of them can be evicted without discarding a LIVE one.
	ErrAtCapacity = errors.New("bmp: receiver at capacity")
	// ErrNoTenant means a session was opened without a tenant. It is a wiring
	// bug and is refused: an unattributed feed must never be stored (§3a).
	ErrNoTenant = errors.New("bmp: refusing to store a session with no tenant")
)

// RIB names which routing table the feed reflects. Presenting an Adj-RIB-Out
// (what we advertise) as an Adj-RIB-In (what we learned) would invert the
// meaning of every prefix on the screen, so it is recorded per peer.
const (
	ribInPre  = "adj-rib-in-pre-policy"
	ribInPost = "adj-rib-in-post-policy"
	ribOut    = "adj-rib-out"
)

// peerState is one monitored BGP peer as seen through this session.
type peerState struct {
	addr       netip.Addr
	as         uint32
	bgpID      netip.Addr
	rib        string
	up         bool
	seen       bool // a Peer Up or Peer Down was actually observed
	changedAt  time.Time
	downReason string
	updates    uint64
	withdraws  uint64
}

// sessionState is the mutable per-connection record.
type sessionState struct {
	id         string
	tenantID   string
	deviceID   string
	remoteAddr string
	routerName string
	routerDesc string
	openedAt   time.Time
	closedAt   time.Time
	closed     bool
	closeNote  string

	peers    map[string]*peerState
	peersCap bool // the peer table hit maxPeersPerSession and is incomplete

	messages    map[string]uint64
	parseErrors uint64
	unsupported uint64

	ring *updateRing
}

// UpdateRecord is one PREFIX-level event: the unit the read API pages over.
// One BGP UPDATE fans out into one record per announced or withdrawn prefix,
// because that is the granularity an operator searches by.
type UpdateRecord struct {
	Seq       uint64
	At        time.Time
	SessionID string
	TenantID  string
	DeviceID  string

	PeerAddr string
	PeerAS   uint32
	RIB      string

	// Kind is "announce" or "withdraw".
	Kind   string
	Prefix netip.Prefix

	NextHop          string
	Origin           string
	ASPath           []uint32
	Communities      []string
	LargeCommunities []string
	MED              *uint32
	LocalPref        *uint32
	// PartialAttrs marks a record built from an update that hit an internal
	// bound or carried families/attributes we did not decode. The flag travels
	// with the row so an incomplete record is never read as a complete one.
	PartialAttrs bool
}

// updateRing is a fixed-capacity, drop-oldest ring. It allocates its whole
// backing array once, so a session's memory footprint is known at open time
// rather than discovered under load.
type updateRing struct {
	buf     []UpdateRecord
	head    int // next write position
	count   int
	dropped uint64
}

func newUpdateRing(capacity int) *updateRing {
	if capacity < 1 {
		capacity = 1
	}
	return &updateRing{buf: make([]UpdateRecord, capacity)}
}

// push adds a record, evicting the oldest when full and counting the eviction.
func (r *updateRing) push(rec UpdateRecord) {
	if r.count == len(r.buf) {
		r.dropped++
	} else {
		r.count++
	}
	r.buf[r.head] = rec
	r.head = (r.head + 1) % len(r.buf)
}

// newestFirst walks the ring from the most recent record backwards, calling fn
// until it returns false. It copies nothing until the caller keeps a record.
func (r *updateRing) newestFirst(fn func(UpdateRecord) bool) {
	for i := 0; i < r.count; i++ {
		idx := (r.head - 1 - i + len(r.buf)*2) % len(r.buf)
		if !fn(r.buf[idx]) {
			return
		}
	}
}

// Store holds every session's state. It is safe for concurrent use: the
// listener writes from N connection goroutines while the HTTP handlers read.
type Store struct {
	mu        sync.Mutex
	sessions  map[string]*sessionState
	order     []string // insertion order, for deterministic eviction
	seq       uint64
	maxRecs   int
	ringDepth int
	now       func() time.Time
}

// NewStore builds the store. maxRecords caps session records (live + closed)
// and ringDepth caps updates held per session; both fall back to the package
// constants when non-positive, so a miswired zero can never mean "unbounded".
func NewStore(now func() time.Time, maxRecords, ringDepth int) *Store {
	if now == nil {
		now = time.Now
	}
	if maxRecords <= 0 {
		maxRecords = MaxSessionRecords
	}
	if ringDepth <= 0 {
		ringDepth = MaxUpdatesPerSession
	}
	return &Store{
		sessions:  map[string]*sessionState{},
		maxRecs:   maxRecords,
		ringDepth: ringDepth,
		now:       now,
	}
}

// Open registers a new session. tenantID MUST be non-empty — the caller has
// already resolved the remote address against the inventory, and a session
// that could not be attributed is closed rather than stored (§3a).
func (s *Store) Open(id, tenantID, deviceID, remoteAddr string) error {
	if strings.TrimSpace(tenantID) == "" {
		return ErrNoTenant
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[id]; exists {
		// A duplicate id means the previous session for this connection was
		// never closed. Reuse is not safe (its counters belong to a different
		// connection), so refuse rather than silently merge two routers' feeds.
		return ErrAtCapacity
	}
	if len(s.sessions) >= s.maxRecs && !s.evictOldestClosedLocked() {
		return ErrAtCapacity
	}
	s.sessions[id] = &sessionState{
		id:         id,
		tenantID:   tenantID,
		deviceID:   deviceID,
		remoteAddr: remoteAddr,
		openedAt:   s.now(),
		peers:      map[string]*peerState{},
		messages:   map[string]uint64{},
		ring:       newUpdateRing(s.ringDepth),
	}
	s.order = append(s.order, id)
	return nil
}

// evictOldestClosedLocked drops the oldest CLOSED session record. It returns
// false when every record is live — in which case the new connection is
// refused, because evicting a live session would silently stop monitoring a
// router that is still talking to us.
func (s *Store) evictOldestClosedLocked() bool {
	for i, id := range s.order {
		st, ok := s.sessions[id]
		if !ok {
			continue
		}
		if st.closed {
			delete(s.sessions, id)
			s.order = append(s.order[:i:i], s.order[i+1:]...)
			return true
		}
	}
	return false
}

// Close marks a session closed with an operator-readable reason.
func (s *Store) Close(id, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sessions[id]
	if !ok {
		return
	}
	st.closed = true
	st.closedAt = s.now()
	st.closeNote = reason
	for _, p := range st.peers {
		// The session is gone, so every peer's state is now UNKNOWN rather than
		// up. Reporting a stale "up" after the feed died is exactly the
		// comfortable lie this module exists not to tell.
		p.up = false
		p.seen = false
		p.changedAt = st.closedAt
		if p.downReason == "" {
			p.downReason = "bmp session closed"
		}
	}
}

// RecordParseError counts a skipped frame against the session.
func (s *Store) RecordParseError(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.sessions[id]; ok {
		st.parseErrors++
	}
}

// MaxAnnouncedPerMessage bounds how many announced prefixes ONE message reports
// back through Applied.Announced. The observer this feeds (bogon sightings) is
// a screen, not an archive — the ring is still the record — so a jumbo update
// contributes a bounded slice rather than an unbounded allocation on the
// receive path (§9).
const MaxAnnouncedPerMessage = 64

// AnnouncedPrefix is ONE NLRI this receiver just stored, stamped with the
// session's OWNING TENANT (resolved from inventory at session open — never from
// anything the peer said). It exists so an observer can act on an announcement
// the moment it arrives without polling the ring, and without this package
// having to know what the observer is for.
//
// It deliberately carries NO origin: BGP's ORIGIN attribute is igp/egp/
// incomplete, not an ASN, and the sighting register's Origin field is an ASN.
// Handing one where the other is meant would put a wrong number on the page —
// and the periodic sweep (which reads the ring) leaves it unset for BMP rows,
// so an immediate note that filled it in would make the same sighting look
// different depending on which path saw it first.
type AnnouncedPrefix struct {
	TenantID string
	DeviceID string
	PeerAddr string
	Prefix   netip.Prefix
	At       time.Time
}

// Applied reports what one message contributed, so the caller can move the
// package-level metrics without reaching into the store's lock.
type Applied struct {
	StoredUpdates       int
	DroppedUpdates      int
	UnsupportedFamilies int
	UnknownAttributes   int
	// Announced carries up to MaxAnnouncedPerMessage of the prefixes this
	// message announced, for the caller's observer. It is returned rather than
	// dispatched from inside Apply on purpose: Apply holds the store lock, and
	// calling an injected function under it would let a slow observer stall
	// every session in the process.
	Announced []AnnouncedPrefix
}

// Apply folds one parsed message into the session record.
func (s *Store) Apply(id string, msg *Message) Applied {
	var out Applied
	if msg == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sessions[id]
	if !ok {
		return out
	}
	st.messages[msg.Header.Type.String()]++

	switch {
	case msg.Initiation != nil:
		if msg.Initiation.SysName != "" {
			st.routerName = msg.Initiation.SysName
		}
		if msg.Initiation.SysDesc != "" {
			st.routerDesc = msg.Initiation.SysDesc
		}
	case msg.Termination != nil:
		st.closeNote = "router sent termination"
	case msg.PeerUp != nil && msg.Peer != nil:
		if p := st.peer(msg.Peer); p != nil {
			p.up, p.seen, p.changedAt, p.downReason = true, true, s.now(), ""
		} else {
			st.peersCap = true
		}
	case msg.PeerDown != nil && msg.Peer != nil:
		if p := st.peer(msg.Peer); p != nil {
			p.up, p.seen, p.changedAt = false, true, s.now()
			p.downReason = msg.PeerDown.ReasonText()
		} else {
			st.peersCap = true
		}
	case msg.Update != nil && msg.Peer != nil:
		out = st.applyUpdate(s, msg)
	}
	return out
}

// peer returns the per-peer record, creating it within the cap. A nil return
// means the peer table is full; the caller records that the table is partial
// rather than silently discarding the observation.
func (st *sessionState) applyUpdate(s *Store, msg *Message) Applied {
	var out Applied
	u := msg.Update
	out.UnsupportedFamilies = u.UnsupportedFamilies
	out.UnknownAttributes = u.UnknownAttributes

	p := st.peer(msg.Peer)
	if p == nil {
		st.peersCap = true
	}
	partial := u.Truncated || u.UnsupportedFamilies > 0
	nextHop := ""
	if u.HasNextHop {
		nextHop = u.NextHop.String()
	}
	var med, localPref *uint32
	if u.HasMED {
		v := u.MED
		med = &v
	}
	if u.HasLocalPref {
		v := u.LocalPref
		localPref = &v
	}
	rib := ribFor(msg.Peer)
	at := s.now()

	add := func(kind string, prefix netip.Prefix) {
		s.seq++
		before := st.ring.dropped
		rec := UpdateRecord{
			Seq:          s.seq,
			At:           at,
			SessionID:    st.id,
			TenantID:     st.tenantID,
			DeviceID:     st.deviceID,
			PeerAddr:     msg.Peer.Address.String(),
			PeerAS:       msg.Peer.AS,
			RIB:          rib,
			Kind:         kind,
			Prefix:       prefix,
			Origin:       u.Origin,
			PartialAttrs: partial,
		}
		if kind == "announce" {
			// Withdrawals carry no path attributes; attaching the announcement's
			// would attribute a next hop to a route that was just removed.
			rec.NextHop = nextHop
			rec.ASPath = cloneU32(u.ASPath)
			rec.Communities = cloneStrings(u.Communities)
			rec.LargeCommunities = cloneStrings(u.LargeCommunities)
			rec.MED, rec.LocalPref = med, localPref
		} else {
			rec.Origin = ""
		}
		st.ring.push(rec)
		out.StoredUpdates++
		if st.ring.dropped > before {
			out.DroppedUpdates++
		}
		if kind == "announce" && len(out.Announced) < MaxAnnouncedPerMessage {
			out.Announced = append(out.Announced, AnnouncedPrefix{
				TenantID: st.tenantID, DeviceID: st.deviceID,
				PeerAddr: rec.PeerAddr, Prefix: prefix, At: at,
			})
		}
	}

	for _, pfx := range u.Announced {
		add("announce", pfx)
		if p != nil {
			p.updates++
		}
	}
	for _, pfx := range u.Withdrawn {
		add("withdraw", pfx)
		if p != nil {
			p.withdraws++
		}
	}
	if u.UnsupportedFamilies > 0 || u.UnknownAttributes > 0 {
		st.unsupported += countU64(u.UnsupportedFamilies) + countU64(u.UnknownAttributes)
	}
	return out
}

// peer returns (creating within the cap) the record for a per-peer header.
func (st *sessionState) peer(ph *PeerHeader) *peerState {
	key := peerKey(ph)
	if p, ok := st.peers[key]; ok {
		return p
	}
	if len(st.peers) >= maxPeersPerSession {
		return nil
	}
	p := &peerState{addr: ph.Address, as: ph.AS, bgpID: ph.BGPID, rib: ribFor(ph)}
	st.peers[key] = p
	return p
}

// peerKey identifies a monitored peer within a session. The route distinguisher
// is part of the key so the same address in two VRFs is two peers.
func peerKey(ph *PeerHeader) string {
	var b strings.Builder
	b.WriteString(ph.Address.String())
	b.WriteByte('|')
	b.WriteString(uitoa(uint64(ph.AS)))
	b.WriteByte('|')
	b.WriteString(uitoa(ph.Distinguisher))
	b.WriteByte('|')
	b.WriteString(ribFor(ph))
	return b.String()
}

// ribFor names which table the peer's feed reflects (RFC 7854 §4.2 L flag,
// RFC 8671 O flag).
func ribFor(ph *PeerHeader) string {
	switch {
	case ph == nil:
		return ribInPre
	case ph.AdjRIBOut():
		return ribOut
	case ph.PostPolicy():
		return ribInPost
	default:
		return ribInPre
	}
}

func uitoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// countU64 widens a non-negative count. A negative input is a programming bug,
// and clamping it to zero is the safe rendering: a counter that wraps to
// eighteen quintillion is a number an operator would act on.
func countU64(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

func cloneU32(src []uint32) []uint32 {
	if len(src) == 0 {
		return nil
	}
	out := make([]uint32, len(src))
	copy(out, src)
	return out
}

func cloneStrings(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// ── reads (always tenant-scoped) ────────────────────────────────────────────

// scope decides which sessions a principal may see. It is the ONE place the
// rule lives, and it is default-closed: no tenant and no cross-tenant grant
// reads nothing at all, rather than everything.
func scopeAdmits(st *sessionState, tenant string, cross bool) bool {
	if cross {
		return true
	}
	if tenant == "" {
		return false
	}
	return st.tenantID == tenant
}

// PeerView is one monitored BGP peer in a response.
type PeerView struct {
	Address string `json:"address"`
	AS      uint32 `json:"as"`
	BGPID   string `json:"bgp_id,omitempty"`
	RIB     string `json:"rib"`
	// State is "up", "down", or "unknown" — the last is used when no Peer Up /
	// Peer Down has actually been observed, so an assumed state is never shown
	// as a measured one.
	State      string `json:"state"`
	ChangedAt  string `json:"changed_at,omitempty"`
	DownReason string `json:"down_reason,omitempty"`
	Announces  uint64 `json:"announced_prefixes"`
	Withdraws  uint64 `json:"withdrawn_prefixes"`
}

// SessionView is one BMP session in a response.
type SessionView struct {
	ID           string            `json:"id"`
	DeviceID     string            `json:"device_id"`
	RemoteAddr   string            `json:"remote_addr"`
	Router       string            `json:"router,omitempty"`
	RouterDescr  string            `json:"router_descr,omitempty"`
	State        string            `json:"state"` // "up" | "closed"
	OpenedAt     string            `json:"opened_at"`
	ClosedAt     string            `json:"closed_at,omitempty"`
	CloseReason  string            `json:"close_reason,omitempty"`
	Peers        []PeerView        `json:"peers"`
	PeersPartial bool              `json:"peers_partial"`
	Messages     map[string]uint64 `json:"messages"`
	Updates      uint64            `json:"updates_held"`
	Dropped      uint64            `json:"updates_dropped"`
	ParseErrors  uint64            `json:"parse_errors"`
	Unsupported  uint64            `json:"unsupported_elements"`

	// tenantID is unexported so it is never marshalled into a response; it is
	// read back only through TenantOf, by the composition root and its tests.
	tenantID string
}

// TenantOf reports the tenant a session was attributed to. It is deliberately
// a METHOD and not a JSON field: the owning tenant is an internal attribution
// fact, and echoing it in a response would hand a cross-tenant reader another
// tenant's identifier for free.
func (v SessionView) TenantOf() string { return v.tenantID }

// Sessions returns the caller's sessions, newest first. A principal with no
// tenant and no cross-tenant grant gets an EMPTY list, never the fleet's.
func (s *Store) Sessions(tenant string, cross bool) []SessionView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SessionView, 0, len(s.sessions))
	for _, st := range s.sessions {
		if !scopeAdmits(st, tenant, cross) {
			continue
		}
		out = append(out, st.view())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OpenedAt != out[j].OpenedAt {
			return out[i].OpenedAt > out[j].OpenedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (st *sessionState) view() SessionView {
	v := SessionView{
		ID:           st.id,
		DeviceID:     st.deviceID,
		RemoteAddr:   st.remoteAddr,
		Router:       st.routerName,
		RouterDescr:  st.routerDesc,
		State:        "up",
		OpenedAt:     st.openedAt.UTC().Format(time.RFC3339),
		Peers:        make([]PeerView, 0, len(st.peers)),
		PeersPartial: st.peersCap,
		Messages:     copyCounts(st.messages),
		Updates:      countU64(st.ring.count),
		Dropped:      st.ring.dropped,
		ParseErrors:  st.parseErrors,
		Unsupported:  st.unsupported,
		tenantID:     st.tenantID,
	}
	// The reason is shown as soon as it is KNOWN — a router that has sent its
	// Termination has told us why it is going away, and hiding that until the
	// socket actually closes would drop the one fact an operator wants.
	v.CloseReason = st.closeNote
	if st.closed {
		v.State = "closed"
		v.ClosedAt = st.closedAt.UTC().Format(time.RFC3339)
	}
	for _, p := range st.peers {
		pv := PeerView{
			Address:    p.addr.String(),
			AS:         p.as,
			RIB:        p.rib,
			State:      "unknown",
			DownReason: p.downReason,
			Announces:  p.updates,
			Withdraws:  p.withdraws,
		}
		if p.bgpID.IsValid() {
			pv.BGPID = p.bgpID.String()
		}
		if p.seen {
			pv.State = "down"
			if p.up {
				pv.State = "up"
			}
		}
		if !p.changedAt.IsZero() {
			pv.ChangedAt = p.changedAt.UTC().Format(time.RFC3339)
		}
		v.Peers = append(v.Peers, pv)
	}
	sort.Slice(v.Peers, func(i, j int) bool { return v.Peers[i].Address < v.Peers[j].Address })
	return v
}

// UpdateFilter bounds an updates read. Every field is already validated by the
// handler; the store re-applies the tenant scope regardless.
type UpdateFilter struct {
	// Prefix, when set, matches records whose prefix is EQUAL TO or CONTAINED
	// IN it. "10.0.0.0/8" therefore finds 10.1.2.0/24 — the question an
	// operator is actually asking.
	Prefix    netip.Prefix
	HasPrefix bool
	// Peer, when set, matches the monitored peer's address exactly.
	Peer string
	// Session, when set, narrows to one session id.
	Session string
	// Before is the keyset cursor: only records with Seq < Before are returned.
	// Zero means "from the newest".
	Before uint64
	Limit  int
}

// UpdateView is one update record in a response.
type UpdateView struct {
	Seq              uint64   `json:"seq"`
	At               string   `json:"at"`
	SessionID        string   `json:"session_id"`
	DeviceID         string   `json:"device_id"`
	Peer             string   `json:"peer"`
	PeerAS           uint32   `json:"peer_as"`
	RIB              string   `json:"rib"`
	Kind             string   `json:"kind"`
	Prefix           string   `json:"prefix"`
	NextHop          string   `json:"next_hop,omitempty"`
	Origin           string   `json:"origin,omitempty"`
	ASPath           []uint32 `json:"as_path,omitempty"`
	Communities      []string `json:"communities,omitempty"`
	LargeCommunities []string `json:"large_communities,omitempty"`
	MED              *uint32  `json:"med,omitempty"`
	LocalPref        *uint32  `json:"local_pref,omitempty"`
	PartialAttrs     bool     `json:"partial_attrs"`
}

// Updates returns matching records newest-first, at most f.Limit of them.
//
// It merges the per-session rings by sequence number. Because each ring is
// already newest-first, the merge only ever holds f.Limit records — a caller
// cannot make the server materialize the whole feed.
func (s *Store) Updates(tenant string, cross bool, f UpdateFilter) []UpdateView {
	limit := f.Limit
	if limit <= 0 {
		limit = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	picked := make([]UpdateRecord, 0, limit)
	for _, st := range s.sessions {
		if !scopeAdmits(st, tenant, cross) {
			continue
		}
		if f.Session != "" && st.id != f.Session {
			continue
		}
		st.ring.newestFirst(func(rec UpdateRecord) bool {
			if f.Before != 0 && rec.Seq >= f.Before {
				return true // newer than the cursor; keep walking back
			}
			if !matches(rec, f) {
				return true
			}
			picked = insertDesc(picked, rec, limit)
			// Once the buffer is full and this session's records are all older
			// than the weakest kept one, nothing further back can qualify.
			return !(len(picked) == limit && rec.Seq <= picked[limit-1].Seq)
		})
	}
	out := make([]UpdateView, 0, len(picked))
	for _, rec := range picked {
		out = append(out, viewOf(rec))
	}
	return out
}

// matches applies the non-tenant filters.
func matches(rec UpdateRecord, f UpdateFilter) bool {
	if f.Peer != "" && rec.PeerAddr != f.Peer {
		return false
	}
	if f.HasPrefix {
		if rec.Prefix.Addr().Is4() != f.Prefix.Addr().Is4() {
			return false
		}
		if rec.Prefix.Bits() < f.Prefix.Bits() || !f.Prefix.Contains(rec.Prefix.Addr()) {
			return false
		}
	}
	return true
}

// insertDesc keeps `dst` sorted by Seq descending, capped at limit.
func insertDesc(dst []UpdateRecord, rec UpdateRecord, limit int) []UpdateRecord {
	pos := sort.Search(len(dst), func(i int) bool { return dst[i].Seq < rec.Seq })
	if pos >= limit {
		return dst
	}
	if len(dst) < limit {
		dst = append(dst, UpdateRecord{})
	}
	copy(dst[pos+1:], dst[pos:])
	dst[pos] = rec
	return dst
}

func viewOf(rec UpdateRecord) UpdateView {
	return UpdateView{
		Seq:              rec.Seq,
		At:               rec.At.UTC().Format(time.RFC3339Nano),
		SessionID:        rec.SessionID,
		DeviceID:         rec.DeviceID,
		Peer:             rec.PeerAddr,
		PeerAS:           rec.PeerAS,
		RIB:              rec.RIB,
		Kind:             rec.Kind,
		Prefix:           rec.Prefix.String(),
		NextHop:          rec.NextHop,
		Origin:           rec.Origin,
		ASPath:           rec.ASPath,
		Communities:      rec.Communities,
		LargeCommunities: rec.LargeCommunities,
		MED:              rec.MED,
		LocalPref:        rec.LocalPref,
		PartialAttrs:     rec.PartialAttrs,
	}
}

// StatsView is the caller's own aggregate. It is derived from the caller's
// sessions ONLY — the process-wide metrics are deliberately NOT exposed here,
// because "how many frames did the fleet send" is another tenant's volume.
type StatsView struct {
	Sessions        int               `json:"sessions"`
	SessionsUp      int               `json:"sessions_up"`
	Peers           int               `json:"peers"`
	PeersUp         int               `json:"peers_up"`
	Messages        map[string]uint64 `json:"messages"`
	UpdatesHeld     uint64            `json:"updates_held"`
	UpdatesDropped  uint64            `json:"updates_dropped"`
	ParseErrors     uint64            `json:"parse_errors"`
	Unsupported     uint64            `json:"unsupported_elements"`
	OldestUpdateSeq uint64            `json:"oldest_update_seq"`
	NewestUpdateSeq uint64            `json:"newest_update_seq"`
}

// Stats aggregates the caller's own sessions.
func (s *Store) Stats(tenant string, cross bool) StatsView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := StatsView{Messages: map[string]uint64{}}
	for _, st := range s.sessions {
		if !scopeAdmits(st, tenant, cross) {
			continue
		}
		out.Sessions++
		if !st.closed {
			out.SessionsUp++
		}
		for _, p := range st.peers {
			out.Peers++
			if p.seen && p.up {
				out.PeersUp++
			}
		}
		for k, v := range st.messages {
			out.Messages[k] += v
		}
		out.UpdatesHeld += countU64(st.ring.count)
		out.UpdatesDropped += st.ring.dropped
		out.ParseErrors += st.parseErrors
		out.Unsupported += st.unsupported
		st.ring.newestFirst(func(rec UpdateRecord) bool {
			if rec.Seq > out.NewestUpdateSeq {
				out.NewestUpdateSeq = rec.Seq
			}
			if out.OldestUpdateSeq == 0 || rec.Seq < out.OldestUpdateSeq {
				out.OldestUpdateSeq = rec.Seq
			}
			return true
		})
	}
	return out
}
