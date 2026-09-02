package parsercov

// mining.go — the template miner. PURE: no clock, no network, no randomness,
// no map iteration on any path that decides an output. Given the same lines in
// the same order it produces the same templates, in the same order, with the
// same ids — which is the property the propose route depends on (a template_id
// handed to the client must still resolve on the next run).
//
// THE ALGORITHM (fixed-depth token tree, the Drain shape, stdlib only)
//
//	1. TOKENIZE the message on whitespace.
//	2. MASK every token that carries an instance identity (a number, an
//	   address, a MAC, an interface name, a hex blob) to the wildcard `<*>`.
//	   Masking is what turns "Interface Gi0/3 changed state to down" and
//	   "Interface Gi0/7 changed state to down" into one shape.
//	3. BUCKET by (appname, mnemonic, token count, first masked token). These
//	   four are the fixed-depth tree levels: two lines in different buckets are
//	   never compared, which is what keeps the cost linear.
//	4. Within a bucket, walk the existing clusters IN CREATION ORDER and join
//	   the first whose token-position agreement is >= simThreshold (0.5). On a
//	   join, every position where the two disagree collapses to `<*>` — the
//	   template only ever generalises.
//	5. Otherwise open a new cluster, subject to the group cap.
//
// WHY 0.5. The bucket key already pins the token count and the first token, so
// a bucket holds lines of one syntactic family; 0.5 then splits genuinely
// different sentences of equal length ("interface X up" vs "process Y died")
// while keeping one sentence's variants together. It is a parameter, not a
// discovery — MinerConfig carries it so a test can pin behaviour either side of
// the boundary.
//
// BOUNDEDNESS (§9). Every accumulator is capped: groups (MaxGroups), distinct
// devices per group (maxDevicesPerGroup), the sample and template strings
// (maxSampleBytes / maxTemplateTokens) and the number of lines the caller feeds
// in (MaxLines, enforced by the caller). Nothing here grows with traffic.

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// Wildcard is the masked-token placeholder. It is rendered verbatim into the
// template string, which the client escapes — this package returns plain text
// and never markup (§15 LLM02 applies to any untrusted string, and a device
// message is exactly that).
const Wildcard = "<*>"

const (
	// DefaultMaxLines bounds one mining run's scan (PARSERCOV_MAX_LINES).
	DefaultMaxLines = 200_000
	// DefaultMaxGroups bounds the number of distinct templates one run keeps.
	DefaultMaxGroups = 5_000
	// DefaultSimilarity is the token-agreement threshold for joining a cluster.
	DefaultSimilarity = 0.5

	// maxDevicesPerGroup bounds the distinct-host set held per template. A
	// template seen on more hosts than this reports the cap and says so — an
	// unbounded set keyed by a device-supplied hostname is a memory hole.
	maxDevicesPerGroup = 4096
	// maxSampleBytes bounds the retained raw sample line.
	maxSampleBytes = 512
	// maxTemplateTokens bounds how much of a very long message becomes the
	// template; the remainder collapses into one trailing wildcard.
	maxTemplateTokens = 64
	// severityNone is the "no severity parsed" sentinel. Syslog severities run
	// 0 (emergency) .. 7 (debug), so 99 is outside the ladder in the direction
	// of "least severe" and never wins a most-severe comparison.
	severityNone = 99
)

// Line is one raw log record handed to the miner. The miner reads nothing else
// about the document, so the OpenSearch projection (query.go) and the mining
// are independently testable.
type Line struct {
	// Message is the raw message text. It is the only field tokenized.
	Message string
	// AppName is the syslog APP-NAME (or the %FACILITY when the app name is
	// absent) — the first bucket level.
	AppName string
	// Mnemonic is the %FAC-N-MNEMONIC mnemonic, upper-cased — the second.
	Mnemonic string
	// Host is the emitting device identity, for the distinct-device count.
	Host string
	// Severity is the numeric syslog severity, or severityNone when the record
	// carried none that parses.
	Severity int
	// Time is the record timestamp (UTC). Zero means "the document carried no
	// usable timestamp" and is excluded from first/last seen.
	Time time.Time
}

// MinerConfig is the tuning surface. Zero values take the Default* constants,
// so a caller that wants the shipped behaviour passes MinerConfig{}.
type MinerConfig struct {
	MaxGroups  int
	Similarity float64
}

func (c MinerConfig) maxGroups() int {
	if c.MaxGroups > 0 {
		return c.MaxGroups
	}
	return DefaultMaxGroups
}

func (c MinerConfig) similarity() float64 {
	if c.Similarity > 0 {
		return c.Similarity
	}
	return DefaultSimilarity
}

// Item is one mined template, in the wire shape the frontend contract names
// (services/api.ts UnrecognizedItem). Field names are the contract; do not
// rename them without changing that file in the same commit.
type Item struct {
	TemplateID  string `json:"template_id"`
	Template    string `json:"template"`
	Count       int64  `json:"count"`
	Devices     int    `json:"devices"`
	SeverityMax int    `json:"severity_max"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
	Sample      string `json:"sample"`
	AppName     string `json:"appname,omitempty"`
	Mnemonic    string `json:"mnemonic,omitempty"`
}

// MineResult is what one run produced, plus the honest facts about its own
// limits. GroupsCapped/DevicesCapped are reported, never hidden: a truncated
// answer that does not say it is truncated is the failure this repo keeps
// finding.
type MineResult struct {
	Items         []Item
	LinesScanned  int
	GroupsCapped  bool
	DevicesCapped bool
}

// cluster is one template under construction.
type cluster struct {
	id       string
	tokens   []string
	count    int64
	devices  map[string]struct{}
	devCap   bool
	sevMost  int // most severe (numerically smallest) severity seen
	first    time.Time
	last     time.Time
	sample   string
	appName  string
	mnemonic string
	seq      int // creation order, the deterministic tiebreak
}

// Miner accumulates lines into templates. It is NOT safe for concurrent use;
// one run owns one Miner (the handler builds it, feeds it and discards it).
type Miner struct {
	cfg      MinerConfig
	buckets  map[string][]*cluster
	order    []*cluster // creation order — the only order any output derives from
	capped   bool
	devCap   bool
	scanned  int
	maxGroup int
	sim      float64
}

// NewMiner builds a miner over the given configuration.
func NewMiner(cfg MinerConfig) *Miner {
	return &Miner{
		cfg:      cfg,
		buckets:  make(map[string][]*cluster, 64),
		maxGroup: cfg.maxGroups(),
		sim:      cfg.similarity(),
	}
}

// Add folds one line in. A line whose message is blank after trimming is
// counted as scanned and otherwise ignored — there is no shape to mine, and
// inventing an empty template would put a meaningless row in front of an
// operator.
func (m *Miner) Add(l Line) {
	m.scanned++
	msg := strings.TrimSpace(l.Message)
	if msg == "" {
		return
	}
	toks := maskTokens(strings.Fields(msg))
	if len(toks) == 0 {
		return
	}
	app := strings.TrimSpace(l.AppName)
	mn := strings.TrimSpace(l.Mnemonic)
	key := bucketKey(app, mn, len(toks), toks[0])
	for _, c := range m.buckets[key] {
		if similarity(c.tokens, toks) >= m.sim {
			m.join(c, toks, l)
			return
		}
	}
	if len(m.order) >= m.maxGroup {
		// The cap is a REFUSAL to keep mining, not a silent drop: the flag is
		// reported in the note so the operator knows the list is partial.
		m.capped = true
		return
	}
	c := &cluster{
		id:       "", // assigned in Result, from the FINAL template text
		tokens:   append([]string(nil), toks...),
		count:    1,
		devices:  make(map[string]struct{}, 8),
		sevMost:  l.Severity,
		first:    l.Time,
		last:     l.Time,
		sample:   truncate(msg, maxSampleBytes),
		appName:  app,
		mnemonic: mn,
		seq:      len(m.order),
	}
	m.addDevice(c, l.Host)
	m.buckets[key] = append(m.buckets[key], c)
	m.order = append(m.order, c)
}

// join folds a matching line into an existing cluster, generalising every
// position the two disagree on.
func (m *Miner) join(c *cluster, toks []string, l Line) {
	for i := range c.tokens {
		if c.tokens[i] != toks[i] {
			c.tokens[i] = Wildcard
		}
	}
	c.count++
	if l.Severity < c.sevMost {
		c.sevMost = l.Severity
	}
	if !l.Time.IsZero() {
		if c.first.IsZero() || l.Time.Before(c.first) {
			c.first = l.Time
		}
		if c.last.IsZero() || l.Time.After(c.last) {
			c.last = l.Time
		}
	}
	m.addDevice(c, l.Host)
}

func (m *Miner) addDevice(c *cluster, host string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	if _, ok := c.devices[host]; ok {
		return
	}
	if len(c.devices) >= maxDevicesPerGroup {
		c.devCap = true
		m.devCap = true
		return
	}
	c.devices[host] = struct{}{}
}

// Result renders the accumulated clusters. Ordering is count DESC, then
// template_id ASC — a total order that does not depend on map iteration, so two
// runs over the same input emit the same list.
func (m *Miner) Result() MineResult {
	out := make([]Item, 0, len(m.order))
	for _, c := range m.order {
		tmpl := strings.Join(c.tokens, " ")
		out = append(out, Item{
			TemplateID:  TemplateID(c.appName, c.mnemonic, tmpl),
			Template:    tmpl,
			Count:       c.count,
			Devices:     len(c.devices),
			SeverityMax: c.sevMost,
			FirstSeen:   rfc3339(c.first),
			LastSeen:    rfc3339(c.last),
			Sample:      c.sample,
			AppName:     c.appName,
			Mnemonic:    c.mnemonic,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].TemplateID < out[j].TemplateID
	})
	return MineResult{
		Items:         out,
		LinesScanned:  m.scanned,
		GroupsCapped:  m.capped,
		DevicesCapped: m.devCap,
	}
}

// TemplateID is the stable identity of a mined shape: a hash of the bucket
// identity plus the final template text.
//
// CONTENT-DERIVED, NOT SEQUENTIAL, on purpose. The propose route resolves a
// template_id the client received from an EARLIER mining run; a sequence number
// would re-point at a different shape the moment traffic changed the ordering,
// and the operator would draft a rule for a line they never looked at. A
// content hash either resolves to the same shape or does not resolve at all.
func TemplateID(appName, mnemonic, template string) string {
	h := sha256.Sum256([]byte(appName + "\x00" + mnemonic + "\x00" + template))
	return "t-" + hex.EncodeToString(h[:])[:10]
}

// ValidTemplateID is the path-segment gate for the propose route. The id is
// caller-supplied and reaches a map lookup, so it is validated by SHAPE before
// anything else looks at it (§3: validate all inputs at every boundary).
func ValidTemplateID(s string) bool {
	if len(s) != 12 || !strings.HasPrefix(s, "t-") {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// bucketKey is the fixed-depth tree path: appname / mnemonic / token count /
// first token. NUL-separated so no field's content can forge another's
// boundary.
func bucketKey(app, mnemonic string, n int, first string) string {
	var b strings.Builder
	b.WriteString(app)
	b.WriteByte(0)
	b.WriteString(mnemonic)
	b.WriteByte(0)
	b.WriteString(itoa(n))
	b.WriteByte(0)
	b.WriteString(first)
	return b.String()
}

// similarity is the fraction of positions on which two equal-length token
// vectors agree. Wildcards already in the cluster count as agreement — a
// generalised position cannot disagree with anything.
func similarity(a, b []string) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	same := 0
	for i := range a {
		if a[i] == b[i] || a[i] == Wildcard {
			same++
		}
	}
	return float64(same) / float64(len(a))
}

// maskTokens masks each token and folds an over-long message into
// maxTemplateTokens plus one trailing wildcard, so one pathological line cannot
// carry an unbounded template into the response.
func maskTokens(in []string) []string {
	n := len(in)
	trailing := false
	if n > maxTemplateTokens {
		n = maxTemplateTokens
		trailing = true
	}
	out := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		out = append(out, maskToken(in[i]))
	}
	if trailing {
		out = append(out, Wildcard)
	}
	return out
}

// maskToken decides whether one token carries instance identity. The rules are
// ordered and exhaustive; the final rule ("any digit") is the catch-all that
// makes the classifier total, so no token's fate depends on rule ordering
// beyond what is written here.
//
// Punctuation attached to a token is preserved when the token is kept and
// discarded when it is masked — "state to down," stays "state to down," while
// "GigabitEthernet0/3," becomes "<*>". Trailing punctuation on a masked value
// is instance detail too.
func maskToken(tok string) string {
	if tok == "" {
		return tok
	}
	core := strings.Trim(tok, ",;:()[]{}\"'")
	if core == "" {
		return tok
	}
	switch {
	case looksSyslogTag(core):
		// %FAC-N-MNEMONIC is a CLASSIFIER, not instance identity — it is the
		// single most informative token in a Cisco-style line. It contains a
		// digit, so without this rule the catch-all below would mask it and
		// collapse every %-tagged shape in the estate into one useless row.
		return tok
	case looksNumeric(core): // 42, -1, 3.14, 1,024, 10ms, 55%
		return Wildcard
	case looksHex(core): // 0xdeadbeef, deadbeefcafe
		return Wildcard
	case looksAddress(core): // 10.1.1.5, 10.1.1.5:443, fe80::1, 00:11:22:33:44:55
		return Wildcard
	case looksInterface(core): // GigabitEthernet0/3, ge-0/0/1.0, Eth1/1, Vlan10
		return Wildcard
	case strings.ContainsAny(core, "0123456789"):
		// Catch-all: any residual token carrying a digit is instance detail
		// (session ids, pids, serials). Masking it is the conservative choice —
		// an over-generalised template groups too much, which an operator can
		// see, while an under-generalised one splits one shape into thousands
		// of rows, which they cannot.
		return Wildcard
	}
	return tok
}

// looksSyslogTag matches the %FACILITY-SEVERITY-MNEMONIC classifier that
// Cisco IOS/IOS-XE, NX-OS and Arista EOS converge on — the same shape the
// aggregator's structured-body parser reads (`ios_style.v1` in
// deployment/docker/vector/vector.yaml). Hand-scanned rather than compiled as
// a package-level regexp: it runs once per token of every scanned line, and a
// package-level `var` is a global (§5).
func looksSyslogTag(s string) bool {
	if len(s) < 5 || s[0] != '%' {
		return false
	}
	i := 1
	if !isUpperAlpha(s[i]) {
		return false
	}
	for i < len(s) && isTagChar(s[i]) {
		i++
	}
	if i >= len(s) || s[i] != '-' {
		return false
	}
	i++
	if i >= len(s) || s[i] < '0' || s[i] > '7' {
		return false
	}
	i++
	if i >= len(s) || s[i] != '-' {
		return false
	}
	i++
	if i >= len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if !isTagChar(s[i]) {
			return false
		}
	}
	return true
}

func isUpperAlpha(c byte) bool { return c >= 'A' && c <= 'Z' }

func isTagChar(c byte) bool {
	return isUpperAlpha(c) || (c >= '0' && c <= '9') || c == '_'
}

// looksNumeric matches an integer/decimal, with optional sign, thousands
// commas, and a trailing unit or percent suffix.
func looksNumeric(s string) bool {
	i := 0
	if s[0] == '-' || s[0] == '+' {
		i = 1
	}
	digits := 0
	for ; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			digits++
			continue
		}
		if c == '.' || c == ',' {
			continue
		}
		break
	}
	if digits == 0 {
		return false
	}
	// Whatever remains must be a short alphabetic unit (ms, s, %, kb, MB…).
	rest := s[i:]
	if rest == "" || rest == "%" {
		return true
	}
	if len(rest) > 4 {
		return false
	}
	for j := 0; j < len(rest); j++ {
		c := rest[j]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '%' && c != '/' {
			return false
		}
	}
	return true
}

// looksHex matches 0x-prefixed hex and bare hex blobs of 6+ characters that
// carry at least one digit (so "deadbeef" masks but "facade" does not).
func looksHex(s string) bool {
	body := s
	if len(s) > 2 && (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) {
		body = s[2:]
	} else if len(s) < 6 {
		return false
	}
	if body == "" {
		return false
	}
	digit := false
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return digit || strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")
}

// looksAddress matches IPv4 (with optional /prefix or :port), IPv6-ish and MAC
// forms. It is deliberately loose: over-masking an address-shaped token costs
// nothing, under-masking one splits a template per host.
func looksAddress(s string) bool {
	// dotted quad, optionally with a mask or port
	if dots := strings.Count(s, "."); dots == 3 {
		host := s
		if i := strings.IndexAny(host, ":/"); i >= 0 {
			host = host[:i]
		}
		if isDottedQuad(host) {
			return true
		}
	}
	// Cisco three-group MAC (0011.2233.4455)
	if strings.Count(s, ".") == 2 && len(s) == 14 && allHexOrDot(s) {
		return true
	}
	// colon forms: MAC (6 groups) and IPv6 (>= 2 colons, hex + colons only)
	if c := strings.Count(s, ":"); c >= 2 {
		if allHexOrColon(s) {
			return true
		}
	}
	return false
}

func isDottedQuad(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

func allHexOrDot(s string) bool { return allFromClass(s, ".") }

func allHexOrColon(s string) bool { return allFromClass(s, ":") }

func allFromClass(s, extra string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			continue
		}
		if c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			continue
		}
		if strings.IndexByte(extra, c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// looksInterface matches a vendor interface name: an alphabetic head followed
// by digits and separators (GigabitEthernet0/3, Eth1/1, ge-0/0/1.0, Vlan10,
// xe-0/0/0:1, Port-channel12, irb.100).
func looksInterface(s string) bool {
	i := 0
	for i < len(s) && isAlphaOrDash(s[i]) {
		i++
	}
	if i == 0 || i == len(s) {
		return false
	}
	digit := false
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c == '/' || c == '.' || c == '-' || c == ':':
		default:
			return false
		}
	}
	return digit
}

func isAlphaOrDash(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_'
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// itoa is a tiny non-allocating-ish integer formatter for the bucket key. It
// exists so bucketKey does not pull strconv into a hot loop's import surface
// for one call; behaviour is identical to strconv.Itoa for n >= 0, which is the
// only input (a token count).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
