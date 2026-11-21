// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// gate.go — switching a collector on and off WHILE the process runs (Paths
// redesign P2, 2026-11-20), the key-value channel as an injectable dependency,
// and the validated target source the measurement collectors read.
//
// The prober's path discovery and STAMP sender used to be decided once, at
// start, from the environment. A platform administrator now switches them on
// the Features page; the api publishes the resolved switch and the prober
// re-checks it every few seconds (internal/probercontrol). Pool.Gate wraps a
// collector so it is started when its switch reads on and cancelled when it
// reads off — no restart, and no change to the collector itself.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/probercontrol"
	"netops/backend/internal/probetarget"
	"netops/backend/safego"
)

// GateFunc answers, at each check, whether a collector may run and why. The
// reason is a closed, low-cardinality word (it becomes a metric label).
type GateFunc func(ctx context.Context) (on bool, reason string)

// Gate makes a registered collector switchable at run time: it is always
// launched by Start, runs its inner loop only while g reads on, and is
// cancelled within one check when g turns off. Must be called before Start.
// An unknown name is a wiring bug and is refused loudly.
func (p *Pool) Gate(name string, g GateFunc, every time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.collectors[name]
	if !ok {
		return fmt.Errorf("collectors: gate for unknown collector %q", name)
	}
	if g == nil {
		return fmt.Errorf("collectors: nil gate for %q", name)
	}
	if every <= 0 {
		every = 15 * time.Second
	}
	p.collectors[name] = newGated(c, g, every, emitMetrics)
	p.enabled[name] = true
	return nil
}

// gatedCollector runs inner only while its gate reads on.
type gatedCollector struct {
	inner Collector
	gate  GateFunc
	every time.Duration
	emit  func(ctx context.Context, body string)

	mu      sync.Mutex
	running bool
	reason  string
}

func newGated(inner Collector, g GateFunc, every time.Duration, emit func(context.Context, string)) *gatedCollector {
	return &gatedCollector{inner: inner, gate: g, every: every, emit: emit, reason: "not_checked"}
}

func (g *gatedCollector) Name() string { return g.inner.Name() }

// Status is the inner collector's while it runs; switched off it says so
// (Enabled false, healthy — off is a choice, not a fault) with the reason.
func (g *gatedCollector) Status() Status {
	g.mu.Lock()
	running, reason := g.running, g.reason
	g.mu.Unlock()
	if running {
		st := g.inner.Status()
		st.Enabled = true
		return st
	}
	st := g.inner.Status()
	return Status{Name: st.Name, Kind: st.Kind, Enabled: false, Healthy: true,
		LastError: "switched off (" + reason + ")"}
}

// Run checks the gate now and then every g.every until ctx ends.
func (g *gatedCollector) Run(ctx context.Context) error {
	var (
		cancel context.CancelFunc
		done   chan struct{}
	)
	stop := func() {
		if cancel != nil {
			cancel()
			<-done
			cancel, done = nil, nil
		}
	}
	defer stop()
	t := time.NewTicker(g.every)
	defer t.Stop()
	for {
		// A collector that exited on its own (a bind error) is no longer
		// running; it is relaunched on the next check that reads on, so a
		// failure retries at the check cadence instead of hot-looping.
		if done != nil {
			select {
			case <-done:
				cancel()
				cancel, done = nil, nil
			default:
			}
		}
		on, why := g.gate(ctx)
		switch {
		case on && done == nil:
			cctx, c := context.WithCancel(ctx)
			cancel, done = c, make(chan struct{})
			d := done
			name := g.inner.Name()
			safego.Go("collector:"+name, func() {
				defer close(d)
				if err := g.inner.Run(cctx); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("collector %s exited: %v", name, err)
				}
			})
		case !on:
			stop()
		}
		g.mu.Lock()
		g.running, g.reason = done != nil, why
		g.mu.Unlock()
		if g.emit != nil {
			g.emit(ctx, fmt.Sprintf(`prober_collector_enabled{collector=%q,reason=%q} %d %d`,
				g.inner.Name(), why, b2i(on), time.Now().UnixMilli()))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// ControlKV is the key-value channel (Valkey, SEC-012 authenticated) as an
// injectable dependency for internal/probercontrol, which must not import
// this package.
type ControlKV struct{}

// Configured reports whether this deployment has the channel at all.
func (ControlKV) Configured() bool { return RedisAddr() != "" }

// SetEX writes key with a TTL. A failure is counted under channel and logged
// (throttled) like every other publisher, and returned.
func (ControlKV) SetEX(ctx context.Context, channel, key, val string, ttlSec int) error {
	err := redisSetEX(ctx, key, val, ttlSec)
	if err != nil {
		surfacePublishFailure(channel, key, err)
	}
	return err
}

// Get reads key; "" with a nil error when nothing is published there.
func (ControlKV) Get(ctx context.Context, key string) (string, error) {
	c, err := redisDial(ctx)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return redisCmd(c, "GET", key)
}

// ProbeTarget is one destination a measurement collector probes, with the
// tenant that owns it (Paths redesign P3). Every result is stamped with that
// tenant, so a path measured for one tenant is never served to another. An
// install-time list has no owner: Tenant "" is the platform's (the api maps it
// to PATH_GRAPH_TENANT when that is set — the single-tenant install).
type ProbeTarget struct {
	Addr   string // host, IP, or host:port — what the collector dials
	Tenant string // owning tenant; "" = the platform's
	Site   string // the site the destination belongs to, when known
}

// Addrs projects targets onto their dial addresses.
func Addrs(ts []ProbeTarget) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Addr)
	}
	return out
}

// TargetSource supplies a measurement collector's targets each tick. The
// install's environment is one source; the api's signed catalogue projection
// (P3) is another, behind this interface.
type TargetSource interface {
	Targets(ctx context.Context) ([]ProbeTarget, error)
}

// targetsRecord is the prober-side reader of the api's signed target record,
// injected (probercontrol.TargetsReader in production).
type targetsRecord interface {
	Configured() bool
	Read(ctx context.Context, which string) ([]probercontrol.WireTarget, int, probercontrol.Reason)
}

// catalogueTargets is the P3 target source: the per-tenant Digital Experience
// targets with "trace the path" / "STAMP probe" ticked, which the api resolves,
// checks against each tenant's own inventory and publishes SIGNED with every
// target's tenant (internal/probercontrol targets.go). With a channel, that
// record is the ONLY source — every doubt is an empty list, never the env list
// and never a stale one. With NO channel at all (a hand-made install without
// the key-value service) the install-time environment list is read, as before.
type catalogueTargets struct {
	rec      targetsRecord
	which    string // probercontrol.ForTraceroute | ForStamp
	port     int    // >0: dial host:port (STAMP's reflector port)
	fallback TargetSource
}

// newCatalogueTargets wires the production reader: the authenticated channel
// and the rendered signing key.
func newCatalogueTargets(which string, port int, fallback TargetSource) *catalogueTargets {
	return &catalogueTargets{
		rec:      probercontrol.NewTargetsReader(ControlKV{}, probercontrol.KeyringFromEnv(os.Getenv, log.Printf), time.Now),
		which:    which,
		port:     port,
		fallback: fallback,
	}
}

// Targets returns the verified catalogue targets. A list that does not read
// is an error on the collector's status (with the reason, never an address).
func (c *catalogueTargets) Targets(ctx context.Context) ([]ProbeTarget, error) {
	if c.rec == nil || !c.rec.Configured() {
		return c.fallback.Targets(ctx)
	}
	list, refused, why := c.rec.Read(ctx, c.which)
	if why != probercontrol.ReasonPublished {
		if why == probercontrol.ReasonNotPublished {
			return nil, nil // the api has published no catalogue target (yet): nothing to measure
		}
		return nil, fmt.Errorf("catalogue targets not read (%s): nothing is measured until a signed list arrives", why)
	}
	out := make([]ProbeTarget, 0, len(list))
	for _, t := range list {
		addr := t.Addr
		if c.port > 0 {
			addr = net.JoinHostPort(addr, strconv.Itoa(c.port))
		}
		out = append(out, ProbeTarget{Addr: addr, Tenant: t.Tenant, Site: t.Site})
	}
	if refused > 0 {
		return out, fmt.Errorf("%d catalogue target(s) refused by the prober (never probed, or not a pinned address)", refused)
	}
	return out, nil
}

// nameLookup resolves a host name, injected so tests never touch DNS.
type nameLookup func(ctx context.Context, host string) ([]netip.Addr, error)

func systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(cctx, "ip", host)
}

// envTargets reads a comma-separated list from an environment variable and
// keeps only targets the probe-target rule allows. The list is the platform
// operator's own declaration at install, so internal space is allowed (the
// operator owns it); what is NEVER probed — loopback, link-local and the cloud
// metadata service, multicast, reserved space — is refused whoever declared
// it, so a typo or a hostile .env can never point the raw-socket prober at the
// host itself.
type envTargets struct {
	key         string
	defaultPort int // >0: entries are host[:port] and get this port when bare
	lookup      nameLookup
	getenv      func(string) string
}

func newEnvTargets(key string, defaultPort int) *envTargets {
	return &envTargets{key: key, defaultPort: defaultPort, lookup: systemLookup, getenv: os.Getenv}
}

// ownedByOperator owns every address: see envTargets.
func ownedByOperator(netip.Addr) bool { return true }

// Targets returns the allowed targets. A refused or unresolvable entry is
// dropped and counted in the returned error (never the address: a refused
// address is still the customer's data); the allowed rest are returned with
// it, so one bad entry costs that entry only.
func (e *envTargets) Targets(ctx context.Context) ([]ProbeTarget, error) {
	raw := strings.TrimSpace(e.getenv(e.key))
	if raw == "" {
		return nil, nil
	}
	var out []ProbeTarget
	refused, unresolved := 0, 0
	var why string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		host := p
		if e.defaultPort > 0 {
			p = withPort(p, e.defaultPort)
			if h, _, err := net.SplitHostPort(p); err == nil {
				host = h
			}
		}
		_, err := probetarget.Resolve(ctx, probetarget.Lookup(e.lookup), host, ownedByOperator)
		switch {
		case errors.Is(err, probetarget.ErrRefused):
			refused++
			why = err.Error()
			continue
		case err != nil:
			unresolved++
			continue
		}
		out = append(out, ProbeTarget{Addr: p})
	}
	if refused == 0 && unresolved == 0 {
		return out, nil
	}
	msg := fmt.Sprintf("%s: %d target(s) dropped", e.key, refused+unresolved)
	if refused > 0 {
		msg += fmt.Sprintf("; %d refused: %s", refused, why)
	}
	if unresolved > 0 {
		msg += fmt.Sprintf("; %d did not resolve", unresolved)
	}
	return out, errors.New(msg)
}
