// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// oneshot.go — one on-demand measurement from THIS collector (tracker 337
// N-I3, design item 14).
//
// Iris's active probes (run_ping, run_traceroute, run_dns_test, run_http_test)
// run here, on Correlix's own collector — never on a customer device and never
// through a third-party service (owner rule, 2026-11-13). This file only
// MEASURES: the caller has already decided the target is one the workspace
// owns and pinned the address it may dial (internal/probetarget). Nothing here
// resolves a target name to choose where to send traffic; the DNS test
// resolves the declared name because resolving it IS the measurement.
//
// Every measurement is small and fixed — the model chooses none of it:
//
//   - ping: 3 ICMP echoes, 1 s wait each;
//   - traceroute: one ICMP probe per hop, at most 16 hops, 800 ms per hop;
//   - dns: one lookup, 3 s;
//   - http: one GET, 5 s, redirects NOT followed (a redirect would send the
//     request to a host nobody validated), TLS always verified, no body read.
//
// A collector that cannot send ICMP (no unprivileged ICMP and no CAP_NET_RAW)
// says so: Unavailable is set and nothing is pretended.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// OneShotKind is the measurement to take.
type OneShotKind string

const (
	OneShotPing       OneShotKind = "ping"
	OneShotTraceroute OneShotKind = "traceroute"
	OneShotDNS        OneShotKind = "dns"
	OneShotHTTP       OneShotKind = "http"
)

// The fixed sizes of an on-demand measurement.
const (
	oneShotPingPackets  = 3
	oneShotPingWait     = time.Second
	oneShotTraceMaxHops = 16
	oneShotTraceHopWait = 800 * time.Millisecond
	oneShotDNSTimeout   = 3 * time.Second
	oneShotHTTPTimeout  = 5 * time.Second
)

// OneShotRequest is one validated measurement. Addr and Resolver are PINNED
// addresses the caller already cleared; Host is the name an HTTP request
// presents (Host header, TLS server name) or the name a DNS test resolves.
type OneShotRequest struct {
	Kind     OneShotKind
	Addr     netip.Addr     // ping, traceroute, http: the address to dial
	Host     string         // http: Host/SNI; dns: the name to resolve
	Port     int            // http: the port (0 → 443 for https, 80 for http)
	Scheme   string         // http: "https" | "http"
	Path     string         // http: the request path ("" → "/")
	Resolver netip.AddrPort // dns: a pinned resolver; zero → the system resolver
}

// OneShotHop is one TTL position: whether something answered and how fast.
// The responder's address is deliberately NOT kept — a transit router's
// address is not needed to say where loss begins, and it is not ours to show.
type OneShotHop struct {
	TTL     int
	Replied bool
	RTTms   float64
}

// OneShotResult is what the measurement saw.
type OneShotResult struct {
	Kind OneShotKind
	// Unavailable says the collector cannot take this measurement at all
	// (why, in operator words). Nothing else is meaningful when it is set.
	Unavailable string
	Up          bool
	Sent        int
	Received    int
	LossPct     float64
	RTTms       float64
	Hops        []OneShotHop
	Reached     bool
	StatusCode  int
	FailClass   string // dns: nxdomain|timeout|no_answer|dns; http: dns|tls|connect_refused|connect_timeout|timeout|reset|redirect|unknown
	Answers     int    // dns: how many addresses came back
	Elapsed     time.Duration
}

// RunOneShot takes one measurement. It honours ctx and the fixed bounds above.
func RunOneShot(ctx context.Context, req OneShotRequest) OneShotResult {
	start := time.Now()
	var res OneShotResult
	switch req.Kind {
	case OneShotPing:
		res = oneShotPing(ctx, req.Addr)
	case OneShotTraceroute:
		res = oneShotTrace(ctx, req.Addr)
	case OneShotDNS:
		res = oneShotDNS(ctx, req.Host, req.Resolver)
	case OneShotHTTP:
		res = oneShotHTTP(ctx, req)
	default:
		res = OneShotResult{Unavailable: "that measurement is not supported"}
	}
	res.Kind = req.Kind
	res.Elapsed = time.Since(start)
	return res
}

const icmpUnavailable = "this collector cannot send ICMP (no unprivileged ICMP socket and no CAP_NET_RAW)"

func oneShotPing(ctx context.Context, addr netip.Addr) OneShotResult {
	res := OneShotResult{}
	if !addr.IsValid() || !addr.Unmap().Is4() {
		return OneShotResult{Unavailable: "ping needs an IPv4 address"}
	}
	conn, datagram, err := openICMP()
	if err != nil {
		return OneShotResult{Unavailable: icmpUnavailable}
	}
	defer conn.Close()
	ip := net.IP(addr.Unmap().AsSlice())
	var dst net.Addr = &net.IPAddr{IP: ip}
	if datagram {
		dst = &net.UDPAddr{IP: ip}
	}
	id := os.Getpid() & 0xffff
	payload := []byte("correlix-iris-probe")
	buf := make([]byte, 1500)
	var total float64
	for seq := 0; seq < oneShotPingPackets && ctx.Err() == nil; seq++ {
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: payload}}
		wb, merr := msg.Marshal(nil)
		if merr != nil {
			break
		}
		sent := time.Now()
		if _, werr := conn.WriteTo(wb, dst); werr != nil {
			continue
		}
		res.Sent++
		if derr := conn.SetReadDeadline(time.Now().Add(oneShotPingWait)); derr != nil {
			continue // without a deadline the read could hang; count the echo as lost
		}
		for {
			n, _, rerr := conn.ReadFrom(buf)
			if rerr != nil {
				break // deadline: this echo is lost
			}
			m, perr := icmp.ParseMessage(1, buf[:n])
			if perr != nil {
				continue
			}
			echo, ok := m.Body.(*icmp.Echo)
			if m.Type != ipv4.ICMPTypeEchoReply || !ok || echo.Seq != seq {
				continue
			}
			if !datagram && echo.ID != id {
				continue // raw sockets see every reply on the host
			}
			res.Received++
			total += float64(time.Since(sent)) / float64(time.Millisecond)
			break
		}
	}
	if res.Sent == 0 {
		return OneShotResult{Unavailable: "no echo could be sent from this collector"}
	}
	res.Up = res.Received > 0
	res.LossPct = float64(res.Sent-res.Received) / float64(res.Sent) * 100
	if res.Received > 0 {
		res.RTTms = total / float64(res.Received)
	}
	return res
}

func oneShotTrace(ctx context.Context, addr netip.Addr) OneShotResult {
	if !addr.IsValid() || !addr.Unmap().Is4() {
		return OneShotResult{Unavailable: "traceroute needs an IPv4 address"}
	}
	ip := net.IP(addr.Unmap().AsSlice())
	cfg := traceConfig{maxHops: oneShotTraceMaxHops, probes: 1, timeout: oneShotTraceHopWait, method: "icmp"}
	var path PathResult
	var err error
	for _, sock := range []string{"udp4", "ip4:icmp"} { // unprivileged first
		cfg.socketNet = sock
		path, err = traceICMP(ctx, addr.String(), &net.IPAddr{IP: ip}, cfg)
		if err == nil {
			break
		}
	}
	if err != nil {
		return OneShotResult{Unavailable: icmpUnavailable}
	}
	res := OneShotResult{Reached: path.Reached, Up: path.Reached}
	for _, h := range path.Hops {
		res.Hops = append(res.Hops, OneShotHop{TTL: h.TTL, Replied: h.IP != "", RTTms: h.RTTms})
	}
	return res
}

func oneShotDNS(ctx context.Context, name string, resolver netip.AddrPort) OneShotResult {
	if name == "" {
		return OneShotResult{Unavailable: "no name to resolve"}
	}
	var r demResolver = net.DefaultResolver
	if resolver.IsValid() {
		r = demSystemResolver(resolver.String(), oneShotDNSTimeout)
	}
	cctx, cancel := context.WithTimeout(ctx, oneShotDNSTimeout)
	defer cancel()
	start := time.Now()
	addrs, err := r.LookupHost(cctx, name)
	res := OneShotResult{RTTms: float64(time.Since(start)) / float64(time.Millisecond)}
	switch {
	case err != nil:
		res.FailClass = classifyDNSErr(err)
	case len(addrs) == 0:
		res.FailClass = "no_answer"
	default:
		res.Up, res.Answers = true, len(addrs)
	}
	return res
}

func oneShotHTTP(ctx context.Context, req OneShotRequest) OneShotResult {
	if !req.Addr.IsValid() || req.Host == "" {
		return OneShotResult{Unavailable: "no web target to test"}
	}
	scheme := req.Scheme
	if scheme != "http" {
		scheme = "https"
	}
	port := req.Port
	if port <= 0 || port > 65535 {
		port = 443
		if scheme == "http" {
			port = 80
		}
	}
	path := req.Path
	if path == "" || path[0] != '/' {
		path = "/"
	}
	pinned := net.JoinHostPort(req.Addr.Unmap().String(), strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: oneShotHTTPTimeout}
	transport := &http.Transport{
		// Every connection goes to the PINNED address, whatever host the
		// request names: the name is never resolved again here.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, pinned)
		},
		TLSClientConfig:       &tls.Config{ServerName: req.Host, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   oneShotHTTPTimeout,
		ResponseHeaderTimeout: oneShotHTTPTimeout,
		DisableKeepAlives:     true,
		Proxy:                 nil, // never through a proxy: the target was validated, a proxy was not
	}
	client := &http.Client{
		Timeout:   oneShotHTTPTimeout,
		Transport: transport,
		// A redirect is reported, never followed: following it would send the
		// request to a host nobody validated.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	hostPort := req.Host
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		hostPort = net.JoinHostPort(req.Host, strconv.Itoa(port))
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+hostPort+path, nil)
	if err != nil {
		return OneShotResult{Unavailable: "the web target is not a valid address"}
	}
	hreq.Header.Set("User-Agent", "correlix-iris-probe/1")
	start := time.Now()
	resp, err := client.Do(hreq)
	res := OneShotResult{RTTms: float64(time.Since(start)) / float64(time.Millisecond)}
	if err != nil {
		res.FailClass = classifyOneShotHTTPErr(err)
		return res
	}
	_ = resp.Body.Close() // best-effort: the status was already measured; a close error changes nothing about it
	res.StatusCode = resp.StatusCode
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		res.FailClass = "redirect" // answered with a redirect we did not follow
		res.Up = true
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		res.Up = true
	}
	return res
}

func classifyOneShotHTTPErr(err error) string {
	var certErr *tls.CertificateVerificationError
	var recErr tls.RecordHeaderError
	var nerr net.Error
	switch {
	case errors.As(err, &certErr), errors.As(err, &recErr):
		return "tls"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connect_refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &nerr) && nerr.Timeout():
		return "timeout"
	default:
		return "unknown"
	}
}
