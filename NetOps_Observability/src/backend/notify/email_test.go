// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

import (
	"net"
	"strings"
	"testing"
	"time"

	"netops/backend/models"
)

// email_test.go — the SMTP transport must always be bounded. net/smtp dials
// with no timeout and sets no deadlines, so before this a tarpitting relay
// parked one goroutine plus one socket permanently, per alert.

func testAlert() models.Alert {
	return models.Alert{Rule: "iface-down", Severity: "critical", DeviceID: "core-1", FiredAt: time.Now()}
}

// A relay that accepts the TCP connection and then says nothing — the classic
// tarpit. Send must return an error inside the conversation deadline instead of
// blocking forever.
func TestSendTimesOutOnSilentRelay(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c // held open, never greeted
	}()

	e := NewEmail(ln.Addr().String(), "netops@example.com").
		WithRecipients("noc@example.com").
		WithTimeouts(500*time.Millisecond, 300*time.Millisecond)

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- e.Send(testAlert()) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from a silent relay")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("took %v — deadline not applied", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send hung: no deadline on the SMTP conversation (goroutine + socket leaked)")
	}
	if c := <-accepted; c != nil {
		_ = c.Close()
	}
}

// A relay that greets and then stalls mid-conversation must also be bounded —
// the deadline is absolute over the whole exchange, not just the greeting.
func TestSendTimesOutMidConversation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("220 tarpit.example.com ESMTP\r\n"))
		// EHLO arrives; we never answer it.
		buf := make([]byte, 128)
		_, _ = c.Read(buf)
		time.Sleep(3 * time.Second)
	}()

	e := NewEmail(ln.Addr().String(), "netops@example.com").
		WithRecipients("noc@example.com").
		WithTimeouts(time.Second, 300*time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- e.Send(testAlert()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from a stalled relay")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send hung mid-conversation: connection deadline not applied")
	}
}

// The dial itself is bounded on the implicit-TLS (465) path too, where the
// handshake happens inside the dial.
func TestTLSOnConnectDialIsBounded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(3 * time.Second) // accept, never complete the TLS handshake
	}()

	e := NewEmail(ln.Addr().String(), "netops@example.com").
		WithTLSOnConnect(true).
		WithRecipients("noc@example.com").
		WithTimeouts(300*time.Millisecond, time.Second)

	done := make(chan error, 1)
	go func() { done <- e.Send(testAlert()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a handshake timeout")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("implicit-TLS dial hung: no dial timeout")
	}
}

// A host without a port used to be swallowed (SplitHostPort's error was
// discarded) and surfaced only as an opaque dial failure.
func TestSendRejectsHostWithoutPort(t *testing.T) {
	e := NewEmail("smtp.example.com", "netops@example.com").WithRecipients("noc@example.com")
	err := e.Send(testAlert())
	if err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("want a host:port error, got %v", err)
	}
}

// Happy path over a scripted relay: proves the hand-rolled conversation that
// replaced smtp.SendMail still speaks SMTP correctly.
func TestSendDeliversOverPlainRelay(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var seen strings.Builder
		buf := make([]byte, 4096)
		write := func(s string) { _, _ = c.Write([]byte(s)) }
		write("220 relay.example.com ESMTP\r\n")
		for {
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			line := string(buf[:n])
			seen.WriteString(line)
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				write("250-relay.example.com\r\n250 SIZE 1000000\r\n")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				write("250 OK\r\n")
			case strings.HasPrefix(line, "DATA"):
				write("354 End data with <CR><LF>.<CR><LF>\r\n")
			case strings.HasPrefix(line, "QUIT"):
				write("221 Bye\r\n")
				got <- seen.String()
				return
			case strings.HasSuffix(line, "\r\n.\r\n"):
				write("250 Queued\r\n")
			}
		}
		got <- seen.String()
	}()

	e := NewEmail(ln.Addr().String(), "netops@example.com").
		WithRecipients("noc@example.com").
		WithTimeouts(2*time.Second, 5*time.Second)
	if err := e.Send(testAlert()); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case conversation := <-got:
		for _, want := range []string{"MAIL FROM:<netops@example.com>", "RCPT TO:<noc@example.com>", "iface-down"} {
			if !strings.Contains(conversation, want) {
				t.Errorf("conversation missing %q:\n%s", want, conversation)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay never completed the conversation")
	}
}
