package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func startFakeSOCKSProxy(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var h [2]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				methods := make([]byte, int(h[1]))
				if _, e := io.ReadFull(c, methods); e != nil {
					return
				}
				_, _ = c.Write([]byte{5, 0})
				var req [4]byte
				if _, e := io.ReadFull(c, req[:]); e != nil {
					return
				}
				switch req[3] {
				case 1:
					_, _ = io.CopyN(io.Discard, c, 6)
				case 4:
					_, _ = io.CopyN(io.Discard, c, 18)
				case 3:
					var n [1]byte
					if _, e := io.ReadFull(c, n[:]); e != nil {
						return
					}
					_, _ = io.CopyN(io.Discard, c, int64(n[0])+2)
				default:
					return
				}
				_, _ = c.Write(socksReply(0))
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln
}

func openLocalAccelConnect(t *testing.T, addr string) (net.Conn, []byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	var greet [2]byte
	if _, err = io.ReadFull(c, greet[:]); err != nil {
		t.Fatal(err)
	}
	if greet != [2]byte{5, 0} {
		t.Fatalf("unexpected local SOCKS greeting: %v", greet)
	}
	_, _ = c.Write([]byte{5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb})
	rep := make([]byte, 10)
	if _, err = io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	return c, rep
}

func connectToLocalAccel(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, rep := openLocalAccelConnect(t, addr)
	if rep[1] != 0 {
		_ = c.Close()
		t.Fatalf("CONNECT failed with SOCKS reply %d", rep[1])
	}
	_ = c.SetDeadline(time.Time{})
	return c
}

func startFakeHTTPProxy(t *testing.T, status int, expectedAuth string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(4 * time.Second))
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				if req.Body != nil {
					_ = req.Body.Close()
				}
				if req.Method != http.MethodConnect || req.Host != "example.com:443" || req.Header.Get("Proxy-Authorization") != expectedAuth {
					_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
					return
				}
				if status != http.StatusOK {
					_, _ = io.WriteString(c, fmt.Sprintf("HTTP/1.1 %d Test Failure\r\nContent-Length: 0\r\n\r\n", status))
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln
}

func startStaleThenHealthySOCKSProxy(t *testing.T) (net.Listener, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n := accepted.Add(1)
			go func(c net.Conn, number int32) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(4 * time.Second))
				var greeting [2]byte
				if _, err := io.ReadFull(c, greeting[:]); err != nil {
					return
				}
				methods := make([]byte, int(greeting[1]))
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				_, _ = c.Write([]byte{5, 0})
				if number <= 2 {
					// Simulate the provider silently expiring idle prewarmed sockets.
					time.Sleep(150 * time.Millisecond)
					return
				}
				var head [4]byte
				if _, err := io.ReadFull(c, head[:]); err != nil {
					return
				}
				switch head[3] {
				case 1:
					_, err = io.CopyN(io.Discard, c, 6)
				case 4:
					_, err = io.CopyN(io.Discard, c, 18)
				case 3:
					var size [1]byte
					if _, err = io.ReadFull(c, size[:]); err == nil {
						_, err = io.CopyN(io.Discard, c, int64(size[0])+2)
					}
				default:
					return
				}
				if err != nil {
					return
				}
				_, _ = c.Write(socksReply(0))
				_, _ = io.Copy(c, c)
			}(conn, n)
		}
	}()
	return ln, &accepted
}

func TestSOCKSReplyDescription(t *testing.T) {
	if got := socksReplyDescription(5); got != "сервер прокси отклонил TCP-подключение к адресу назначения (connection refused)" {
		t.Fatalf("unexpected SOCKS5 code 5 description: %q", got)
	}
	if got := socksReplyDescription(2); got != "подключение запрещено правилами прокси" {
		t.Fatalf("unexpected SOCKS5 code 2 description: %q", got)
	}
}

func TestAccelRelaysHTTPConnectWithBasicAuth(t *testing.T) {
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-pass"))
	proxy := startFakeHTTPProxy(t, http.StatusOK, expectedAuth)
	defer proxy.Close()
	host, port, _ := net.SplitHostPort(proxy.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	s := DefaultSettings()
	s.ProxyType = "http"
	s.Host, s.Port = host, p
	s.Username, s.Password = "proxy-user", "proxy-pass"
	s.Accelerate = true
	a := NewAccel(s, nil)
	addr, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	client := connectToLocalAccel(t, addr)
	defer client.Close()
	defer a.Close()
	if _, err := client.Write([]byte("http-connect-probe")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("http-connect-probe"))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "http-connect-probe" {
		t.Fatalf("unexpected HTTP CONNECT relay payload %q", got)
	}
}

func TestAccelMapsHTTPProxyAuthenticationFailure(t *testing.T) {
	proxy := startFakeHTTPProxy(t, http.StatusProxyAuthRequired, "Basic "+base64.StdEncoding.EncodeToString([]byte("wrong:credentials")))
	defer proxy.Close()
	host, port, _ := net.SplitHostPort(proxy.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	s := DefaultSettings()
	s.ProxyType = "http"
	s.Host, s.Port = host, p
	s.Username, s.Password = "wrong", "credentials"
	a := NewAccel(s, nil)
	addr, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	client, reply := openLocalAccelConnect(t, addr)
	defer client.Close()
	if reply[1] != 2 {
		t.Fatalf("HTTP 407 must map to SOCKS connection-not-allowed, got %d", reply[1])
	}
}

func TestAccelRetriesExpiredPooledSOCKSConnection(t *testing.T) {
	proxy, accepted := startStaleThenHealthySOCKSProxy(t)
	defer proxy.Close()
	host, port, _ := net.SplitHostPort(proxy.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	s := DefaultSettings()
	s.Host, s.Port = host, p
	a := NewAccel(s, nil)
	addr, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, idle := a.Stats()
		if idle >= accelPoolSize {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	_, idle := a.Stats()
	if idle == 0 {
		t.Fatal("accelerator did not prewarm the SOCKS5 pool")
	}
	time.Sleep(250 * time.Millisecond) // allow the fake provider to expire both idle sockets
	client := connectToLocalAccel(t, addr)
	defer client.Close()
	if _, err := client.Write([]byte("retry-probe")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("retry-probe"))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "retry-probe" {
		t.Fatalf("unexpected retry relay payload %q", got)
	}
	if accepted.Load() < 3 {
		t.Fatalf("expected stale pooled sockets plus a fresh retry, accepted=%d", accepted.Load())
	}
}

func TestAccelRelaysAndClosesTunnel(t *testing.T) {
	proxy := startFakeSOCKSProxy(t)
	defer proxy.Close()
	host, port, _ := net.SplitHostPort(proxy.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	s := DefaultSettings()
	s.Host = host
	s.Port = p
	a := NewAccel(s, nil)
	addr, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	c := connectToLocalAccel(t, addr)
	if _, err := c.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "probe" {
		t.Fatalf("unexpected relay payload %q", buf)
	}
	_ = c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		active, _ := a.Stats()
		if active == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	active, _ := a.Stats()
	if active != 0 {
		t.Fatalf("active tunnel was not removed: %d", active)
	}
	a.Close()
	active, idle := a.Stats()
	if active != 0 || idle != 0 {
		t.Fatalf("connections remain after Close: active=%d idle=%d", active, idle)
	}
}

func TestAccelCloseTerminatesActiveTunnel(t *testing.T) {
	proxy := startFakeSOCKSProxy(t)
	defer proxy.Close()
	host, port, _ := net.SplitHostPort(proxy.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	s := DefaultSettings()
	s.Host = host
	s.Port = p
	a := NewAccel(s, nil)
	addr, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	c := connectToLocalAccel(t, addr)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		active, _ := a.Stats()
		if active > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, err = c.Read(b[:])
	if err == nil {
		t.Fatal("client socket remained open after accelerator Close")
	}
	_ = c.Close()
}

func startHangingSOCKSProxy(t *testing.T) (net.Listener, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seenConnect := make(chan struct{})
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		var h [2]byte
		if _, e = io.ReadFull(c, h[:]); e != nil {
			return
		}
		methods := make([]byte, int(h[1]))
		if _, e = io.ReadFull(c, methods); e != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0})
		var req [4]byte
		if _, e = io.ReadFull(c, req[:]); e != nil {
			return
		}
		switch req[3] {
		case 1:
			_, e = io.CopyN(io.Discard, c, 6)
		case 4:
			_, e = io.CopyN(io.Discard, c, 18)
		case 3:
			var n [1]byte
			if _, e = io.ReadFull(c, n[:]); e == nil {
				_, e = io.CopyN(io.Discard, c, int64(n[0])+2)
			}
		default:
			return
		}
		if e == nil {
			close(seenConnect)
			// Deliberately never send the SOCKS CONNECT reply. This models a
			// proxy that accepted TCP but stalled during its handshake.
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	return ln, seenConnect
}

func TestAccelCloseTerminatesPendingUpstreamHandshake(t *testing.T) {
	proxy, seenConnect := startHangingSOCKSProxy(t)
	defer proxy.Close()
	host, port, _ := net.SplitHostPort(proxy.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	s := DefaultSettings()
	s.Host, s.Port = host, p
	a := NewAccel(s, nil)
	addr, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}

	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err = io.ReadFull(c, greeting[:]); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte{5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb})
	select {
	case <-seenConnect:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream proxy did not receive CONNECT")
	}

	active, _ := a.Stats()
	if active != 1 {
		t.Fatalf("pending handshake must be tracked as active, got %d", active)
	}
	a.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := c.Read(b[:]); err == nil {
		t.Fatal("local client remained open after accelerator Close")
	}
	_ = c.Close()
	active, idle := a.Stats()
	if active != 0 || idle != 0 {
		t.Fatalf("connections remain after Close: active=%d idle=%d", active, idle)
	}
}

func TestAccelPreservesResponseAfterClientHalfClose(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() {
		c, e := proxy.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		var h [2]byte
		if _, e = io.ReadFull(c, h[:]); e != nil {
			return
		}
		methods := make([]byte, int(h[1]))
		if _, e = io.ReadFull(c, methods); e != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0})
		var req [4]byte
		if _, e = io.ReadFull(c, req[:]); e != nil {
			return
		}
		switch req[3] {
		case 1:
			_, e = io.CopyN(io.Discard, c, 6)
		case 4:
			_, e = io.CopyN(io.Discard, c, 18)
		case 3:
			var n [1]byte
			if _, e = io.ReadFull(c, n[:]); e == nil {
				_, e = io.CopyN(io.Discard, c, int64(n[0])+2)
			}
		default:
			return
		}
		if e != nil {
			return
		}
		_, _ = c.Write(socksReply(0))
		_, _ = io.Copy(io.Discard, c)
		time.Sleep(150 * time.Millisecond)
		_, _ = c.Write([]byte("response-after-fin"))
	}()

	host, port, _ := net.SplitHostPort(proxy.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	s := DefaultSettings()
	s.Host, s.Port = host, p
	a := NewAccel(s, nil)
	addr, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	c := connectToLocalAccel(t, addr)
	if _, err := c.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal("local client connection does not support CloseWrite")
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response-after-fin" {
		t.Fatalf("response after half-close was lost: %q", response)
	}
	_ = c.Close()
	a.Close()
}

func TestAccelClosesIdleTunnelAfterInactivity(t *testing.T) {
	proxy := startFakeSOCKSProxy(t)
	defer proxy.Close()
	host, port, _ := net.SplitHostPort(proxy.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	s := DefaultSettings()
	s.Host, s.Port = host, p
	a := NewAccel(s, nil)
	a.idleTimeout = 150 * time.Millisecond
	addr, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	client := connectToLocalAccel(t, addr)
	defer client.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		active, _ := a.Stats()
		if active == 0 {
			a.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	active, idle := a.Stats()
	a.Close()
	t.Fatalf("idle tunnel was not closed: active=%d idle=%d", active, idle)
}

func TestAccelCloseAfterUnsupportedProxyStartDoesNotBlock(t *testing.T) {
	s := DefaultSettings()
	s.ProxyType = "unsupported"
	a := NewAccel(s, nil)
	if _, err := a.Start(); err == nil {
		t.Fatal("unsupported proxy type must be rejected")
	}
	done := make(chan struct{})
	go func() { a.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked after Start failed")
	}
}

func TestAccelCloseBeforeStartDoesNotBlock(t *testing.T) {
	a := NewAccel(DefaultSettings(), nil)
	done := make(chan struct{})
	go func() { a.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked when Start was never called")
	}
}

func TestDialReadyCancellationInterruptsSOCKSGreeting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		var b [2]byte
		_, _ = io.ReadFull(conn, b[:])
		// Deliberately do not answer the SOCKS greeting; wait for client close.
		_, _ = io.Copy(io.Discard, conn)
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	s := DefaultSettings()
	s.Host, s.Port = host, p
	a := NewAccel(s, nil)
	ctx, cancel := context.WithCancel(a.ctx)
	done := make(chan error, 1)
	go func() {
		_, err := a.dialReady(ctx)
		done <- err
	}()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		a.Close()
		cancel()
		t.Fatal("upstream TCP connection was not accepted")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected canceled SOCKS handshake to return an error")
		}
	case <-time.After(time.Second):
		a.Close()
		t.Fatal("cancel did not interrupt the stalled SOCKS greeting")
	}
	a.Close()
}

func TestAccelPrewarmsSmallPoolOnStart(t *testing.T) {
	proxy := startFakeSOCKSProxy(t)
	defer proxy.Close()
	host, port, _ := net.SplitHostPort(proxy.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	s := DefaultSettings()
	s.Host, s.Port = host, p
	a := NewAccel(s, nil)
	if _, err := a.Start(); err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, idle := a.Stats()
		if idle > 0 {
			if idle > accelPoolSize {
				t.Fatalf("idle pool exceeded configured size: %d > %d", idle, accelPoolSize)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	_, idle := a.Stats()
	t.Fatalf("accelerator did not prewarm a SOCKS5 connection; idle=%d", idle)
}
