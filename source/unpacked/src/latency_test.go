package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func proxySettingsForTest(t *testing.T, proxyType, addr, username, password string) Settings {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return Settings{ProxyType: proxyType, Host: host, Port: port, Username: username, Password: password}
}

func startFakeSOCKSProbeProxy(t *testing.T, username, password string, replyCode byte) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
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
				chosen := byte(0)
				if username != "" {
					chosen = 2
				}
				offered := false
				for _, method := range methods {
					if method == chosen {
						offered = true
						break
					}
				}
				if !offered {
					_, _ = c.Write([]byte{5, 0xff})
					return
				}
				_, _ = c.Write([]byte{5, chosen})
				if chosen == 2 {
					var authHead [2]byte
					if _, err := io.ReadFull(c, authHead[:]); err != nil {
						return
					}
					user := make([]byte, int(authHead[1]))
					if _, err := io.ReadFull(c, user); err != nil {
						return
					}
					var passLen [1]byte
					if _, err := io.ReadFull(c, passLen[:]); err != nil {
						return
					}
					pass := make([]byte, int(passLen[0]))
					if _, err := io.ReadFull(c, pass); err != nil {
						return
					}
					if authHead[0] != 1 || string(user) != username || string(pass) != password {
						_, _ = c.Write([]byte{1, 1})
						return
					}
					_, _ = c.Write([]byte{1, 0})
				}
				target, err := readSOCKSConnectTarget(c)
				if err != nil {
					return
				}
				if target != "1.1.1.1:443" {
					_, _ = c.Write(socksReply(5))
					return
				}
				_, _ = c.Write(socksReply(replyCode))
				if replyCode == 0 {
					_, _ = io.Copy(io.Discard, c)
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func readSOCKSConnectTarget(c net.Conn) (string, error) {
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", err
	}
	if head[0] != 5 || head[1] != 1 {
		return "", fmt.Errorf("unexpected SOCKS request: %v", head)
	}
	var host string
	switch head[3] {
	case 1:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(c, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()
	case 4:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(c, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return "", err
		}
		addr := make([]byte, int(n[0]))
		if _, err := io.ReadFull(c, addr); err != nil {
			return "", err
		}
		host = string(addr)
	default:
		return "", fmt.Errorf("unexpected SOCKS address type %d", head[3])
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(c, portBytes[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes[:])))), nil
}

func startFakeHTTPProbeProxy(t *testing.T, status int, expectedAuth string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
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
				if req.Method != http.MethodConnect || req.Host != "1.1.1.1:443" || req.Header.Get("Proxy-Authorization") != expectedAuth {
					_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
					return
				}
				if status == http.StatusOK {
					_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
					_, _ = io.Copy(io.Discard, c)
					return
				}
				_, _ = io.WriteString(c, fmt.Sprintf("HTTP/1.1 %d Test Failure\r\nContent-Length: 0\r\n\r\n", status))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestMeasureProxyRTTUsesSOCKS5Connect(t *testing.T) {
	addr := startFakeSOCKSProbeProxy(t, "", "", 0)
	proxy := proxySettingsForTest(t, "socks5", addr, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	got, err := measureProxyRTT(ctx, proxy, proxyProbeTargets)
	if err != nil {
		t.Fatal(err)
	}
	if got < time.Millisecond || got > time.Second {
		t.Fatalf("unexpected proxy CONNECT duration: %s", got)
	}
}

func TestMeasureProxyRTTUsesSOCKS5Authentication(t *testing.T) {
	addr := startFakeSOCKSProbeProxy(t, "proxy-user", "proxy-pass", 0)
	proxy := proxySettingsForTest(t, "socks5", addr, "proxy-user", "proxy-pass")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := measureProxyRTT(ctx, proxy, proxyProbeTargets); err != nil {
		t.Fatal(err)
	}
}

func TestMeasureProxyRTTUsesHTTPConnectAndBasicAuth(t *testing.T) {
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-pass"))
	addr := startFakeHTTPProbeProxy(t, http.StatusOK, wantAuth)
	proxy := proxySettingsForTest(t, "http", addr, "proxy-user", "proxy-pass")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := measureProxyRTT(ctx, proxy, proxyProbeTargets); err != nil {
		t.Fatal(err)
	}
}

func TestMeasureProxyRTTRejectsSOCKS5Refusal(t *testing.T) {
	addr := startFakeSOCKSProbeProxy(t, "", "", 5)
	proxy := proxySettingsForTest(t, "socks5", addr, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := measureProxyRTT(ctx, proxy, proxyProbeTargets); err == nil || !strings.Contains(err.Error(), "код 5") {
		t.Fatalf("expected SOCKS5 refusal to be reported, got %v", err)
	}
}

func TestMeasureProxyRTTRejectsHTTP502(t *testing.T) {
	addr := startFakeHTTPProbeProxy(t, http.StatusBadGateway, "")
	proxy := proxySettingsForTest(t, "http", addr, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := measureProxyRTT(ctx, proxy, proxyProbeTargets); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("expected HTTP 502 to be reported, got %v", err)
	}
}

func TestMeasureProxyRTTThroughLocalAccelerator(t *testing.T) {
	upstreamAddr := startFakeSOCKSProbeProxy(t, "", "", 0)
	upstream := proxySettingsForTest(t, "socks5", upstreamAddr, "", "")
	accel := NewAccel(upstream, nil)
	localAddr, err := accel.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer accel.Close()

	local := proxySettingsForTest(t, "socks5", localAddr, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := measureProxyRTT(ctx, local, proxyProbeTargets); err != nil {
		t.Fatal(err)
	}
}

func TestMeasureProxyRTTRejectsEmptyTargets(t *testing.T) {
	proxy := Settings{ProxyType: "socks5", Host: "127.0.0.1", Port: 1080}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := measureProxyRTT(ctx, proxy, nil); err == nil {
		t.Fatal("expected an error when no TCP CONNECT targets are configured")
	}
}
