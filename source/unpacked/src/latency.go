package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	proxyProbeTimeout = 2500 * time.Millisecond
	proxyProbeCount   = 3
	pingMeasurementDuration = 10 * time.Second
	pingSampleInterval = 250 * time.Millisecond
)

// This fixed IPv4 target avoids sending AAAA destinations to proxies that reject them.
// Timing includes TCP to the proxy and the complete CONNECT handshake.
var proxyProbeTargets = []string{"1.1.1.1:443"}

func measureProxyRTT(ctx context.Context, proxy Settings, targets []string) (time.Duration, error) {
	if len(targets) == 0 {
		return 0, errors.New("не заданы адреса TCP CONNECT-проверки")
	}
	if err := proxy.Validate(); err != nil {
		return 0, err
	}
	samples := make([]time.Duration, 0, proxyProbeCount)
	errs := make([]error, 0, proxyProbeCount)
	for i := 0; i < proxyProbeCount; i++ {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		target := targets[i%len(targets)]
		sampleCtx, cancel := context.WithTimeout(ctx, proxyProbeTimeout)
		start := time.Now()
		conn, err := proxyConnect(sampleCtx, proxy, target)
		elapsed := time.Since(start)
		cancel()
		if conn != nil {
			_ = conn.Close()
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", target, err))
			continue
		}
		if elapsed < time.Millisecond {
			elapsed = time.Millisecond
		}
		samples = append(samples, elapsed)
	}
	if len(samples) != proxyProbeCount {
		return 0, fmt.Errorf("успешно завершено %d из %d TCP CONNECT-проверок: %w", len(samples), proxyProbeCount, errors.Join(errs...))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], nil
}

// measureProxyRTTWindow samples the active proxy for the full measurement window
// and returns the median successful TCP CONNECT handshake time.
func measureProxyRTTWindow(ctx context.Context, proxy Settings, targets []string, duration time.Duration) (time.Duration, error) {
	if duration <= 0 { return 0, errors.New("длительность измерения должна быть больше нуля") }
	if len(targets) == 0 { return 0, errors.New("не заданы адреса TCP CONNECT-проверки") }
	if err := proxy.Validate(); err != nil { return 0, err }
	deadline := time.Now().Add(duration)
	samples := make([]time.Duration, 0, 32)
	var probeErrors []error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil { return 0, err }
		target := targets[len(samples)%len(targets)]
		sampleStarted := time.Now()
		sampleCtx, cancel := context.WithDeadline(ctx, deadline)
		conn, err := proxyConnect(sampleCtx, proxy, target)
		elapsed := time.Since(sampleStarted)
		cancel()
		if conn != nil { _ = conn.Close() }
		if err == nil {
			if elapsed < time.Millisecond { elapsed = time.Millisecond }
			samples = append(samples, elapsed)
		} else { probeErrors = append(probeErrors, err) }
		wait := time.NewTimer(pingSampleInterval)
		select {
		case <-ctx.Done():
			if !wait.Stop() { select { case <-wait.C: default: } }
			return 0, ctx.Err()
		case <-wait.C:
		}
	}
	if len(samples) == 0 {
		if len(probeErrors) > 0 { return 0, fmt.Errorf("за 10 секунд не удалось выполнить ни одной проверки: %w", errors.Join(probeErrors...)) }
		return 0, errors.New("за 10 секунд не получено ни одного результата")
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	mid := len(samples)/2
	if len(samples)%2 == 0 { return (samples[mid-1]+samples[mid])/2, nil }
	return samples[mid], nil
}

func proxyConnect(ctx context.Context, proxy Settings, target string) (net.Conn, error) {
	if err := proxy.Validate(); err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(strings.Trim(proxy.Host, "[]"), strconv.Itoa(proxy.Port))
	conn, err := (&net.Dialer{Timeout: proxyProbeTimeout, KeepAlive: -1}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("подключение к прокси %s: %w", addr, err)
	}
	keep := false
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		stopCancel()
		if !keep {
			_ = conn.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	switch proxy.ProxyType {
	case "socks5":
		err = socks5Connect(conn, proxy, target)
	case "http":
		err = httpProxyConnect(conn, proxy, target)
	default:
		err = fmt.Errorf("неподдерживаемый тип прокси %q", proxy.ProxyType)
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	keep = true
	return conn, nil
}

func socks5Connect(conn net.Conn, proxy Settings, target string) error {
	methods := []byte{0}
	if proxy.Username != "" {
		methods = []byte{0, 2}
	}
	if err := writeAll(conn, append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("SOCKS5 greeting: %w", err)
	}
	var methodReply [2]byte
	if _, err := io.ReadFull(conn, methodReply[:]); err != nil {
		return fmt.Errorf("ответ SOCKS5 greeting: %w", err)
	}
	if methodReply[0] != 5 || methodReply[1] == 0xff {
		return errors.New("SOCKS5 не принял методы авторизации")
	}
	switch methodReply[1] {
	case 0:
	case 2:
		if proxy.Username == "" {
			return errors.New("SOCKS5 запросил авторизацию, но логин не задан")
		}
		if len(proxy.Username) > 255 || len(proxy.Password) > 255 {
			return errors.New("логин или пароль SOCKS5 длиннее 255 байт")
		}
		auth := []byte{1, byte(len(proxy.Username))}
		auth = append(auth, proxy.Username...)
		auth = append(auth, byte(len(proxy.Password)))
		auth = append(auth, proxy.Password...)
		if err := writeAll(conn, auth); err != nil {
			return fmt.Errorf("SOCKS5 auth: %w", err)
		}
		var authReply [2]byte
		if _, err := io.ReadFull(conn, authReply[:]); err != nil {
			return fmt.Errorf("ответ SOCKS5 auth: %w", err)
		}
		if authReply[0] != 1 || authReply[1] != 0 {
			return errors.New("SOCKS5 отклонил логин или пароль")
		}
	default:
		return fmt.Errorf("SOCKS5 выбрал неподдерживаемый метод %d", methodReply[1])
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("неверная цель TCP CONNECT %q: %w", target, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("неверный порт TCP CONNECT %q", target)
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, 1)
			request = append(request, v4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("неверная длина домена TCP CONNECT %q", host)
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = append(request, byte(port>>8), byte(port))
	if err := writeAll(conn, request); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT request: %w", err)
	}
	reply, err := readSocksReply(conn)
	if err != nil {
		return fmt.Errorf("SOCKS5 CONNECT reply: %w", err)
	}
	if reply[0] != 5 || reply[2] != 0 {
		return errors.New("неверный ответ SOCKS5 CONNECT")
	}
	if reply[1] != 0 {
		return fmt.Errorf("SOCKS5 CONNECT отклонён: код %d (%s)", reply[1], socksReplyDescription(reply[1]))
	}
	return nil
}

func httpProxyConnect(conn net.Conn, proxy Settings, target string) error {
	var request strings.Builder
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n", target, target)
	if proxy.Username != "" {
		token := base64.StdEncoding.EncodeToString([]byte(proxy.Username + ":" + proxy.Password))
		fmt.Fprintf(&request, "Proxy-Authorization: Basic %s\r\n", token)
	}
	request.WriteString("\r\n")
	if err := writeAll(conn, []byte(request.String())); err != nil {
		return fmt.Errorf("HTTP CONNECT request: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fmt.Errorf("ответ HTTP CONNECT: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		return fmt.Errorf("HTTP CONNECT отклонён: %s", response.Status)
	}
	return nil
}

func socksReplyDescription(code byte) string {
	switch code {
	case 1:
		return "общая ошибка SOCKS5-сервера"
	case 2:
		return "подключение запрещено правилами прокси"
	case 3:
		return "сеть недоступна"
	case 4:
		return "узел назначения недоступен"
	case 5:
		return "сервер прокси отклонил TCP-подключение к адресу назначения (connection refused)"
	case 6:
		return "истёк TTL запроса"
	case 7:
		return "команда не поддерживается"
	case 8:
		return "тип адреса не поддерживается"
	default:
		return "неизвестная ошибка SOCKS5-сервера"
	}
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
