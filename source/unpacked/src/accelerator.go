package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	accelPoolSize    = 2
	accelIdleTTL     = 20 * time.Second
	accelFillEvery   = 2 * time.Second
	accelDialTimeout = 10 * time.Second
)

type pooledConn struct {
	conn      net.Conn
	idleSince time.Time
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func newBufferedConn(conn net.Conn) *bufferedConn {
	return &bufferedConn{Conn: conn, reader: bufio.NewReader(conn)}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type relayActivity struct {
	mu      sync.Mutex
	client  net.Conn
	upstream net.Conn
	timeout time.Duration
}

func (r *relayActivity) touch() {
	r.mu.Lock()
	deadline := time.Now().Add(r.timeout)
	_ = r.client.SetDeadline(deadline)
	_ = r.upstream.SetDeadline(deadline)
	r.mu.Unlock()
}

type activityConn struct {
	net.Conn
	activity *relayActivity
}

func (c activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.activity.touch()
	}
	return n, err
}

func (c activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.activity.touch()
	}
	return n, err
}

func (c activityConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
type activeTunnel struct {
	client   net.Conn
	mu       sync.Mutex
	upstream net.Conn
	closed   bool
	once     sync.Once
}

func (t *activeTunnel) replaceUpstream(upstream net.Conn) bool {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = upstream.Close()
		return false
	}
	old := t.upstream
	t.upstream = upstream
	t.mu.Unlock()
	if old != nil && old != upstream {
		_ = old.Close()
	}
	return true
}

func (t *activeTunnel) close() {
	t.once.Do(func() {
		t.mu.Lock()
		t.closed = true
		upstream := t.upstream
		t.mu.Unlock()
		_ = t.client.Close()
		if upstream != nil {
			_ = upstream.Close()
		}
	})
}

type Accel struct {
	settings   Settings
	logf       func(string)
	listener   net.Listener
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	pool       []pooledConn
	active     map[*activeTunnel]struct{}
	lastDemand time.Time
	idleTimeout time.Duration
	lastLog    map[string]time.Time
	started    bool
	closed     bool
	wg         sync.WaitGroup
	acceptDone chan struct{}
}

func NewAccel(s Settings, logf func(string)) *Accel {
	ctx, cancel := context.WithCancel(context.Background())
	return &Accel{settings: s, logf: logf, ctx: ctx, cancel: cancel, active: make(map[*activeTunnel]struct{}), idleTimeout: 2 * time.Minute, lastLog: make(map[string]time.Time), acceptDone: make(chan struct{})}
}

func (a *Accel) log(msg string) {
	if a.logf != nil {
		a.logf("Ускоритель: " + msg)
	}
}

func (a *Accel) logLimited(key, msg string, interval time.Duration) {
	a.mu.Lock()
	now := time.Now()
	last := a.lastLog[key]
	if !last.IsZero() && now.Sub(last) < interval {
		a.mu.Unlock()
		return
	}
	a.lastLog[key] = now
	a.mu.Unlock()
	a.log(msg)
}

func (a *Accel) Start() (string, error) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return "", net.ErrClosed
	}
	if a.started {
		a.mu.Unlock()
		return "", errors.New("ускоритель уже запускался")
	}
	a.started = true
	if a.settings.ProxyType != "socks5" && a.settings.ProxyType != "http" {
		close(a.acceptDone)
		a.mu.Unlock()
		return "", fmt.Errorf("ускоритель не поддерживает тип прокси %q", a.settings.ProxyType)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		close(a.acceptDone)
		a.mu.Unlock()
		return "", err
	}
	a.listener = ln
	a.lastDemand = time.Now()
	a.wg.Add(1)
	go a.fillLoop()
	go a.acceptLoop()
	addr := ln.Addr().String()
	a.mu.Unlock()
	a.log("запущен; свободный пул до 2 предварительно открытых TCP-соединений, неактивные туннели закрываются через 2 минуты")
	return addr, nil
}

func (a *Accel) acceptLoop() {
	defer close(a.acceptDone)
	for {
		c, err := a.listener.Accept()
		if err != nil {
			if a.ctx.Err() != nil {
				return
			}
			a.logLimited("accept", "ошибка локального SOCKS5: "+err.Error(), 30*time.Second)
			continue
		}
		a.wg.Add(1)
		go func() { defer a.wg.Done(); a.handleClient(c) }()
	}
}

func (a *Accel) fillLoop() {
	defer a.wg.Done()
	t := time.NewTicker(accelFillEvery)
	defer t.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		if a.closed {
			a.mu.Unlock()
			return
		}
		idle := time.Since(a.lastDemand)
		if a.lastDemand.IsZero() || idle > accelIdleTTL {
			// Do not pre-open proxy sessions at startup or keep idle pool
			// entries alive just because another long-lived tunnel exists.
			old := a.pool
			a.pool = nil
			a.mu.Unlock()
			for _, p := range old {
				_ = p.conn.Close()
			}
			continue
		}
		need := accelPoolSize - len(a.pool)
		a.mu.Unlock()
		for i := 0; i < need; i++ {
			c, err := a.dialReady(a.ctx)
			if err != nil {
				if a.ctx.Err() == nil {
					a.logLimited("prefill", "не удалось открыть запасное соединение: "+err.Error(), 30*time.Second)
				}
				break
			}
			a.mu.Lock()
			if a.closed || a.lastDemand.IsZero() || time.Since(a.lastDemand) > accelIdleTTL || len(a.pool) >= accelPoolSize {
				a.mu.Unlock()
				_ = c.Close()
				break
			}
			a.pool = append(a.pool, pooledConn{conn: c, idleSince: time.Now()})
			a.mu.Unlock()
		}
	}
}

func (a *Accel) dialReady(parent context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(parent, accelDialTimeout)
	defer cancel()
	d := net.Dialer{Timeout: accelDialTimeout, KeepAlive: 15 * time.Second}
	addr := net.JoinHostPort(strings.Trim(a.settings.Host, "[]"), strconv.Itoa(a.settings.Port))
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	// Canceling the accelerator must also interrupt proxy handshakes,
	// not only the initial TCP dial.
	stopCancel := context.AfterFunc(ctx, func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(accelDialTimeout))
	if a.settings.ProxyType == "http" {
		_ = c.SetDeadline(time.Time{})
		stopped := stopCancel()
		if ctx.Err() != nil || !stopped {
			_ = c.Close()
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, net.ErrClosed
		}
		return newBufferedConn(c), nil
	}
	if a.settings.ProxyType != "socks5" {
		_ = c.Close()
		_ = stopCancel()
		return nil, fmt.Errorf("неподдерживаемый тип прокси %q", a.settings.ProxyType)
	}
	methods := []byte{0}
	if a.settings.Username != "" {
		methods = []byte{0, 2}
	}
	if _, err = c.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		c.Close()
		return nil, err
	}
	var reply [2]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil {
		c.Close()
		return nil, err
	}
	if reply[0] != 5 || reply[1] == 0xff {
		c.Close()
		return nil, errors.New("SOCKS5-сервер не принял методы авторизации")
	}
	if reply[1] == 2 {
		u, p := []byte(a.settings.Username), []byte(a.settings.Password)
		if len(u) > 255 || len(p) > 255 {
			c.Close()
			return nil, errors.New("логин или пароль SOCKS5 длиннее 255 байт")
		}
		msg := []byte{1, byte(len(u))}
		msg = append(msg, u...)
		msg = append(msg, byte(len(p)))
		msg = append(msg, p...)
		if _, err = c.Write(msg); err != nil {
			c.Close()
			return nil, err
		}
		if _, err = io.ReadFull(c, reply[:]); err != nil {
			c.Close()
			return nil, err
		}
		if reply[0] != 1 || reply[1] != 0 {
			c.Close()
			return nil, errors.New("SOCKS5: неверный логин или пароль")
		}
	} else if reply[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("SOCKS5 выбрал неподдерживаемый метод %d", reply[1])
	}
	_ = c.SetDeadline(time.Time{})
	stopped := stopCancel()
	if ctx.Err() != nil || !stopped {
		_ = c.Close()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	}
	return c, nil
}

func (a *Accel) get() (net.Conn, bool, error) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, false, net.ErrClosed
	}
	a.lastDemand = time.Now()
	for len(a.pool) > 0 {
		p := a.pool[0]
		a.pool = a.pool[1:]
		if time.Since(p.idleSince) <= accelIdleTTL {
			a.mu.Unlock()
			return p.conn, true, nil
		}
		_ = p.conn.Close()
	}
	a.mu.Unlock()
	conn, err := a.dialReady(a.ctx)
	return conn, false, err
}

func (a *Accel) handleClient(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(client, h[:]); err != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = client.Write([]byte{5, 0xff})
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	var reqHead [4]byte
	if _, err := io.ReadFull(client, reqHead[:]); err != nil {
		return
	}
	if reqHead[0] != 5 || reqHead[1] != 1 {
		_, _ = client.Write(socksReply(7))
		return
	}
	var addrTail []byte
	switch reqHead[3] {
	case 1:
		addrTail = make([]byte, 4+2)
	case 4:
		addrTail = make([]byte, 16+2)
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(client, n[:]); err != nil {
			return
		}
		addrTail = append([]byte{n[0]}, make([]byte, int(n[0])+2)...)
	default:
		_, _ = client.Write(socksReply(8))
		return
	}
	readTail := addrTail
	if reqHead[3] == 3 {
		readTail = addrTail[1:]
	}
	if _, err := io.ReadFull(client, readTail); err != nil {
		return
	}
	request := append(append([]byte{}, reqHead[:]...), addrTail...)
	target, err := socksRequestTarget(reqHead, addrTail)
	if err != nil {
		_, _ = client.Write(socksReply(8))
		return
	}

	// Allow time for a slow upstream dial and its CONNECT handshake.
	_ = client.SetDeadline(time.Now().Add(2*accelDialTimeout + 5*time.Second))
	up, pooled, err := a.get()
	if err != nil {
		_, _ = client.Write(socksReply(1))
		a.logLimited("get", "не удалось получить соединение: "+err.Error(), 10*time.Second)
		return
	}

	// Track the checked-out socket before the upstream CONNECT handshake so
	// Close() can interrupt a stalled proxy response.
	t := &activeTunnel{client: client, upstream: up}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		t.close()
		return
	}
	a.active[t] = struct{}{}
	a.mu.Unlock()
	defer func() {
		t.close()
		a.mu.Lock()
		delete(a.active, t)
		a.lastDemand = time.Now()
		a.mu.Unlock()
	}()

	_ = up.SetDeadline(time.Now().Add(10 * time.Second))
	response, retryable, failureCode, connectErr := a.connectUpstream(up, request, target)
	if connectErr != nil && pooled && retryable {
		// A proxy may close an idle pre-authenticated socket without notifying
		// the client. Retry once with a new TCP connection instead of failing
		// this user's first request after an idle period.
		_ = up.Close()
		fresh, dialErr := a.dialReady(a.ctx)
		if dialErr != nil {
			connectErr = errors.Join(connectErr, fmt.Errorf("повторное подключение: %w", dialErr))
		} else if !t.replaceUpstream(fresh) {
			return
		} else {
			up = fresh
			_ = up.SetDeadline(time.Now().Add(10 * time.Second))
			response, _, failureCode, connectErr = a.connectUpstream(up, request, target)
		}
	}
	if connectErr != nil {
		_, _ = client.Write(socksReply(failureCode))
		a.logLimited("connect", fmt.Sprintf("CONNECT к %s через %s не выполнен: %v", target, a.settings.ProxyType, connectErr), 5*time.Second)
		return
	}
	if len(response) < 2 {
		_, _ = client.Write(socksReply(1))
		return
	}
	if err := writeAll(client, response); err != nil {
		return
	}
	if response[1] != 0 {
		a.logLimited("refused", fmt.Sprintf("прокси отклонил CONNECT к %s: %s (SOCKS-код %d)", target, socksReplyDescription(response[1]), response[1]), 5*time.Second)
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})
	a.relay(t)
}

func (a *Accel) connectUpstream(up net.Conn, request []byte, target string) ([]byte, bool, byte, error) {
	switch a.settings.ProxyType {
	case "socks5":
		if err := writeAll(up, request); err != nil {
			return nil, true, 1, fmt.Errorf("отправка SOCKS5 CONNECT: %w", err)
		}
		response, err := readSocksReply(up)
		if err != nil {
			return nil, true, 1, fmt.Errorf("ответ SOCKS5 CONNECT: %w", err)
		}
		if len(response) < 10 || response[0] != 5 || response[2] != 0 {
			return nil, true, 1, errors.New("неверный заголовок ответа SOCKS5 CONNECT")
		}
		return response, false, 1, nil
	case "http":
		conn, ok := up.(*bufferedConn)
		if !ok {
			return nil, true, 1, errors.New("HTTP upstream не имеет буферизованного reader")
		}
		var requestText strings.Builder
		fmt.Fprintf(&requestText, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n", target, target)
		if a.settings.Username != "" {
			token := base64.StdEncoding.EncodeToString([]byte(a.settings.Username + ":" + a.settings.Password))
			fmt.Fprintf(&requestText, "Proxy-Authorization: Basic %s\r\n", token)
		}
		requestText.WriteString("\r\n")
		if err := writeAll(conn.Conn, []byte(requestText.String())); err != nil {
			return nil, true, 1, fmt.Errorf("отправка HTTP CONNECT: %w", err)
		}
		response, err := http.ReadResponse(conn.reader, &http.Request{Method: http.MethodConnect})
		if err != nil {
			return nil, true, 1, fmt.Errorf("ответ HTTP CONNECT: %w", err)
		}
		if response.StatusCode != http.StatusOK {
			if response.Body != nil {
				_ = response.Body.Close()
			}
			return nil, false, httpStatusToSOCKSCode(response.StatusCode), fmt.Errorf("HTTP CONNECT отклонён: %s", response.Status)
		}
		return socksReply(0), false, 1, nil
	default:
		return nil, false, 1, fmt.Errorf("неподдерживаемый тип прокси %q", a.settings.ProxyType)
	}
}

func socksRequestTarget(head [4]byte, tail []byte) (string, error) {
	var host string
	var portBytes []byte
	switch head[3] {
	case 1:
		if len(tail) != 6 {
			return "", errors.New("неверная длина IPv4 SOCKS-адреса")
		}
		host = net.IP(tail[:4]).String()
		portBytes = tail[4:]
	case 4:
		if len(tail) != 18 {
			return "", errors.New("неверная длина IPv6 SOCKS-адреса")
		}
		host = net.IP(tail[:16]).String()
		portBytes = tail[16:]
	case 3:
		if len(tail) < 3 {
			return "", errors.New("неверная длина доменного SOCKS-адреса")
		}
		n := int(tail[0])
		if n == 0 || len(tail) != n+3 {
			return "", errors.New("неверная длина доменного SOCKS-адреса")
		}
		host = string(tail[1 : n+1])
		portBytes = tail[n+1:]
		if strings.ContainsAny(host, "\r\n\t /\\\x00") {
			return "", errors.New("недопустимые символы в домене SOCKS CONNECT")
		}
	default:
		return "", errors.New("неподдерживаемый тип SOCKS-адреса")
	}
	port := int(binary.BigEndian.Uint16(portBytes))
	if port == 0 {
		return "", errors.New("порт SOCKS CONNECT не может быть нулевым")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func httpStatusToSOCKSCode(status int) byte {
	switch status {
	case http.StatusProxyAuthRequired, http.StatusUnauthorized, http.StatusForbidden:
		return 2
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return 4
	default:
		return 5
	}
}

func readSocksReply(c net.Conn) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 5 || h[2] != 0 {
		return nil, errors.New("неверный заголовок ответа SOCKS5")
	}
	var n int
	switch h[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var b [1]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return nil, err
		}
		n = int(b[0])
		return readReplyTail(c, h[:], append([]byte{b[0]}, make([]byte, n+2)...), n+2)
	default:
		return nil, errors.New("неизвестный тип адреса в ответе SOCKS5")
	}
	return readReplyTail(c, h[:], make([]byte, n+2), n+2)
}
func readReplyTail(c net.Conn, head, tail []byte, n int) ([]byte, error) {
	if _, err := io.ReadFull(c, tail[len(tail)-n:]); err != nil {
		return nil, err
	}
	return append(head, tail...), nil
}
func socksReply(code byte) []byte { return []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0} }

func (a *Accel) relay(t *activeTunnel) {
	activity := &relayActivity{
		client: t.client, upstream: t.upstream, timeout: a.idleTimeout,
	}
	activity.touch()
	client := activityConn{Conn: t.client, activity: activity}
	upstream := activityConn{Conn: t.upstream, activity: activity}

	done := make(chan error, 2)
	copyHalf := func(dst net.Conn, src net.Conn) {
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			if closeErr := cw.CloseWrite(); err == nil && closeErr != nil {
				err = closeErr
			}
		}
		done <- err
	}
	go copyHalf(upstream, client)
	go copyHalf(client, upstream)

	// Preserve normal TCP half-close so a request can still receive its final
	// response. A shared activity deadline closes both sockets only after a
	// period with no bytes in either direction.
	select {
	case err := <-done:
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				a.logLimited("idle-tunnel", "закрыт TCP-туннель без активности", 30*time.Second)
			}
			t.close()
			<-done
			return
		}
	case <-a.ctx.Done():
		t.close()
		<-done
		<-done
		return
	}
	select {
	case <-done:
	case <-a.ctx.Done():
		t.close()
		<-done
	}
	t.close()
}

func (a *Accel) Stats() (active, idle int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.active), len(a.pool)
}

func (a *Accel) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	listener := a.listener
	if !a.started {
		// Close is also safe when Start was never called.
		a.started = true
		close(a.acceptDone)
	}
	a.mu.Unlock()

	a.cancel()
	if listener != nil {
		_ = listener.Close()
	}
	<-a.acceptDone

	a.mu.Lock()
	pool := a.pool
	a.pool = nil
	active := make([]*activeTunnel, 0, len(a.active))
	for t := range a.active {
		active = append(active, t)
	}
	a.mu.Unlock()
	for _, p := range pool {
		_ = p.conn.Close()
	}
	for _, t := range active {
		t.close()
	}
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		a.log("часть обработчиков не завершилась за 5 секунд после закрытия сокетов")
		return
	}
	a.log("остановлен; активные туннели и свободный пул закрыты")
}

func (a *Accel) EndpointHostPort() string {
	if a.listener == nil {
		return ""
	}
	return strings.TrimSpace(a.listener.Addr().String())
}
