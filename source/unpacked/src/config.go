package main

import (
	"encoding/json"
	"fmt"
	"net"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Settings contains only settings that are part of the current PrivateVPN Next UI.
type Settings struct {
	ProxyType    string   `json:"proxy_type"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	Username     string   `json:"username"`
	Password     string   `json:"password,omitempty"`
	BlockQUIC    bool     `json:"block_quic"`
	UDPOverSocks bool     `json:"udp_over_socks"`
	Accelerate   bool     `json:"accelerate"`
	Bypass       string   `json:"bypass"`
	BypassApps   []string `json:"bypass_apps"`
	Theme        string   `json:"theme,omitempty"`
}

func validUITheme(theme string) bool {
	switch theme {
	case "violet", "ocean", "emerald", "rose", "amber":
		return true
	default:
		return false
	}
}

func DefaultSettings() Settings {
	return Settings{ProxyType: "socks5", Port: 1080, BlockQUIC: true, Theme: "violet"}
}

func (s Settings) Validate() error {
	if s.ProxyType != "socks5" && s.ProxyType != "http" {
		return fmt.Errorf("неизвестный тип прокси: %q", s.ProxyType)
	}
	if s.Theme != "" && !validUITheme(s.Theme) {
		return fmt.Errorf("неизвестная цветовая схема: %q", s.Theme)
	}
	h := strings.TrimSpace(s.Host)
	if h == "" {
		return fmt.Errorf("не указан адрес сервера")
	}
	if strings.ContainsAny(h, " /\\") || (strings.Contains(h, ":") && net.ParseIP(strings.Trim(h, "[]")) == nil) {
		return fmt.Errorf("укажите адрес сервера без схемы и порта")
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("порт должен быть от 1 до 65535")
	}
	if s.Password != "" && s.Username == "" {
		return fmt.Errorf("указан пароль, но не указан логин")
	}
	if s.ProxyType == "http" && s.UDPOverSocks {
		return fmt.Errorf("HTTP-прокси не поддерживает UDP")
	}
	if _, err := ParseBypassDomains(s.Bypass); err != nil {
		return err
	}
	for _, p := range s.BypassApps {
		if !isWindowsAbsPath(p) || !strings.EqualFold(filepath.Ext(strings.ReplaceAll(p, "\\", "/")), ".exe") {
			return fmt.Errorf("путь приложения должен быть абсолютным путём к EXE: %q", p)
		}
	}
	return nil
}

func ParseBypassDomains(raw string) ([]string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' ' })
	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	for _, item := range fields {
		d := strings.ToLower(strings.TrimSpace(item))
		d = strings.TrimPrefix(d, "*.")
		d = strings.TrimPrefix(d, ".")
		d = strings.TrimSuffix(d, ".")
		if d == "" {
			continue
		}
		if strings.ContainsAny(d, ":/@\\_") || strings.Contains(d, "*") || net.ParseIP(d) != nil {
			return nil, fmt.Errorf("некорректный домен в списке обхода: %q", item)
		}
		if len(d) > 253 || !validDomain(d) {
			return nil, fmt.Errorf("некорректный домен в списке обхода: %q", item)
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out, nil
}

func validDomain(d string) bool {
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return strings.Contains(d, ".")
}

func ParseProxyURL(raw string) (Settings, error) {
	s := DefaultSettings()
	raw = strings.TrimSpace(raw)
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return s, fmt.Errorf("ожидается ссылка socks5://логин:пароль@хост:порт или http://хост:порт")
	}
	switch strings.ToLower(scheme) {
	case "socks", "socks5", "socks5h":
		s.ProxyType = "socks5"
	case "http":
		s.ProxyType, s.Port = "http", 8080
	case "https":
		return s, fmt.Errorf("HTTPS-прокси пока не поддерживается; используйте http:// или socks5://")
	default:
		return s, fmt.Errorf("поддерживаются только socks5:// и http://")
	}
	rest = strings.TrimSuffix(rest, "/")
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		cred := rest[:at]
		rest = rest[at+1:]
		u, p, _ := strings.Cut(cred, ":")
		s.Username, s.Password = urlUnescape(u), urlUnescape(p)
	}
	host, portStr, err := net.SplitHostPort(rest)
	if err != nil {
		s.Host = strings.Trim(rest, "[]")
	} else {
		s.Host = host
		p, e := strconv.Atoi(portStr)
		if e != nil {
			return s, fmt.Errorf("неверный порт: %s", portStr)
		}
		s.Port = p
	}
	return s, s.Validate()
}

func urlUnescape(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '%' && i+2 < len(v) {
			if n, err := strconv.ParseUint(v[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

type obj = map[string]any

// BuildConfig generates a sing-box 1.14-compatible TUN configuration.
// accelAddr is an optional local SOCKS5 endpoint used for TCP acceleration.
func BuildConfig(s Settings, coreDir string, tun bool, accelAddr string) ([]byte, error) {
	var proxyIPs []net.IP
	if ip := net.ParseIP(strings.Trim(strings.TrimSpace(s.Host), "[]")); ip != nil {
		proxyIPs = []net.IP{ip}
	}
	return buildConfig(s, coreDir, tun, accelAddr, proxyIPs)
}

// BuildConfigWithProxyIPs pins the proxy endpoint to addresses resolved before TUN startup.
const tunInterfaceName = "PVPNNext-TUN"

func BuildConfigWithProxyIPs(s Settings, coreDir string, tun bool, accelAddr string, proxyIPs []net.IP) ([]byte, error) {
	return buildConfig(s, coreDir, tun, accelAddr, proxyIPs)
}

func buildConfig(s Settings, coreDir string, tun bool, accelAddr string, proxyIPs []net.IP) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.Accelerate && accelAddr == "" {
		return nil, fmt.Errorf("ускоритель включён, но локальный SOCKS5 relay не запущен")
	}
	proxyHost := strings.Trim(strings.TrimSpace(s.Host), "[]")
	proxyServer := proxyHost
	if len(proxyIPs) > 0 {
		proxyServer = proxyIPs[0].String()
	}
	proxy := obj{"tag": "proxy", "server": proxyServer, "server_port": s.Port}
	if s.ProxyType == "socks5" {
		proxy["type"] = "socks"
		proxy["version"] = "5"
	} else {
		proxy["type"] = "http"
	}
	if s.Username != "" {
		proxy["username"], proxy["password"] = s.Username, s.Password
	}

	bypass, err := ParseBypassDomains(s.Bypass)
	if err != nil {
		return nil, err
	}
	dnsRules := []any{}
	routeRules := []any{
		obj{"action": "sniff"},
		obj{"protocol": "dns", "action": "hijack-dns"},
	}
	if cidrs := proxyIPCIDRs(proxyIPs); len(cidrs) > 0 {
		routeRules = append(routeRules, obj{"ip_cidr": cidrs, "port": s.Port, "outbound": "direct"})
	}
	if net.ParseIP(proxyHost) == nil {
		routeRules = append(routeRules, obj{"domain": strings.TrimSuffix(proxyHost, "."), "port": s.Port, "outbound": "direct"})
	}
	routeRules = append(routeRules, obj{"ip_is_private": true, "outbound": "direct"})
	if len(bypass) > 0 {
		dnsRules = append(dnsRules, obj{"domain_suffix": bypass, "action": "route", "server": "dns-direct", "strategy": "prefer_ipv4"})
		routeRules = append(routeRules, obj{"domain_suffix": bypass, "outbound": "direct"})
	}
	apps := normalizeAppPaths(s.BypassApps)
	if len(apps) > 0 {
		dnsRules = append(dnsRules, obj{"process_path": apps, "action": "route", "server": "dns-direct", "strategy": "prefer_ipv4"})
		routeRules = append(routeRules, obj{"process_path": apps, "outbound": "direct"})
	}
	if s.ProxyType == "http" || !s.UDPOverSocks {
		// HTTP CONNECT and SOCKS5 TCP-only mode cannot carry UDP.
		routeRules = append(routeRules, obj{"network": "udp", "action": "reject"})
	} else if s.BlockQUIC {
		routeRules = append(routeRules, obj{"network": "udp", "port": 443, "action": "reject"})
	}

	outbounds := []any{proxy, obj{"type": "direct", "tag": "direct"}}
	finalOutbound := "proxy"
	if accelAddr != "" && s.Accelerate {
		h, p, e := net.SplitHostPort(accelAddr)
		if e != nil {
			return nil, fmt.Errorf("неверный локальный адрес ускорителя: %w", e)
		}
		port, e := strconv.Atoi(p)
		if e != nil {
			return nil, e
		}
		outbounds = append(outbounds, obj{"type": "socks", "tag": "accel", "server": h, "server_port": port, "version": "5"})
		if s.UDPOverSocks {
			routeRules = append(routeRules, obj{"network": "udp", "outbound": "proxy"})
		}
		finalOutbound = "accel"
	}
	cfg := obj{
		"log": obj{"level": "info", "timestamp": true},
		"dns": obj{
			"servers": []any{
				// DoH uses TCP/443, which is accepted by standard HTTP CONNECT
				// proxies; raw DNS-over-TCP on port 53 is commonly blocked.
				obj{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "tls": obj{"enabled": true, "server_name": "cloudflare-dns.com"}, "detour": "proxy"},
				obj{"type": "udp", "tag": "dns-direct", "server": "77.88.8.8"},
			},
			"rules": dnsRules, "final": "dns-remote", "strategy": "ipv4_only",
		},
		"outbounds": outbounds,
		"route":     obj{"rules": routeRules, "final": finalOutbound, "auto_detect_interface": true, "find_process": true, "default_domain_resolver": "dns-direct"},
	}
	if tun {
		cfg["inbounds"] = []any{obj{"type": "tun", "tag": "tun-in", "interface_name": tunInterfaceName, "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "mtu": 9000, "auto_route": true, "strict_route": true, "stack": "mixed"}}
	} else {
		cfg["inbounds"] = []any{obj{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

var drivePathRE = regexp.MustCompile(`^[a-zA-Z]:\\`)

func isWindowsAbsPath(p string) bool {
	p = strings.TrimSpace(p)
	return drivePathRE.MatchString(p) || strings.HasPrefix(p, `\\`)
}

func normalizeAppPaths(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(strings.ReplaceAll(p, "/", `\`))
		clean := path.Clean(strings.ReplaceAll(p, `\`, "/"))
		p = strings.ReplaceAll(clean, "/", `\`)
		key := strings.ToLower(p)
		if p == "." || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}
