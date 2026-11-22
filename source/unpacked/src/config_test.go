package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestBuildConfigHasNoGeoRouting(t *testing.T) {
	s := DefaultSettings()
	s.Host = "proxy.example.com"
	s.Port = 1080
	b, err := BuildConfig(s, `C:\PrivateVPN-Next\core`, true, "")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, forbidden := range []string{"split_ru", "geosite-ru", "geoip-ru", "category-ru"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("unexpected legacy rule %q in config", forbidden)
		}
	}
	if !strings.Contains(text, `"strategy": "ipv4_only"`) {
		t.Fatal("ipv4_only DNS strategy missing for proxied traffic")
	}
}

func TestBuildConfigBypassDomainsAndApps(t *testing.T) {
	s := DefaultSettings()
	s.Host = "proxy.example.com"
	s.Port = 1080
	s.Bypass = "example.org, .example.net;*.example.com"
	s.BypassApps = []string{`C:\Apps\browser.exe`}
	b, err := BuildConfig(s, `C:\PrivateVPN-Next\core`, true, "")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	route := v["route"].(map[string]any)
	joined, _ := json.Marshal(route["rules"])
	for _, want := range []string{"example.org", "example.net", "example.com", "browser.exe", `"outbound":"direct"`} {
		if !strings.Contains(string(joined), want) {
			t.Fatalf("missing %q in route rules: %s", want, joined)
		}
	}
}

func TestParseBypassDomains(t *testing.T) {
	got, err := ParseBypassDomains("example.com, *.example.com; .other.net")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "example.com" || got[1] != "other.net" {
		t.Fatalf("unexpected domains: %#v", got)
	}
	if _, err := ParseBypassDomains("https://example.com"); err == nil {
		t.Fatal("URL must be rejected")
	}
}

func TestParseHTTPSProxyRejected(t *testing.T) {
	if _, err := ParseProxyURL("https://proxy.example.com:443"); err == nil {
		t.Fatal("https proxy must not silently become plain HTTP")
	}
}

func TestBuildConfigAcceleratorSeparatesUDP(t *testing.T) {
	s := DefaultSettings()
	s.Host = "proxy.example.net"
	s.Port = 1080
	s.Accelerate = true
	s.UDPOverSocks = true
	b, err := BuildConfig(s, `C:\PrivateVPN-Next\core`, true, "127.0.0.1:2081")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	outbounds := v["outbounds"].([]any)
	foundAccel := false
	for _, item := range outbounds {
		m := item.(map[string]any)
		if m["tag"] == "accel" {
			foundAccel = true
		}
	}
	if !foundAccel {
		t.Fatal("local accelerator outbound missing")
	}
	route := v["route"].(map[string]any)
	if route["final"] != "accel" {
		t.Fatalf("final outbound = %v, want accel", route["final"])
	}
	rules, _ := json.Marshal(route["rules"])
	if !strings.Contains(string(rules), `"network":"udp","outbound":"proxy"`) {
		t.Fatalf("UDP traffic must bypass TCP accelerator: %s", rules)
	}
}

func TestHTTPAllowsTCPAcceleratorButRejectsUDP(t *testing.T) {
	s := DefaultSettings()
	s.ProxyType = "http"
	s.Host = "proxy.example.net"
	s.Port = 8080
	s.Accelerate = true
	if err := s.Validate(); err != nil {
		t.Fatalf("HTTP CONNECT acceleration should be valid: %v", err)
	}
	s.Accelerate = false
	s.UDPOverSocks = true
	if err := s.Validate(); err == nil {
		t.Fatal("HTTP UDP must be rejected")
	}
}

func TestBuildConfigHTTPAcceleratorUsesLocalSOCKSRelay(t *testing.T) {
	s := DefaultSettings()
	s.ProxyType = "http"
	s.Host = "proxy.example.net"
	s.Port = 8080
	s.Username = "proxy-user"
	s.Password = "proxy-pass"
	s.Accelerate = true
	b, err := BuildConfig(s, `C:\PrivateVPN-Next\core`, true, "127.0.0.1:2081")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	outbounds := cfg["outbounds"].([]any)
	var proxy, accel map[string]any
	for _, item := range outbounds {
		m := item.(map[string]any)
		switch m["tag"] {
		case "proxy":
			proxy = m
		case "accel":
			accel = m
		}
	}
	if proxy == nil || proxy["type"] != "http" || proxy["server_port"] != float64(8080) {
		t.Fatalf("HTTP upstream outbound is missing: %#v", proxy)
	}
	if accel == nil || accel["type"] != "socks" || accel["server"] != "127.0.0.1" || accel["server_port"] != float64(2081) {
		t.Fatalf("local SOCKS relay outbound is missing: %#v", accel)
	}
	route := cfg["route"].(map[string]any)
	if route["final"] != "accel" {
		t.Fatalf("HTTP accelerated final outbound = %v, want accel", route["final"])
	}
	rules := route["rules"].([]any)
	udpRejected := false
	for _, item := range rules {
		rule := item.(map[string]any)
		if rule["network"] == "udp" && rule["action"] == "reject" {
			udpRejected = true
			break
		}
	}
	if !udpRejected {
		t.Fatalf("HTTP mode must reject unsupported UDP: %#v", rules)
	}
}

func TestBuildConfigHTTPUsesDoHOverCONNECT(t *testing.T) {
	s := DefaultSettings()
	s.ProxyType = "http"
	s.Host = "proxy.example.net"
	s.Port = 8080
	s.Username = "proxy-user"
	s.Password = "proxy-pass"
	b, err := BuildConfig(s, `C:\\PrivateVPN-Next\\core`, true, "")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	outbounds := cfg["outbounds"].([]any)
	var proxy map[string]any
	for _, item := range outbounds {
		m := item.(map[string]any)
		if m["tag"] == "proxy" {
			proxy = m
		}
	}
	if proxy == nil || proxy["type"] != "http" || proxy["server_port"] != float64(8080) {
		t.Fatalf("HTTP outbound was not generated correctly: %#v", proxy)
	}
	if proxy["username"] != "proxy-user" || proxy["password"] != "proxy-pass" {
		t.Fatalf("HTTP proxy credentials missing: %#v", proxy)
	}
	dns := cfg["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	var remote map[string]any
	for _, item := range servers {
		m := item.(map[string]any)
		if m["tag"] == "dns-remote" {
			remote = m
		}
	}
	if remote == nil || remote["type"] != "https" || remote["server_port"] != float64(443) || remote["detour"] != "proxy" {
		t.Fatalf("remote DNS must use DoH through the HTTP proxy: %#v", remote)
	}
	tls := remote["tls"].(map[string]any)
	if tls["enabled"] != true || tls["server_name"] != "cloudflare-dns.com" {
		t.Fatalf("DoH TLS settings are incomplete: %#v", tls)
	}
	route := cfg["route"].(map[string]any)
	if route["final"] != "proxy" {
		t.Fatalf("HTTP route final = %v, want proxy", route["final"])
	}
	rules := route["rules"].([]any)
	for _, item := range rules {
		m := item.(map[string]any)
		if m["network"] == "udp" && m["action"] != "reject" {
			t.Fatalf("HTTP mode must not route UDP: %#v", m)
		}
	}
}

func TestBuildConfigDNSBypassUsesRouteAction(t *testing.T) {
	s := DefaultSettings()
	s.Host = "proxy.example.net"
	s.Port = 1080
	s.Bypass = "example.org"
	b, err := BuildConfig(s, `C:\\PrivateVPN-Next\\core`, true, "")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	dns := cfg["dns"].(map[string]any)
	rules := dns["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("expected one DNS bypass rule, got %#v", rules)
	}
	rule := rules[0].(map[string]any)
	if rule["action"] != "route" || rule["server"] != "dns-direct" || rule["strategy"] != "prefer_ipv4" {
		t.Fatalf("DNS bypass rule must use direct DNS with dual-stack preference: %#v", rule)
	}
}


func TestBuildConfigProxyEndpointBypassesTUN(t *testing.T) {
	s := DefaultSettings()
	s.Host = "195.158.193.147"
	s.Port = 8000
	b, err := BuildConfig(s, `C:\PrivateVPN-Next\core`, true, "")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	route := cfg["route"].(map[string]any)
	rules := route["rules"].([]any)
	found := false
	for _, item := range rules {
		rule := item.(map[string]any)
		if rule["outbound"] != "direct" || rule["port"] != float64(8000) {
			continue
		}
		cidrs, _ := rule["ip_cidr"].([]any)
		for _, cidr := range cidrs {
			if cidr == "195.158.193.147/32" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("proxy endpoint must bypass TUN on its configured port: %#v", rules)
	}
}

func TestBuildConfigPinsResolvedProxyAddresses(t *testing.T) {
	s := DefaultSettings()
	s.Host = "proxy.example.net"
	s.Port = 8000
	ips := []net.IP{net.ParseIP("195.158.193.147"), net.ParseIP("2001:db8::10")}
	b, err := BuildConfigWithProxyIPs(s, `C:\PrivateVPN-Next\core`, true, "", ips)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	outbounds := cfg["outbounds"].([]any)
	var proxy map[string]any
	for _, item := range outbounds {
		m := item.(map[string]any)
		if m["tag"] == "proxy" {
			proxy = m
		}
	}
	if proxy == nil || proxy["server"] != "195.158.193.147" {
		t.Fatalf("proxy outbound must use the pre-resolved IPv4 endpoint: %#v", proxy)
	}
	route := cfg["route"].(map[string]any)
	rules := route["rules"].([]any)
	found := false
	for _, item := range rules {
		rule := item.(map[string]any)
		if rule["outbound"] != "direct" || rule["port"] != float64(8000) {
			continue
		}
		cidrs, _ := rule["ip_cidr"].([]any)
		if len(cidrs) == 2 && cidrs[0] == "195.158.193.147/32" && cidrs[1] == "2001:db8::10/128" {
			found = true
		}
	}
	if !found {
		t.Fatalf("all resolved proxy addresses must bypass TUN: %#v", rules)
	}
}

func TestUIThemeValidation(t *testing.T) {
	s := DefaultSettings()
	s.Host = "proxy.example.com"
	for _, theme := range []string{"violet", "ocean", "emerald", "rose", "amber"} {
		s.Theme = theme
		if err := s.Validate(); err != nil {
			t.Fatalf("theme %q should be valid: %v", theme, err)
		}
	}
	s.Theme = "neon"
	if err := s.Validate(); err == nil {
		t.Fatal("unknown UI theme must be rejected")
	}
}

func TestBuildConfigUsesDedicatedTUNAdapterName(t *testing.T) {
	s := DefaultSettings()
	s.Host = "proxy.example.com"
	s.Port = 1080
	b, err := BuildConfig(s, `C:\\PrivateVPN-Next\\core`, true, "")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	inbounds := cfg["inbounds"].([]any)
	tun := inbounds[0].(map[string]any)
	if got := tun["interface_name"]; got != tunInterfaceName {
		t.Fatalf("TUN interface_name = %v, want %q", got, tunInterfaceName)
	}
	if tunInterfaceName == "PrivateVPN-Next" {
		t.Fatal("TUN adapter name must not reuse the legacy adapter name")
	}
}
