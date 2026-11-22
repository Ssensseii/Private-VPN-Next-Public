package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// resolveProxyIPs runs before TUN startup. Its results are reused by sing-box,
// the accelerator and the latency probe for the lifetime of this connection.
func resolveProxyIPs(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return nil, errors.New("не указан адрес прокси")
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{append(net.IP(nil), ip...)}, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("не удалось разрешить адрес прокси %q до запуска TUN: %w", host, err)
	}
	unique := make([]net.IP, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		var normalized net.IP
		if v4 := ip.To4(); v4 != nil {
			normalized = append(net.IP(nil), v4...)
		} else if v6 := ip.To16(); v6 != nil {
			normalized = append(net.IP(nil), v6...)
		} else {
			continue
		}
		key := normalized.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, normalized)
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("для прокси %q DNS не вернул IP-адресов", host)
	}
	sort.SliceStable(unique, func(i, j int) bool {
		return unique[i].To4() != nil && unique[j].To4() == nil
	})
	return unique, nil
}

func proxyIPCIDRs(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		var cidr string
		if v4 := ip.To4(); v4 != nil {
			cidr = v4.String() + "/32"
		} else if v6 := ip.To16(); v6 != nil {
			cidr = v6.String() + "/128"
		} else {
			continue
		}
		if _, ok := seen[cidr]; ok {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	return out
}
