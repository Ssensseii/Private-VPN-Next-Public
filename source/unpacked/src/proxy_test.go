package main

import (
	"context"
	"net"
	"reflect"
	"testing"
)

func TestResolveProxyIPsLiteral(t *testing.T) {
	ips, err := resolveProxyIPs(context.Background(), "195.158.193.147")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].String() != "195.158.193.147" {
		t.Fatalf("unexpected resolved literal: %#v", ips)
	}
}

func TestProxyIPCIDRsDeduplicatesIPv4AndIPv6(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("195.158.193.147"),
		net.ParseIP("2001:db8::10"),
		net.ParseIP("195.158.193.147"),
	}
	got := proxyIPCIDRs(ips)
	want := []string{"195.158.193.147/32", "2001:db8::10/128"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("proxyIPCIDRs() = %#v, want %#v", got, want)
	}
}
