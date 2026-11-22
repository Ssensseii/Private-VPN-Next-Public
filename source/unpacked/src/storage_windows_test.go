//go:build windows

package main

import (
	"os"
	"testing"
)

func TestHTTPAccelerationPersistsAcrossSettingsLoad(t *testing.T) {
	appData, err := os.MkdirTemp("", "privatevpn-settings-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(appData)
	t.Setenv("APPDATA", appData)

	want := DefaultSettings()
	want.ProxyType = "http"
	want.Host = "proxy.example.com"
	want.Port = 8080
	want.Accelerate = true
	want.UDPOverSocks = false
	want.Theme = "ocean"

	if err := SaveSettings(want); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	got := LoadSettings()
	if !got.Accelerate {
		t.Fatal("HTTP TCP acceleration was disabled while loading saved settings")
	}
	if got.UDPOverSocks {
		t.Fatal("HTTP profile must not restore SOCKS5 UDP forwarding")
	}
	if got.ProxyType != want.ProxyType || got.Host != want.Host || got.Port != want.Port || got.Theme != want.Theme {
		t.Fatalf("settings changed during round trip: got %#v, want %#v", got, want)
	}
}
