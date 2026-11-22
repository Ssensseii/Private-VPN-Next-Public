//go:build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

type dataBlob struct {
	Size uint32
	Data *byte
}

type storedSettings struct {
	Settings
	PasswordDPAPI string `json:"password_dpapi,omitempty"`
}

func appDataDir() string {
	base := os.Getenv("APPDATA")
	if base == "" {
		base, _ = os.UserConfigDir()
	}
	if base == "" {
		base = os.TempDir()
	}
	d := filepath.Join(base, "PrivateVPN-Next")
	_ = os.MkdirAll(d, 0700)
	return d
}

func LoadSettings() Settings {
	s := DefaultSettings()
	b, err := os.ReadFile(filepath.Join(appDataDir(), "settings.json"))
	if err != nil {
		return s
	}
	var st storedSettings
	if json.Unmarshal(b, &st) != nil {
		return s
	}
	s = st.Settings
	if st.PasswordDPAPI != "" {
		if enc, e := base64.StdEncoding.DecodeString(st.PasswordDPAPI); e == nil {
			if dec, e := dpapiDecrypt(enc); e == nil {
				s.Password = string(dec)
			}
		}
	}
	if s.ProxyType == "" {
		s.ProxyType = "socks5"
	}
	if !validUITheme(s.Theme) {
		s.Theme = "violet"
	}
	if s.Port == 0 {
		if s.ProxyType == "http" {
			s.Port = 8080
		} else {
			s.Port = 1080
		}
	}
	if s.ProxyType == "http" {
		s.UDPOverSocks = false
	}
	return s
}

func SaveSettings(s Settings) error {
	st := storedSettings{Settings: s}
	st.Password = ""
	if s.Password != "" {
		enc, err := dpapiEncrypt([]byte(s.Password))
		if err != nil {
			return fmt.Errorf("DPAPI: %w", err)
		}
		st.PasswordDPAPI = base64.StdEncoding.EncodeToString(enc)
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(appDataDir(), "settings.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func dpapiEncrypt(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}
	in := dataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var out dataBlob
	r, _, e := procCryptProtectData.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, e
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func dpapiDecrypt(enc []byte) ([]byte, error) {
	if len(enc) == 0 {
		return nil, nil
	}
	in := dataBlob{Size: uint32(len(enc)), Data: &enc[0]}
	var out dataBlob
	r, _, e := procCryptUnprotectData.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, e
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
