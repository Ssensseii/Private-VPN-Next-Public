//go:build windows

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxSavedProfiles = 20

type ProxyProfile struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Settings Settings `json:"settings"`
}

type profileStore struct {
	Profiles        []ProxyProfile `json:"profiles"`
	ActiveProfileID string         `json:"activeProfileId"`
}

type storedProfile struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Settings      Settings `json:"settings"`
	PasswordDPAPI string   `json:"password_dpapi,omitempty"`
}

type storedProfileStore struct {
	Profiles        []storedProfile `json:"profiles"`
	ActiveProfileID string          `json:"activeProfileId"`
}

// Profiles contain only proxy credentials and endpoint data; routing, UI and
// acceleration preferences remain global application settings.
func profileProxySettings(s Settings) Settings {
	return Settings{ProxyType:s.ProxyType, Host:s.Host, Port:s.Port, Username:s.Username, Password:s.Password}
}

func mergeProxySettings(base, profile Settings) Settings {
	base.ProxyType = profile.ProxyType
	base.Host = profile.Host
	base.Port = profile.Port
	base.Username = profile.Username
	base.Password = profile.Password
	if base.ProxyType == "http" { base.UDPOverSocks = false }
	return base
}

func LoadProfileStore() (profileStore, error) {
	out := profileStore{Profiles: []ProxyProfile{}}
	data, err := os.ReadFile(filepath.Join(appDataDir(), "profiles.json"))
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	var disk storedProfileStore
	if err := json.Unmarshal(data, &disk); err != nil {
		return out, fmt.Errorf("файл профилей повреждён: %w", err)
	}
	out.ActiveProfileID = disk.ActiveProfileID
	for _, item := range disk.Profiles {
		s := item.Settings
		s.Password = ""
		if item.PasswordDPAPI != "" {
			encrypted, err := base64.StdEncoding.DecodeString(item.PasswordDPAPI)
			if err != nil {
				return out, fmt.Errorf("не удалось прочитать пароль профиля %q", item.Name)
			}
			plain, err := dpapiDecrypt(encrypted)
			if err != nil {
				return out, fmt.Errorf("не удалось расшифровать пароль профиля %q: %w", item.Name, err)
			}
			s.Password = string(plain)
		}
		out.Profiles = append(out.Profiles, ProxyProfile{ID: item.ID, Name: item.Name, Settings: s})
	}
	return out, nil
}

func SaveProfileStore(store profileStore) error {
	if len(store.Profiles) > maxSavedProfiles {
		return fmt.Errorf("можно сохранить не более %d профилей", maxSavedProfiles)
	}
	disk := storedProfileStore{Profiles: make([]storedProfile, 0, len(store.Profiles)), ActiveProfileID: store.ActiveProfileID}
	ids := make(map[string]bool, len(store.Profiles))
	names := make(map[string]bool, len(store.Profiles))
	activeFound := store.ActiveProfileID == ""
	for i := range store.Profiles {
		p := store.Profiles[i]
		p.ID = strings.TrimSpace(p.ID)
		p.Name = strings.TrimSpace(p.Name)
		if p.ID == "" || len(p.ID) > 64 {
			return errors.New("идентификатор профиля некорректен")
		}
		if p.Name == "" || len([]rune(p.Name)) > 40 {
			return errors.New("название профиля должно содержать от 1 до 40 символов")
		}
		if ids[p.ID] {
			return errors.New("обнаружен повторяющийся идентификатор профиля")
		}
		key := strings.ToLower(p.Name)
		if names[key] {
			return fmt.Errorf("профиль с названием %q уже существует", p.Name)
		}
		ids[p.ID], names[key] = true, true
		if p.ID == store.ActiveProfileID {
			activeFound = true
		}
		proxySettings := profileProxySettings(p.Settings)
		if err := proxySettings.Validate(); err != nil {
			return fmt.Errorf("профиль %q: %w", p.Name, err)
		}
		item := storedProfile{ID: p.ID, Name: p.Name, Settings: proxySettings}
		item.Settings.Password = ""
		if p.Settings.Password != "" {
			encrypted, err := dpapiEncrypt([]byte(p.Settings.Password))
			if err != nil {
				return fmt.Errorf("шифрование пароля профиля %q: %w", p.Name, err)
			}
			item.PasswordDPAPI = base64.StdEncoding.EncodeToString(encrypted)
		}
		disk.Profiles = append(disk.Profiles, item)
	}
	if !activeFound {
		return errors.New("активный профиль отсутствует в списке")
	}
	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(appDataDir(), "profiles.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func newProfileID() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
