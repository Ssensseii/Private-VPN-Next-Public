//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const appTitle = "PrivateVPN Next"

var appVersion = "dev"

type toastState struct {
	Title string `json:"title"`
	Text  string `json:"text"`
	OK    bool   `json:"ok"`
}
type uiState struct {
	Updating bool `json:"updating"`
	UpdateProgress int `json:"updateProgress"`
	UpdateStage string `json:"updateStage"`
	Update    *updateInfo `json:"update,omitempty"`
	State     string      `json:"state"`
	Stopping  bool        `json:"stopping"`
	Since     int64       `json:"since"`
	IP        string      `json:"ip"`
	Latency   int64       `json:"latency"`
	RTT       int64       `json:"rtt"`
	Pinging   bool        `json:"pinging"`
	Step      string      `json:"step"`
	Settings  Settings    `json:"settings"`
	Log       []string    `json:"log"`
	Toast     *toastState `json:"toast,omitempty"`
}
type procItem struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type app struct {
	mu          sync.Mutex
	logMu       sync.Mutex
	trayMu      sync.Mutex
	hwnd        uintptr
	controller  uintptr
	environment uintptr
	loaderDLL   *syscall.DLL
	notifyData  notifyIconData
	webview     uintptr
	server      *http.Server
	listener    net.Listener
	token       string
	exeDir      string
	core        *Core
	settings    Settings
	activeProfileID string
	state       string
	stopping    bool
	step        string
	since       int64
	ip          string
	latency     int64
	rtt         int64
	pinging     bool
	updating bool
	updateProgress int
	updateStage string
	logs        []string
	toast       *toastState
	quitting    bool
	trayIcon    uintptr
	trayAdded   bool
}

func main() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := runApp(); err != nil {
		showNativeError(appTitle, err.Error())
	}
}

func runApp() error {
	if alreadyRunning() {
		restoreExistingWindow()
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	a := &app{exeDir: filepath.Dir(exe), settings: LoadSettings(), state: "off"}
	coreExe := filepath.Join(a.exeDir, "core", "sing-box.exe")
	a.core = NewCore(filepath.Join(a.exeDir, "core"), a.addLog, a.coreDied)
	defer a.core.Close()
	existingPIDs, findErr := findCoreProcesses(coreExe)
	if findErr != nil {
		return fmt.Errorf("не удалось проверить ранее запущенное сетевое ядро: %w", findErr)
	}
	if len(existingPIDs) > 0 {
		// Adopt the oldest matching process and terminate any duplicate copies.
		for _, duplicatePID := range existingPIDs[1:] {
			if err := terminateCoreProcess(duplicatePID); err != nil {
				return fmt.Errorf("найдено несколько процессов sing-box; %w", err)
			}
		}
		if err := a.core.AttachExistingProcess(existingPIDs[0], a.settings); err != nil {
			return fmt.Errorf("не удалось восстановить управление существующим VPN-туннелем: %w", err)
		}
		a.mu.Lock()
		a.state = "on"
		a.since = time.Now().Unix()
		a.mu.Unlock()
		a.addLog(fmt.Sprintf("Восстановлено управление ранее запущенным VPN-туннелем (PID %d)", existingPIDs[0]))
		if a.settings.Accelerate {
			a.addLog("Внимание: ускоритель TCP работает в процессе интерфейса; после аварийного закрытия приложения он мог остановиться")
		}
	}
	if err := a.startHTTP(); err != nil {
		return err
	}
	defer a.server.Close()
	return a.runWebView()
}

func alreadyRunning() bool { return acquireAppMutex() }

func (a *app) addLog(line string) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	line = time.Now().Format("15:04:05") + " " + line
	a.mu.Lock()
	a.logs = append(a.logs, line)
	if len(a.logs) > 700 {
		a.logs = append([]string(nil), a.logs[len(a.logs)-700:]...)
	}
	a.mu.Unlock()
	_ = os.MkdirAll(filepath.Join(appDataDir(), "logs"), 0700)
	f, err := os.OpenFile(filepath.Join(appDataDir(), "logs", "PrivateVPN-Next.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		_, _ = f.WriteString(line + "\r\n")
		_ = f.Close()
	}
}

func (a *app) clearLog() error {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	logDir := filepath.Join(appDataDir(), "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(logDir, "PrivateVPN-Next.log"), []byte{}, 0600); err != nil {
		return err
	}
	a.mu.Lock()
	a.logs = nil
	a.mu.Unlock()
	return nil
}

func (a *app) setToast(title, msg string, ok bool) {
	a.mu.Lock()
	a.toast = &toastState{Title: title, Text: msg, OK: ok}
	a.mu.Unlock()
}

func (a *app) reconcileCoreState() {
	running := a.core != nil && a.core.Running()
	a.mu.Lock()
	changed := false
	recovered := false
	if running && a.state == "off" {
		a.state = "on"
		a.stopping = false
		a.step = ""
		if a.since == 0 {
			a.since = time.Now().Unix()
		}
		changed = true
		recovered = true
	} else if !running && a.state == "on" {
		a.state = "off"
		a.stopping = false
		a.since = 0
		a.ip = ""
		a.pinging = false
		changed = true
	}
	a.mu.Unlock()
	if changed {
		if recovered {
			a.addLog("Состояние восстановлено: процесс sing-box продолжает работать в фоне")
		} else {
			a.addLog("Состояние синхронизировано: процесс sing-box не запущен")
		}
		a.updateTray()
	}
}

func (a *app) snapshot() uiState {
	a.reconcileCoreState()
	a.mu.Lock()
	defer a.mu.Unlock()
	logs := append([]string(nil), a.logs...)
	toast := a.toast
	a.toast = nil
	return uiState{State:a.state,Stopping:a.stopping,Since:a.since,IP:a.ip,Latency:a.latency,RTT:a.rtt,Pinging:a.pinging,Step:a.step,Updating:a.updating,UpdateProgress:a.updateProgress,UpdateStage:a.updateStage,Settings:a.settings,Log:logs,Toast:toast}
}

func isExistingTunInterfaceError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "tun") &&
		(strings.Contains(msg, "cannot create a file when that file already exists") ||
			strings.Contains(msg, "already exists"))
}

func (a *app) coreDied(err error) {
	a.mu.Lock()
	a.state = "off"
	a.stopping = false
	a.since = 0
	a.ip = ""
	a.mu.Unlock()
	a.addLog("sing-box аварийно завершился: " + err.Error())
	a.setToast("VPN отключился", "Проверьте журнал для подробностей.", false)
	a.updateTray()
}

func (a *app) toggle() {
	a.reconcileCoreState()
	coreRunning := a.core != nil && a.core.Running()
	a.mu.Lock()
	if a.updating { a.mu.Unlock(); a.setToast("Обновление выполняется","Нельзя включить VPN-туннель во время обновления.",false); return }
	if a.state == "connecting" { a.mu.Unlock(); return }
	if a.state == "on" || coreRunning {
		a.state = "connecting"
		a.stopping = true
		a.step = "Отключаю туннель"
		a.mu.Unlock()
		a.updateTray()
		go func() {
			a.core.Stop()
			a.mu.Lock()
			a.state = "off"
			a.stopping = false
			a.since = 0
			a.ip = ""
			a.step = ""
			a.mu.Unlock()
			a.addLog("VPN отключён")
			a.setToast("Отключено", "", true)
			a.updateTray()
		}()
		return
	}
	s := a.settings
	if err := s.Validate(); err != nil {
		a.mu.Unlock()
		a.setToast("Проверьте настройки", err.Error(), false)
		return
	}
	a.state = "connecting"
	a.stopping = false
	a.step = "Запуск сетевого ядра"
	a.ip = ""
	a.latency = 0
	a.rtt = 0
	a.mu.Unlock()
	a.updateTray()
	go func() {
		a.addLog("Запуск sing-box")
		err := a.core.Start(s)
		if err != nil && isExistingTunInterfaceError(err) {
			if stopped, cleanupErr := stopOrphanCoreProcesses(a.core.Exe()); cleanupErr == nil && stopped > 0 {
				a.addLog(fmt.Sprintf("Обнаружен оставшийся процесс sing-box: завершено процессов %d, повторяю запуск TUN", stopped))
				time.Sleep(750 * time.Millisecond)
				err = a.core.Start(s)
			} else if cleanupErr != nil {
				a.addLog("Не удалось очистить оставшийся процесс sing-box: " + cleanupErr.Error())
			}
		}
		var latency time.Duration
		if err == nil {
			probeSettings, ok := a.core.ProbeSettings()
			if !ok {
				err = errors.New("не удалось получить активный маршрут прокси для проверки")
			} else {
				probeCtx, cancelProbe := context.WithTimeout(context.Background(), 8*time.Second)
				latency, err = measureProxyRTT(probeCtx, probeSettings, proxyProbeTargets)
				cancelProbe()
			}
			if err != nil {
				a.core.Stop()
				err = fmt.Errorf("проверка TCP CONNECT через выбранный маршрут не пройдена: %w", err)
			}
		}
		if err != nil {
			a.mu.Lock()
			a.state = "off"
			a.step = ""
			a.since = 0
			a.latency = 0
			a.mu.Unlock()
			a.addLog("Ошибка запуска/проверки прокси: " + err.Error())
			a.setToast("Не удалось подключиться", err.Error(), false)
			a.updateTray()
			return
		}
		a.mu.Lock()
		a.state = "on"
		a.since = time.Now().Unix()
		a.latency = latency.Milliseconds()
		a.step = ""
		a.mu.Unlock()
		routeLabel := "через прокси"
		if s.Accelerate {
			routeLabel = "через ускоритель"
		}
		a.addLog(fmt.Sprintf("Проверка %s пройдена: TCP CONNECT %s, задержка %d мс", routeLabel, proxyProbeTargets[0], latency.Milliseconds()))
		a.addLog("VPN подключён: прокси подтвердил установление удалённого TCP-соединения")
		a.setToast("Подключено", "Прокси подтвердил TCP CONNECT через выбранный маршрут.", true)
		a.updateTray()
		a.checkExternalIP()
	}()
}

func (a *app) checkExternalIP() {
	// External-IP lookup is informational; it is not used as a latency metric.
	ipCtx, cancelIP := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelIP()
	req, err := http.NewRequestWithContext(ipCtx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		a.addLog("Проверка внешнего IP: " + err.Error())
		return
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		IdleConnTimeout:       5 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		a.addLog("Проверка внешнего IP: " + err.Error())
		a.mu.Lock()
		if a.state == "on" {
			a.ip = "Проверка IP не удалась"
		}
		a.mu.Unlock()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("сервис вернул HTTP %d", resp.StatusCode)
		a.addLog("Проверка внешнего IP: " + err.Error())
		a.mu.Lock()
		if a.state == "on" {
			a.ip = "Проверка IP не удалась"
		}
		a.mu.Unlock()
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		a.addLog("Чтение внешнего IP: " + err.Error())
		return
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		a.addLog("Проверка внешнего IP: сервис вернул некорректный адрес")
		return
	}
	a.mu.Lock()
	if a.state == "on" {
		a.ip = ip
	}
	a.mu.Unlock()
	a.addLog("Внешний IP: " + ip)
}

func (a *app) ping() {
	a.reconcileCoreState()
	a.mu.Lock()
	if a.state != "on" || a.pinging {
		a.mu.Unlock()
		return
	}
	a.pinging = true
	a.rtt = 0
	a.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), pingMeasurementDuration+2*time.Second)
		defer cancel()
		probeSettings, ok := a.core.ProbeSettings()
		var rtt time.Duration
		var err error
		if !ok {
			err = errors.New("активный маршрут прокси недоступен")
		} else {
			rtt, err = measureProxyRTTWindow(ctx, probeSettings, proxyProbeTargets, pingMeasurementDuration)
		}
		a.mu.Lock()
		a.pinging = false
		if err == nil {
			a.rtt = rtt.Milliseconds()
		} else {
			a.rtt = 0
		}
		a.mu.Unlock()
		if err != nil {
			a.addLog("Проверка TCP CONNECT не удалась: " + err.Error())
			a.setToast("Проверка не удалась", "Прокси не установил удалённое TCP-соединение: "+err.Error(), false)
			return
		}
		ms := rtt.Milliseconds()
		a.addLog(fmt.Sprintf("Измерение пинга за 10 секунд завершено: медиана %d мс", ms))
		a.setToast("Измерение завершено", fmt.Sprintf("Пинг за 10 секунд: %d мс", ms), true)
	}()
}

func (a *app) saveTheme(theme string) string {
	if !validUITheme(theme) {
		return "Неизвестная цветовая схема"
	}
	a.mu.Lock()
	oldTheme := a.settings.Theme
	s := a.settings
	s.Theme = theme
	a.settings = s
	a.mu.Unlock()
	if err := SaveSettings(s); err != nil {
		a.mu.Lock()
		if a.settings.Theme == theme {
			a.settings.Theme = oldTheme
		}
		a.mu.Unlock()
		return err.Error()
	}
	a.addLog("Цветовая схема изменена: " + theme)
	return ""
}

func (a *app) saveSettings(s Settings) string {
	a.reconcileCoreState()
	coreRunning := a.core != nil && a.core.Running()
	a.mu.Lock()
	running := a.state != "off" || coreRunning
	a.mu.Unlock()
	if running {
		return "Сначала отключите VPN, чтобы изменить настройки"
	}
	if err := s.Validate(); err != nil {
		return err.Error()
	}
	if err := SaveSettings(s); err != nil {
		return err.Error()
	}
	a.mu.Lock()
	a.settings = s
	a.mu.Unlock()
	a.addLog("Настройки сохранены")
	return ""
}

func (a *app) startHTTP() error {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	a.listener = ln
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	a.token = hex.EncodeToString(raw)
	page := strings.ReplaceAll(uiHTML, "<title>PrivateVPN</title>", "<title>PrivateVPN Next</title>")
	page = strings.ReplaceAll(page, "__APP_VERSION__", appVersion)
	page = strings.Replace(page, "// Мост к Go: функции привязаны как window.vpn_<имя> и возвращают Promise.", a.bridgeScript()+"\n// Мост к Go: функции привязаны как window.vpn_<имя> и возвращают Promise.", 1)
	page = strings.ReplaceAll(page, "<div class=\"brand\">PrivateVPN<small>личный клиент</small></div>", "<div class=\"brand\">PrivateVPN Next<small>личный клиент</small></div>")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, page)
	})
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !a.authorized(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		writeJSON(w, a.snapshot())
	})
	mux.HandleFunc("/api/", a.handleAPI)
	a.server = &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	go func() {
		if e := a.server.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
			a.addLog("HTTP bridge: " + e.Error())
		}
	}()
	return nil
}

func (a *app) bridgeScript() string {
	return fmt.Sprintf(`const VPN_TOKEN=%q;
async function vpnCall(name,args=[]){const r=await fetch('/api/'+name,{method:'POST',headers:{'Content-Type':'application/json','X-PVPN-Token':VPN_TOKEN},body:JSON.stringify(args)});if(!r.ok)throw new Error('HTTP '+r.status);return await r.json();}
window.vpn_ready=async()=>{const s=await vpnCall('ready');if(window.onUpdate)window.onUpdate(s);return s};
window.vpn_checkUpdates=()=>vpnCall('checkUpdates');
window.vpn_listProfiles=()=>vpnCall('listProfiles');
window.vpn_saveProfile=p=>vpnCall('saveProfile',[p]);
window.vpn_selectProfile=id=>vpnCall('selectProfile',[id]);
window.vpn_deleteProfile=id=>vpnCall('deleteProfile',[id]);
window.vpn_toggle=()=>vpnCall('toggle');
window.vpn_showMini=()=>vpnCall('showMini');
window.vpn_ping=()=>vpnCall('ping');
window.vpn_saveSettings=s=>vpnCall('saveSettings',[s]);
window.vpn_saveTheme=theme=>vpnCall('saveTheme',[theme]);
window.vpn_parseLink=t=>vpnCall('parseLink',[t||'']);
window.vpn_listProcs=()=>vpnCall('listProcs');
window.vpn_pickApp=async()=>{const p=await vpnCall('pickApp');if(p&&window.onPickedApp)window.onPickedApp(p);return p};
window.vpn_openLogFile=()=>vpnCall('openLogFile');
window.vpn_clearLog=()=>vpnCall('clearLog');
window.vpn_openReleases=()=>vpnCall('openReleases');
window.vpn_restoreWindow=()=>vpnCall('restoreWindow');
setInterval(()=>fetch('/api/state',{headers:{'X-PVPN-Token':VPN_TOKEN}}).then(r=>r.ok?r.json():null).then(s=>{if(s&&window.onUpdate)window.onUpdate(s)}).catch(()=>{}),700);
`, a.token)
}

func (a *app) authorized(r *http.Request) bool {
	got := r.Header.Get("X-PVPN-Token")
	return len(got) == len(a.token) && subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) == 1
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func (a *app) handleAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !a.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	defer r.Body.Close()
	var args []json.RawMessage
	_ = json.Unmarshal(body, &args)
	switch name {
	case "ready":
		writeJSON(w, a.snapshot())
	case "checkUpdates":
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		info, err := checkStableUpdate(ctx, appVersion)
		if err != nil { writeJSON(w, map[string]string{"error": err.Error()}); return }
		writeJSON(w, info)
	case "downloadUpdate":
		a.mu.Lock()
		active := a.state != "off" || (a.core != nil && a.core.Running())
		if active { a.mu.Unlock(); writeJSON(w,map[string]string{"error":"Перед установкой обновления отключите VPN-туннель."}); return }
		if a.updating { a.mu.Unlock(); writeJSON(w,map[string]string{"error":"Обновление уже выполняется."}); return }
		a.updating=true; a.updateProgress=0; a.updateStage="Подготовка загрузки"
		a.mu.Unlock()
		ctx,cancel:=context.WithTimeout(r.Context(),3*time.Minute);defer cancel()
		rel,err:=latestStableRelease(ctx)
		if err==nil&&compareSemver(strings.TrimPrefix(rel.TagName,"v"),appVersion)<=0{err=errors.New("Новая стабильная версия не найдена.")}
		var installer string
		if err==nil{installer,err=downloadVerifiedInstaller(ctx,rel,func(done,total int64){a.mu.Lock();if total>0{a.updateProgress=int(done*100/total)};a.updateStage="Загрузка установщика";a.mu.Unlock()})}
		if err==nil{a.mu.Lock();a.updateProgress=100;a.updateStage="Проверка и подготовка установки";a.mu.Unlock();err=prepareRollback(a.exeDir,appVersion)}
		if err==nil{err=launchUpdateAfterExit(installer,a.exeDir)}
		if err!=nil{a.mu.Lock();a.updating=false;a.updateProgress=0;a.updateStage="";a.mu.Unlock();writeJSON(w,map[string]string{"error":err.Error()});return}
		a.mu.Lock();a.updateStage="Установка обновления";a.mu.Unlock()
		writeJSON(w,map[string]any{"ok":true,"version":strings.TrimPrefix(rel.TagName,"v"),"message":"Установщик запущен. Приложение закроется для завершения обновления."})
		go func(){time.Sleep(1500*time.Millisecond);a.quit()}()
	case "rollback":
		a.mu.Lock()
		active := a.state != "off" || (a.core != nil && a.core.Running())
		a.mu.Unlock()
		if active { writeJSON(w, map[string]string{"error":"Перед откатом отключите VPN-туннель."}); return }
		if err := launchRollback(); err != nil { writeJSON(w, map[string]string{"error":err.Error()}); return }
		writeJSON(w, map[string]any{"ok":true,"message":"Восстановление предыдущей версии запущено."})
		go func(){ time.Sleep(500*time.Millisecond); a.quit() }()
	case "showMini":
		if a.hwnd != 0 { pPostMessageW.Call(a.hwnd, uintptr(wmShowMini), 0, 0) }
		writeJSON(w,nil)
	case "toggle":
		a.toggle()
		writeJSON(w, nil)
	case "ping":
		a.ping()
		writeJSON(w, nil)
	case "saveTheme":
		var theme string
		if len(args) == 0 || json.Unmarshal(args[0], &theme) != nil {
			writeJSON(w, "Не получена цветовая схема")
			return
		}
		writeJSON(w, a.saveTheme(theme))
	case "listProfiles":
		store, err := LoadProfileStore()
		if err != nil { writeJSON(w, map[string]string{"error": err.Error()}); return }
		if len(store.Profiles) == 0 && a.settings.Host != "" {
			id, e := newProfileID()
			if e != nil { writeJSON(w, map[string]string{"error": e.Error()}); return }
			store.Profiles = append(store.Profiles, ProxyProfile{ID:id, Name:"Основной профиль", Settings:a.settings})
			store.ActiveProfileID = id
			if e = SaveProfileStore(store); e != nil { writeJSON(w, map[string]string{"error": e.Error()}); return }
		}
		writeJSON(w, store)
	case "saveProfile":
		a.mu.Lock()
		active := a.state != "off" || (a.core != nil && a.core.Running())
		a.mu.Unlock()
		if active { writeJSON(w, map[string]string{"error":"Отключите VPN перед изменением профилей."}); return }
		if len(args) == 0 { writeJSON(w, map[string]string{"error":"Не получены данные профиля"}); return }
		var p ProxyProfile
		if err := json.Unmarshal(args[0], &p); err != nil { writeJSON(w, map[string]string{"error":err.Error()}); return }
		p.Name = strings.TrimSpace(p.Name)
		if err := profileProxySettings(p.Settings).Validate(); err != nil { writeJSON(w, map[string]string{"error":err.Error()}); return }
		store, err := LoadProfileStore()
		if err != nil { writeJSON(w, map[string]string{"error":err.Error()}); return }
		if p.ID == "" {
			if len(store.Profiles) >= maxSavedProfiles { writeJSON(w, map[string]string{"error":fmt.Sprintf("Достигнут лимит: %d профилей",maxSavedProfiles)}); return }
			p.ID, err = newProfileID()
			if err != nil { writeJSON(w, map[string]string{"error":err.Error()}); return }
			store.Profiles = append(store.Profiles,p)
		} else {
			found := false
			for i := range store.Profiles { if store.Profiles[i].ID == p.ID { store.Profiles[i] = p; found = true; break } }
			if !found { writeJSON(w, map[string]string{"error":"Профиль не найден. Обновите список профилей."}); return }
		}
		if err = SaveProfileStore(store); err != nil { writeJSON(w, map[string]string{"error":err.Error()}); return }
		if store.ActiveProfileID == p.ID {
			a.mu.Lock(); merged := mergeProxySettings(a.settings, p.Settings); a.mu.Unlock()
			if err = SaveSettings(merged); err != nil { writeJSON(w, map[string]string{"error":err.Error()}); return }
			a.mu.Lock(); a.settings = merged; a.mu.Unlock()
		}
		writeJSON(w, map[string]any{"ok":true,"profile":p})
	case "selectProfile":
		if len(args) == 0 { writeJSON(w, map[string]string{"error":"Не указан профиль"}); return }
		var id string; _ = json.Unmarshal(args[0], &id)
		a.mu.Lock()
		active := a.state != "off" || (a.core != nil && a.core.Running())
		a.mu.Unlock()
		if active { writeJSON(w, map[string]string{"error":"Отключите VPN перед переключением профиля."}); return }
		store, err := LoadProfileStore()
		if err != nil { writeJSON(w, map[string]string{"error":err.Error()}); return }
		found := false
		var selected Settings
		for _, p := range store.Profiles { if p.ID == id { selected=p.Settings; found=true; break } }
		if !found { writeJSON(w, map[string]string{"error":"Профиль не найден"}); return }
		a.mu.Lock(); merged := mergeProxySettings(a.settings, selected); a.mu.Unlock()
		if err = SaveSettings(merged); err != nil { writeJSON(w, map[string]string{"error":err.Error()}); return }
		store.ActiveProfileID = id
		if err = SaveProfileStore(store); err != nil { writeJSON(w, map[string]string{"error":err.Error()}); return }
		a.mu.Lock(); a.settings=merged; a.activeProfileID=id; a.mu.Unlock()
		writeJSON(w, map[string]any{"ok":true,"settings":merged,"activeProfileId":id})
	case "deleteProfile":
		if len(args) == 0 { writeJSON(w, map[string]string{"error":"Не указан профиль"}); return }
		var id string; _ = json.Unmarshal(args[0], &id)
		a.mu.Lock()
		active := a.state != "off" || (a.core != nil && a.core.Running())
		a.mu.Unlock()
		if active { writeJSON(w, map[string]string{"error":"Отключите VPN перед удалением профиля."}); return }
		store, err := LoadProfileStore()
		if err != nil { writeJSON(w, map[string]string{"error":err.Error()}); return }
		filtered := make([]ProxyProfile,0,len(store.Profiles))
		found := false
		for _, p := range store.Profiles { if p.ID==id { found=true; continue }; filtered=append(filtered,p) }
		if !found { writeJSON(w, map[string]string{"error":"Профиль не найден"}); return }
		store.Profiles=filtered
		if store.ActiveProfileID==id { store.ActiveProfileID=""; a.mu.Lock(); a.activeProfileID=""; a.mu.Unlock() }
		if err=SaveProfileStore(store); err!=nil { writeJSON(w,map[string]string{"error":err.Error()}); return }
		writeJSON(w,map[string]any{"ok":true})
	case "saveSettings":
		if len(args) == 0 {
			writeJSON(w, "Не получены настройки")
			return
		}
		var s Settings
		if err := json.Unmarshal(args[0], &s); err != nil {
			writeJSON(w, err.Error())
			return
		}
		writeJSON(w, a.saveSettings(s))
	case "parseLink":
		var raw string
		if len(args) > 0 {
			_ = json.Unmarshal(args[0], &raw)
		}
		s, err := ParseProxyURL(raw)
		if err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"settings": s})
	case "listProcs":
		items, err := listProcesses()
		if err != nil {
			a.addLog("Список процессов: " + err.Error())
		}
		writeJSON(w, items)
	case "pickApp":
		p, err := pickExecutable(a.hwnd)
		if err != nil {
			writeJSON(w, "")
			return
		}
		writeJSON(w, p)
	case "openLogFile":
		_ = os.MkdirAll(filepath.Join(appDataDir(), "logs"), 0700)
		_ = exec.Command("notepad.exe", filepath.Join(appDataDir(), "logs", "PrivateVPN-Next.log")).Start()
		writeJSON(w, nil)
	case "clearLog":
		if err := a.clearLog(); err != nil {
			writeJSON(w, err.Error())
			return
		}
		writeJSON(w, nil)
	case "openReleases":
		_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", "https://github.com/Ssensseii/Private-VPN-Next-Public/releases").Start()
		writeJSON(w, nil)
	case "restoreWindow":
		if a.hwnd != 0 {
			pPostMessageW.Call(a.hwnd, uintptr(wmRestoreMain), 0, 0)
		}
		writeJSON(w, nil)
	default:
		http.NotFound(w, r)
	}
}

func (a *app) runWebView() error { return runWebViewWindow(a) }

func (a *app) updateTray() {
	if a.hwnd != 0 {
		updateTrayIcon(a)
	}
}

func (a *app) quit() {
	a.mu.Lock()
	if a.quitting {
		a.mu.Unlock()
		return
	}
	a.quitting = true
	a.mu.Unlock()
	a.core.Close()
	if a.controller != 0 {
		comCall(a.controller, 24)
	}
	if a.server != nil {
		_ = a.server.Close()
	}
	removeTrayIcon(a)
	destroyMainWindow(a)
}

func (a *app) onTrayToggle() { a.toggle() }

func (a *app) openLogFile() {
	_ = exec.Command("notepad.exe", filepath.Join(appDataDir(), "logs", "PrivateVPN-Next.log")).Start()
}

func (a *app) appDir() string { return a.exeDir }

func (a *app) localURL() string {
	if a.listener == nil {
		return "about:blank"
	}
	return "http://" + a.listener.Addr().String() + "/"
}

func (a *app) validateAppPath(p string) error {
	if !strings.EqualFold(filepath.Ext(p), ".exe") {
		return errors.New("выберите EXE-файл")
	}
	return nil
}

func (a *app) setStatusOff() {
	a.mu.Lock()
	a.state = "off"
	a.stopping = false
	a.since = 0
	a.mu.Unlock()
	a.updateTray()
}

var _ = subtle.ConstantTimeCompare
