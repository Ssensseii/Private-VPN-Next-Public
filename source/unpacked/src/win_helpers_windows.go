//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	kernel32H                   = syscall.NewLazyDLL("kernel32.dll")
	user32H                     = syscall.NewLazyDLL("user32.dll")
	shell32H                    = syscall.NewLazyDLL("shell32.dll")
	comdlg32H                   = syscall.NewLazyDLL("comdlg32.dll")
	pCreateMutexW               = kernel32H.NewProc("CreateMutexW")
	pGetLastError               = kernel32H.NewProc("GetLastError")
	pCreateToolhelp32Snapshot   = kernel32H.NewProc("CreateToolhelp32Snapshot")
	pProcess32FirstW            = kernel32H.NewProc("Process32FirstW")
	pProcess32NextW             = kernel32H.NewProc("Process32NextW")
	pOpenProcessH               = kernel32H.NewProc("OpenProcess")
	pQueryFullProcessImageNameW = kernel32H.NewProc("QueryFullProcessImageNameW")
	pTerminateProcessH          = kernel32H.NewProc("TerminateProcess")
	pWaitForSingleObjectH       = kernel32H.NewProc("WaitForSingleObject")
	pCloseHandleH               = kernel32H.NewProc("CloseHandle")
	pFindWindowW                = user32H.NewProc("FindWindowW")
	pLoadImageW                 = user32H.NewProc("LoadImageW")
	pLoadIconW                  = user32H.NewProc("LoadIconW")
	pDestroyIcon                = user32H.NewProc("DestroyIcon")
	pShellNotifyIconW           = shell32H.NewProc("Shell_NotifyIconW")
	pCreatePopupMenu            = user32H.NewProc("CreatePopupMenu")
	pAppendMenuW                = user32H.NewProc("AppendMenuW")
	pTrackPopupMenu             = user32H.NewProc("TrackPopupMenu")
	pDestroyMenu                = user32H.NewProc("DestroyMenu")
	pGetCursorPos               = user32H.NewProc("GetCursorPos")
	pPostMessageW               = user32H.NewProc("PostMessageW")
	pSendMessageW               = user32H.NewProc("SendMessageW")
	pGetOpenFileNameW           = comdlg32H.NewProc("GetOpenFileNameW")
)

const (
	th32csSnapProcess              = 0x00000002
	processQueryLimitedInformation = 0x1000
	processSynchronize              = 0x00100000
	imageIcon                      = 1
	lrLoadFromFile                 = 0x0010
	lrDefaultSize                  = 0x0040
	nimAdd                         = 0
	nimModify                      = 1
	nimDelete                      = 2
	nifMessage                     = 1
	nifIcon                        = 2
	nifTip                         = 4
	mfString                       = 0
	mfSeparator                    = 0x0800
	tpmRightButton                 = 0x0002
	tpmReturnCommand               = 0x0100
	ofNPathMustExist               = 0x00000800
	ofNFileMustExist               = 0x00001000
	ofNNoChangeDir                 = 0x00000008
)

var appMutex uintptr

type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	Priority        int32
	Flags           uint32
	ExeFile         [260]uint16
}

type openFileName struct {
	StructSize    uint32
	Owner         uintptr
	Instance      uintptr
	Filter        *uint16
	CustomFilter  *uint16
	MaxCustFilter uint32
	FilterIndex   uint32
	File          *uint16
	MaxFile       uint32
	FileTitle     *uint16
	MaxFileTitle  uint32
	InitialDir    *uint16
	Title         *uint16
	Flags         uint32
	FileOffset    uint16
	FileExtension uint16
	DefExt        *uint16
	CustData      uintptr
	Hook          uintptr
	TemplateName  *uint16
	Reserved      uintptr
	Reserved2     uint32
	FlagsEx       uint32
}

type notifyIconData struct {
	Size             uint32
	Wnd              uintptr
	ID               uint32
	Flags            uint32
	CallbackMessage  uint32
	Icon             uintptr
	Tip              [128]uint16
	State            uint32
	StateMask        uint32
	Info             [256]uint16
	TimeoutOrVersion uint32
	InfoTitle        [64]uint16
	InfoFlags        uint32
	GUID             [16]byte
	BalloonIcon      uintptr
}

type cursorPoint struct{ X, Y int32 }

func acquireAppMutex() bool {
	name, _ := syscall.UTF16PtrFromString(`Local\PrivateVPN-Next-single-instance`)
	h, _, _ := pCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return false
	}
	appMutex = h
	err, _, _ := pGetLastError.Call()
	if err == 183 {
		pCloseHandleH.Call(h)
		appMutex = 0
		return true
	}
	return false
}

// restoreExistingWindow brings the existing tray instance back instead of
// showing a second-instance warning that leaves the user with no visible UI.
func restoreExistingWindow() bool {
	className, _ := syscall.UTF16PtrFromString("PrivateVPNNextWindowClass")
	hwnd, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(className)), 0)
	if hwnd == 0 {
		return false
	}
	r, _, _ := pPostMessageW.Call(hwnd, uintptr(wmRestoreMain), 0, 0)
	return r != 0
}

// findCoreProcesses returns PIDs for the sing-box executable bundled with this
// installation. It never matches another installation or a user's unrelated process.
func findCoreProcesses(exePath string) ([]uint32, error) {
	snap, _, callErr := pCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == uintptr(^uintptr(0)) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", callErr)
	}
	defer pCloseHandleH.Call(snap)

	expected := filepath.Clean(exePath)
	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	r, _, _ := pProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	if r == 0 {
		return []uint32{}, nil
	}

	var pids []uint32
	for {
		if pe.ProcessID != 0 {
			h, _, _ := pOpenProcessH.Call(processQueryLimitedInformation, 0, uintptr(pe.ProcessID))
			if h != 0 {
				buf := make([]uint16, 32768)
				n := uint32(len(buf))
				ok, _, _ := pQueryFullProcessImageNameW.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
				pCloseHandleH.Call(h)
				if ok != 0 && strings.EqualFold(filepath.Clean(syscall.UTF16ToString(buf[:n])), expected) {
					pids = append(pids, pe.ProcessID)
				}
			}
		}
		r, _, _ = pProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			break
		}
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	return pids, nil
}

func terminateCoreProcess(pid uint32) error {
	h, _, openErr := pOpenProcessH.Call(processQueryLimitedInformation|processTerminate|processSynchronize, 0, uintptr(pid))
	if h == 0 {
		if openErr != syscall.Errno(0) {
			return fmt.Errorf("PID %d: OpenProcess: %w", pid, openErr)
		}
		return fmt.Errorf("PID %d: OpenProcess не вернул дескриптор", pid)
	}
	defer pCloseHandleH.Call(h)

	terminated, _, terminateErr := pTerminateProcessH.Call(h, 1)
	if terminated == 0 {
		wait, _, _ := pWaitForSingleObjectH.Call(h, 0)
		if wait == 0 {
			return nil
		}
		return fmt.Errorf("PID %d: TerminateProcess: %v", pid, terminateErr)
	}
	wait, _, _ := pWaitForSingleObjectH.Call(h, 5000)
	if wait != 0 {
		return fmt.Errorf("PID %d: процесс не завершился за 5 секунд", pid)
	}
	return nil
}

// stopOrphanCoreProcesses is used only when recovering from a duplicate TUN
// adapter error. It targets the bundled executable path, not every sing-box.exe.
func stopOrphanCoreProcesses(exePath string) (int, error) {
	pids, err := findCoreProcesses(exePath)
	if err != nil {
		return 0, err
	}
	stopped := 0
	var failures []string
	for _, pid := range pids {
		if err := terminateCoreProcess(pid); err != nil {
			failures = append(failures, err.Error())
		} else {
			stopped++
		}
	}
	if len(failures) != 0 {
		return stopped, fmt.Errorf("не удалось завершить оставшийся sing-box: %s", strings.Join(failures, "; "))
	}
	return stopped, nil
}

func addTrayIcon(a *app) error {
	iconPath := filepath.Join(a.exeDir, "app.ico")
	p, _ := syscall.UTF16PtrFromString(iconPath)
	h, _, _ := pLoadImageW.Call(0, uintptr(unsafe.Pointer(p)), imageIcon, 0, 0, lrLoadFromFile|lrDefaultSize)
	if h == 0 {
		h, _, _ = pLoadIconW.Call(0, 32512)
	}
	a.trayIcon = h
	if h != 0 {
		pSendMessageW.Call(a.hwnd, 0x0080, 1, h)
		pSendMessageW.Call(a.hwnd, 0x0080, 0, h)
	}
	var d notifyIconData
	d.Size = uint32(unsafe.Sizeof(d))
	d.Wnd = a.hwnd
	d.ID = 1
	d.Flags = nifMessage | nifIcon | nifTip
	d.CallbackMessage = wmTrayCallback
	d.Icon = h
	copy(d.Tip[:], mustUTF16(appTitle+" — отключено"))
	a.notifyData = d
	r, _, _ := pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&a.notifyData)))
	if r == 0 {
		return fmt.Errorf("Shell_NotifyIconW(NIM_ADD) failed")
	}
	a.trayAdded = true
	return nil
}

func updateTrayIcon(a *app) {
	a.trayMu.Lock()
	defer a.trayMu.Unlock()
	if !a.trayAdded {
		return
	}
	a.mu.Lock()
	state := a.state
	stopping := a.stopping
	a.mu.Unlock()
	text := appTitle + " — отключено"
	if state == "on" {
		text = appTitle + " — подключено"
	} else if state == "connecting" {
		if stopping {
			text = appTitle + " — отключение"
		} else {
			text = appTitle + " — подключение"
		}
	}
	copy(a.notifyData.Tip[:], mustUTF16(text))
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&a.notifyData)))
}

func removeTrayIcon(a *app) {
	a.trayMu.Lock()
	defer a.trayMu.Unlock()
	if a.trayAdded {
		pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&a.notifyData)))
		a.trayAdded = false
	}
	if a.trayIcon != 0 {
		pDestroyIcon.Call(a.trayIcon)
		a.trayIcon = 0
	}
}

func showTrayMenu(a *app) {
	menu, _, _ := pCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer pDestroyMenu.Call(menu)
	a.mu.Lock()
	on := a.state == "on"
	busy := a.state == "connecting"
	a.mu.Unlock()
	toggleText := "Подключить"
	if on {
		toggleText = "Отключить"
	}
	if busy {
		toggleText = "Подключение…"
	}
	appendMenu(menu, mfString, idTrayToggle, toggleText)
	appendMenu(menu, mfString, idTrayMini, "Компактная панель")
	appendMenu(menu, mfString, idTrayShow, "Открыть PrivateVPN Next")
	appendMenu(menu, mfSeparator, 0, "")
	appendMenu(menu, mfString, idTrayExit, "Выход")
	var pt cursorPoint
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundWindow.Call(a.hwnd)
	cmd, _, _ := pTrackPopupMenu.Call(menu, tpmReturnCommand|tpmRightButton, uintptr(pt.X), uintptr(pt.Y), 0, a.hwnd, 0)
	pPostMessageW.Call(a.hwnd, 0, 0, 0)
	switch uint32(cmd) {
	case idTrayToggle:
		a.onTrayToggle()
	case idTrayMini:
		a.showMini()
	case idTrayShow:
		a.show()
	case idTrayExit:
		a.quit()
	}
}

func appendMenu(menu uintptr, flags, id uint32, text string) {
	var p uintptr
	if text != "" {
		u, _ := syscall.UTF16PtrFromString(text)
		p = uintptr(unsafe.Pointer(u))
	}
	pAppendMenuW.Call(menu, uintptr(flags), uintptr(id), p)
}
func mustUTF16(s string) []uint16 {
	u, _ := syscall.UTF16FromString(s)
	if len(u) > 128 {
		u = u[:127]
		u = append(u, 0)
	}
	return u
}

func listProcesses() ([]procItem, error) {
	snap, _, e := pCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == uintptr(^uintptr(0)) {
		return nil, e
	}
	defer pCloseHandleH.Call(snap)
	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	r, _, _ := pProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	if r == 0 {
		return []procItem{}, nil
	}
	seen := map[string]bool{}
	out := make([]procItem, 0, 64)
	for {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		if name != "" {
			h, _, _ := pOpenProcessH.Call(processQueryLimitedInformation, 0, uintptr(pe.ProcessID))
			if h != 0 {
				buf := make([]uint16, 32768)
				n := uint32(len(buf))
				ok, _, _ := pQueryFullProcessImageNameW.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
				pCloseHandleH.Call(h)
				if ok != 0 {
					path := syscall.UTF16ToString(buf[:n])
					key := strings.ToLower(path)
					if !seen[key] {
						seen[key] = true
						out = append(out, procItem{Name: filepath.Base(path), Path: path})
					}
				}
			}
		}
		r, _, _ = pProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

func pickExecutable(owner uintptr) (string, error) {
	buf := make([]uint16, 32768)
	filter := utf16.Encode([]rune("Executable files (*.exe)\x00*.exe\x00All files (*.*)\x00*.*\x00\x00"))
	title, _ := syscall.UTF16PtrFromString("Выберите приложение для обхода прокси")
	of := openFileName{StructSize: uint32(unsafe.Sizeof(openFileName{})), Owner: owner, Filter: &filter[0], File: &buf[0], MaxFile: uint32(len(buf)), Title: title, Flags: ofNPathMustExist | ofNFileMustExist | ofNNoChangeDir}
	r, _, e := pGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&of)))
	if r == 0 {
		return "", e
	}
	return syscall.UTF16ToString(buf), nil
}
