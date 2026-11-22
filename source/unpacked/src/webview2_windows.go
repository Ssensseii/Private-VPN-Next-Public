//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var (
	ole32                = syscall.NewLazyDLL("ole32.dll")
	user32               = syscall.NewLazyDLL("user32.dll")
	dwmapi               = syscall.NewLazyDLL("dwmapi.dll")
	pDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
	pCoInitializeEx      = ole32.NewProc("CoInitializeEx")
	pCoUninitialize      = ole32.NewProc("CoUninitialize")
	pCoTaskMemAlloc      = ole32.NewProc("CoTaskMemAlloc")
	pCoTaskMemFree       = ole32.NewProc("CoTaskMemFree")
	pDefWindowProc       = user32.NewProc("DefWindowProcW")
	pGetModuleHandle     = syscall.NewLazyDLL("kernel32.dll").NewProc("GetModuleHandleW")
	pRegisterClassEx     = user32.NewProc("RegisterClassExW")
	pCreateWindowEx      = user32.NewProc("CreateWindowExW")
	pShowWindow          = user32.NewProc("ShowWindow")
	pUpdateWindow        = user32.NewProc("UpdateWindow")
	pGetMessage          = user32.NewProc("GetMessageW")
	pTranslateMessage    = user32.NewProc("TranslateMessage")
	pDispatchMessage     = user32.NewProc("DispatchMessageW")
	pPostQuitMessage     = user32.NewProc("PostQuitMessage")
	pDestroyWindow       = user32.NewProc("DestroyWindow")
	pGetClientRect       = user32.NewProc("GetClientRect")
	pSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	pSetActiveWindow     = user32.NewProc("SetActiveWindow")
	pSetFocus            = user32.NewProc("SetFocus")
	pSetWindowPos       = user32.NewProc("SetWindowPos")
	pLoadCursor          = user32.NewProc("LoadCursorW")
)

const (
	// COM vtable indexes include IUnknown's QueryInterface/AddRef/Release at 0..2.
	webViewEnvironmentCreateControllerIndex = 3
	webViewControllerPutIsVisibleIndex      = 4
	webViewControllerPutBoundsIndex         = 6
	webViewControllerGetCoreWebView2Index   = 25
	coinitApartmentThreaded                 = 0x2
	wsOverlappedWindow                      = 0x00CF0000
	cwUseDefault                            = 0x80000000
	swHide                                  = 0
	swShow                                  = 5
	swRestore                               = 9
	swpNoMove                               = 0x0002
	swpNoZOrder                             = 0x0004
	swpShowWindow                           = 0x0040
	wmDestroy                               = 0x0002
	wmSize                                  = 0x0005
	wmWindowPosChanged                      = 0x0047
	wmClose                                 = 0x0010
	wmCommand                               = 0x0111
	wmApp                                   = 0x8000
	wmRestoreMain                           = wmApp + 2
	wmShowMini                              = wmApp + 3
	wmTrayCallback                          = wmApp + 1
	wmLButtonUp                             = 0x0202
	wmRButtonUp                             = 0x0205
	idTrayToggle                            = 41001
	idTrayShow                              = 41002
	idTrayExit                              = 41003
	idTrayMini                              = 41004
)

type point struct{ X, Y int32 }
type rect struct{ Left, Top, Right, Bottom int32 }
type msg struct {
	HWnd           uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Pt             point
	LPrivate       uint32
}
type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

var activeApp *app
var windowProcPtr = syscall.NewCallback(windowProc)
var comQueryPtr uintptr
var comAddRefPtr uintptr
var comReleasePtr uintptr
var comInvokePtr uintptr
var comVTable uintptr

func runWebViewWindow(a *app) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hr, _, _ := pCoInitializeEx.Call(0, coinitApartmentThreaded)
	if int32(hr) < 0 {
		return fmt.Errorf("CoInitializeEx завершился ошибкой HRESULT 0x%08X", uint32(hr))
	}
	defer pCoUninitialize.Call()
	activeApp = a
	if err := createMainWindow(a); err != nil {
		activeApp = nil
		return err
	}
	if err := addTrayIcon(a); err != nil {
		a.addLog("Не удалось создать значок трея: " + err.Error())
	}
	if err := createWebView(a); err != nil {
		removeTrayIcon(a)
		destroyMainWindow(a)
		activeApp = nil
		return err
	}
	pShowWindow.Call(a.hwnd, swShow)
	pUpdateWindow.Call(a.hwnd)
	var m msg
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	a.quit()
	if a.controller != 0 {
		comReleasePtrCall(a.controller)
		a.controller = 0
	}
	if a.webview != 0 {
		comReleasePtrCall(a.webview)
		a.webview = 0
	}
	if a.environment != 0 {
		comReleasePtrCall(a.environment)
		a.environment = 0
	}
	if comVTable != 0 {
		pCoTaskMemFree.Call(comVTable)
		comVTable = 0
	}
	if a.loaderDLL != nil {
		_ = a.loaderDLL.Release()
		a.loaderDLL = nil
	}
	activeApp = nil
	return nil
}

func createMainWindow(a *app) error {
	className, _ := syscall.UTF16PtrFromString("PrivateVPNNextWindowClass")
	title, _ := syscall.UTF16PtrFromString(appTitle)
	inst, _, _ := pGetModuleHandle.Call(0)
	cursor, _, _ := pLoadCursor.Call(0, 32512)
	wc := wndClassEx{Size: uint32(unsafe.Sizeof(wndClassEx{})), WndProc: windowProcPtr, Instance: inst, Cursor: cursor, Background: 6, ClassName: className}
	r, _, e := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
	if r == 0 && e != syscall.Errno(1410) {
		return fmt.Errorf("RegisterClassExW: %v", e)
	}
	hwnd, _, e := pCreateWindowEx.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(title)), wsOverlappedWindow, cwUseDefault, cwUseDefault, 1180, 800, 0, 0, inst, 0)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW: %v", e)
	}
	a.hwnd = hwnd
	applyDarkTitleBar(hwnd)
	return nil
}

// applyDarkTitleBar asks DWM to render the native caption in dark mode.
// Attribute 20 is used on newer Windows builds; 19 is the compatibility value
// used by earlier Windows 10 releases. Unsupported attributes are harmless.
func applyDarkTitleBar(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	enabled := int32(1)
	size := uintptr(unsafe.Sizeof(enabled))
	hr, _, _ := pDwmSetWindowAttribute.Call(hwnd, 20, uintptr(unsafe.Pointer(&enabled)), size)
	if int32(hr) < 0 {
		_, _, _ = pDwmSetWindowAttribute.Call(hwnd, 19, uintptr(unsafe.Pointer(&enabled)), size)
	}
}

func createWebView(a *app) error {
	dllPath := filepath.Join(a.exeDir, "WebView2Loader.dll")
	dll, err := syscall.LoadDLL(dllPath)
	if err != nil {
		return fmt.Errorf("не найден WebView2Loader.dll рядом с PrivateVPN-Next.exe: %w", err)
	}
	proc, err := dll.FindProc("CreateCoreWebView2EnvironmentWithOptions")
	if err != nil {
		dll.Release()
		return err
	}
	userData := filepath.Join(appDataDir(), "WebView2")
	if err := os.MkdirAll(userData, 0700); err != nil {
		dll.Release()
		return err
	}
	userDataW, _ := syscall.UTF16PtrFromString(userData)
	handler := newCOMHandler(1)
	if handler == 0 {
		dll.Release()
		return fmt.Errorf("не удалось выделить WebView2 callback handler")
	}
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(userDataW)), 0, handler)
	comReleasePtrCall(handler)
	if int32(r) < 0 {
		dll.Release()
		return fmt.Errorf("WebView2 не удалось создать окружение (HRESULT 0x%08X). Проверьте наличие Microsoft Edge WebView2 Runtime", uint32(r))
	}
	a.loaderDLL = dll
	return nil
}

func windowProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	a := activeApp
	if a == nil {
		r, _, _ := pDefWindowProc.Call(hwnd, uintptr(message), wParam, lParam)
		return r
	}
	switch message {
	case wmSize:
		r, _, _ := pDefWindowProc.Call(hwnd, uintptr(message), wParam, lParam)
		updateWebViewBounds(a)
		return r
	case wmWindowPosChanged:
		r, _, _ := pDefWindowProc.Call(hwnd, uintptr(message), wParam, lParam)
		updateWebViewBounds(a)
		return r
	case wmClose:
		coreRunning := a.core != nil && a.core.Running()
		a.mu.Lock()
		running := a.state != "off" || coreRunning
		a.mu.Unlock()
		if running {
			pShowWindow.Call(hwnd, swHide)
			return 0
		}
		a.quit()
		return 0
	case wmDestroy:
		pPostQuitMessage.Call(0)
		return 0
	case wmTrayCallback:
		ev := uint32(lParam)
		if ev == wmLButtonUp {
			a.showMini()
		} else if ev == wmRButtonUp {
			showTrayMenu(a)
		}
		return 0
	case wmRestoreMain:
		a.show()
		return 0
	case wmShowMini:
		a.showMini()
		return 0
	case wmCommand:
		switch uint32(wParam & 0xffff) {
		case idTrayToggle:
			a.onTrayToggle()
		case idTrayShow:
			a.show()
		case idTrayExit:
			a.quit()
		}
		return 0
	}
	r, _, _ := pDefWindowProc.Call(hwnd, uintptr(message), wParam, lParam)
	return r
}

func updateWebViewBounds(a *app) {
	if a.controller == 0 || a.hwnd == 0 {
		return
	}
	var rc rect
	ok, _, _ := pGetClientRect.Call(a.hwnd, uintptr(unsafe.Pointer(&rc)))
	if ok == 0 {
		return
	}
	comCall(a.controller, webViewControllerPutBoundsIndex, uintptr(unsafe.Pointer(&rc)))
}

func (a *app) show() {
	a.reconcileCoreState()
	if a.hwnd == 0 {
		return
	}

	// Restore the native top-level window before resizing the WebView host.
	// SW_RESTORE also handles the case where the main window was minimized.
	pShowWindow.Call(a.hwnd, swRestore)
	if ok, _, _ := pSetWindowPos.Call(a.hwnd, 0, 0, 0, 1180, 800, swpNoMove|swpNoZOrder|swpShowWindow); ok == 0 {
		a.addLog("Не удалось изменить размер основного окна при возврате из мини-панели.")
	}
	pSetForegroundWindow.Call(a.hwnd)
	pSetActiveWindow.Call(a.hwnd)
	pSetFocus.Call(a.hwnd)

	// WebView2 owns a child HWND. Recalculate its bounds after the host window
	// has been restored, then explicitly make the controller visible again.
	updateWebViewBounds(a)
	if a.controller != 0 {
		comCall(a.controller, webViewControllerPutIsVisibleIndex, 1)
	}
	pUpdateWindow.Call(a.hwnd)

	// Change the document layout only after the native window has its final size.
	a.executeScript("requestAnimationFrame(()=>requestAnimationFrame(()=>{if(window.exitMiniPanel)window.exitMiniPanel();if(window.vpn_ready)window.vpn_ready();window.dispatchEvent(new Event('resize'))}))")
}

func (a *app) showMini() {
	a.reconcileCoreState()
	if a.hwnd != 0 {
		pShowWindow.Call(a.hwnd, swShow)
		pSetWindowPos.Call(a.hwnd, 0, 0, 0, 500, 590, swpNoMove|swpNoZOrder|swpShowWindow)
		pSetForegroundWindow.Call(a.hwnd)
		updateWebViewBounds(a)
		pUpdateWindow.Call(a.hwnd)
		a.executeScript("requestAnimationFrame(()=>{window.openMiniPanel&&window.openMiniPanel();window.vpn_ready&&window.vpn_ready();requestAnimationFrame(()=>window.dispatchEvent(new Event('resize')))})")
	}
}

func (a *app) executeScript(script string) {
	if a.webview == 0 {
		return
	}
	scriptW, err := syscall.UTF16PtrFromString(script)
	if err != nil {
		return
	}
	handler := newCOMHandler(3)
	if handler == 0 {
		return
	}
	hr := comCall(a.webview, 29, uintptr(unsafe.Pointer(scriptW)), handler)
	comReleasePtrCall(handler)
	if int32(hr) < 0 {
		a.addLog(fmt.Sprintf("WebView2 ExecuteScript failed: 0x%08X", uint32(hr)))
	}
}

func destroyMainWindow(a *app) {
	if a.hwnd != 0 {
		pDestroyWindow.Call(a.hwnd)
		a.hwnd = 0
	}
}

func showNativeError(title, text string) { showMessageBox(title, text, 0x10) }
func showNativeInfo(title, text string)  { showMessageBox(title, text, 0x40) }
func showMessageBox(title, text string, flags uintptr) {
	p := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(text)
	p.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), flags)
}

func comCall(obj uintptr, index int, args ...uintptr) uintptr {
	if obj == 0 {
		return 0
	}
	vt := *(*uintptr)(unsafe.Pointer(obj))
	fn := *(*uintptr)(unsafe.Pointer(vt + uintptr(index)*unsafe.Sizeof(uintptr(0))))
	all := make([]uintptr, 1, len(args)+1)
	all[0] = obj
	all = append(all, args...)
	r, _, _ := syscall.SyscallN(fn, all...)
	return r
}

func comReleasePtrCall(obj uintptr) {
	if obj != 0 {
		comCall(obj, 2)
	}
}

func ensureCOMVTable() uintptr {
	if comVTable != 0 {
		return comVTable
	}
	if comQueryPtr == 0 {
		comQueryPtr = syscall.NewCallback(comQueryInterface)
		comAddRefPtr = syscall.NewCallback(comAddRef)
		comReleasePtr = syscall.NewCallback(comRelease)
		comInvokePtr = syscall.NewCallback(comInvoke)
	}
	p, _, _ := pCoTaskMemAlloc.Call(4 * unsafe.Sizeof(uintptr(0)))
	if p == 0 {
		return 0
	}
	v := unsafe.Slice((*uintptr)(unsafe.Pointer(p)), 4)
	v[0], v[1], v[2], v[3] = comQueryPtr, comAddRefPtr, comReleasePtr, comInvokePtr
	comVTable = p
	return p
}

func newCOMHandler(kind uintptr) uintptr {
	vt := ensureCOMVTable()
	if vt == 0 {
		return 0
	}
	p, _, _ := pCoTaskMemAlloc.Call(3 * unsafe.Sizeof(uintptr(0)))
	if p == 0 {
		return 0
	}
	v := unsafe.Slice((*uintptr)(unsafe.Pointer(p)), 3)
	v[0] = vt
	v[1] = 1
	v[2] = kind
	return p
}

type comGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	iidIUnknown             = comGUID{Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	iidEnvironmentCompleted = comGUID{Data1: 0x4E8A3389, Data2: 0xC9D8, Data3: 0x4BD2, Data4: [8]byte{0xB6, 0xB5, 0x12, 0x4F, 0xEE, 0x6C, 0xC1, 0x4D}}
	iidControllerCompleted  = comGUID{Data1: 0x6C4819F3, Data2: 0xC9B7, Data3: 0x4260, Data4: [8]byte{0x81, 0x27, 0xC9, 0xF5, 0xBD, 0xE7, 0xF6, 0x8C}}
	iidExecuteScriptCompleted = comGUID{Data1: 0x49511172, Data2: 0xCC67, Data3: 0x4BCA, Data4: [8]byte{0x99, 0x23, 0x13, 0x71, 0x12, 0xF4, 0xC4, 0xCC}}
)

func comQueryInterface(this, riid, ppv uintptr) uintptr {
	if ppv == 0 || riid == 0 {
		return 0x80004003 // E_POINTER
	}
	*(*uintptr)(unsafe.Pointer(ppv)) = 0
	requested := *(*comGUID)(unsafe.Pointer(riid))
	kind := *(*uintptr)(unsafe.Pointer(this + 2*unsafe.Sizeof(uintptr(0))))
	if requested != iidIUnknown &&
		!(kind == 1 && requested == iidEnvironmentCompleted) &&
		!(kind == 2 && requested == iidControllerCompleted) &&
		!(kind == 3 && requested == iidExecuteScriptCompleted) {
		return 0x80004002 // E_NOINTERFACE
	}
	*(*uintptr)(unsafe.Pointer(ppv)) = this
	comAddRef(this)
	return 0 // S_OK
}
func comAddRef(this uintptr) uintptr {
	p := (*uint32)(unsafe.Pointer(this + unsafe.Sizeof(uintptr(0))))
	return uintptr(atomicAddUint32(p, 1))
}
func comRelease(this uintptr) uintptr {
	p := (*uint32)(unsafe.Pointer(this + unsafe.Sizeof(uintptr(0))))
	n := atomicAddUint32(p, ^uint32(0))
	if n == 0 {
		pCoTaskMemFree.Call(this)
	}
	return uintptr(n)
}
func atomicAddUint32(p *uint32, delta uint32) uint32 { return atomic.AddUint32(p, delta) }

func comInvoke(this, hr, result uintptr) uintptr {
	kind := *(*uintptr)(unsafe.Pointer(this + 2*unsafe.Sizeof(uintptr(0))))
	a := activeApp
	if a == nil {
		return 0
	}
	if int32(hr) < 0 {
		msg := fmt.Sprintf("WebView2 callback error HRESULT 0x%08X", uint32(hr))
		a.addLog(msg)
		a.setToast("Ошибка WebView2", msg, false)
		showNativeError(appTitle, msg+". Проверьте Microsoft Edge WebView2 Runtime.")
		return 0
	}
	switch kind {
	case 1:
		comCall(result, 1) // retain environment until application shutdown
		a.environment = result
		h := newCOMHandler(2)
		if h == 0 {
			a.addLog("Не удалось создать WebView2 controller handler")
			return 0
		}
		hrCreate := comCall(result, webViewEnvironmentCreateControllerIndex, a.hwnd, h)
		comReleasePtrCall(h)
		if int32(hrCreate) < 0 {
			msg := fmt.Sprintf("CreateCoreWebView2Controller failed: 0x%08X", uint32(hrCreate))
			a.addLog(msg)
			showNativeError(appTitle, msg)
		}
	case 2:
		comCall(result, 1) // retain controller after callback returns
		a.controller = result
		var wv uintptr
		r := comCall(result, webViewControllerGetCoreWebView2Index, uintptr(unsafe.Pointer(&wv)))
		if int32(r) < 0 || wv == 0 {
			a.addLog("WebView2 не вернул CoreWebView2")
			return 0
		}
		a.webview = wv
		comCall(result, webViewControllerPutIsVisibleIndex, 1)
		nav, _ := syscall.UTF16PtrFromString(a.localURL())
		hrNav := comCall(wv, 5, uintptr(unsafe.Pointer(nav)))
		if int32(hrNav) < 0 {
			a.addLog(fmt.Sprintf("WebView2 Navigate failed: 0x%08X", uint32(hrNav)))
		}
		updateWebViewBounds(a)
	case 3:
		// ExecuteScript completion result is intentionally ignored.
	}
	return 0
}
