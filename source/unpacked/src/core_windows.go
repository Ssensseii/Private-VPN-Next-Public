//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernelCore                = syscall.NewLazyDLL("kernel32.dll")
	pCreateJobObject          = kernelCore.NewProc("CreateJobObjectW")
	pSetInformationJobObject  = kernelCore.NewProc("SetInformationJobObject")
	pOpenProcess              = kernelCore.NewProc("OpenProcess")
	pAssignProcessToJobObject = kernelCore.NewProc("AssignProcessToJobObject")
	pCloseHandle              = kernelCore.NewProc("CloseHandle")
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x00002000
	processSetQuota                   = 0x0100
	processTerminate                  = 0x0001
)

type jobBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}
type jobIOCounters struct{ ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount uint64 }
type jobExtendedLimitInformation struct {
	Basic                 jobBasicLimitInformation
	IO                    jobIOCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

func createKillJob() uintptr {
	h, _, _ := pCreateJobObject.Call(0, 0)
	if h == 0 {
		return 0
	}
	info := jobExtendedLimitInformation{Basic: jobBasicLimitInformation{LimitFlags: jobObjectLimitKillOnJobClose}}
	r, _, _ := pSetInformationJobObject.Call(h, jobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r == 0 {
		pCloseHandle.Call(h)
		return 0
	}
	return h
}

func assignToJob(job uintptr, pid int) error {
	if job == 0 {
		return errors.New("Windows Job Object не создан")
	}
	h, _, openErr := pOpenProcess.Call(processSetQuota|processTerminate, 0, uintptr(uint32(pid)))
	if h == 0 {
		if openErr != syscall.Errno(0) {
			return fmt.Errorf("OpenProcess: %w", openErr)
		}
		return errors.New("OpenProcess не вернул дескриптор процесса")
	}
	defer pCloseHandle.Call(h)
	r, _, assignErr := pAssignProcessToJobObject.Call(job, h)
	if r == 0 {
		if assignErr != syscall.Errno(0) {
			return fmt.Errorf("AssignProcessToJobObject: %w", assignErr)
		}
		return errors.New("AssignProcessToJobObject завершился ошибкой")
	}
	return nil
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type Core struct {
	dir         string
	onLog       func(string)
	onEnd       func(error)
	mu          sync.Mutex
	cmd         *exec.Cmd
	done        chan struct{}
	stopped     bool
	started     bool
	starting    bool
	closed      bool
	startCancel context.CancelFunc
	job         uintptr
	accel          *Accel
	probeSettings  Settings
	externalHandle uintptr
	externalDone   chan struct{}
}

func NewCore(dir string, onLog func(string), onEnd func(error)) *Core {
	return &Core{dir: dir, onLog: onLog, onEnd: onEnd, job: createKillJob()}
}
func (c *Core) Exe() string { return filepath.Join(c.dir, "sing-box.exe") }
func (c *Core) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmd != nil || c.externalHandle != 0
}

func (c *Core) ProbeSettings() (Settings, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if (c.cmd == nil && c.externalHandle == 0) || c.probeSettings.Host == "" {
		return Settings{}, false
	}
	return c.probeSettings, true
}

// AttachExistingProcess adopts a sing-box process left by an abruptly closed
// UI instance so the restored client can display and stop the existing tunnel.
func (c *Core) AttachExistingProcess(pid uint32, settings Settings) error {
	h, _, openErr := pOpenProcess.Call(processQueryLimitedInformation|processTerminate|processSynchronize, 0, uintptr(pid))
	if h == 0 {
		if openErr != syscall.Errno(0) {
			return fmt.Errorf("не удалось открыть ранее запущенный sing-box (PID %d): %w", pid, openErr)
		}
		return fmt.Errorf("не удалось открыть ранее запущенный sing-box (PID %d)", pid)
	}
	wait, _, _ := pWaitForSingleObjectH.Call(h, 0)
	if wait == 0 {
		pCloseHandle.Call(h)
		return errors.New("ранее запущенный sing-box уже завершился")
	}
	if wait != 258 {
		pCloseHandle.Call(h)
		return errors.New("не удалось проверить состояние ранее запущенного sing-box")
	}

	c.mu.Lock()
	if c.closed || c.cmd != nil || c.externalHandle != 0 || c.starting {
		c.mu.Unlock()
		pCloseHandle.Call(h)
		return errors.New("невозможно восстановить уже занятое сетевое ядро")
	}
	done := make(chan struct{})
	c.externalHandle = h
	c.externalDone = done
	c.probeSettings = settings
	c.started = true
	c.stopped = false
	c.mu.Unlock()

	go func() {
		pWaitForSingleObjectH.Call(h, 0xFFFFFFFF)
		c.mu.Lock()
		intentional := c.stopped
		if c.externalHandle == h {
			c.externalHandle = 0
			c.externalDone = nil
			c.probeSettings = Settings{}
		}
		c.mu.Unlock()
		pCloseHandle.Call(h)
		if !intentional && c.onEnd != nil {
			c.onEnd(errors.New("ранее запущенный sing-box завершился"))
		}
		close(done)
	}()
	return nil
}

func (c *Core) Start(s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("клиент уже завершает работу")
	}
	if c.job == 0 {
		c.mu.Unlock()
		return errors.New("не удалось создать Windows Job Object для контроля процесса sing-box")
	}
	if c.cmd != nil || c.externalHandle != 0 || c.starting {
		c.mu.Unlock()
		return errors.New("уже подключено или выполняется запуск")
	}
	startCtx, cancelStart := context.WithCancel(context.Background())
	c.starting = true
	c.startCancel = cancelStart
	c.mu.Unlock()

	var accel *Accel
	attached := false
	defer func() {
		c.mu.Lock()
		if c.starting {
			c.starting = false
			c.startCancel = nil
		}
		if !attached && c.accel == accel {
			c.accel = nil
		}
		c.mu.Unlock()
		cancelStart()
		if accel != nil && !attached {
			accel.Close()
		}
	}()

	if _, err := os.Stat(c.Exe()); err != nil {
		return fmt.Errorf("не найден %s", c.Exe())
	}
	resolveCtx, cancelResolve := context.WithTimeout(startCtx, 5*time.Second)
	proxyIPs, err := resolveProxyIPs(resolveCtx, s.Host)
	cancelResolve()
	if err != nil {
		return err
	}
	runtimeSettings := s
	runtimeSettings.Host = proxyIPs[0].String()
	probeSettings := runtimeSettings

	var accelAddr string
	if s.Accelerate {
		accel = NewAccel(runtimeSettings, c.onLog)
		addr, err := accel.Start()
		if err != nil {
			return fmt.Errorf("не удалось запустить ускоритель: %w", err)
		}
		accelAddr = addr
		localHost, localPort, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			return fmt.Errorf("неверный локальный адрес ускорителя: %w", splitErr)
		}
		localPortNumber, parseErr := strconv.Atoi(localPort)
		if parseErr != nil {
			return fmt.Errorf("неверный порт локального ускорителя: %w", parseErr)
		}
		probeSettings = Settings{ProxyType: "socks5", Host: localHost, Port: localPortNumber}
		c.mu.Lock()
		if c.closed || startCtx.Err() != nil {
			c.mu.Unlock()
			return errors.New("запуск отменён")
		}
		c.accel = accel
		c.mu.Unlock()
	}
	cfg, err := BuildConfigWithProxyIPs(s, c.dir, true, accelAddr, proxyIPs)
	if err != nil {
		return err
	}
	workDir := filepath.Join(appDataDir(), "work")
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return err
	}
	if startCtx.Err() != nil {
		return errors.New("запуск отменён")
	}
	cmd := exec.Command(c.Exe(), "run", "-c", "stdin", "-D", workDir, "--disable-color")
	cmd.Stdin = bytes.NewReader(cfg)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("не удалось запустить sing-box: %w", err)
	}
	if err := assignToJob(c.job, cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("не удалось включить контроль жизненного цикла sing-box: %w", err)
	}

	// Serialize process publication with Stop/Close. If shutdown won the race
	// while CreateProcess was running, terminate this just-created process
	// instead of publishing an orphan after the UI has exited.
	c.mu.Lock()
	if c.closed || startCtx.Err() != nil {
		c.mu.Unlock()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return errors.New("запуск отменён")
	}
	assignToJob(c.job, cmd.Process.Pid)
	done := make(chan struct{})
	c.cmd, c.done, c.stopped, c.started = cmd, done, false, false
	c.probeSettings = probeSettings
	c.starting = false
	c.startCancel = nil
	attached = true
	c.mu.Unlock()

	ready := make(chan error, 1)
	scanDone := make(chan struct{})
	var once sync.Once
	signal := func(e error) { once.Do(func() { ready <- e }) }
	var tail []string
	go func() {
		defer close(scanDone)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := ansiRE.ReplaceAllString(sc.Text(), "")
			tail = append(tail, line)
			if len(tail) > 8 {
				tail = tail[1:]
			}
			if strings.Contains(line, "sing-box started") {
				signal(nil)
			}
			if strings.Contains(strings.ToLower(line), "fatal") || strings.Contains(strings.ToLower(line), "panic") {
				signal(errors.New(line))
			}
			if c.onLog != nil {
				c.onLog(line)
			}
		}
		if e := sc.Err(); e != nil && c.onLog != nil {
			c.onLog("Чтение журнала sing-box: " + e.Error())
		}
	}()
	go func() {
		err := cmd.Wait()
		<-scanDone
		c.mu.Lock()
		intentional := c.stopped
		wasStarted := c.started
		accelToClose := c.accel
		c.accel = nil
		c.cmd = nil
		c.done = nil
		c.probeSettings = Settings{}
		c.mu.Unlock()
		if accelToClose != nil {
			accelToClose.Close()
		}
		if err == nil {
			err = errors.New("sing-box завершился")
		}
		if !intentional && wasStarted && c.onEnd != nil {
			c.onEnd(fmt.Errorf("ядро остановилось: %s (%v)", strings.Join(tail, " | "), err))
		}
		close(done)
		signal(fmt.Errorf("sing-box завершился до готовности: %s", strings.Join(tail, " | ")))
	}()
	select {
	case e := <-ready:
		if e != nil {
			c.Stop()
			return e
		}
		c.mu.Lock()
		c.started = true
		alive := c.cmd != nil && !c.closed
		c.mu.Unlock()
		if !alive {
			c.Stop()
			return errors.New("sing-box завершился сразу после запуска")
		}
		return nil
	case <-time.After(20 * time.Second):
		c.Stop()
		return errors.New("sing-box не сообщил о готовности за 20 секунд")
	}
}

func (c *Core) Stop() {
	c.mu.Lock()
	cmd, done, accel, cancelStart := c.cmd, c.done, c.accel, c.startCancel
	externalHandle, externalDone := c.externalHandle, c.externalDone
	c.stopped = true
	var externalStopErr error
	if externalHandle != 0 {
		terminated, _, terminateErr := pTerminateProcessH.Call(externalHandle, 1)
		if terminated == 0 {
			wait, _, _ := pWaitForSingleObjectH.Call(externalHandle, 0)
			if wait != 0 {
				externalStopErr = fmt.Errorf("не удалось завершить восстановленный sing-box: %v", terminateErr)
			}
		}
	}
	c.mu.Unlock()
	if externalStopErr != nil && c.onLog != nil {
		c.onLog(externalStopErr.Error())
	}
	if cancelStart != nil {
		cancelStart()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
	if externalDone != nil {
		select {
		case <-externalDone:
		case <-time.After(5 * time.Second):
		}
	}
	if accel != nil {
		accel.Close()
	}
	c.mu.Lock()
	if c.accel == accel {
		c.accel = nil
	}
	c.mu.Unlock()
}

func (c *Core) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.Stop()
	c.mu.Lock()
	job := c.job
	c.job = 0
	c.mu.Unlock()
	if job != 0 {
		pCloseHandle.Call(job)
	}
}

func (c *Core) AccelStats() (active, idle int) {
	c.mu.Lock()
	a := c.accel
	c.mu.Unlock()
	if a == nil {
		return 0, 0
	}
	return a.Stats()
}
