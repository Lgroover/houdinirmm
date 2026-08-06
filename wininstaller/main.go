package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

//go:embed payload/agent.exe payload/config.yml payload/branding.json
var files embed.FS

func main() {
	product := productName()
	fmt.Println(product + " Agent Installer")
	fmt.Println(strings.Repeat("=", len(product)+16))

	// Installing to Program Files + Windows service requires elevation.
	if !isElevated() {
		fmt.Println("Administrator privileges required.")
		fmt.Println("Requesting elevation (UAC)...")
		if err := relaunchElevated(); err != nil {
			fail("elevation", err)
		}
		// Elevated child continues the install; this process exits.
		os.Exit(0)
	}

	base := installDir(product)
	fmt.Println("Install path:", base)

	if err := os.MkdirAll(base, 0755); err != nil {
		fail("create install dir", fmt.Errorf("%w\nTip: right-click the installer → Run as administrator", err))
	}

	agentName := safeFile(product) + "-Agent.exe"
	if err := writeFile(base, agentName, "payload/agent.exe"); err != nil {
		fail("write agent", err)
	}
	if err := writeFile(base, "config.yml", "payload/config.yml"); err != nil {
		fail("write config", err)
	}
	_ = writeFile(base, "branding.json", "payload/branding.json")

	agent := filepath.Join(base, agentName)
	cfg := filepath.Join(base, "config.yml")

	// Uninstall previous service instance (ignore errors).
	_ = run(agent, "service", "-c", cfg, "uninstall")
	time.Sleep(500 * time.Millisecond)

	if err := run(agent, "service", "-c", cfg, "install"); err != nil {
		fmt.Println("Service install failed.")
		fmt.Println(err)
		fmt.Println("You can manually run (as Administrator):")
		fmt.Printf("  %q service -c %q install\n", agent, cfg)
		wait()
		os.Exit(1)
	}

	// Best-effort start
	_ = run(agent, "service", "-c", cfg, "start")

	fmt.Println("Installed successfully.")
	fmt.Println("Install path:", base)
	fmt.Println("The agent will connect using the embedded config.")
	wait()
}

func productName() string {
	b, err := files.ReadFile("payload/branding.json")
	if err != nil {
		return "HoudiniRMM"
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return "HoudiniRMM"
	}
	if s, ok := m["product_name"].(string); ok && strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	return "HoudiniRMM"
}

func safeFile(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return "HoudiniRMM"
	}
	return out
}

func installDir(product string) string {
	name := safeFile(product)
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, name)
}

func writeFile(dir, name, embedPath string) error {
	src, err := files.Open(embedPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dstPath := filepath.Join(dir, name)
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func fail(msg string, err error) {
	fmt.Println("ERROR:", msg, err)
	wait()
	os.Exit(1)
}

func wait() {
	fmt.Println("Press Enter to exit...")
	fmt.Scanln()
}

// ---- Windows elevation helpers ----

var (
	modShell32           = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW    = modShell32.NewProc("ShellExecuteW")
	modAdvapi32          = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken = modAdvapi32.NewProc("OpenProcessToken")
	procGetTokenInfo     = modAdvapi32.NewProc("GetTokenInformation")
	modKernel32          = syscall.NewLazyDLL("kernel32.dll")
	procGetCurrentProc   = modKernel32.NewProc("GetCurrentProcess")
)

const (
	tokenQuery     = 0x0008
	tokenElevation = 20
)

type tokenElevationType struct {
	TokenIsElevated uint32
}

func isElevated() bool {
	hProc, _, _ := procGetCurrentProc.Call()
	var hToken syscall.Handle
	r, _, _ := procOpenProcessToken.Call(hProc, tokenQuery, uintptr(unsafe.Pointer(&hToken)))
	if r == 0 {
		return false
	}
	defer syscall.CloseHandle(hToken)

	var elev tokenElevationType
	var retLen uint32
	r, _, _ = procGetTokenInfo.Call(
		uintptr(hToken),
		tokenElevation,
		uintptr(unsafe.Pointer(&elev)),
		unsafe.Sizeof(elev),
		uintptr(unsafe.Pointer(&retLen)),
	)
	return r != 0 && elev.TokenIsElevated != 0
}

func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Resolve any symlink-ish paths
	if abs, err2 := filepath.Abs(exe); err2 == nil {
		exe = abs
	}

	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	// forward CLI args (if any)
	params := strings.Join(os.Args[1:], " ")
	paramPtr, err := syscall.UTF16PtrFromString(params)
	if err != nil {
		return err
	}
	// SW_SHOWNORMAL = 1
	ret, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(paramPtr)),
		0,
		1,
	)
	// ShellExecute returns value > 32 on success
	if ret <= 32 {
		return fmt.Errorf("UAC elevation denied or failed (code %d). Right-click the installer and choose Run as administrator", ret)
	}
	return nil
}