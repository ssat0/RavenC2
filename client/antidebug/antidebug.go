package antidebug

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type CheckFunc func() bool

type AntiDebug struct {
	enabled bool
	checks  []CheckFunc
}

// Custom hash function
func customHash(input string) string {
	// First step: SHA256
	h := sha256.New()
	h.Write([]byte(input))
	hash := h.Sum(nil)

	// Second step: Custom mixing
	result := make([]byte, 32)
	for i := 0; i < 32; i++ {
		result[i] = hash[i] ^ byte(i*7) ^ hash[(i+1)%32]
	}

	// Third step: Convert to hex
	return hex.EncodeToString(result)
}

// Debugger hash table
var debuggerHashes = map[string]bool{
	// Windows debuggers
	"a7b3c9d1e5f2g4h6i8j0k2l4m6n8o0p2q4r6s8t0u2v4w6x8y0z2": true, // windbg
	"b8c4d0e6f2g8h4i0j6k2l8m4n0o6p2q8r4s0t6u2v8w4x0y6z2a8": true, // ollydbg
	"c9d5e1f7g3h9i5j1k7l3m9n5o1p7q3r9s5t1u7v3w9x5y1z7a3b9": true, // x64dbg
	"d0e6f2g8h4i0j6k2l8m4n0o6p2q8r4s0t6u2v8w4x0y6z2a8b4c0": true, // immunity
	"e1f7g3h9i5j1k7l3m9n5o1p7q3r9s5t1u7v3w9x5y1z7a3b9c5d1": true, // process hacker

	// Unix debuggers
	"f2g8h4i0j6k2l8m4n0o6p2q8r4s0t6u2v8w4x0y6z2a8b4c0d6e2": true, // gdb
	"g3h9i5j1k7l3m9n5o1p7q3r9s5t1u7v3w9x5y1z7a3b9c5d1e7f3": true, // lldb
	//"h4i0j6k2l8m4n0o6p2q8r4s0t6u2v8w4x0y6z2a8b4c0d6e2f8g4": true, // strace
	"i5j1k7l3m9n5o1p7q3r9s5t1u7v3w9x5y1z7a3b9c5d1e7f3g9h5": true, // ltrace
	"j6k2l8m4n0o6p2q8r4s0t6u2v8w4x0y6z2a8b4c0d6e2f8g4h0i6": true, // valgrind
}

func New() *AntiDebug {
	ad := &AntiDebug{
		enabled: true,
		checks:  make([]CheckFunc, 0),
	}

	// Add default checks
	ad.AddCheck(ad.checkTimingAnomaly)
	ad.AddCheck(ad.checkDebugEnv)
	ad.AddCheck(ad.checkEmulator)
	ad.AddCheck(ad.checkHardwareAnomalies)

	return ad
}

func (a *AntiDebug) AddCheck(check CheckFunc) {
	a.checks = append(a.checks, check)
}

func (a *AntiDebug) Check() bool {
	if !a.enabled {
		return false
	}

	// Run all checks
	for _, check := range a.checks {
		if check() {
			return true
		}
	}

	// Platform-specific checks
	if runtime.GOOS == "windows" {
		return a.checkDebuggerProcesses()
	}

	if runtime.GOOS == "linux" {
		return a.checkDebuggerProcesses()
	}

	return a.isDebuggerPresent()
}

func (a *AntiDebug) checkTimingAnomaly() bool {
	start := time.Now()
	time.Sleep(10 * time.Millisecond)
	elapsed := time.Since(start)
	return elapsed > 20*time.Millisecond
}

func (a *AntiDebug) checkDebugEnv() bool {
	debugVars := []string{
		"TERM_PROGRAM_DEBUG",
		"DEBUG",
		"GO_DEBUG",
		"_DEBUG",
	}

	for _, v := range debugVars {
		if val := os.Getenv(v); val != "" {
			return true
		}
	}
	return false
}

func (a *AntiDebug) checkEmulator() bool {
	return a.checkVMArtifacts() ||
		a.checkTimingAnomalies() ||
		a.checkSystemArtifacts()
}

func (a *AntiDebug) checkHardwareAnomalies() bool {
	// Check CPU information
	if a.checkCPUCores() {
		return true
	}

	// Check RAM size
	if a.checkRAMSize() {
		return true
	}

	return false
}

func (a *AntiDebug) checkCPUCores() bool {
	cores := runtime.NumCPU()
	return cores < 2 || cores > 32
}

func (a *AntiDebug) checkRAMSize() bool {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys < 1024*1024*1024 // Less than 1GB RAM
}

func (a *AntiDebug) checkTimingAnomalies() bool {
	start := time.Now()
	time.Sleep(100 * time.Millisecond)
	elapsed := time.Since(start)

	// Timing anomalies in emulators
	return elapsed > 150*time.Millisecond || elapsed < 50*time.Millisecond
}

func (a *AntiDebug) checkSystemArtifacts() bool {
	// Check system information
	if a.checkSystemInfo() {
		return true
	}

	return false
}

func (a *AntiDebug) checkSystemInfo() bool {
	// Check basic system information
	hostname, err := os.Hostname()
	if err != nil {
		return true
	}

	// VM hostnames usually have a specific format
	vmHostnames := []string{
		"vm", "virtual", "vbox", "qemu", "docker",
	}

	for _, vmName := range vmHostnames {
		if contains(hostname, vmName) {
			return true
		}
	}

	return false
}

func contains(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) && s[0:len(substr)] == substr
}

func (a *AntiDebug) checkDebuggerProcesses() bool {
	// Platform-specific checks
	if runtime.GOOS == "windows" {
		return a.checkWindowsDebuggers()
	}
	return a.checkUnixDebuggers()
}

func (a *AntiDebug) checkWindowsDebuggers() bool {
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Split output into lines
	lines := strings.Split(string(output), "\n")

	// Check each line
	for _, line := range lines {
		// Hash the line
		hash := customHash(strings.ToLower(strings.TrimSpace(line)))

		// Check hash table
		if debuggerHashes[hash] {
			return true
		}
	}

	return false
}

func (a *AntiDebug) checkUnixDebuggers() bool {
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Split output into lines
	lines := strings.Split(string(output), "\n")

	// Check each line
	for _, line := range lines {
		// Hash the line
		hash := customHash(strings.ToLower(strings.TrimSpace(line)))

		// Check hash table
		if debuggerHashes[hash] {
			return true
		}
	}

	return false
}
