//go:build windows

package antidebug

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (a *AntiDebug) isDebuggerPresent() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
	ret, _, _ := isDebuggerPresent.Call()
	return ret != 0
}

func (a *AntiDebug) checkVMArtifacts() bool {
	// Check for VM artifacts
	if a.checkVMWare() || a.checkVirtualBox() || a.checkQEMU() {
		return true
	}

	// Check for VM drivers
	if a.checkVMDrivers() {
		return true
	}

	return false
}

func (a *AntiDebug) checkVMWare() bool {
	// Check for VMWare artifacts
	vmwareFiles := []string{
		"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
		"C:\\Windows\\System32\\drivers\\vmci.sys",
		"C:\\Windows\\System32\\drivers\\vmx_svga.sys",
		"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
		"C:\\Windows\\System32\\drivers\\vmxnet.sys",
	}

	for _, file := range vmwareFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	return false
}

func (a *AntiDebug) checkVirtualBox() bool {
	// Check for VirtualBox artifacts
	vboxFiles := []string{
		"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
		"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
		"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
		"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
		"C:\\Windows\\System32\\vboxdisp.dll",
	}

	for _, file := range vboxFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	return false
}

func (a *AntiDebug) checkQEMU() bool {
	// Check for QEMU artifacts
	qemuFiles := []string{
		"C:\\Windows\\System32\\drivers\\qemu-ga.sys",
		"C:\\Windows\\System32\\drivers\\qemupciserial.sys",
		"C:\\Windows\\System32\\drivers\\qemupciserial.sys",
	}

	for _, file := range qemuFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	return false
}

func (a *AntiDebug) checkVMDrivers() bool {
	// Check for VM drivers
	vmDrivers := []string{
		"vmmouse", "vmhgfs", "vmci", "vmx_svga",
		"VBoxMouse", "VBoxGuest", "VBoxSF",
		"qemu-ga", "qemupciserial",
	}

	cmd := exec.Command("driverquery")
	output, err := cmd.Output()
	if err == nil {
		for _, driver := range vmDrivers {
			if strings.Contains(strings.ToLower(string(output)), strings.ToLower(driver)) {
				return true
			}
		}
	}

	return false
}

func (a *AntiDebug) checkAdvancedDebugging() bool {
	// Check for PEB
	if a.checkPEB() {
		return true
	}

	// Check for NTDLL hooks
	if a.checkNTDLLHooks() {
		return true
	}

	return false
}

func (a *AntiDebug) checkPEB() bool {
	// Check for PEB debug flags
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
	ret, _, _ := isDebuggerPresent.Call()
	return ret != 0
}

func (a *AntiDebug) checkNTDLLHooks() bool {
	// Check for NTDLL hooks
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	var processInfo uint32
	handle, _ := syscall.GetCurrentProcess()
	ret, _, _ := ntQueryInformationProcess.Call(
		uintptr(handle),
		0x1F, // ProcessDebugPort
		uintptr(unsafe.Pointer(&processInfo)),
		uintptr(unsafe.Sizeof(processInfo)),
		0,
	)

	return ret == 0 && processInfo != 0
}
