//go:build !windows

package antidebug

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func (a *AntiDebug) isDebuggerPresent() bool {
	if err := syscall.PtraceAttach(os.Getpid()); err != nil {
		return true // Debugger detected
	}
	syscall.PtraceDetach(os.Getpid())
	return false
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
		"/dev/vmware",
		"/dev/vmmem",
		"/dev/vmci",
		"/dev/vmmon",
		"/proc/scsi/scsi",
		"/proc/ide/hda/driver",
		"/proc/ide/hdb/driver",
	}

	for _, file := range vmwareFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}

	// Check for VMWare MAC addresses
	if a.checkVMWareMAC() {
		return true
	}

	return false
}

func (a *AntiDebug) checkVirtualBox() bool {
	// Check for VirtualBox artifacts
	vboxFiles := []string{
		"/dev/vboxguest",
		"/dev/vboxuser",
		"/proc/modules",
	}

	for _, file := range vboxFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}

	// Check for VirtualBox MAC addresses
	if a.checkVirtualBoxMAC() {
		return true
	}

	return false
}

func (a *AntiDebug) checkQEMU() bool {
	// Check for QEMU artifacts
	qemuFiles := []string{
		"/dev/kvm",
		"/dev/qemu",
		"/proc/modules",
	}

	for _, file := range qemuFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}

	// Check for QEMU MAC addresses
	if a.checkQEMUMAC() {
		return true
	}

	return false
}

func (a *AntiDebug) checkVMDrivers() bool {
	// Check for VM drivers
	vmDrivers := []string{
		"vmware", "vbox", "qemu", "kvm",
		"vmhgfs", "vmci", "vmxnet",
		"vboxguest", "vboxsf",
	}

	// Check for VM drivers in /proc/modules
	if data, err := ioutil.ReadFile("/proc/modules"); err == nil {
		content := strings.ToLower(string(data))
		for _, driver := range vmDrivers {
			if strings.Contains(content, strings.ToLower(driver)) {
				return true
			}
		}
	}

	return false
}

func (a *AntiDebug) checkVMWareMAC() bool {
	// Check for VMWare MAC addresses
	vmwareMACs := []string{
		"00:05:69",
		"00:0C:29",
		"00:1C:14",
		"00:50:56",
	}

	return a.checkMACAddresses(vmwareMACs)
}

func (a *AntiDebug) checkVirtualBoxMAC() bool {
	// Check for VirtualBox MAC addresses
	vboxMACs := []string{
		"08:00:27",
		"0A:00:27",
	}

	return a.checkMACAddresses(vboxMACs)
}

func (a *AntiDebug) checkQEMUMAC() bool {
	// Check for QEMU MAC addresses
	qemuMACs := []string{
		"52:54:00",
	}

	return a.checkMACAddresses(qemuMACs)
}

func (a *AntiDebug) checkMACAddresses(macPrefixes []string) bool {
	// Check for MAC addresses in /sys/class/net
	netDir := "/sys/class/net"
	entries, err := ioutil.ReadDir(netDir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() {
			// Read MAC address
			macFile := filepath.Join(netDir, entry.Name(), "address")
			if data, err := ioutil.ReadFile(macFile); err == nil {
				mac := strings.TrimSpace(string(data))
				for _, prefix := range macPrefixes {
					if strings.HasPrefix(strings.ToLower(mac), strings.ToLower(prefix)) {
						return true
					}
				}
			}
		}
	}

	return false
}
