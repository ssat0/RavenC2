package utils

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

func GenerateClientID() string {
	var identifiers []string

	// 1. Stable hardware information
	switch runtime.GOOS {
	case "windows":
		// Just use the most stable values
		cmds := [][]string{
			{"wmic", "csproduct", "get", "UUID"},         // System UUID
			{"wmic", "bios", "get", "SerialNumber"},      // BIOS Serial
			{"wmic", "baseboard", "get", "SerialNumber"}, // Motherboard Serial
		}
		for _, cmd := range cmds {
			if out, err := exec.Command(cmd[0], cmd[1:]...).Output(); err == nil {
				lines := strings.Split(string(out), "\n")
				if len(lines) > 1 {
					value := strings.TrimSpace(lines[1])
					if value != "" && !strings.Contains(strings.ToLower(value), "null") {
						identifiers = append(identifiers, value)
					}
				}
			}
		}

	case "linux":
		// Use only the most stable files
		files := []string{
			"/etc/machine-id",
			"/var/lib/dbus/machine-id",
			"/sys/class/dmi/id/product_uuid",
		}
		for _, file := range files {
			if data, err := os.ReadFile(file); err == nil {
				value := strings.TrimSpace(string(data))
				if value != "" {
					identifiers = append(identifiers, value)
				}
			}
		}

	case "darwin":
		// macOS only hardware UUID
		cmd := exec.Command("sh", "-c", "ioreg -d2 -c IOPlatformExpertDevice | awk -F\\\" '/IOPlatformUUID/{print $(NF-1)}'")
		if out, err := cmd.Output(); err == nil {
			uuid := strings.TrimSpace(string(out))
			if uuid != "" {
				identifiers = append(identifiers, uuid)
			}
		}

		// Also add macOS serial number
		cmd = exec.Command("sh", "-c", "system_profiler SPHardwareDataType | awk '/Serial Number/{print $4}'")
		if out, err := cmd.Output(); err == nil {
			serial := strings.TrimSpace(string(out))
			if serial != "" {
				identifiers = append(identifiers, serial)
			}
		}
	}

	// Remove variables that could change:
	// - MAC addresses
	// - Hostname
	// - User information
	// Just add the OS type
	identifiers = append(identifiers, runtime.GOOS)

	// Combine the information
	combinedInfo := strings.Join(identifiers, "|")
	combinedInfo = strings.ToLower(combinedInfo)
	combinedInfo = strings.ReplaceAll(combinedInfo, " ", "")
	combinedInfo = strings.ReplaceAll(combinedInfo, "-", "")

	// Hash the information
	hash := sha256.Sum256([]byte(combinedInfo))
	return hex.EncodeToString(hash[:16])
}

func HTTPClientConfig() *http.Client {
	var once sync.Once
	var httpClient *http.Client

	once.Do(func() {
		transport := &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     90 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 90 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   false,
		}

		httpClient = &http.Client{
			Transport: transport,
			Timeout:   time.Second * 30,
		}
	})

	return httpClient
}

func GetFileTransferHTTPClient() *http.Client {
	var fileTransferClient *http.Client
	var fileTransferOnce sync.Once

	fileTransferOnce.Do(func() {
		transport := &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 2, // For file transfer, 2 connections
			IdleConnTimeout:     90 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 90 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   false,
			// For file transfer, increase buffer sizes
			ReadBufferSize:  64 * 1024, // 64KB
			WriteBufferSize: 64 * 1024, // 64KB
		}

		fileTransferClient = &http.Client{
			Transport: transport,
			// For file transfer, longer timeout
			Timeout: time.Minute * 10, // 10 minutes
		}
	})

	return fileTransferClient
}
