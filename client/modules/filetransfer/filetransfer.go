package filetransfer

import (
	"client/config"
	"client/utils"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// FileTransfer, manages file transfer operations
type FileTransfer struct {
	ServerURL  string      // Server URL
	TLSConfig  *tls.Config // TLS configuration
	ChunkSize  int64       // Size of each chunk (automatically set)
	MaxRetries int         // Number of retries if failed
	client     *http.Client
}

// FileResponse, represents the response from the server
type FileResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Hash    string `json:"hash,omitempty"`
	Size    int64  `json:"size,omitempty"`
}

// New, creates a new FileTransfer instance
func New() *FileTransfer {
	return &FileTransfer{
		ServerURL:  fmt.Sprintf("https://%s:%s", config.SERVER_IP, config.SERVER_PORT),
		TLSConfig:  &tls.Config{InsecureSkipVerify: true}, // For development, certificate verification should be enabled in production
		ChunkSize:  2 * 1024 * 1024,                       // 2MB chunks (automatically set)
		MaxRetries: 3,
		client:     utils.GetFileTransferHTTPClient(),
	}
}

// HandleCommand, handles commands from the server
func (ft *FileTransfer) HandleCommand(command string, args []string) error {
	switch command {
	case "download":
		// download command: Download file from client to server
		if len(args) < 1 {
			return fmt.Errorf("download command requires at least 1 argument: CLIENT_FILE_PATH")
		}

		clientFilePath := args[0]
		return ft.Download(clientFilePath)

	case "upload":
		// upload command: Upload file from server to client
		if len(args) < 2 {
			return fmt.Errorf("upload command requires at least 2 arguments: SERVER_FILE_PATH CLIENT_FOLDER_PATH")
		}

		serverFilePath := args[0]
		clientFolderPath := args[1]
		return ft.Upload(serverFilePath, clientFolderPath)

	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

// Download, downloads
func (ft *FileTransfer) Download(clientFilePath string) error {

	/*if strings.Contains(clientFilePath, "..") {
		return fmt.Errorf("security error: '..' cannot be used in file path")
	}*/

	// Check if the file exists
	file, err := os.Open(clientFilePath)
	if err != nil {
		return fmt.Errorf("file not found: %v", err)
	}
	defer file.Close()

	// Get file information
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("file information not found: %v", err)
	}

	// Calculate file hash
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("file hash not found: %v", err)
	}
	fileHash := hex.EncodeToString(hash.Sum(nil))

	// Reset file position
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("file position not set: %v", err)
	}

	// Create HTTP request
	url1 := fmt.Sprintf("%s/filetransfer?action=download", ft.ServerURL)

	// Create multipart form
	req, err := http.NewRequest("POST", url1, file)
	if err != nil {
		return fmt.Errorf("request creation failed: %v", err)
	}

	// Add file information to header
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-File-Name", url.QueryEscape(sanitizeFileName(filepath.Base(clientFilePath))))
	req.Header.Set("X-File-Size", fmt.Sprintf("%d", fileInfo.Size()))
	req.Header.Set("X-File-Hash", fileHash)

	req.Header.Set("Connection", "keep-alive")

	// Send request
	fmt.Printf("Sending file: %s\n", clientFilePath)
	startTime := time.Now()

	resp, err := ft.client.Do(req)
	if err != nil {
		return fmt.Errorf("file sending failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server error: %s", resp.Status)
	}

	// Read response
	var response FileResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("response reading failed: %v", err)
	}

	if !response.Success {
		return fmt.Errorf("sending failed: %s", response.Message)
	}

	elapsed := time.Since(startTime).Seconds()
	speed := float64(fileInfo.Size()) / elapsed / 1024 // KB/s

	fmt.Printf("File sending completed: %s (%.2f KB/s)\n", clientFilePath, speed)
	return nil
}

// Upload, uploads file from server to client
func (ft *FileTransfer) Upload(serverFilePath, clientFolderPath string) error {
	// Create target directory
	if err := os.MkdirAll(clientFolderPath, 0755); err != nil {
		return fmt.Errorf("target directory not created: %v", err)
	}

	// Get file name
	fileName := filepath.Base(serverFilePath)
	localFilePath := filepath.Join(clientFolderPath, fileName)

	// Create HTTP request - URL-encode file path securely
	url := fmt.Sprintf("%s/filetransfer?action=upload&path=%s", ft.ServerURL, url.QueryEscape(serverFilePath))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("request creation failed: %v", err)
	}

	req.Header.Set("Connection", "keep-alive")

	// Send request
	resp, err := ft.client.Do(req)
	if err != nil {
		return fmt.Errorf("file sending failed: %v", err)
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
	return nil
}

func sanitizeFileName(fileName string) string {
	// Limit file name to 255 characters
	if len(fileName) > 255 {
		fileName = fileName[:255]
	}

	// Clean dangerous characters
	re := regexp.MustCompile(`[<>:"/\\|?*]`)
	fileName = re.ReplaceAllString(fileName, "_")

	return fileName
}
