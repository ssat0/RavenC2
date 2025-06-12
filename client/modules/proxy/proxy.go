package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ProxyMode string

const (
	ModeForward ProxyMode = "forward"
	ModeSocks5  ProxyMode = "socks5"
)

type Config struct {
	Mode       ProxyMode
	LocalIP    string
	LocalPort  int
	RemoteHost string
	RemotePort int
}

var (
	isRunning         bool
	activeConnections sync.Map
	proxyListener     net.Listener
	mutex             sync.Mutex
	currentConfig     Config
)

func HandleProxyCommand(args ...string) error {
	if isRunning {
		log.Println("[Proxy] Proxy already running. Restarting...")
		Stop()
	}

	if len(args) < 3 {
		return fmt.Errorf("Usage: socks5|forward <localIP> <localPort> [remoteHost remotePort]")
	}

	mode := ModeForward
	if strings.ToLower(args[0]) == "socks5" {
		mode = ModeSocks5
	}

	localIP := args[1]
	localPort, err := strconv.Atoi(args[2])
	if err != nil {
		return fmt.Errorf("Invalid port: %v", err)
	}

	config := Config{
		Mode:      mode,
		LocalIP:   localIP,
		LocalPort: localPort,
	}

	if mode == ModeForward {
		if len(args) < 5 {
			return fmt.Errorf("forward mode requires remoteHost and remotePort")
		}
		config.RemoteHost = args[3]
		config.RemotePort, err = strconv.Atoi(args[4])
		if err != nil {
			return fmt.Errorf("Invalid remote port: %v", err)
		}
	}

	return Start(config)
}

func Start(config Config) error {
	mutex.Lock()
	defer mutex.Unlock()

	address := fmt.Sprintf("%s:%d", config.LocalIP, config.LocalPort)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", address, err)
	}

	proxyListener = listener
	currentConfig = config
	isRunning = true

	log.Printf("[Proxy] Started [%s] on %s", config.Mode, address)

	go acceptConnections()
	return nil
}

func acceptConnections() {
	for isRunning {
		conn, err := proxyListener.Accept()
		if err != nil {
			if isRunning {
				log.Printf("[Proxy] Accept error: %v", err)
			}
			break
		}

		connID := fmt.Sprintf("%s->%s", conn.RemoteAddr(), conn.LocalAddr())
		activeConnections.Store(connID, conn)

		go func() {
			defer activeConnections.Delete(connID)

			if currentConfig.Mode == ModeForward {
				handleForward(conn)
			} else {
				handleSocks5(conn)
			}
		}()
	}
}

func handleForward(localConn net.Conn) {
	defer localConn.Close()

	remoteAddr := fmt.Sprintf("%s:%d", currentConfig.RemoteHost, currentConfig.RemotePort)
	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("[Forward] Dial error: %v", err)
		return
	}
	defer remoteConn.Close()

	pipe(localConn, remoteConn)
}

func handleSocks5(client net.Conn) {
	defer client.Close()

	// SOCKS5 handshake
	buf := make([]byte, 2)
	if _, err := io.ReadFull(client, buf); err != nil || buf[0] != 0x05 {
		return
	}

	methods := make([]byte, int(buf[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	client.Write([]byte{0x05, 0x00}) // no auth

	// Request
	header := make([]byte, 4)
	if _, err := io.ReadFull(client, header); err != nil {
		return
	}
	if header[1] != 0x01 { // only CONNECT supported
		return
	}

	var addr string
	switch header[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		addr = net.IP(ip).String()
	case 0x03: // domain
		length := make([]byte, 1)
		if _, err := io.ReadFull(client, length); err != nil {
			return
		}
		host := make([]byte, length[0])
		if _, err := io.ReadFull(client, host); err != nil {
			return
		}
		addr = string(host)
	default:
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	dest := fmt.Sprintf("%s:%d", addr, port)

	target, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()

	// Success response
	local := target.LocalAddr().(*net.TCPAddr)
	ip := local.IP.To4()
	if ip == nil {
		ip = []byte{0, 0, 0, 0}
	}
	reply := append([]byte{0x05, 0x00, 0x00, 0x01}, ip...)
	reply = append(reply, byte(local.Port>>8), byte(local.Port&0xff))
	client.Write(reply)

	pipe(client, target)
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(a, b)
		a.Close()
		wg.Done()
	}()
	go func() {
		io.Copy(b, a)
		b.Close()
		wg.Done()
	}()

	wg.Wait()
}

func Stop() {
	mutex.Lock()
	defer mutex.Unlock()

	if !isRunning {
		return
	}

	isRunning = false

	if proxyListener != nil {
		proxyListener.Close()
		proxyListener = nil
	}

	activeConnections.Range(func(_, val any) bool {
		if conn, ok := val.(net.Conn); ok {
			conn.Close()
		}
		return true
	})

	log.Println("[Proxy] Stopped")
}
