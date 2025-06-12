package shell

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"server/config"
	"time"

	"golang.org/x/term"
)

func Shell(port string, interactive bool) {
	conn, err := waitForTLSConnection(port, 30*time.Second)
	if err != nil {
		fmt.Printf("Connection error: %v\n", err)
		return
	}
	defer conn.Close()

	if interactive && runtime.GOOS != "windows" {
		if err := interactiveSession(conn); err != nil {
			fmt.Printf("Shell error: %v\n", err)
		}
	} else {
		if err := nonInteractiveSession(conn); err != nil {
			fmt.Printf("Shell error: %v\n", err)
		}
	}
}

func waitForTLSConnection(port string, timeout time.Duration) (net.Conn, error) {
	tlsConfig, err := getTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("TLS config error: %w", err)
	}

	tcpListener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return nil, err
	}
	tcpListener.(*net.TCPListener).SetDeadline(time.Now().Add(timeout))

	listener := tls.NewListener(tcpListener, tlsConfig)
	conn, err := listener.Accept()
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func nonInteractiveSession(conn net.Conn) error {
	fmt.Println("[*] Enter commands. Type 'exit' to quit.\n")

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("PS> ")
		if !scanner.Scan() {
			break
		}
		command := scanner.Text()
		if command == "" {
			continue
		}

		if command == "exit" {
			_, _ = conn.Write([]byte("exit\n"))
			break
		}

		_, err := conn.Write([]byte(command + "\n"))
		if err != nil {
			return fmt.Errorf("command could not be sent: %w", err)
		}

		// Wait for response
		reply := make([]byte, 8192)
		n, err := conn.Read(reply)
		if err != nil {
			return fmt.Errorf("response could not be received: %w", err)
		}
		fmt.Print(string(reply[:n]))
	}
	return nil
}

func interactiveSession(conn net.Conn) error {
	defer fmt.Println("\r\nShell session terminated")

	initialBuf := make([]byte, 4096)
	if n, err := conn.Read(initialBuf); err == nil {
		fmt.Print(string(initialBuf[:n]))
	}

	var oldState *term.State
	var err error

	if runtime.GOOS != "windows" {
		oldState, err = term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	done := make(chan struct{})
	go copyWithExit(conn, os.Stdin, done)
	go copyWithExit(os.Stdout, conn, done)

	<-done
	return nil
}

func copyWithExit(dst io.Writer, src io.Reader, done chan struct{}) {
	buf := make([]byte, 1024)
	var cmdBuf []byte

	showPrompt := dst != os.Stdout

	if showPrompt && runtime.GOOS == "windows" {
		fmt.Print("PS> ")
	}

	for {
		n, err := src.Read(buf)
		if err != nil {
			done <- struct{}{}
			return
		}

		if dst == os.Stdout {
			dst.Write(buf[:n])
			continue
		}

		cmdBuf = append(cmdBuf, buf[:n]...)
		dst.Write(buf[:n])

		if bytes.Contains(buf[:n], []byte("\n")) {
			if bytes.Contains(bytes.ToLower(cmdBuf), []byte("exit")) {
				dst.Write([]byte("Exiting...\r\n"))
				time.Sleep(300 * time.Millisecond)
				done <- struct{}{}
				return
			}
			cmdBuf = cmdBuf[:0]

			if showPrompt && runtime.GOOS == "windows" {
				fmt.Print("PS> ")
			}
		}
	}
}

func getTLSConfig() (*tls.Config, error) {
	// Get the certificates from the config
	cert, err := tls.X509KeyPair([]byte(config.SERVER_CERT), []byte(config.SERVER_KEY))
	if err != nil {
		return nil, fmt.Errorf("server certificate could not be loaded: %v", err)
	}

	// Load the CA certificate
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM([]byte(config.CA_CERT)) {
		return nil, fmt.Errorf("CA certificate could not be loaded")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}
