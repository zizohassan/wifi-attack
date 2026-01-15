# WiFi Penetration Testing Tool

A comprehensive WiFi penetration testing tool written in Go. This tool automates the process of scanning, deauthenticating clients, capturing 4-way handshakes, and cracking WPA/WPA2 passwords.

## Features

- **Automated Scanning**: Scans for available networks using `airodump-ng`.
- **Target Selection**: Interactive menu to select a target network.
- **Deauthentication Attack**: Deauthenticates clients to force a new handshake.
- **Handshake Capture**: Automates the capture of WPA/WPA2 handshakes.
- **Password Cracking**: Uses `aircrack-ng` to crack the captured handshake using a wordlist.
- **Process Management**: Automatically kills conflicting processes and restarts NetworkManager.

## Prerequisites

This tool requires the `aircrack-ng` suite and a wordlist.

### Install Dependencies (Kali/Debian/Ubuntu)
```bash
sudo apt update
sudo apt install aircrack-ng wordlists
```
*Note: Ensure `rockyou.txt` is available in `/usr/share/wordlists/`. If it is gzipped (`rockyou.txt.gz`), the tool will automatically handle it.*

## Installation

1. Clone the repository (or copy the files):
   ```bash
   git clone <repository_url>
   cd wifihack
   ```

2. Build the project:
   ```bash
   go build -o wifihack main.go
   ```

## Usage

Run the tool with root privileges:

```bash
sudo ./wifihack
```

### Steps:
1. **Select Interface**: Choose your wireless network interface from the list.
2. **Scanning**: The tool will scan for networks for 10 seconds.
3. **Select Target**: Enter the ID of the network you want to target.
4. **Capture**: The tool will switch to the target channel and wait for a handshake.  
   *Simultaneously, it will send deauth packets to connected clients.*
5. **Crack**: Once a handshake is captured, it will attempt to crack the password using the default wordlist.

## Disclaimer

**Educational Use Only**. This tool is intended for security research and educational purposes only. Usage of this tool for attacking targets without prior mutual consent is illegal. The author assumes no liability and is not responsible for any misuse or damage caused by this program.
