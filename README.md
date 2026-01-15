# WiFi Penetration Testing Tool

```text
 __          ___ ______ _    _  _   _            _    
 \ \        / (_)  ____(_)  | || | | |          | |   
  \ \  /\  / / _| |__   _   | || | | | __ _  ___| | __
   \ \/  \/ / | |  __| | |  | || |_| |/ _` |/ __| |/ /
    \  /\  /  | | |    | |  |__   _| | (_| | (__|   < 
     \/  \/   |_|_|    |_|     |_| |_|\__,_|\___|_|\_\
                                                      
       [ WiFi Penetration Testing Tool ]
           [ Created by Abdelaziz ]
        [ (c) 2026 - All Rights Reserved ]
```

A comprehensive, professional WiFi penetration testing tool written in Go. Automates scanning, concurrent deauthentication attacks, handshake capturing, and password cracking.

## 🚀 Features

- **🎨 Professional UI**: Stunning ASCII art banner and clear, color-coded output.
- **📡 Automated Scanning**: Rapidly identifies available networks using `airodump-ng`.
- **🎯 Precision Targeting**: Interactive menu to easily select your target.
- **⚡ Concurrent Attacks**: **Deauthentication attacks start immediately** alongside capture for maximum efficiency.
- **🎮 Manual Control**: Full control in your hands—press **'s'** to stop scanning or capturing at any moment.
- **🔐 Handshake Capture**: Intelligent auto-detection of WPA/WPA2 handshakes.
- **🔨 Password Cracking**: Seamlessly transitions to `aircrack-ng` to crack the captured handshake.
- **🛡️ Smart Process Management**: Automatically handles conflicting processes and restores network services.

## 🛠️ Prerequisites

- **Go** (Golang) installed.
- **Aircrack-ng Suite**: `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`.
- **Wordlist**: specifically `rockyou.txt`.

### Install Dependencies (Kali/Debian/Ubuntu)
```bash
sudo apt update
sudo apt install aircrack-ng wordlists
```

## 📥 Installation

1.  **Clone the repository**:
    ```bash
    git clone <your-repo-url>
    cd wifihack
    ```

2.  **Build the tool**:
    ```bash
    go build -o wifihack main.go
    ```

## 💻 Usage

Run with root privileges:

```bash
sudo ./wifihack
```

### 👣 Walkthrough

1.  **Select Interface**: Choose your wireless monitor-capable interface.
2.  **Scanning**: The tool scans for networks.
    -   *Action*: Press **`s` + Enter** to stop scanning when you see your target.
3.  **Select Target**: Enter the ID number of the target network.
4.  **Capture & Attack**:
    -   The tool starts **capturing** on the target channel AND **deauthenticating** clients simultaneously.
    -   *Action*: Wait for auto-detection OR press **`s` + Enter** manually if you see the handshake or want to proceed.
5.  **Crack**: The tool stops the attack, restores your network card, and launches `aircrack-ng` to find the password.

## ⚖️ Disclaimer

**Educational Use Only**. This tool is intended for security research and educational purposes only. Usage of this tool for attacking targets without prior mutual consent is illegal. The author (Abdelaziz) assumes no liability and is not responsible for any misuse or damage caused by this program.

---
*Created by Abdelaziz © 2026*
