// dcfetch fetches current Telegram DC addresses using the MTProto API.
//
// Usage:
//
//	go run ./tools/dcfetch              # uses test credentials (limited)
//	go run ./tools/dcfetch -auth        # interactive login for full access
//
// For authenticated access, get API credentials from https://my.telegram.org/apps
// and set: TELEGRAM_API_ID and TELEGRAM_API_HASH
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/dcs"
	"github.com/gotd/td/tg"
)

func main() {
	authFlag := flag.Bool("auth", false, "Interactive login for full DC list (including CDN)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	apiID, apiHash := getCredentials()

	// Session storage for persistence
	sessionFile := "dcfetch.session"

	dcList := dcs.Prod()
	fmt.Printf("[DEBUG] Production DC 2 addresses: %+v\n", dcList.Options[1]) // DC 2 is index 1

	client := telegram.NewClient(apiID, apiHash, telegram.Options{
		SessionStorage: &telegram.FileSessionStorage{Path: sessionFile},
		DC:             2,
		DCList:         dcList,
	})

	if err := client.Run(ctx, func(ctx context.Context) error {
		if *authFlag {
			// Check if already authorized
			status, err := client.Auth().Status(ctx)
			if err != nil {
				return fmt.Errorf("auth status: %w", err)
			}

			if !status.Authorized {
				if err := authenticate(ctx, client); err != nil {
					return fmt.Errorf("authentication: %w", err)
				}
				fmt.Println("Authentication successful!")
				fmt.Println()
			} else {
				fmt.Println("Using existing session")
				fmt.Println()
			}
		}

		config, err := client.API().HelpGetConfig(ctx)
		if err != nil {
			return fmt.Errorf("help.getConfig: %w", err)
		}

		printConfig(config)
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func getCredentials() (int, string) {
	idStr := os.Getenv("TELEGRAM_API_ID")
	hash := os.Getenv("TELEGRAM_API_HASH")

	if idStr != "" && hash != "" {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid TELEGRAM_API_ID: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[DEBUG] Using API ID: %d\n", id)
		return id, hash
	}

	// Test credentials (limited, but works for basic getConfig)
	fmt.Println("Using test credentials (set TELEGRAM_API_ID and TELEGRAM_API_HASH for full access)")
	fmt.Println()
	return 17349, "344583e45741c457f0b93d57a2aa0d22"
}

func authenticate(ctx context.Context, client *telegram.Client) error {
	fmt.Println("[DEBUG] Starting authentication flow...")
	// Request SMS explicitly instead of relying on app code
	flow := auth.NewFlow(terminalAuth{}, auth.SendCodeOptions{
		AllowFlashCall: false,
		CurrentNumber:  false,
		AllowAppHash:   false, // Disable app hash to force SMS
	})
	err := client.Auth().IfNecessary(ctx, flow)
	if err != nil {
		fmt.Printf("[DEBUG] Auth error: %v\n", err)
	}
	return err
}

// terminalAuth implements auth.UserAuthenticator for terminal input
type terminalAuth struct{}

func (terminalAuth) Phone(_ context.Context) (string, error) {
	phone, err := prompt("Enter phone number (with country code, e.g. +1234567890): ")
	if err != nil {
		return "", err
	}
	fmt.Printf("[DEBUG] Requesting code for phone: %s\n", phone)
	return phone, nil
}

func (terminalAuth) Password(_ context.Context) (string, error) {
	fmt.Println("[DEBUG] 2FA password requested")
	return prompt("Enter 2FA password: ")
}

func (terminalAuth) Code(_ context.Context, sentCode *tg.AuthSentCode) (string, error) {
	fmt.Printf("[DEBUG] Code sent! Type: %T\n", sentCode.Type)
	fmt.Printf("[DEBUG] Phone code hash: %s\n", sentCode.PhoneCodeHash)
	switch t := sentCode.Type.(type) {
	case *tg.AuthSentCodeTypeApp:
		fmt.Printf("[DEBUG] Code sent to Telegram app (length: %d)\n", t.Length)
		fmt.Println("[DEBUG] Check your Telegram app for a message from 'Telegram' service")
	case *tg.AuthSentCodeTypeSMS:
		fmt.Printf("[DEBUG] Code sent via SMS (length: %d)\n", t.Length)
	case *tg.AuthSentCodeTypeCall:
		fmt.Printf("[DEBUG] Code will be delivered via phone call (length: %d)\n", t.Length)
	case *tg.AuthSentCodeTypeFlashCall:
		fmt.Printf("[DEBUG] Flash call from: %s\n", t.Pattern)
	case *tg.AuthSentCodeTypeMissedCall:
		fmt.Printf("[DEBUG] Missed call from: %s (last %d digits)\n", t.Prefix, t.Length)
	case *tg.AuthSentCodeTypeFirebaseSMS:
		fmt.Printf("[DEBUG] Firebase SMS (length: %d)\n", t.Length)
	default:
		fmt.Printf("[DEBUG] Unknown code type: %+v\n", sentCode.Type)
	}
	if sentCode.NextType != nil {
		fmt.Printf("[DEBUG] Next type available: %T (wait for timeout to request)\n", sentCode.NextType)
	}
	fmt.Printf("[DEBUG] Timeout: %d seconds\n", sentCode.Timeout)

	code, err := prompt("Enter code from Telegram (or 'resend' to try SMS): ")
	if err != nil {
		return "", err
	}
	fmt.Printf("[DEBUG] You entered: '%s' (len=%d)\n", code, len(code))
	return code, nil
}

func (terminalAuth) SignUp(_ context.Context) (auth.UserInfo, error) {
	return auth.UserInfo{}, errors.New("sign up not supported")
}

func (terminalAuth) AcceptTermsOfService(_ context.Context, _ tg.HelpTermsOfService) error {
	return nil
}

func prompt(msg string) (string, error) {
	fmt.Print(msg)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

func printConfig(config *tg.Config) {
	fmt.Printf("Telegram DC Configuration\n")
	fmt.Printf("=========================\n")
	fmt.Printf("Date: %s\n", time.Unix(int64(config.Date), 0).Format(time.RFC3339))
	fmt.Printf("Expires: %s\n", time.Unix(int64(config.Expires), 0).Format(time.RFC3339))
	fmt.Printf("This DC: %d\n", config.ThisDC)
	fmt.Printf("Test Mode: %v\n\n", config.TestMode)

	// Group by DC ID
	type dcGroup struct {
		id      int
		options []tg.DCOption
	}

	groups := make(map[int]*dcGroup)
	for _, opt := range config.DCOptions {
		id := opt.ID
		if groups[id] == nil {
			groups[id] = &dcGroup{id: id}
		}
		groups[id].options = append(groups[id].options, opt)
	}

	// Sort DC IDs
	var ids []int
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	// Print each DC
	for _, id := range ids {
		g := groups[id]
		fmt.Printf("DC %d (%d servers)\n", id, len(g.options))
		fmt.Printf("----------------------------------------\n")

		for _, opt := range g.options {
			flags := formatFlags(opt)
			fmt.Printf("  %-45s :%d %s\n", opt.IPAddress, opt.Port, flags)
		}
		fmt.Println()
	}

	// Print Go code for standard DCs
	fmt.Println("\n// Go code for pkg/dc/addrs.go:")
	fmt.Println("var DefaultDCs = map[int][]Addr{")
	for _, id := range ids {
		if id < 1 || id > 5 {
			continue // Skip special DCs for main list
		}
		g := groups[id]
		fmt.Printf("\t%d: {\n", id)
		for _, opt := range g.options {
			if opt.CDN || opt.MediaOnly || opt.Static {
				continue
			}
			network := "tcp4"
			addr := opt.IPAddress
			if opt.Ipv6 {
				network = "tcp6"
				addr = "[" + addr + "]"
			}
			fmt.Printf("\t\t{Network: %q, Address: %q},\n", network, fmt.Sprintf("%s:%d", addr, opt.Port))
		}
		fmt.Printf("\t},\n")
	}
	fmt.Println("}")

	// Print special/CDN DCs
	var specialIDs []int
	for _, id := range ids {
		if id < 1 || id > 5 {
			specialIDs = append(specialIDs, id)
		}
	}
	if len(specialIDs) > 0 {
		fmt.Println("\n// CDN/Special DCs:")
		fmt.Println("var CDNDCs = map[int][]Addr{")
		for _, id := range specialIDs {
			g := groups[id]
			fmt.Printf("\t%d: { // %s\n", id, describeDC(id))
			for _, opt := range g.options {
				if opt.Static {
					continue // Skip static variants
				}
				network := "tcp4"
				addr := opt.IPAddress
				if opt.Ipv6 {
					network = "tcp6"
					addr = "[" + addr + "]"
				}
				fmt.Printf("\t\t{Network: %q, Address: %q},\n", network, fmt.Sprintf("%s:%d", addr, opt.Port))
			}
			fmt.Printf("\t},\n")
		}
		fmt.Println("}")
	}

	// Summary
	fmt.Printf("\nTotal: %d DC options\n", len(config.DCOptions))
}

func formatFlags(opt tg.DCOption) string {
	var flags []string
	if opt.Ipv6 {
		flags = append(flags, "IPv6")
	}
	if opt.MediaOnly {
		flags = append(flags, "MEDIA")
	}
	if opt.CDN {
		flags = append(flags, "CDN")
	}
	if opt.TCPObfuscatedOnly {
		flags = append(flags, "TCPO")
	}
	if opt.Static {
		flags = append(flags, "STATIC")
	}
	if len(flags) == 0 {
		return "[STANDARD]"
	}
	return "[" + strings.Join(flags, ", ") + "]"
}

func describeDC(id int) string {
	switch {
	case id < 0:
		return fmt.Sprintf("media-only for DC %d", -id)
	case id >= 10000:
		return "test server"
	case id >= 200:
		return "CDN"
	default:
		return "unknown"
	}
}
