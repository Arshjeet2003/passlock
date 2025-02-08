package main

import (
	"bufio"
	"fmt"
	"golang.org/x/term"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"passlock/passlock"
)

var pm passlock.PasswordManager
var encryptedFields []string // Stores fields that need encryption

func clearConsole() {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default: // macOS & Linux
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func waitForEnterWithTimeout(timeout time.Duration) bool {
	input := make(chan string, 1)

	// Start a goroutine to read input
	go func() {
		reader := bufio.NewReader(os.Stdin)
		reader.ReadString('\n')
		input <- "entered"
	}()

	select {
	case <-input:
		return true // User pressed Enter
	case <-time.After(timeout):
		return false // Timeout reached
	}
}

func main() {
	// Load saved logins
	pm.Load()

	// Root command
	var rootCmd = &cobra.Command{
		Use:   "passlock",
		Short: "A simple password manager",
	}

	// Start command (Sets master password and generates key)
	var startCmd = &cobra.Command{
		Use:   "start",
		Short: "Initialize with a master password to generate a 32-byte encryption key",
		Run: func(cmd *cobra.Command, args []string) {
			// Ask for master password securely
			fmt.Print("Enter master password: ")
			masterPassword, err := readPassword()
			if err != nil {
				fmt.Println("\nError reading password:", err)
				return
			}

			// Set the encryption key
			passlock.SetEncryptionKey(masterPassword)
			fmt.Println("\n✅ Encryption key set successfully!")
		},
	}

	// Save command

	var saveCmd = &cobra.Command{
		Use:   "save [service] [key1] [value1] [key2] [value2]...",
		Short: "Save a login with optional encrypted fields using -e flag",
		Args:  cobra.MinimumNArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args)%2 == 0 {
				fmt.Println("Error: Keys and values must be in pairs")
				return
			}

			service := args[0]
			fields := make(map[string]string)
			encrypted := make(map[string]string)

			// Parse key-value pairs
			for i := 1; i < len(args); i += 2 {
				key := args[i]
				value := args[i+1]

				if contains(encryptedFields, key) {
					encrypted[key] = value // 🔹 Store raw value, let AddLogin handle encryption
				} else {
					fields[key] = value
				}
			}

			// Save login
			err := pm.AddLogin(service, fields, encrypted)
			if err != nil {
				fmt.Println("Error saving login:", err)
			} else {
				fmt.Println("Login saved successfully!")
			}
		},
	}

	saveCmd.Flags().StringSliceVarP(&encryptedFields, "encrypt", "e", nil, "Specify keys to encrypt (multiple -e allowed)")

	// Delete command
	var deleteCmd = &cobra.Command{
		Use:   "delete [service]",
		Short: "Delete a login",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			err := pm.DeleteLogin(args[0])
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("Login deleted successfully!")
			}
		},
	}

	// Update field command
	var updateCmd = &cobra.Command{
		Use:   "update [service] [field] [new value]",
		Short: "Update a specific field",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			err := pm.UpdateField(args[0], args[1], args[2])
			if err != nil {
				fmt.Println("Error:", err)
			} else {
				fmt.Println("Field updated successfully!")
			}
		},
	}

	var importCmd = &cobra.Command{
		Use:   "import [filePath] -a [oneKeyField]",
		Short: "Import logins from a CSV file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filePath := args[0]
			oneKeyField, _ := cmd.Flags().GetString("a")

			err := pm.ImportLogins(filePath, oneKeyField)
			if err != nil {
				fmt.Println("Error importing logins:", err)
			}
		},
	}

	importCmd.Flags().StringP("a", "a", "", "Specify a one-key field")

	// Interactive search command
	var searchCmd = &cobra.Command{
		Use:   "search",
		Short: "Search for a login using an interactive fuzzy finder",
		Run: func(cmd *cobra.Command, args []string) {
			// Fetch all login services
			services := pm.GetAllServices()
			if len(services) == 0 {
				fmt.Println("No logins found.")
				return
			}

			// Call fzf to let the user select a service
			selectedService, err := fuzzySelect(services)
			if err != nil {
				fmt.Println("No selection made.")
				return
			}

			// Fetch and display login details
			login, err := pm.GetLogin(selectedService)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			// Decrypt passwords without modifying the stored login
			fmt.Println("\n🔐 Login Details:")

			// Show non-encrypted fields
			for key, value := range login.Fields {
				fmt.Println(key+":", value)
			}

			// Mask encrypted fields
			for key := range login.Encrypted {
				fmt.Println(key+":", "******") // Masked password
			}

			// Ask user to reveal passwords
			fmt.Print("\nPress Enter to reveal passwords...")
			fmt.Scanln()

			// Show decrypted passwords without modifying `login`
			fmt.Println("\n🔓 Decrypted Passwords:")
			for key, encValue := range login.Encrypted {
				decryptedValue, err := pm.DecryptPassword(encValue)
				if err == nil {
					fmt.Println(key+":", decryptedValue)
				} else {
					fmt.Println(key+":", "(decryption failed)")
				}
			}
			// Ask user to press Enter to hide passwords or hide automatically after 20 sec
			fmt.Print("\nPress Enter to hide passwords (auto-hides in 20 seconds)...")

			if waitForEnterWithTimeout(20 * time.Second) {
				clearConsole()
				fmt.Println("\n⏳ Passwords hidden again for security.")
			} else {
				clearConsole()
				fmt.Println("\n⏳ Passwords auto-hidden after 20 seconds.")
			}
		},
	}

	// Add commands to root
	rootCmd.AddCommand(startCmd, saveCmd, deleteCmd, updateCmd, searchCmd, importCmd)

	// Show help message when starting
	rootCmd.Help()

	// Interactive shell
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("\n🔐 Passlock Interactive Mode (type 'exit' to quit)")
	for {
		fmt.Print("> ") // Command prompt
		scanner.Scan()
		input := scanner.Text()

		// Exit condition
		if input == "exit" || input == "quit" {
			fmt.Println("Exiting Passlock.")
			break
		}

		// Execute user command
		args := strings.Fields(input)
		if len(args) > 0 {
			rootCmd.SetArgs(args)
			rootCmd.Execute()
		}
	}
}

// Helper function to check if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) { // Case-insensitive comparison
			return true
		}
	}
	return false
}

// Uses `fzf` to create an interactive fuzzy finder for selecting a service
func fuzzySelect(options []string) (string, error) {
	cmd := exec.Command("fzf")
	cmd.Stdin = strings.NewReader(strings.Join(options, "\n"))
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// Read password securely (hides input)
func readPassword() (string, error) {
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Newline after password input
	if err != nil {
		return "", err
	}
	return string(bytePassword), nil
}
