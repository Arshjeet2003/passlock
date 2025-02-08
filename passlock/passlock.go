package passlock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lithammer/fuzzysearch/fuzzy"
)

const dbFile = "logins.json"

type Login struct {
	Service   string            `json:"service"`
	Fields    map[string]string `json:"fields"`
	Encrypted map[string]string `json:"encrypted"`
	Timestamp string            `json:"timestamp"`
}

// PasswordManager struct
type PasswordManager struct {
	Logins []Login
}

// Global encryption key (set via "passlock start")
var encryptionKey []byte

// SetEncryptionKey generates a 32-byte key from the master password
func SetEncryptionKey(masterPassword string) {
	hash := sha256.Sum256([]byte(masterPassword))
	encryptionKey = hash[:]
}

// EncryptAES encrypts plaintext using AES-GCM
func (pm *PasswordManager) EncryptAES(plaintext string) (string, error) {
	if encryptionKey == nil {
		return "", errors.New("encryption key not set. Run 'passlock start <masterpassword>' first")
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts an AES-GCM encrypted string
func (pm *PasswordManager) DecryptAES(encryptedText string) (string, error) {
	if encryptionKey == nil {
		return "", errors.New("encryption key not set. Run 'passlock start <masterpassword>' first")
	}

	cipherText, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", errors.New("invalid encrypted text")
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(cipherText) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	return string(plaintext), nil
}

// Load logins from file
func (pm *PasswordManager) Load() error {
	file, err := os.ReadFile(dbFile)
	if err != nil {
		if os.IsNotExist(err) {
			pm.Logins = []Login{}
			return nil
		}
		return err
	}
	return json.Unmarshal(file, &pm.Logins)
}

// Save logins to file
func (pm *PasswordManager) Save() error {

	data, err := json.MarshalIndent(pm.Logins, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dbFile, data, 0600)
}

// EncryptPassword encrypts the password using AES-GCM
func (pm *PasswordManager) EncryptPassword(password string) (string, error) {
	return pm.EncryptAES(password)
}

// DecryptPassword decrypts an encrypted password using AES-GCM
func (pm *PasswordManager) DecryptPassword(encryptedText string) (string, error) {
	return pm.DecryptAES(encryptedText)
}

// Add a new login or update an existing one
func (pm *PasswordManager) AddLogin(service string, fields map[string]string, encryptedFields map[string]string) error {
	for i, login := range pm.Logins {
		if strings.EqualFold(login.Service, service) {
			// Update existing service
			for k, v := range fields {
				pm.Logins[i].Fields[k] = v
			}
			for k, v := range encryptedFields {
				encVal, err := pm.EncryptAES(v)
				if err != nil {
					return err
				}
				pm.Logins[i].Encrypted[k] = encVal
			}

			// Update timestamp only for this login
			pm.Logins[i].Timestamp = time.Now().Format(time.RFC3339)

			return pm.Save()
		}
	}

	// Create new login
	newEncrypted := make(map[string]string)
	for k, v := range encryptedFields {
		encVal, err := pm.EncryptAES(v)
		if err != nil {
			return err
		}
		newEncrypted[k] = encVal
	}

	// Append new login with timestamp
	pm.Logins = append(pm.Logins, Login{
		Service:   service,
		Fields:    fields,
		Encrypted: newEncrypted,
		Timestamp: time.Now().Format(time.RFC3339), // Set timestamp for new login
	})

	return pm.Save()
}

// Delete a login
func (pm *PasswordManager) DeleteLogin(service string) error {
	for i, login := range pm.Logins {
		if strings.EqualFold(login.Service, service) {
			pm.Logins = append(pm.Logins[:i], pm.Logins[i+1:]...)
			return pm.Save()
		}
	}
	return errors.New("service not found")
}

// Update a field in a login
func (pm *PasswordManager) UpdateField(service, field, value string) error {
	for i, login := range pm.Logins {
		if strings.EqualFold(login.Service, service) {
			updated := false

			if _, exists := login.Fields[field]; exists {
				pm.Logins[i].Fields[field] = value
				updated = true
			} else if _, exists := login.Encrypted[field]; exists {
				encVal, err := pm.EncryptAES(value)
				if err != nil {
					return err
				}
				pm.Logins[i].Encrypted[field] = encVal
				updated = true
			} else {
				return errors.New("field not found")
			}

			// Update timestamp only if a field was changed
			if updated {
				pm.Logins[i].Timestamp = time.Now().Format(time.RFC3339)
			}

			// Save after modifying the login
			return pm.Save()
		}
	}
	return errors.New("service not found")
}

// Get all service names
func (pm *PasswordManager) GetAllServices() []string {
	var services []string
	for _, login := range pm.Logins {
		services = append(services, login.Service)
	}
	return services
}

// Get a specific login
func (pm *PasswordManager) GetLogin(service string) (Login, error) {
	for _, login := range pm.Logins {
		if strings.EqualFold(login.Service, service) {
			return login, nil
		}
	}
	return Login{}, errors.New("login not found")
}

// Search for logins using fuzzy search (returns service names)
func (pm *PasswordManager) SearchLogin(query string) []string {
	var results []string
	for _, login := range pm.Logins {
		if fuzzy.Match(query, login.Service) {
			results = append(results, login.Service)
		}
	}
	return results
}

// ImportLogins imports logins from a CSV file
func (pm *PasswordManager) ImportLogins(filePath, oneKeyField string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comma = ';'          // Use semicolon as CSV delimiter
	reader.FieldsPerRecord = -1 // Allow variable-length records

	rows, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read CSV: %w", err)
	}

	// Process each row (skip header)
	for _, row := range rows[1:] {
		if len(row) < 4 {
			fmt.Println("Skipping invalid row:", row)
			continue
		}

		title := row[1]
		username := row[2]
		password := row[3]

		// Extract additional key-value fields
		fields := make(map[string]string)
		encryptedFields := make(map[string]string)

    fields["Username"] = username
		encryptedFields["Password"] = password

		// Process additional fields dynamically
		for i := 4; i < len(row); i++ {
			parts := strings.SplitN(row[i], "-", 2)
			if len(parts) != 2 {
				fmt.Println("Skipping malformed field:", row[i])
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// Encrypt sensitive fields
			if key == "Profile Password" || key == "PIN" || key == "mPIN" || key == "Transaction Password" || key == "Pin" || key == "Encryption key" {
				encryptedFields[key] = value 
			} else {
				fields[key] = value
			}
		}

		// Save to PasswordManager
		err = pm.AddLogin(title, fields, encryptedFields)
		if err != nil {
			fmt.Println("Error saving login for", title, ":", err)
		}
	}

	fmt.Println("✅ Import completed successfully!")
	return nil
}
