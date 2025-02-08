# Passlock - A Terminal-Based Password Manager

Passlock is a secure and lightweight password manager for the terminal. It allows users to store, encrypt, and manage their credentials safely using a master password.

## Features
- 🔐 **AES Encryption** for passwords and sensitive fields
- 🔍 **Fuzzy Search (fzf)** for quick retrieval
- 📥 **Import from CSV** with flexible formatting
- 💻 **Cross-platform Support** (Linux, macOS, Termux on Android)

## Installation
### **Prerequisites**
- Install Go (1.18 or later)
- Install `fzf` for search functionality:
  ```sh
  # macOS (using Homebrew)
  brew install fzf
  
  # Linux (Debian-based)
  sudo apt install fzf
  
  # Termux (Android)
  pkg install fzf
  ```

### **Build and Install Passlock**
```sh
# Clone the repository
git clone https://github.com/Arshjeet2003/passlock.git
cd passlock

# Build the binary
go build -o passlock

# Move binary to a directory in PATH for macOS, Linux
sudo mv passlock /usr/local/bin/

# Move binary to Termux bin folder for Termux
mv passlock $PREFIX/bin/

# Set executable permissions
chmod +x $PREFIX/bin/passlock
```

## Usage
### **Start Passlock**
```sh
passlock
```
### **Initialize Passlock**
Set the encryption key (master password):
```sh
start [masterpassword]
```

### **Saving a Login**
```sh
save service_name username user@example.com password password123 -e password
```
Any fields after -e will be encrypted.

### **Search for Logins**
```sh
passlock search
```
This will open `fzf` for interactive searching.

### **Updating a Login**
```sh
passlock update service_name username new_username
```

### **Importing from CSV**
```sh
passlock import /path/to/file.csv
```

**CSV Format:**
```
Category;Title;Username;Password;ExtraField1-Key1;ExtraField1-Value1;ExtraField2-Key2;ExtraField2-Value2
```
Anyfields with name Password, PIN, mPIN, pin will be encrypted automatically.

## Security Considerations
- **Master password is not stored** (used to generate the encryption key)
- **Sensitive fields are encrypted** before saving
- **Passwords are masked** by default and revealed only upon request

## License
This project is open-source under the MIT License.
