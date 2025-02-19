# CipherNova

CipherNova is an encryption tool that provides a simple yet effective way to secure messages and files using RSA encryption. It features an intuitive **Tkinter-based GUI**, making encryption and decryption accessible to users of all levels.

## Features

- **Message Encryption & Decryption**: Encrypts and decrypts text messages using RSA encryption.
- **File Encryption & Decryption**: Securely encrypts and decrypts files with RSA.
- **Automatic Key Generation**: Generates an RSA key pair (private and public keys) on first run.
- **Clipboard Copy Functionality**: Quickly copy encrypted or decrypted text.
- **User-Friendly GUI**: A visually appealing Tkinter interface.

## Installation

Ensure you have **Python 3.x** installed. Then, install the required dependencies:

```bash
pip install cryptography
```

## How to Run

1. Clone this repository or download the script.
2. Run the script:
   ```bash
   python ciphernova.py
   ```
3. Use the GUI to encrypt and decrypt messages or files.

## Usage

### Encrypt a Message
1. Enter the message in the input field.
2. Click **Encrypt Message**.
3. The encrypted text will appear in the output section.
4. Copy the encrypted text using the **Copy** button.

### Decrypt a Message
1. Enter the encrypted text in the input field.
2. Click **Decrypt Message**.
3. The original message will appear in the output section.

### Encrypt a File
1. Click **Encrypt File** and select a text file.
2. The file content will be encrypted and saved.

### Decrypt a File
1. Click **Decrypt File** and select an encrypted file.
2. The file content will be decrypted and restored.

## Security Considerations

- This implementation uses **RSA with OAEP padding**, a strong encryption standard.
- Ensure that the **private key (private_key.pem)** remains secure and is not shared.
- The encryption is currently suited for small text messages and files due to RSA's limitations. Future versions may integrate hybrid encryption (AES + RSA) for larger files.

## Future Enhancements

- **Hybrid Encryption (AES + RSA)** for improved efficiency.
- **Post-Quantum Cryptography Support**.
- **Steganography Integration** (Hiding encrypted text inside images/audio).
- **Cloud Storage Integration** for encrypted file management.

## Author

Developed with ❤️ by **Pradnya Khore**.

---

Feel free to contribute and enhance the project! 🚀

