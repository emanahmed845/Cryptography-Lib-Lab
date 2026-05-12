# Video Demo: https://drive.google.com/file/d/1LHB0DGcdtHb_5Sh75i9DddFnD7caDMAz/view?usp=sharing

# Cryptography Lib Lab — Hybrid AES + RSA

## Requirements
```bash
pip install pycryptodome
```

## Project Structure
crypto_project/
├── main.py          # Main Application (GUI + Logic)
├── crypto_utils.py  # Core encryption/decryption functions
├── data/            # Sample input files
└── output/          # Encrypted & decrypted output files

## How to Run

### Main Application (runs all scenarios + AES vs DES comparison):
```bash
python main.py
```

## Algorithms Used
| Algorithm | Role          | Key Size | Mode |
|-----------|---------------|----------|------|
| AES-256   | Encrypt data  | 256 bits | CBC  |
| RSA-2048  | Encrypt AES key | 2048 bits | OAEP |
| DES       | Comparison only | 56 bits | CBC  |
| SHA-256   | Verification  | —        | —    |

## Note
DES is included for educational comparison only.
AES-256 is the recommended algorithm for secure applications.
