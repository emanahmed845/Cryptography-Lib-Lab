# crypto_utils.py
# Core cryptography utility functions
# Algorithms: AES (CBC mode) + RSA (OAEP)
# Library: PyCryptodome

import os
import time
import hashlib
import base64
import json

from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ──────────────────────────────────────────────
# KEY GENERATION
# ──────────────────────────────────────────────

def generate_aes_key(key_size=32):
    """Generate a random AES key. key_size: 16=AES-128, 24=AES-192, 32=AES-256"""
    return get_random_bytes(key_size)


def generate_des_key():
    """Generate a random DES key (8 bytes)."""
    return get_random_bytes(8)


def generate_rsa_keypair(bits=2048):
    """Generate RSA public/private key pair."""
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def save_rsa_keys(private_key, public_key, keys_dir="keys"):
    """Save RSA keys to files."""
    os.makedirs(keys_dir, exist_ok=True)
    with open(os.path.join(keys_dir, "private.pem"), "wb") as f:
        f.write(private_key)
    with open(os.path.join(keys_dir, "public.pem"), "wb") as f:
        f.write(public_key)
    print(f"[OK] RSA keys saved in '{keys_dir}/' folder.")


def load_rsa_keys(keys_dir="keys"):
    """Load RSA keys from files."""
    with open(os.path.join(keys_dir, "private.pem"), "rb") as f:
        private_key = RSA.import_key(f.read())
    with open(os.path.join(keys_dir, "public.pem"), "rb") as f:
        public_key = RSA.import_key(f.read())
    return private_key, public_key


# ──────────────────────────────────────────────
# AES ENCRYPTION / DECRYPTION
# ──────────────────────────────────────────────

def aes_encrypt(data: bytes, aes_key: bytes):
    """
    Encrypt data using AES-CBC.
    Returns: (ciphertext, iv)
    """
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext, iv


def aes_decrypt(ciphertext: bytes, aes_key: bytes, iv: bytes):
    """
    Decrypt AES-CBC ciphertext.
    Returns: original plaintext bytes
    """
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


# ──────────────────────────────────────────────
# RSA ENCRYPTION / DECRYPTION (for AES key only)
# ──────────────────────────────────────────────

def rsa_encrypt_key(aes_key: bytes, public_key):
    """Encrypt the AES key using RSA public key (OAEP padding)."""
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key


def rsa_decrypt_key(encrypted_aes_key: bytes, private_key):
    """Decrypt the AES key using RSA private key."""
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key


# ──────────────────────────────────────────────
# HYBRID ENCRYPT / DECRYPT  (main functions)
# ──────────────────────────────────────────────

def hybrid_encrypt_file(input_path: str, output_path: str, public_key):
    """
    Full hybrid encryption:
    1. Generate AES key
    2. Encrypt file data with AES
    3. Encrypt AES key with RSA
    4. Save everything to output file
    Returns: elapsed_time (seconds)
    """
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)

    with open(input_path, "rb") as f:
        data = f.read()

    start = time.time()

    aes_key = generate_aes_key(32)          # AES-256
    ciphertext, iv = aes_encrypt(data, aes_key)
    encrypted_aes_key = rsa_encrypt_key(aes_key, public_key)

    elapsed = time.time() - start

    # Build metadata bundle (JSON header + binary data)
    metadata = {
        "iv": base64.b64encode(iv).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "original_filename": os.path.basename(input_path),
        "ciphertext_b64": base64.b64encode(ciphertext).decode()
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[OK] Encrypted → {output_path}  ({elapsed:.4f}s)")
    return elapsed


def hybrid_decrypt_file(input_path: str, output_path: str, private_key):
    """
    Full hybrid decryption:
    1. Load encrypted bundle
    2. Decrypt AES key with RSA
    3. Decrypt data with AES
    4. Save recovered file
    Returns: elapsed_time (seconds)
    """
    with open(input_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    iv = base64.b64decode(metadata["iv"])
    encrypted_aes_key = base64.b64decode(metadata["encrypted_aes_key"])
    ciphertext = base64.b64decode(metadata["ciphertext_b64"])

    start = time.time()

    aes_key = rsa_decrypt_key(encrypted_aes_key, private_key)
    plaintext = aes_decrypt(ciphertext, aes_key, iv)

    elapsed = time.time() - start

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"[OK] Decrypted  → {output_path}  ({elapsed:.4f}s)")
    return elapsed


# ──────────────────────────────────────────────
# SHA-256 VERIFICATION
# ──────────────────────────────────────────────

def sha256_hash(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_files(original_path: str, decrypted_path: str) -> bool:
    """
    Compare SHA-256 hashes of two files.
    Returns True if identical.
    """
    h1 = sha256_hash(original_path)
    h2 = sha256_hash(decrypted_path)
    match = (h1 == h2)
    status = "SUCCESS" if match else "FAILED"
    print(f"\n[Verification] {status}")
    print(f"  Original  SHA-256 : {h1}")
    print(f"  Decrypted SHA-256 : {h2}")
    return match


# ──────────────────────────────────────────────
# DES ENCRYPT / DECRYPT  (for comparison only)
# ──────────────────────────────────────────────

def des_encrypt_file(input_path: str, output_path: str, des_key: bytes):
    """Encrypt file using DES-CBC (for comparison with AES)."""
    with open(input_path, "rb") as f:
        data = f.read()

    iv = get_random_bytes(8)
    cipher = DES.new(des_key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, DES.block_size))

    metadata = {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode()
    }
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)


def des_decrypt_file(input_path: str, output_path: str, des_key: bytes):
    """Decrypt DES-CBC encrypted file."""
    with open(input_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    iv = base64.b64decode(metadata["iv"])
    ciphertext = base64.b64decode(metadata["ciphertext_b64"])

    cipher = DES.new(des_key, DES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(plaintext)