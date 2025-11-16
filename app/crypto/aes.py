"""AES-128(ECB)+PKCS#7 helpers (use library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# AES-128 uses 16-byte keys
AES_KEY_SIZE = 16
# AES block size is 128 bits (16 bytes)
AES_BLOCK_SIZE_BITS = 128

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AES-128 in ECB mode with PKCS#7 padding.
    
    key: 16-byte AES key
    plaintext: The data to encrypt
    Returns: The encrypted ciphertext
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 16 bytes (AES-128)")

    # 1. Create a PKCS#7 padder
    padder = padding.PKCS7(AES_BLOCK_SIZE_BITS).padder()
    
    # 2. Apply padding to the plaintext
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # 3. Create the AES-ECB cipher object
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    
    # 4. Encrypt the padded data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext

def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts ciphertext using AES-128 in ECB mode with PKCS#7 padding.
    
    key: 16-byte AES key
    ciphertext: The data to decrypt
    Returns: The original plaintext
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 16 bytes (AES-128)")

    # 1. Create the AES-ECB cipher object
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    
    # 2. Decrypt the ciphertext
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 3. Create a PKCS#7 unpadder
    unpadder = padding.PKCS7(AES_BLOCK_SIZE_BITS).unpadder()
    
    # 4. Remove the padding
    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
    except ValueError:
        # This will fail if the padding is incorrect (e.g., bad key, corrupt data)
        print("Error: Failed to unpad data. Key may be incorrect or data corrupted.")
        raise