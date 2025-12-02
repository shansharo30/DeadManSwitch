"""
AES encryption for sensitive database values.
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logger = logging.getLogger(__name__)

# Encryption key derivation salt (stored in database config on first run)
_encryption_key = None


def _derive_key(master_secret: str, salt: bytes) -> bytes:
    """Derive encryption key from master secret using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_secret.encode())


def initialize_encryption(master_secret: str, salt: bytes | None = None) -> bytes:
    """
    Initialize encryption system with master secret.
    
    Args:
        master_secret: Master password/secret for key derivation
        salt: Optional salt (will be generated if not provided)
    
    Returns:
        Salt used for key derivation (must be stored)
    """
    global _encryption_key
    
    if salt is None:
        salt = os.urandom(16)
    
    _encryption_key = _derive_key(master_secret, salt)
    logger.info("Encryption system initialized")
    
    return salt


def encrypt(plaintext: str) -> str:
    """
    Encrypt plaintext string using AES-256-GCM.
    
    Returns base64-encoded: nonce(12) + ciphertext + tag(16)
    """
    if _encryption_key is None:
        raise RuntimeError("Encryption not initialized. Call initialize_encryption() first.")
    
    if not plaintext:
        return ""
    
    # Generate random nonce (12 bytes for GCM)
    nonce = os.urandom(12)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(_encryption_key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    # Combine nonce + ciphertext + tag
    encrypted_data = nonce + ciphertext + encryptor.tag
    
    # Base64 encode for storage
    return base64.b64encode(encrypted_data).decode('utf-8')


def decrypt(encrypted: str) -> str:
    """
    Decrypt base64-encoded encrypted string.
    
    Args:
        encrypted: Base64-encoded nonce + ciphertext + tag
    
    Returns:
        Decrypted plaintext
    """
    if _encryption_key is None:
        raise RuntimeError("Encryption not initialized. Call initialize_encryption() first.")
    
    if not encrypted:
        return ""
    
    try:
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted)
        
        # Extract components
        nonce = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(_encryption_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')
        
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise ValueError("Failed to decrypt data. Key may be incorrect.")


def is_initialized() -> bool:
    """Check if encryption system is initialized."""
    return _encryption_key is not None
