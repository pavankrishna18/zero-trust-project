"""
Encryption Service for Zero Trust
Data encryption at rest using Fernet (symmetric encryption)
FIXED VERSION - November 8, 2025
"""

import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # ✅ FIXED: Changed from PBKDF2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

logger = logging.getLogger(__name__)

class EncryptionService:
    """Encryption service for sensitive data"""
    
    def __init__(self, encryption_key=None):
        """Initialize encryption service with key"""
        if encryption_key:
            self.fernet = Fernet(encryption_key.encode() if isinstance(encryption_key, str) else encryption_key)
        else:
            # Generate a key if none provided
            self.fernet = Fernet(Fernet.generate_key())
    
    @staticmethod
    def generate_key():
        """Generate a new encryption key"""
        return Fernet.generate_key().decode()
    
    @staticmethod
    def derive_key_from_password(password, salt=None):
        """
        Derive an encryption key from a password
        Returns: (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(  # ✅ FIXED: Using PBKDF2HMAC instead of PBKDF2
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode(), base64.urlsafe_b64encode(salt).decode()
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext string
        Returns: encrypted string (base64)
        """
        try:
            if not plaintext:
                return None
            
            encrypted = self.fernet.encrypt(plaintext.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error('Encryption error: %s', str(e))
            return None
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext
        Returns: decrypted string
        """
        try:
            if not ciphertext:
                return None
            
            decrypted = self.fernet.decrypt(ciphertext.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error('Decryption error: %s', str(e))
            return None
    
    def encrypt_dict(self, data):
        """
        Encrypt dictionary values
        Returns: dict with encrypted values
        """
        encrypted_data = {}
        for key, value in data.items():
            if value is not None:
                encrypted_data[key] = self.encrypt(str(value))
            else:
                encrypted_data[key] = None
        return encrypted_data
    
    def decrypt_dict(self, encrypted_data):
        """
        Decrypt dictionary values
        Returns: dict with decrypted values
        """
        decrypted_data = {}
        for key, value in encrypted_data.items():
            if value is not None:
                decrypted_data[key] = self.decrypt(value)
            else:
                decrypted_data[key] = None
        return decrypted_data


# ==================== USAGE EXAMPLE ====================

def example_usage():
    """Example of how to use the encryption service"""
    
    # Method 1: Generate a random key
    key = EncryptionService.generate_key()
    print(f"Generated Key: {key}")
    
    encryptor = EncryptionService(key)
    
    # Encrypt some data
    plaintext = "sensitive_data_12345"
    encrypted = encryptor.encrypt(plaintext)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt
    decrypted = encryptor.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Method 2: Derive key from password
    password = "MySecurePassword123!"
    key, salt = EncryptionService.derive_key_from_password(password)
    print(f"Derived Key: {key}")
    print(f"Salt: {salt}")
    
    # Use the derived key
    encryptor2 = EncryptionService(key)
    encrypted2 = encryptor2.encrypt("secret_otp_data")
    print(f"Encrypted with derived key: {encrypted2}")


# ==================== HELPER FUNCTIONS ====================

def encrypt_otp_secret(otp_secret, encryption_key):
    """Encrypt OTP secret for database storage"""
    try:
        encryptor = EncryptionService(encryption_key)
        return encryptor.encrypt(otp_secret)
    except Exception as e:
        logger.error('OTP encryption error: %s', str(e))
        return otp_secret  # Return plaintext if encryption fails

def decrypt_otp_secret(encrypted_otp, encryption_key):
    """Decrypt OTP secret from database"""
    try:
        encryptor = EncryptionService(encryption_key)
        return encryptor.decrypt(encrypted_otp)
    except Exception as e:
        logger.error('OTP decryption error: %s', str(e))
        return encrypted_otp  # Return as-is if decryption fails


if __name__ == '__main__':
    example_usage()
