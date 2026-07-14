
### 4. Cryptography/crypto.py

 
#!/usr/bin/env python3
"""
Advanced cryptographic operations for penetration testing.
Supports AES, RSA, and various hashing algorithms.
"""

import base64
import hashlib
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import bcrypt
import json

class CryptoManager:
    """Advanced cryptographic operations class"""
    
    def __init__(self):
        self.available_hashes = ['md5', 'sha1', 'sha256', 'sha512', 'blake2b']
    
    def generate_hash(self, data, algorithm='sha256'):
        """Generate hash of data using specified algorithm"""
        if algorithm not in self.available_hashes:
            raise ValueError(f"Algorithm must be one of: {self.available_hashes}")
        
        hash_func = getattr(hashlib, algorithm)
        return hash_func(data.encode()).hexdigest()
    
    def aes_encrypt(self, data, key=None):
        """AES-256 encryption in CBC mode"""
        if key is None:
            key = get_random_bytes(32)
        elif len(key) < 32:
            key = key.ljust(32, b'\0')
        elif len(key) > 32:
            key = key[:32]
        
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        if isinstance(data, str):
            data = data.encode()
        
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return {
            'encrypted': base64.b64encode(encrypted).decode(),
            'iv': base64.b64encode(iv).decode(),
            'key': base64.b64encode(key).decode()
        }
    
    def aes_decrypt(self, encrypted_data, key, iv):
        """AES-256 decryption in CBC mode"""
        encrypted = base64.b64decode(encrypted_data)
        iv = base64.b64decode(iv)
        key = base64.b64decode(key)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode()
    
    def generate_rsa_keypair(self, key_size=2048):
        """Generate RSA key pair"""
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        return {
            'private': private_key.decode(),
            'public': public_key.decode()
        }
    
    def rsa_encrypt(self, data, public_key_str):
        """Encrypt data with RSA public key"""
        public_key = RSA.import_key(public_key_str)
        cipher = PKCS1_OAEP.new(public_key)
        
        if isinstance(data, str):
            data = data.encode()
        
        encrypted = cipher.encrypt(data)
        return base64.b64encode(encrypted).decode()
    
    def rsa_decrypt(self, encrypted_data, private_key_str):
        """Decrypt data with RSA private key"""
        private_key = RSA.import_key(private_key_str)
        cipher = PKCS1_OAEP.new(private_key)
        
        encrypted = base64.b64decode(encrypted_data)
        decrypted = cipher.decrypt(encrypted)
        return decrypted.decode()
    
    def bcrypt_hash(self, password, rounds=12):
        """Generate bcrypt hash of password"""
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password.encode(), salt).decode()
    
    def bcrypt_verify(self, password, hash_str):
        """Verify password against bcrypt hash"""
        return bcrypt.checkpw(password.encode(), hash_str.encode())

# Example usage
if __name__ == "__main__":
    crypto = CryptoManager()
    
    # Hash example
    print(f"Hash: {crypto.generate_hash('password123')}")
    
    # AES example
    data = "Secret message for penetration testing"
    encrypted = crypto.aes_encrypt(data)
    print(f"AES Encrypted: {encrypted['encrypted']}")
    
    decrypted = crypto.aes_decrypt(
        encrypted['encrypted'],
        encrypted['key'],
        encrypted['iv']
    )
    print(f"AES Decrypted: {decrypted}")
    
    # RSA example
    keys = crypto.generate_rsa_keypair()
    rsa_encrypted = crypto.rsa_encrypt("Secure data", keys['public'])
    print(f"RSA Encrypted: {rsa_encrypted}")
    
    rsa_decrypted = crypto.rsa_decrypt(rsa_encrypted, keys['private'])
    print(f"RSA Decrypted: {rsa_decrypted}")