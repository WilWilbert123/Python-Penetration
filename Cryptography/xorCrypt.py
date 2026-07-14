#!/usr/bin/env python3
"""
XOR cipher implementation for simple encryption/decryption.
Useful for understanding basic cryptography and obfuscation.
"""

import base64
import argparse
import sys

class XORCipher:
    """XOR cipher implementation with various modes"""
    
    def __init__(self, key):
        self.key = key
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using XOR cipher"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        encrypted = bytearray()
        for i, byte in enumerate(plaintext):
            key_byte = ord(self.key[i % len(self.key)])
            encrypted.append(byte ^ key_byte)
        
        return base64.b64encode(bytes(encrypted)).decode()
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext using XOR cipher"""
        encrypted = base64.b64decode(ciphertext)
        
        decrypted = bytearray()
        for i, byte in enumerate(encrypted):
            key_byte = ord(self.key[i % len(self.key)])
            decrypted.append(byte ^ key_byte)
        
        return bytes(decrypted).decode()
    
    def encrypt_file(self, input_file, output_file):
        """Encrypt a file using XOR cipher"""
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
            
            encrypted = bytearray()
            for i, byte in enumerate(data):
                key_byte = ord(self.key[i % len(self.key)])
                encrypted.append(byte ^ key_byte)
            
            with open(output_file, 'wb') as f:
                f.write(bytes(encrypted))
            
            print(f"File encrypted: {output_file}")
        except Exception as e:
            print(f"Error: {e}")
    
    def decrypt_file(self, input_file, output_file):
        """Decrypt a file using XOR cipher"""
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
            
            decrypted = bytearray()
            for i, byte in enumerate(data):
                key_byte = ord(self.key[i % len(self.key)])
                decrypted.append(byte ^ key_byte)
            
            with open(output_file, 'wb') as f:
                f.write(bytes(decrypted))
            
            print(f"File decrypted: {output_file}")
        except Exception as e:
            print(f"Error: {e}")
    
    def bruteforce_key(self, ciphertext, min_key_len=1, max_key_len=5):
        """Bruteforce XOR key (for educational purposes)"""
        encrypted = base64.b64decode(ciphertext)
        
        for key_len in range(min_key_len, max_key_len + 1):
            for key in range(256 ** key_len):
                key_bytes = key.to_bytes(key_len, 'big')
                key_str = key_bytes.decode('latin-1')
                
                decrypted = bytearray()
                for i, byte in enumerate(encrypted):
                    key_byte = key_bytes[i % key_len]
                    decrypted.append(byte ^ key_byte)
                
                try:
                    decoded = bytes(decrypted).decode('utf-8')
                    if all(32 <= ord(c) < 127 for c in decoded):
                        print(f"Potential key: {key_str}")
                        print(f"Decrypted: {decoded}")
                        return key_str
                except:
                    continue
        
        return None

def main():
    parser = argparse.ArgumentParser(description='XOR cipher tool')
    parser.add_argument('-k', '--key', required=True, help='Encryption key')
    parser.add_argument('-e', '--encrypt', help='Text to encrypt')
    parser.add_argument('-d', '--decrypt', help='Ciphertext to decrypt')
    parser.add_argument('-f', '--file', help='File to encrypt/decrypt')
    parser.add_argument('-o', '--output', help='Output file for file operations')
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], 
                       help='Mode for file operations')
    
    args = parser.parse_args()
    
    cipher = XORCipher(args.key)
    
    if args.encrypt:
        result = cipher.encrypt(args.encrypt)
        print(f"Encrypted: {result}")
    
    elif args.decrypt:
        result = cipher.decrypt(args.decrypt)
        print(f"Decrypted: {result}")
    
    elif args.file and args.output and args.mode:
        if args.mode == 'encrypt':
            cipher.encrypt_file(args.file, args.output)
        else:
            cipher.decrypt_file(args.file, args.output)
    
    else:
        # Interactive mode
        print("XOR Cipher - Interactive Mode")
        print("Enter text to encrypt/decrypt (or 'quit' to exit)")
        while True:
            text = input("\nText: ")
            if text.lower() == 'quit':
                break
            
            option = input("Encrypt or Decrypt? (e/d): ").lower()
            
            if option == 'e':
                result = cipher.encrypt(text)
                print(f"Encrypted: {result}")
            elif option == 'd':
                try:
                    result = cipher.decrypt(text)
                    print(f"Decrypted: {result}")
                except:
                    print("Invalid ciphertext")
            else:
                print("Invalid option")

if __name__ == "__main__":
    main()