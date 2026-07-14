#!/usr/bin/env python3
"""
Convert text to various hash formats for password cracking and analysis.
"""

import hashlib
import argparse
import sys

class HashGenerator:
    """Generate various hashes from text input"""
    
    def __init__(self):
        self.algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
            'sha3_224': hashlib.sha3_224,
            'sha3_256': hashlib.sha3_256,
            'sha3_384': hashlib.sha3_384,
            'sha3_512': hashlib.sha3_512,
        }
    
    def generate_hash(self, text, algorithm='sha256'):
        """Generate hash of text using specified algorithm"""
        if algorithm not in self.algorithms:
            raise ValueError(f"Algorithm must be one of: {', '.join(self.algorithms.keys())}")
        
        hash_func = self.algorithms[algorithm]()
        hash_func.update(text.encode('utf-8'))
        return hash_func.hexdigest()
    
    def generate_all_hashes(self, text):
        """Generate all hash types for given text"""
        hashes = {}
        for name in self.algorithms:
            hashes[name] = self.generate_hash(text, name)
        return hashes
    
    def generate_hash_with_salt(self, text, salt, algorithm='sha256'):
        """Generate salted hash"""
        salted = text + salt
        return self.generate_hash(salted, algorithm)
    
    def generate_multiple_hashes(self, texts, algorithm='sha256'):
        """Generate hashes for multiple texts"""
        results = []
        for text in texts:
            results.append({
                'text': text,
                'hash': self.generate_hash(text, algorithm)
            })
        return results

def main():
    parser = argparse.ArgumentParser(description='Generate hashes from text')
    parser.add_argument('-t', '--text', help='Text to hash')
    parser.add_argument('-a', '--algorithm', default='sha256', 
                       help='Hash algorithm (default: sha256)')
    parser.add_argument('-s', '--salt', help='Salt for hash')
    parser.add_argument('--all', action='store_true', 
                       help='Generate all hash types')
    parser.add_argument('-f', '--file', help='File containing texts to hash')
    
    args = parser.parse_args()
    
    generator = HashGenerator()
    
    if args.text:
        if args.salt:
            hash_result = generator.generate_hash_with_salt(
                args.text, args.salt, args.algorithm
            )
            print(f"Salted {args.algorithm} hash: {hash_result}")
        elif args.all:
            hashes = generator.generate_all_hashes(args.text)
            for name, h in hashes.items():
                print(f"{name}: {h}")
        else:
            hash_result = generator.generate_hash(args.text, args.algorithm)
            print(f"{args.algorithm} hash: {hash_result}")
    
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                texts = [line.strip() for line in f if line.strip()]
            
            results = generator.generate_multiple_hashes(texts, args.algorithm)
            for result in results:
                print(f"{result['text']}: {result['hash']}")
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found")
            sys.exit(1)
    
    else:
        # Interactive mode
        print("Hash Generator - Interactive Mode")
        print("Enter text to hash (or 'quit' to exit)")
        while True:
            text = input("\nText: ")
            if text.lower() == 'quit':
                break
            
            print("\nAvailable algorithms:")
            print(", ".join(generator.algorithms.keys()))
            
            algo = input("Algorithm (default: sha256): ") or 'sha256'
            
            salt = input("Salt (optional): ") or None
            
            if salt:
                result = generator.generate_hash_with_salt(text, salt, algo)
                print(f"Salted {algo} hash: {result}")
            else:
                result = generator.generate_hash(text, algo)
                print(f"{algo} hash: {result}")

if __name__ == "__main__":
    main()