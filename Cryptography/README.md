================================================================================
CRYPTOGRAPHY TOOLS
================================================================================

FILES:
-------
crypto.py         - AES/RSA encryption/decryption
text_to_hash.py   - Hash text using various algorithms
xorCrypt.py       - XOR encryption/decryption

INSTALL:
--------
pip install pycryptodome bcrypt

USAGE:
------
# Run crypto.py example
python3 Cryptography/crypto.py

# Hash text
python3 Cryptography/text_to_hash.py -t "Hello World"
python3 Cryptography/text_to_hash.py -t "Hello World" -a sha512
python3 Cryptography/text_to_hash.py -t "Hello World" --all

# XOR encrypt/decrypt
python3 Cryptography/xorCrypt.py -k "mykey" -e "Hello World"
python3 Cryptography/xorCrypt.py -k "mykey" -d "JSUqJQkmJFE="

# Interactive mode
python3 Cryptography/text_to_hash.py
python3 Cryptography/xorCrypt.py

TROUBLESHOOT:
------------
If import errors: pip install pycryptodome bcrypt
If permission denied: chmod +x Cryptography/*.py

================================================================================