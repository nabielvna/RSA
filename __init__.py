"""
RSA (Rivest-Shamir-Adleman) Implementation Package

This package provides RSA encryption, decryption, and digital signature functionality
implemented in pure Python.

Examples:
    Basic usage for encryption/decryption:

    >>> from rsa import generate_keypair, encrypt, decrypt
    >>> from rsa.utils import bytes_to_int, int_to_bytes
    >>> 
    >>> public_key, private_key = generate_keypair(bits=1024)
    >>> message = "Hello, RSA!"
    >>> message_int = bytes_to_int(message.encode())
    >>> encrypted = encrypt(message_int, public_key)
    >>> decrypted = decrypt(encrypted, private_key)
    >>> decrypted_message = int_to_bytes(decrypted).decode()
    >>> assert message == decrypted_message

    Digital signatures:

    >>> from rsa import sign, verify_signature
    >>> signature = sign(message_int, private_key)
    >>> is_valid = verify_signature(message_int, signature, public_key)
    >>> assert is_valid == True
"""

__version__ = "1.0.0"
__author__ = "nabielvna"

# Key management and core operations
from .core import (
    RSAKey,
    generate_keypair,
    encrypt,
    decrypt,
    sign,
    verify_signature,
)

# Utility functions
from .utils import (
    int_to_bytes,
    bytes_to_int,
    save_key_to_pem,
    load_key_from_pem,
)

# Define public API
__all__ = [
    # Core functionality
    'RSAKey',
    'generate_keypair',
    'encrypt',
    'decrypt',
    'sign',
    'verify_signature',
    
    # Utilities
    'int_to_bytes',
    'bytes_to_int',
    'save_key_to_pem',
    'load_key_from_pem',
]