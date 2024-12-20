# RSA (Rivest-Shamir-Adleman) Implementation

This project implements the RSA (Rivest-Shamir-Adleman) encryption algorithm in Python. It provides functionality for key generation, encryption/decryption, and digital signatures using the RSA algorithm.

## Overview

The RSA implementation consists of several Python modules that work together to provide cryptographic functionality:

- `core.py`: Contains core RSA operations (key generation, encryption, decryption)
- `primitives.py`: Implements cryptographic primitives like prime number generation
- `utils.py`: Provides utility functions for data conversion and key storage
- `main.py`: Contains test cases and demonstration code
- `rsa.py`: Standalone complete implementation file

## Features

- RSA key pair generation
- Message encryption and decryption
- Digital signature creation and verification
- PEM format key storage
- Prime number generation
- Miller-Rabin primality testing
- Built-in testing suite

## Requirements

- Python 3.6 or higher
- No additional external dependencies required

## Installation

1. Clone or download all the project files
2. Ensure all files are in the same directory
3. Run `main.py` to test the implementation

```bash
python main.py
```

## Usage

### Key Generation

```python
from core import generate_keypair

# Generate new RSA key pair (default 1024 bits)
public_key, private_key = generate_keypair()
```

### Encryption and Decryption

```python
from core import encrypt, decrypt
from utils import int_to_bytes, bytes_to_int

# Convert message to integer
message = "Hello, RSA!"
message_int = bytes_to_int(message.encode())

# Encrypt
encrypted = encrypt(message_int, public_key)

# Decrypt
decrypted = decrypt(encrypted, private_key)
decrypted_message = int_to_bytes(decrypted).decode()
```

### Digital Signatures

```python
from core import sign, verify_signature

# Sign a message
signature = sign(message_int, private_key)

# Verify signature
is_valid = verify_signature(message_int, signature, public_key)
```

## Technical Details

### Project Structure

- `core.py`: Core RSA operations and key types
- `primitives.py`: Prime number generation and primality testing
- `utils.py`: Conversion utilities and key format handling
- `main.py`: Test implementation and examples
- `rsa.py`: Complete standalone implementation

### Implementation Details

The implementation follows the standard RSA algorithm:

1. Key Generation:
   - Prime number generation using Miller-Rabin test
   - Modulus calculation (n = p * q)
   - Euler's totient calculation
   - Public/private exponent generation
2. Encryption/Decryption:
   - Uses modular exponentiation
   - Handles message encoding/decoding
3. Digital Signatures:
   - Sign using private key
   - Verify using public key

Key features:

- Configurable key size (default 1024 bits)
- Common public exponent (e = 65537)
- PEM format key storage
- Miller-Rabin primality testing
- Extended Euclidean algorithm for modular inverse

### Utility Functions

The `utils.py` module provides several important functions:

- `int_to_bytes()`: Converts integers to bytes
- `bytes_to_int()`: Converts bytes to integers
- `save_key_to_pem()`: Saves keys in PEM format
- `load_key_from_pem()`: Loads keys from PEM format

## Security Considerations

Please note:

1. This is an educational implementation
2. Not recommended for production use
3. Use established cryptographic libraries for production:
   - cryptography
   - pycryptodome
   - pyOpenSSL
4. Private keys should be stored securely
5. Key size should be at least 2048 bits for security

## Error Handling

The implementation includes basic error handling for:

- Key generation failures
- Invalid message sizes
- Encoding/decoding errors
- Key format errors
- Signature verification failures

## Testing

Run the test suite:

```bash
python main.py
```

The tests cover:
- Key generation
- Encryption/decryption
- Digital signatures
- Key storage/loading

## Acknowledgments

This implementation is based on the RSA algorithm developed by Ron Rivest, Adi Shamir, and Leonard Adleman. It follows standard RSA specifications and includes standard implementations of necessary cryptographic primitives.
