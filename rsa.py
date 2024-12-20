import random
from math import gcd
from typing import Tuple, NamedTuple

class RSAKey(NamedTuple):
    n: int
    e: int  # Public key
    d: int  # Private key

def is_prime(n: int, k: int = 5) -> bool:
    # Miller-Rabin primality test
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False

    # n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1
        if is_prime(n):
            return n

def mod_inverse(e: int, phi: int) -> int:
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, d, _ = extended_gcd(e, phi)
    return d % phi

def generate_keypair(bits: int = 1024) -> Tuple[RSAKey, RSAKey]:
    # Generate two distinct primes
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose public exponent (e)
    e = 65537 
    while gcd(e, phi) != 1:
        e = random.randrange(3, phi, 2)

    # Calculate private exponent (d)
    d = mod_inverse(e, phi)

    public_key = RSAKey(n=n, e=e, d=0)
    private_key = RSAKey(n=n, e=e, d=d)

    return public_key, private_key

def encrypt(message: int, public_key: RSAKey) -> int:
    """Encrypt a message using RSA public key"""
    return pow(message, public_key.e, public_key.n)

def decrypt(ciphertext: int, private_key: RSAKey) -> int:
    """Decrypt a message using RSA private key"""
    return pow(ciphertext, private_key.d, private_key.n)

def sign(message: int, private_key: RSAKey) -> int:
    """Sign a message using RSA private key"""
    return pow(message, private_key.d, private_key.n)

def verify_signature(message: int, signature: int, public_key: RSAKey) -> bool:
    """Verify a signature using RSA public key"""
    return pow(signature, public_key.e, public_key.n) == message

# Utilities
def int_to_bytes(n: int) -> bytes:
    """Convert integer to bytes"""
    return n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

# Convert bytes to integer
def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

# Convert RSA key 
def save_key_to_pem(key: RSAKey, is_private: bool = False) -> str:
    key_type = "RSA PRIVATE KEY" if is_private else "RSA PUBLIC KEY"
    
    key_data = f"{key.n},{key.e},{key.d if is_private else 0}"
    import base64
    encoded = base64.b64encode(key_data.encode()).decode()
    return f"-----BEGIN {key_type}-----\n{encoded}\n-----END {key_type}-----"

# Load RSA key
def load_key_from_pem(pem_str: str) -> RSAKey:
    import base64
    lines = pem_str.strip().split('\n')
    key_data = base64.b64decode(lines[1]).decode()
    n, e, d = map(int, key_data.split(','))
    return RSAKey(n=n, e=e, d=d)

def test_encryption_decryption():
    print("\n=== Testing Encryption and Decryption ===")
    # Generate keypair
    public_key, private_key = generate_keypair(bits=1024)
    print(f"Generated keypair with n of length: {len(bin(public_key.n))-2} bits")

    # Test with a simple message
    original_message = "Hello, RSA!"
    message_int = bytes_to_int(original_message.encode())
    
    print(f"\nOriginal message: {original_message}")
    
    # Encrypt
    encrypted = encrypt(message_int, public_key)
    print(f"Encrypted (int): {encrypted}")
    
    # Decrypt
    decrypted = decrypt(encrypted, private_key)
    decrypted_message = int_to_bytes(decrypted).decode()
    print(f"Decrypted message: {decrypted_message}")
    
    # Verify result
    assert original_message == decrypted_message
    print("✓ Encryption/Decryption test passed!")

def test_signing():
    print("\n=== Testing Digital Signature ===")
    # Generate keypair
    public_key, private_key = generate_keypair(bits=1024)
    
    # Message to sign
    message = "Sign this message"
    message_int = bytes_to_int(message.encode())
    print(f"Original message: {message}")
    
    # Sign
    signature = sign(message_int, private_key)
    print(f"Signature (int): {signature}")
    
    # Verify
    is_valid = verify_signature(message_int, signature, public_key)
    print(f"Signature valid: {is_valid}")
    
    # Try with wrong message
    wrong_message = "Different message"
    wrong_message_int = bytes_to_int(wrong_message.encode())
    is_invalid = verify_signature(wrong_message_int, signature, public_key)
    print(f"Wrong message signature valid (should be False): {is_invalid}")
    
    assert is_valid == True
    assert is_invalid == False
    print("✓ Signature test passed!")

def test_key_storage():
    print("\n=== Testing Key Storage ===")
    # Generate keypair
    public_key, private_key = generate_keypair(bits=1024)
    
    # Save keys to PEM format
    public_pem = save_key_to_pem(public_key)
    private_pem = save_key_to_pem(private_key, is_private=True)
    
    print("Public Key PEM:")
    print(public_pem)
    print("\nPrivate Key PEM:")
    print(private_pem)
    
    # Load keys back
    loaded_public = load_key_from_pem(public_pem)
    loaded_private = load_key_from_pem(private_pem)
    
    # Verify loaded keys work
    message = "Test message for loaded keys"
    message_int = bytes_to_int(message.encode())
    
    # Test encryption with loaded keys
    encrypted = encrypt(message_int, loaded_public)
    decrypted = decrypt(encrypted, loaded_private)
    decrypted_message = int_to_bytes(decrypted).decode()
    
    assert message == decrypted_message
    print("✓ Key storage test passed!")

def main():
    print("Starting RSA Implementation Tests")
    try:
        test_encryption_decryption()
        test_signing()
        test_key_storage()
        print("\n✓ All tests passed successfully!")
    except AssertionError:
        print("\n✗ Test failed!")
    except Exception as e:
        print(f"\n✗ Test failed with error: {str(e)}")

if __name__ == "__main__":
    main()