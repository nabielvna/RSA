import random
from typing import NamedTuple, Tuple
from math import gcd
from primitives import generate_prime, mod_inverse

class RSAKey(NamedTuple):
    n: int
    e: int
    d: int

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