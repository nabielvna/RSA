from core import RSAKey

# Convert integer to bytes
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