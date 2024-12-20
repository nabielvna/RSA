from core import generate_keypair, encrypt, decrypt, sign, verify_signature
from utils import int_to_bytes, bytes_to_int, save_key_to_pem, load_key_from_pem

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