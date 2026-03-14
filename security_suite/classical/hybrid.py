from . import rsa
from . import aes
import os

def classical_kem_dem_encapsulate(public_key):
    """Encapsulates a new symmetric key using RSA-KEM."""
    # Generate a fresh symmetric key for the DEM
    symmetric_key = os.urandom(32)  # AES-256
    
    # Encrypt the symmetric key with RSA (KEM)
    encapsulated_key = rsa.rsa_encrypt(public_key, symmetric_key)
    
    return encapsulated_key, symmetric_key

def classical_kem_dem_decapsulate(private_key, encapsulated_key):
    """Decapsulates a symmetric key using RSA-KEM."""
    # Decrypt the symmetric key with RSA
    symmetric_key = rsa.rsa_decrypt(private_key, encapsulated_key)
    
    return symmetric_key

def classical_hybrid_encrypt(public_key, plaintext):
    """Encrypts data using a classical RSA-KEM + AES-DEM hybrid scheme."""
    encapsulated_key, symmetric_key = classical_kem_dem_encapsulate(public_key)
    
    # Encrypt the actual message with AES (DEM)
    ciphertext = aes.aes_encrypt(symmetric_key, plaintext)
    
    return encapsulated_key + ciphertext

def classical_hybrid_decrypt(private_key, hybrid_ciphertext):
    """Decrypts data using a classical RSA-KEM + AES-DEM hybrid scheme."""
    # Extract the encapsulated key and the DEM ciphertext
    # Assuming a fixed-size RSA key (e.g., 2048 bits = 256 bytes)
    rsa_key_size_bytes = 256 
    encapsulated_key = hybrid_ciphertext[:rsa_key_size_bytes]
    ciphertext = hybrid_ciphertext[rsa_key_size_bytes:]
    
    # Decapsulate the symmetric key
    symmetric_key = classical_kem_dem_decapsulate(private_key, encapsulated_key)
    
    # Decrypt the message with AES
    plaintext = aes.aes_decrypt(symmetric_key, ciphertext)
    
    return plaintext
