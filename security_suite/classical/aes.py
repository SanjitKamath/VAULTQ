from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

def aes_encrypt(key, plaintext):
    """Encrypts plaintext using AES-GCM."""
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()
    
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ct

def aes_decrypt(key, ciphertext):
    """Decrypts ciphertext using AES-GCM."""
    iv = ciphertext[:12]
    tag = ciphertext[12:28]
    ct = ciphertext[28:]
    
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    
    return decryptor.update(ct) + decryptor.finalize()
