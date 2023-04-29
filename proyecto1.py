# Proyecto 1: Criptografía

# Chacha20 Key Size 256 bits
# AES-EBC Key Size 256 bits
# AES-GCM Key size 256 bits
# SHA-2 Hash size 512 bits
# SHA-3 Hash size 512 bits
# Scrypt Output size 32 bits
# RSA-OAEP 2048 bits
# RSA-PSS 2048 bits
# ECDSA ECDSA, 521 Bits (P-521)
# EdDSA ECDSA, 32 Bits (Curve25519)

import hashlib
import hmac
import base64
from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Hash import SHA256, SHA512, SHA3_512
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

# Chacha20 Key Size 256 bits
def chacha20_encrypt(key, plaintext):
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def chacha20_decrypt(key, ciphertext):
    cipher = ChaCha20.new(key=key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# AES-EBC Key Size 256 bits
def aes_ecb_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def aes_ecb_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# AES-GCM Key size 256 bits
def aes_gcm_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag, cipher.nonce

def aes_gcm_decrypt(key, ciphertext, tag, nonce):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# SHA-2 Hash size 512 bits
def sha256_hash(message):
    hash_object = SHA256.new(data=message)
    return hash_object.digest()

# SHA-3 Hash size 512 bits
def sha3_512_hash(message):
    hash_object = SHA3_512.new(data=message)
    return hash_object.digest()

# Scrypt Output size 32 bits
def scrypt_key(password, salt):
    key = scrypt(password, salt, key_len=32, N=16384, r=8, p=1)
    return key