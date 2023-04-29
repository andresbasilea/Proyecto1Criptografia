#pip install pycryptodomex
#pip install cryptography
#pip install pycryptodome
#pip install pynacl

# Proyecto 1: Criptografía


# Each algorithm is used for some goal; therefore, you need to compare only the ones that
# share such a goal. For example, if you want to compare hashing algorithms you compare
# the efficiency of SHA-2 and SHA-3 by using the same input testing vector.

# Following this idea, you need to create a table or a graph comparing the efficiency of these
# algorithms for the following operations:
#    Encryption
#    Decryption
#    Hashing
#    Signing
#    Verifying

# After the execution of your program, you should show the results for each operation. These
# should be presented using a visual component (i.e., a table, a graph). Coming back to the
# hashing example, after the execution of all hashing algorithms with all the hashing vectors,
# you could show a table similar to the following or a graph that can show your results.


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
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from Crypto.PublicKey import Ed25519
from Crypto.Signature import Ed25519ph
from Crypto.Hash import SHA512


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

# Generar un par de claves RSA
def keys_rsa(public_exponent=65537,key_size=2048):
  private_key = rsa.generate_private_key(public_exponent,key_size)
  public_key = private_key.public_key()
  return private_key,public_key

# Cifrar un mensaje con RSA-OAEP
def rsa_oaep_encrypt(message, public_key):
  ciphertext = public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
  return ciphertext

# Descifrar el mensaje con RSA-OAEP
def rsa_oaep_decrypt(ciphertext, private_key):
  decrypted_message = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
  return decrypted_message  

# Firmar un mensaje con RSA-PSS
def rsa_pss_sign(message, private_key):
    signature = private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

# Verificar la firma con RSA-PSS
def rsa_pss_verify_sign(message, signature, public_key):
    try:
        public_key.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        print("Firma válida.")
    except InvalidSignature:
        print("Firma no válida.")

# Generar un par de claves ECDSA
def keys_ecdsa():
    private_key = ec.generate_private_key(ec.SECP521R1()) # también conocido como prime256v1 o P-256
    public_key = private_key.public_key()
    return private_key, public_key

# Firmar un mensaje con ECDSA
def ecdsa_sign(message, private_key):
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

# Verificar la firma con ECDSA
def ecdsa_verify_sign(message, signature, public_key):
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        print("Firma válida.")
    except InvalidSignature:
        print("Firma no válida.")

# Generar un par de claves EdDSA
def keys_eddsa():
    key = Ed25519.generate()
    private_key = key.signing_key
    public_key = key.verifying_key
    return private_key, public_key

# Firmar un mensaje con EdDSA
def eddsa_sign(message, private_key):
    hash_object = SHA512.new(message)
    signature = private_key.sign(hash_object)
    return signature

# Verificar la firma con EdDSA
def eddsa_verify_sign(message, signature, public_key):
    try:
        hash_object = SHA512.new(message)
        public_key.verify(signature, hash_object)
        print("Firma válida.")
    except ValueError:
        print("Firma no válida.")

