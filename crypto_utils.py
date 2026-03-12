import json
import base64
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement

def generate_key_pair():
    """Generates an ECC key pair for ECDH."""
    key = ECC.generate(curve='P-256')
    return key, key.public_key()

def derive_shared_secret(private_key, peer_public_key_bytes):
    """Derives a shared secret using ECDH."""
    peer_public_key = ECC.import_key(peer_public_key_bytes)
    shared_secret = key_agreement(static_priv=private_key, 
                                  static_pub=peer_public_key, 
                                  kdf=lambda x: x)
    return shared_secret

def derive_keys(shared_secret):
    """Derives AES and HMAC keys from the shared secret using HKDF."""
    # Derive 64 bytes total: 32 for AES-256 and 32 for HMAC-SHA256
    keys = HKDF(shared_secret, 64, b'', SHA256)
    aes_key = keys[:32]
    hmac_key = keys[32:]
    return aes_key, hmac_key

def encrypt_message(message, aes_key, hmac_key):
    """Encrypts a message and generates an HMAC for integrity."""
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    
    # Generate HMAC
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(iv + ciphertext)
    signature = h.digest()
    
    return {
        "iv": base64.b64encode(iv).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "hmac": base64.b64encode(signature).decode('utf-8')
    }

def decrypt_message(payload, aes_key, hmac_key):
    """Verifies HMAC and decrypts the message."""
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    received_hmac = base64.b64decode(payload["hmac"])
    
    # Verify HMAC before decryption
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(iv + ciphertext)
    try:
        h.verify(received_hmac)
    except ValueError:
        return None, "HMAC verification failed"
    
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode('utf-8'), None
    except Exception as e:
        return None, str(e)
