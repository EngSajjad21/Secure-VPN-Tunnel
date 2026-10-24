import base64
import json
import struct

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Util.Padding import pad, unpad


def generate_key_pair():
    """Generate an ECC key pair for ECDH."""
    key = ECC.generate(curve="P-256")
    return key, key.public_key()


def derive_shared_secret(private_key, peer_public_key_bytes):
    """Derive a shared secret using ECDH."""
    peer_public_key = ECC.import_key(peer_public_key_bytes)
    return key_agreement(
        static_priv=private_key,
        static_pub=peer_public_key,
        kdf=lambda value: value,
    )


def derive_keys(shared_secret):
    """Derive separate AES-256 and HMAC-SHA256 keys using HKDF."""
    keys = HKDF(shared_secret, 64, b"", SHA256)
    return keys[:32], keys[32:]


def _counter_bytes(counter):
    if not isinstance(counter, int) or counter < 0:
        raise ValueError("counter must be a non-negative integer")
    return struct.pack("!Q", counter)


def encrypt_message(message, aes_key, hmac_key, counter=0):
    """Encrypt a message and authenticate its counter, IV, and ciphertext."""
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
    counter_bytes = _counter_bytes(counter)

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(counter_bytes + iv + ciphertext)

    return {
        "counter": counter,
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "hmac": base64.b64encode(hmac.digest()).decode("ascii"),
    }


def decrypt_message(payload, aes_key, hmac_key, expected_counter=None):
    """Verify counter/HMAC and decrypt a message, rejecting replayed messages."""
    try:
        counter = payload["counter"]
        counter_bytes = _counter_bytes(counter)
        iv = base64.b64decode(payload["iv"], validate=True)
        ciphertext = base64.b64decode(payload["ciphertext"], validate=True)
        received_hmac = base64.b64decode(payload["hmac"], validate=True)
    except (KeyError, TypeError, ValueError, struct.error) as exc:
        return None, f"Invalid encrypted payload: {exc}"

    if expected_counter is not None and counter != expected_counter:
        return None, "Unexpected message counter (possible replay or reordering)"

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(counter_bytes + iv + ciphertext)
    try:
        hmac.verify(received_hmac)
    except ValueError:
        return None, "HMAC verification failed"

    try:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode("utf-8"), None
    except (ValueError, UnicodeDecodeError) as exc:
        return None, str(exc)


def send_frame(sock, payload):
    """Send one length-prefixed bytes frame over TCP."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_exact(sock, size):
    """Receive exactly size bytes or return None if the peer disconnects."""
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock, max_size=1024 * 1024):
    """Receive one length-prefixed bytes frame with a size limit."""
    header = recv_exact(sock, 4)
    if header is None:
        return None
    (size,) = struct.unpack("!I", header)
    if size > max_size:
        raise ValueError("incoming frame exceeds the maximum allowed size")
    return recv_exact(sock, size)


def send_json(sock, payload):
    send_frame(sock, json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def recv_json(sock):
    data = recv_frame(sock)
    if data is None:
        return None
    return json.loads(data.decode("utf-8"))
