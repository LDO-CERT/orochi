import base64
import hashlib
import os

from Crypto.Cipher import AES
from django.conf import settings


def _derive_key() -> bytes:
    """Derive a 256-bit AES encryption key from the Django SECRET_KEY."""
    return hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret string using AES-256-GCM.

    Returns a URL-safe base64 string.
    """
    if not plaintext:
        return ""
    key = _derive_key()
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    payload = nonce + tag + ciphertext
    return base64.urlsafe_b64encode(payload).decode("utf-8")


def decrypt_secret(encrypted_text: str) -> str:
    """Decrypt a secret string produced by encrypt_secret.

    Raises an exception if the ciphertext or authentication tag is invalid.
    """
    if not encrypted_text:
        return ""
    key = _derive_key()
    payload = base64.urlsafe_b64decode(encrypted_text.encode("utf-8"))
    nonce = payload[:12]
    tag = payload[12:28]
    ciphertext = payload[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")
