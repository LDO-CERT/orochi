import base64
import hashlib
import os

from Crypto.Cipher import AES
from django.conf import settings


def _derive_key(secret_key: str | None = None) -> bytes:
    """Derive a 256-bit AES encryption key from the Django SECRET_KEY."""
    return hashlib.sha256((secret_key or settings.SECRET_KEY).encode("utf-8")).digest()


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

    Tries SECRET_KEY first, then each of SECRET_KEY_FALLBACKS, so secrets stay readable
    while the key is being rotated. Raises ValueError if no key authenticates the ciphertext.
    """
    if not encrypted_text:
        return ""
    payload = base64.urlsafe_b64decode(encrypted_text.encode("utf-8"))
    nonce = payload[:12]
    tag = payload[12:28]
    ciphertext = payload[28:]
    for secret_key in [settings.SECRET_KEY, *getattr(settings, "SECRET_KEY_FALLBACKS", [])]:
        cipher = AES.new(_derive_key(secret_key), AES.MODE_GCM, nonce=nonce)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
        except ValueError:
            continue
    raise ValueError("Unable to decrypt secret with SECRET_KEY or SECRET_KEY_FALLBACKS")
