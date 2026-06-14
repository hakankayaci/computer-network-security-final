"""Cryptographic helpers for the educational end-to-end encryption demo.

The project uses X25519 for key exchange and AES-GCM for authenticated
encryption. AES-GCM provides both confidentiality and message integrity.
"""

import base64
import binascii
import os
from typing import Dict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import config


class MessageIntegrityError(Exception):
    """Raised when AES-GCM authentication fails during decryption."""


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def generate_private_key() -> x25519.X25519PrivateKey:
    """Create an ephemeral X25519 private key for this demo session."""
    return x25519.X25519PrivateKey.generate()


def public_key_to_base64(private_key: x25519.X25519PrivateKey) -> str:
    """Serialize the public part of an X25519 key as a base64 string."""
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64encode(public_bytes)


def load_peer_public_key(public_key_b64: str) -> x25519.X25519PublicKey:
    """Load a peer public key received through the chat server."""
    return x25519.X25519PublicKey.from_public_bytes(_b64decode(public_key_b64))


def derive_shared_key(
    private_key: x25519.X25519PrivateKey,
    peer_public_key_b64: str,
) -> bytes:
    """Derive a 256-bit AES key from an X25519 shared secret."""
    peer_public_key = load_peer_public_key(peer_public_key_b64)
    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=config.CRYPTO_INFO,
    ).derive(shared_secret)


def encrypt_message(key: bytes, plaintext: str) -> Dict[str, str]:
    """Encrypt plaintext with AES-GCM and return a JSON-safe payload."""
    nonce = os.urandom(config.AES_GCM_NONCE_BYTES)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(config.ENCODING), None)
    return {
        "algorithm": "AES-256-GCM",
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }


def decrypt_message(key: bytes, encrypted_payload: Dict[str, str]) -> str:
    """Decrypt an AES-GCM payload and verify its authentication tag."""
    try:
        nonce = _b64decode(encrypted_payload["nonce"])
        ciphertext = _b64decode(encrypted_payload["ciphertext"])
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode(config.ENCODING)
    except (InvalidTag, KeyError, ValueError, binascii.Error) as exc:
        raise MessageIntegrityError(
            "Message integrity check failed. Message may have been modified."
        ) from exc


def ciphertext_hex_preview(encrypted_payload: Dict[str, str], max_hex_chars: int = 80) -> str:
    """Return a short hex preview that is safe for the spy server display."""
    try:
        raw = _b64decode(encrypted_payload.get("ciphertext", ""))
    except (ValueError, binascii.Error):
        return "<invalid ciphertext>"

    hex_text = raw.hex()
    if len(hex_text) > max_hex_chars:
        return f"{hex_text[:max_hex_chars]}..."
    return hex_text


def tamper_encrypted_payload(encrypted_payload: Dict[str, str]) -> Dict[str, str]:
    """Flip one bit in the ciphertext for a safe local integrity demo."""
    tampered = dict(encrypted_payload)
    raw = bytearray(_b64decode(tampered["ciphertext"]))
    if not raw:
        raise ValueError("Cannot tamper with an empty ciphertext.")
    raw[0] ^= 0x01
    tampered["ciphertext"] = _b64encode(bytes(raw))
    tampered["tampered_for_demo"] = "true"
    return tampered

