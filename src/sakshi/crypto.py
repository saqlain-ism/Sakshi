"""Cryptographic primitives used across Sakshi.

* Ed25519            - signing (requests, receipts, credentials, tree heads)
* X25519 + HKDF      - key agreement for the registry onboarding challenge
* AES-256-GCM        - authenticated encryption of that challenge
* BLAKE2b-512        - request body digest (what ONDC/Beckn specifies)
* SHA-256            - Merkle tree hashing (RFC 6962 style)

Keys travel as base64 of their *raw* bytes (32 bytes each), which is what
ONDC participants publish in the registry. A 64-byte libsodium-style secret
key (seed || public) is accepted when loading, for compatibility.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_NOENC = serialization.NoEncryption()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def blake2b_512(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=64).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --------------------------------------------------------------------- signing
def _seed(private_b64: str) -> bytes:
    raw = b64d(private_b64)
    if len(raw) == 64:          # libsodium secret key = seed || public key
        raw = raw[:32]
    if len(raw) != 32:
        raise ValueError("Ed25519 private key must be 32 (seed) or 64 bytes")
    return raw


def load_signing_key(private_b64: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_seed(private_b64))


def load_verify_key(public_b64: str) -> Ed25519PublicKey:
    raw = b64d(public_b64)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def sign(private_b64: str, message: bytes) -> str:
    return b64e(load_signing_key(private_b64).sign(message))


def verify(public_b64: str, message: bytes, signature_b64: str) -> bool:
    """True only for a valid signature. Never raises on bad input."""
    try:
        load_verify_key(public_b64).verify(b64d(signature_b64), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ------------------------------------------------------------------ encryption
def _hkdf(shared: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def shared_key(own_private_b64: str, peer_public_b64: str, info: bytes = b"sakshi/challenge/v1") -> bytes:
    """X25519 key agreement, stretched through HKDF into an AES-256 key."""
    own = X25519PrivateKey.from_private_bytes(b64d(own_private_b64))
    peer = X25519PublicKey.from_public_bytes(b64d(peer_public_b64))
    return _hkdf(own.exchange(peer), info)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> str:
    """AES-256-GCM. Output: base64(nonce || ciphertext || tag)."""
    nonce = os.urandom(12)
    return b64e(nonce + AESGCM(key).encrypt(nonce, plaintext, aad))


def decrypt(key: bytes, token_b64: str, aad: bytes = b"") -> bytes:
    raw = b64d(token_b64)
    try:
        return AESGCM(key).decrypt(raw[:12], raw[12:], aad)
    except InvalidTag as exc:
        raise ValueError("decryption failed: wrong key or tampered ciphertext") from exc


# ------------------------------------------------------------------- key pairs
@dataclass(frozen=True)
class KeyPair:
    """A participant's two key pairs: one to sign, one to agree encryption keys."""

    signing_private: str
    signing_public: str
    encryption_private: str
    encryption_public: str

    @classmethod
    def generate(cls) -> KeyPair:
        sk = Ed25519PrivateKey.generate()
        ek = X25519PrivateKey.generate()
        return cls(
            signing_private=b64e(sk.private_bytes(_RAW, _RAW_PRIV, _NOENC)),
            signing_public=b64e(sk.public_key().public_bytes(_RAW, _RAW_PUB)),
            encryption_private=b64e(ek.private_bytes(_RAW, _RAW_PRIV, _NOENC)),
            encryption_public=b64e(ek.public_key().public_bytes(_RAW, _RAW_PUB)),
        )

    @classmethod
    def from_seed(cls, seed: bytes) -> KeyPair:
        """Deterministic keys (for reproducible demos and test vectors only)."""
        s = hashlib.sha256(b"sign" + seed).digest()
        e = hashlib.sha256(b"enc" + seed).digest()
        sk = Ed25519PrivateKey.from_private_bytes(s)
        ek = X25519PrivateKey.from_private_bytes(e)
        return cls(b64e(s), b64e(sk.public_key().public_bytes(_RAW, _RAW_PUB)),
                   b64e(e), b64e(ek.public_key().public_bytes(_RAW, _RAW_PUB)))

    def sign(self, message: bytes) -> str:
        return sign(self.signing_private, message)
