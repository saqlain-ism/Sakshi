"""Request authentication in the ONDC / Beckn wire format.

Every request between participants carries::

    Authorization: Signature keyId="<subscriber_id>|<unique_key_id>|ed25519",
        algorithm="ed25519",created="<unix>",expires="<unix>",
        headers="(created) (expires) digest",signature="<base64>"

The signature covers this *signing string*::

    (created): <created>
    (expires): <expires>
    digest: BLAKE-512=<base64(blake2b-512(raw body))>

Verification goes further than the bare format requires. It enforces a
maximum validity window and clock-skew tolerance, rejects replays inside the
window, checks the key's validity period and revocation status, and (in the
services) checks that the signer is the participant the message claims to
come from.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Protocol

from .crypto import b64e, blake2b_512, sign, verify

ALGORITHM = "ed25519"
SIGNED_HEADERS = "(created) (expires) digest"
DEFAULT_TTL_S = 30           # how long a signed request stays valid
MAX_WINDOW_S = 300           # reject signatures that claim a longer life
CLOCK_SKEW_S = 5             # tolerated difference between participants' clocks

_PARAM = re.compile(r'(\w+)="([^"]*)"')


class AuthError(Exception):
    """Authentication failure with a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class KeyRecord:
    """What the registry knows about one signing key."""

    subscriber_id: str
    unique_key_id: str
    signing_public_key: str
    valid_from: float
    valid_until: float
    status: str = "SUBSCRIBED"           # or REVOKED / INITIATED
    type: str = ""

    def usable_at(self, ts: float) -> bool:
        return self.status == "SUBSCRIBED" and self.valid_from <= ts <= self.valid_until


class KeyResolver(Protocol):
    async def resolve(self, subscriber_id: str, unique_key_id: str) -> KeyRecord | None: ...


class ReplayStore(Protocol):
    async def first_seen(self, key: str, ttl_s: int) -> bool:
        """Atomically record `key`; True if it had not been seen before."""
        ...


@dataclass(frozen=True)
class SignatureParams:
    subscriber_id: str
    unique_key_id: str
    algorithm: str
    created: int
    expires: int
    headers: str
    signature: str


@dataclass(frozen=True)
class VerifiedSender:
    subscriber_id: str
    unique_key_id: str
    created: int
    expires: int
    digest: str


def body_digest(body: bytes) -> str:
    return b64e(blake2b_512(body))


def signing_string(created: int, expires: int, digest_b64: str) -> str:
    return f"(created): {created}\n(expires): {expires}\ndigest: BLAKE-512={digest_b64}"


def create_authorization_header(body: bytes, subscriber_id: str, unique_key_id: str, private_key_b64: str,
                                created: int | None = None, ttl_s: int = DEFAULT_TTL_S) -> str:
    created = int(time.time()) if created is None else int(created)
    expires = created + ttl_s
    signature = sign(private_key_b64, signing_string(created, expires, body_digest(body)).encode())
    return (
        f'Signature keyId="{subscriber_id}|{unique_key_id}|{ALGORITHM}",algorithm="{ALGORITHM}",'
        f'created="{created}",expires="{expires}",headers="{SIGNED_HEADERS}",signature="{signature}"'
    )


def parse_authorization_header(header: str | None) -> SignatureParams:
    if not header:
        raise AuthError("AUTH_MISSING", "no Authorization header")
    if not header.startswith("Signature "):
        raise AuthError("AUTH_MALFORMED", "expected 'Signature' scheme")
    params = dict(_PARAM.findall(header))
    required = {"keyId", "algorithm", "created", "expires", "headers", "signature"}
    if missing := required - params.keys():
        raise AuthError("AUTH_MALFORMED", f"missing parameters: {sorted(missing)}")
    parts = params["keyId"].split("|")
    if len(parts) != 3 or not all(parts):
        raise AuthError("AUTH_MALFORMED", "keyId must be subscriber_id|unique_key_id|algorithm")
    try:
        created, expires = int(params["created"]), int(params["expires"])
    except ValueError as exc:
        raise AuthError("AUTH_MALFORMED", "created/expires must be unix timestamps") from exc
    return SignatureParams(parts[0], parts[1], params["algorithm"], created, expires,
                           params["headers"], params["signature"])


async def verify_authorization(header: str | None, body: bytes, resolver: KeyResolver,
                               replay: ReplayStore | None = None, now: float | None = None,
                               max_window_s: int = MAX_WINDOW_S, skew_s: int = CLOCK_SKEW_S) -> VerifiedSender:
    """Verify a signed request. Returns who signed it, or raises AuthError.

    Checks run cheapest-first so junk is rejected before any key lookup or
    signature math.
    """
    now = time.time() if now is None else now
    p = parse_authorization_header(header)

    if p.algorithm != ALGORITHM or p.headers != SIGNED_HEADERS:
        raise AuthError("AUTH_UNSUPPORTED", f"algorithm={p.algorithm!r} headers={p.headers!r}")
    if p.expires <= p.created:
        raise AuthError("AUTH_MALFORMED", "expires must be after created")
    if p.expires - p.created > max_window_s:
        raise AuthError("AUTH_WINDOW_TOO_LONG", f"validity window over {max_window_s}s")
    if p.created > now + skew_s:
        raise AuthError("AUTH_NOT_YET_VALID", "created is in the future")
    if p.expires < now - skew_s:
        raise AuthError("AUTH_EXPIRED", f"signature expired {int(now - p.expires)}s ago")

    key = await resolver.resolve(p.subscriber_id, p.unique_key_id)
    if key is None:
        raise AuthError("AUTH_UNKNOWN_KEY", f"no key {p.unique_key_id} for {p.subscriber_id}")
    if key.status == "REVOKED":
        raise AuthError("AUTH_KEY_REVOKED", f"key {p.unique_key_id} of {p.subscriber_id} is revoked")
    if not key.usable_at(p.created):
        raise AuthError("AUTH_KEY_INACTIVE", f"key {p.unique_key_id} not valid at signing time")

    digest = body_digest(body)
    if not verify(key.signing_public_key, signing_string(p.created, p.expires, digest).encode(), p.signature):
        raise AuthError("AUTH_BAD_SIGNATURE", "signature does not match body or key")

    # Only *valid* requests are recorded, so an attacker can't pre-poison the
    # replay cache with garbage to block a genuine message.
    if replay is not None:
        ttl = max(1, int(p.expires - now + skew_s))
        if not await replay.first_seen(f"{p.subscriber_id}|{p.signature}", ttl):
            raise AuthError("AUTH_REPLAY", "this exact signed request was already accepted")

    return VerifiedSender(p.subscriber_id, p.unique_key_id, p.created, p.expires, digest)
