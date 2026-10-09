"""Participant-side helpers: registry lookups and signed HTTP calls."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from .auth import AuthError, KeyRecord, create_authorization_header, parse_authorization_header, verify_authorization

REGISTRY_SIG_HEADER = "X-Registry-Signature"


class StaticResolver:
    """Resolver over a fixed set of keys (tests, offline verification)."""

    def __init__(self, records: list[KeyRecord] | None = None) -> None:
        self.records = {(r.subscriber_id, r.unique_key_id): r for r in records or []}

    def add(self, record: KeyRecord) -> None:
        self.records[(record.subscriber_id, record.unique_key_id)] = record

    async def resolve(self, subscriber_id: str, unique_key_id: str) -> KeyRecord | None:
        return self.records.get((subscriber_id, unique_key_id))


def record_from_entry(e: dict) -> KeyRecord:
    return KeyRecord(e["subscriber_id"], e["ukId"], e["signing_public_key"], float(e["valid_from"]),
                     float(e["valid_until"]), e.get("status", "SUBSCRIBED"), e.get("type", ""))


class _PinnedRegistry:
    """Resolves only the registry itself, from a key pinned in configuration."""

    def __init__(self, record: KeyRecord) -> None:
        self.record = record

    async def resolve(self, subscriber_id: str, unique_key_id: str) -> KeyRecord | None:
        r = self.record
        return r if (subscriber_id, unique_key_id) == (r.subscriber_id, r.unique_key_id) else None


class RegistryResolver:
    """Looks keys up in the registry, with a short-lived cache.

    The registry is the network's phone book. If an attacker could answer
    lookups instead of it, they could hand out their own public key and
    impersonate anyone. So every lookup response must carry a signature
    by the registry, checked against the registry key **pinned** in our
    configuration, never one fetched over the network.

    Caching trades freshness for load: a revoked key keeps working for at
    most `ttl_s` seconds on this participant. Negative results are cached
    briefly too, so a flood of requests with made-up key ids can't flood
    the registry.
    """

    def __init__(self, registry_url: str, registry_key: KeyRecord, http: httpx.AsyncClient,
                 ttl_s: float = 30.0, negative_ttl_s: float = 5.0) -> None:
        self.url = registry_url.rstrip("/")
        self.pinned = _PinnedRegistry(registry_key)
        self.http = http
        self.ttl_s = ttl_s
        self.negative_ttl_s = negative_ttl_s
        self._cache: dict[tuple[str, str], tuple[float, KeyRecord | None]] = {}
        self.hits = 0
        self.misses = 0

    def invalidate(self, subscriber_id: str | None = None) -> None:
        if subscriber_id is None:
            self._cache.clear()
        else:
            for k in [k for k in self._cache if k[0] == subscriber_id]:
                del self._cache[k]

    async def lookup(self, query: dict) -> list[dict]:
        resp = await self.http.post(f"{self.url}/lookup", content=json.dumps(query).encode(),
                                    headers={"Content-Type": "application/json"})
        resp.raise_for_status()
        try:
            await verify_authorization(resp.headers.get(REGISTRY_SIG_HEADER), resp.content, self.pinned)
        except AuthError as exc:
            raise AuthError("REGISTRY_UNTRUSTED", f"lookup response not signed by the registry ({exc.code})") from exc
        return resp.json()

    async def resolve(self, subscriber_id: str, unique_key_id: str) -> KeyRecord | None:
        if (subscriber_id, unique_key_id) == (self.pinned.record.subscriber_id, self.pinned.record.unique_key_id):
            return self.pinned.record
        key = (subscriber_id, unique_key_id)
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached and cached[0] > now:
            self.hits += 1
            return cached[1]
        self.misses += 1
        entries = await self.lookup({"subscriber_id": subscriber_id, "ukId": unique_key_id})
        record = record_from_entry(entries[0]) if entries else None
        self._cache[key] = (now + (self.ttl_s if record else self.negative_ttl_s), record)
        return record


class SignedClient:
    """Sends Beckn-style signed POST requests.

    The body is serialised **once** and those exact bytes are both hashed
    and sent. Re-serialising after signing (different key order or
    whitespace) is the classic way to break your own signatures.
    """

    def __init__(self, subscriber_id: str, unique_key_id: str, private_key_b64: str,
                 http: httpx.AsyncClient, ttl_s: int = 30) -> None:
        self.subscriber_id = subscriber_id
        self.unique_key_id = unique_key_id
        self.private_key = private_key_b64
        self.http = http
        self.ttl_s = ttl_s

    def sign_body(self, payload: Any) -> tuple[bytes, str]:
        body = payload if isinstance(payload, bytes) else json.dumps(payload, separators=(",", ":")).encode()
        return body, create_authorization_header(body, self.subscriber_id, self.unique_key_id,
                                                 self.private_key, ttl_s=self.ttl_s)

    async def post(self, url: str, payload: Any, extra_headers: dict | None = None) -> httpx.Response:
        body, auth = self.sign_body(payload)
        headers = {"Content-Type": "application/json", "Authorization": auth, **(extra_headers or {})}
        return await self.http.post(url, content=body, headers=headers)


def signer_of(header: str | None) -> str | None:
    try:
        return parse_authorization_header(header).subscriber_id
    except AuthError:
        return None
