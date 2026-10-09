"""Replay protection stores.

A captured signed request is still cryptographically valid until it
expires, so an attacker could re-send it ("buy this again"). We remember
every accepted signature until its expiry and refuse to see it twice.

* MemoryReplayStore - single process (tests, all-in-one demo)
* RedisReplayStore  - shared across replicas; SET NX EX is atomic, so two
  replicas can't both accept the same request.
"""

from __future__ import annotations

import asyncio
import heapq
import time


class MemoryReplayStore:
    def __init__(self, max_entries: int = 200_000) -> None:
        self._seen: dict[str, float] = {}
        self._expiry: list[tuple[float, str]] = []
        self._lock = asyncio.Lock()
        self.max_entries = max_entries

    def _evict(self, now: float) -> None:
        while self._expiry and (self._expiry[0][0] <= now or len(self._seen) > self.max_entries):
            ts, key = heapq.heappop(self._expiry)
            if self._seen.get(key) == ts:
                del self._seen[key]

    async def first_seen(self, key: str, ttl_s: int) -> bool:
        now = time.monotonic()
        async with self._lock:
            self._evict(now)
            if key in self._seen:
                return False
            until = now + ttl_s
            self._seen[key] = until
            heapq.heappush(self._expiry, (until, key))
            return True

    def __len__(self) -> int:
        return len(self._seen)


class RedisReplayStore:
    def __init__(self, client, prefix: str = "sakshi:replay:") -> None:
        self.client = client          # redis.asyncio.Redis
        self.prefix = prefix

    async def first_seen(self, key: str, ttl_s: int) -> bool:
        return bool(await self.client.set(self.prefix + key, b"1", nx=True, ex=ttl_s))
