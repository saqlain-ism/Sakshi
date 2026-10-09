"""Background traffic: genuine buyers shopping, plus one seller's sock puppets.

The simulator is only a *client* of the buyer app's public API, so it
exercises the same code paths a real frontend would.
"""

from __future__ import annotations

import asyncio
import random
import time

import httpx

from .common import EventBus, spawn
from .world import QUERIES

BOOSTER = "star-traders"


class Simulator:
    def __init__(self, bap_url: str, http: httpx.AsyncClient, bus: EventBus, orders_per_s: float = 0.8,
                 buyers: int = 40, puppets: int = 6, idle_pause_s: float = 600, seed: int | None = None) -> None:
        self.bap_url = bap_url
        self.http = http
        self.bus = bus
        self.rate = orders_per_s
        self.buyers = [f"buyer-{i:02d}" for i in range(buyers)]
        self.puppets = [f"puppet-{i:02d}" for i in range(puppets)]
        self.idle_pause_s = idle_pause_s
        self.rng = random.Random(seed)
        self.running = True
        self.placed = 0
        self.failed = 0
        self.last_viewer = time.time()

    @property
    def active(self) -> bool:
        """Pauses itself when nobody has looked at the dashboard for a while (cheap free hosting)."""
        return self.running and time.time() - self.last_viewer < self.idle_pause_s

    async def order(self, buyer: str, query: str, seller_id: str | None = None, fake: bool = False) -> dict:
        try:
            r = await self.http.post(f"{self.bap_url}/api/orders", timeout=30,
                                     json={"buyer": buyer, "query": query, "seller_id": seller_id, "sim_fake": fake})
            self.placed += 1
            return r.json()
        except (httpx.HTTPError, ValueError) as exc:
            self.failed += 1
            return {"status": "ERROR", "error": str(exc)}

    async def burst(self, n: int = 6) -> None:
        """The booster seller's puppets place quick, small orders with it."""
        for _ in range(n):
            spawn(self.order(self.rng.choice(self.puppets), "", seller_id=BOOSTER, fake=True))
            await asyncio.sleep(0.4 + self.rng.random())

    async def run(self) -> None:
        last_burst = time.time()
        while True:
            if not self.active:
                await asyncio.sleep(2)
                continue
            spawn(self.order(self.rng.choice(self.buyers), self.rng.choice(QUERIES)))
            if time.time() - last_burst > 20:
                last_burst = time.time()
                spawn(self.burst(self.rng.randint(6, 9)))
            await asyncio.sleep(self.rng.expovariate(self.rate))
