"""Gateway (BG): fans a buyer app's search out to every relevant seller app.

The gateway verifies the buyer app's signature first, so forged searches die
here instead of being amplified to every seller. It then forwards the
untouched body with **both** signatures: the buyer app's original
`Authorization` and its own `X-Gateway-Authorization`. Seller apps can check
the request came from a real buyer app *and* through a real gateway.
"""

from __future__ import annotations

import json

import httpx
from fastapi import APIRouter, Request

from sakshi.auth import create_authorization_header
from sakshi.client import RegistryResolver

from .common import ACK, EventBus, Participant, Rejected, authenticate, nack, spawn
from .registry import on_subscribe_router


class Gateway:
    def __init__(self, me: Participant, http: httpx.AsyncClient, resolver: RegistryResolver, replay,
                 bus: EventBus, registry_encryption_public: str) -> None:
        self.me = me
        self.http = http
        self.resolver = resolver
        self.replay = replay
        self.bus = bus
        self.forwarded = 0
        self.router = APIRouter()
        self.router.include_router(on_subscribe_router(lambda: self.me, registry_encryption_public, bus))
        self.router.add_api_route("/search", self.search, methods=["POST"])

    async def search(self, request: Request):
        body = await request.body()
        try:
            claimed = json.loads(body)["context"]["bap_id"]
        except (ValueError, KeyError):
            return nack("CONTEXT_MISSING", "context.bap_id required", 400, "CONTEXT-ERROR")
        try:
            await authenticate(request, self.resolver, self.replay, self.bus, self.me.subscriber_id,
                               expect_signer=claimed)
        except Rejected as r:
            return r.response
        bpps = await self.resolver.lookup({"type": "BPP", "domain": json.loads(body)["context"]["domain"]})
        targets = {e["subscriber_id"]: e["subscriber_url"] for e in bpps if e["status"] == "SUBSCRIBED"}
        gw_sig = create_authorization_header(body, self.me.subscriber_id, self.me.unique_key_id,
                                             self.me.keys.signing_private)
        for url in targets.values():
            spawn(self._forward(url, body, request.headers["Authorization"], gw_sig))
        self.bus.emit("order", self.me.subscriber_id,
                      f"verified search from {claimed}, forwarded to {len(targets)} seller apps", "success")
        return ACK

    async def _forward(self, url: str, body: bytes, bap_auth: str, gw_auth: str) -> None:
        try:
            await self.http.post(f"{url}/search", content=body, timeout=10, headers={
                "Content-Type": "application/json", "Authorization": bap_auth, "X-Gateway-Authorization": gw_auth})
            self.forwarded += 1
        except httpx.HTTPError as exc:
            self.bus.emit("order", self.me.subscriber_id, f"could not reach {url}: {exc}", "warning")
