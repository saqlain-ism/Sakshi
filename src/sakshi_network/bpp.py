"""Seller app (BPP): hosts several sellers ("providers") and their catalogues.

Each seller has a behaviour profile, so the network contains the trust
problems Sakshi is meant to expose:

  reliable  delivers well within its promise
  slow      often delivers after the promised time
  flaky     confirms orders and then cancels many of them
  ghost     confirms orders and never delivers
  bait      quotes one price, then confirms a higher one (bait-and-switch)
  booster   genuine trade, plus fake orders from its own sock-puppet buyers
            that it "delivers" instantly to inflate its reputation
  forged    presents a GST credential it signed itself

The seller app signs every commitment it makes: quotes, order contracts,
deliveries and cancellations. That is all a buyer needs for evidence.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
import uuid
from dataclasses import dataclass, field

import httpx
from fastapi import APIRouter, Request

from sakshi.client import RegistryResolver, SignedClient
from sakshi.receipts import new_receipt

from .common import ACK, EventBus, Participant, Rejected, authenticate, callback_context, nack, spawn
from .registry import on_subscribe_router


@dataclass
class Seller:
    id: str
    name: str
    profile: str
    items: list[dict]                  # {"id", "name", "price": "123.00"}
    gstin: str
    promise_s: int = 30                # promised delivery time (demo scale: seconds)
    credential: dict | None = None
    stats: dict = field(default_factory=lambda: {"orders": 0, "delivered": 0, "cancelled": 0})


def _money(paise: int) -> str:
    return f"{paise // 100}.{paise % 100:02d}"


def _paise(value: str) -> int:
    r, _, p = value.partition(".")
    return int(r) * 100 + int((p + "00")[:2])


class SellerApp:
    def __init__(self, me: Participant, sellers: list[Seller], http: httpx.AsyncClient, resolver: RegistryResolver,
                 replay, bus: EventBus, registry_encryption_public: str, time_scale: float = 1.0,
                 rng: random.Random | None = None) -> None:
        self.me = me
        self.sellers = {s.id: s for s in sellers}
        self.http = http
        self.resolver = resolver
        self.replay = replay
        self.bus = bus
        self.time_scale = time_scale
        self.rng = rng or random.Random()
        self.orders: dict[str, dict] = {}
        self.router = APIRouter()
        self.router.include_router(on_subscribe_router(lambda: self.me, registry_encryption_public, bus))
        for action in ("search", "select", "init", "confirm", "status"):
            self.router.add_api_route(f"/{action}", getattr(self, action), methods=["POST"])

    @property
    def client(self) -> SignedClient:
        return SignedClient(self.me.subscriber_id, self.me.unique_key_id, self.me.keys.signing_private, self.http)

    async def _type_of(self, sub: str, ukid: str) -> str | None:
        rec = await self.resolver.resolve(sub, ukid)
        return rec.type if rec else None

    async def _verify(self, request: Request) -> dict:
        try:
            body = json.loads(await request.body())
            claimed = body["context"]["bap_id"]
            body["message"]  # noqa: B018 - presence check
        except (ValueError, KeyError, TypeError) as exc:
            raise Rejected(nack("CONTEXT_MISSING", "malformed Beckn message", 400, "CONTEXT-ERROR")) from exc
        await authenticate(request, self.resolver, self.replay, self.bus, self.me.subscriber_id,
                           expect_signer=claimed)
        return body

    async def _callback(self, ctx: dict, action: str, message: dict) -> None:
        payload = {"context": callback_context(ctx, action, self.me), "message": message}
        try:
            await self.client.post(f"{ctx['bap_uri']}/{action}", payload)
        except httpx.HTTPError as exc:
            self.bus.emit("order", self.me.subscriber_id, f"{action} to {ctx['bap_id']} failed: {exc}", "warning")

    def _sign(self, receipt) -> dict:
        return receipt.sign_as_issuer(self.me.unique_key_id, self.me.keys.signing_private).to_dict()

    # ------------------------------------------------------------------ search
    async def search(self, request: Request):
        try:
            await authenticate(request, self.resolver, self.replay, self.bus, self.me.subscriber_id,
                               header="X-Gateway-Authorization", expect_type="BG", type_of=self._type_of)
            body = await self._verify(request)
        except Rejected as r:
            return r.response
        except (ValueError, KeyError):
            return nack("CONTEXT_MISSING", "malformed search", 400, "CONTEXT-ERROR")
        query = (body["message"].get("intent", {}).get("item", {}).get("descriptor", {}).get("name") or "").lower()
        providers = []
        for s in self.sellers.values():
            items = [i for i in s.items if not query or query in i["name"].lower()]
            if items:
                providers.append({"id": s.id, "descriptor": {"name": s.name},
                                  "items": [{"id": i["id"], "descriptor": {"name": i["name"]},
                                             "price": {"currency": "INR", "value": i["price"]}} for i in items],
                                  "tags": [{"code": "delivery_promise_s", "value": str(s.promise_s)}],
                                  "sakshi_credential": s.credential})
        if providers:
            spawn(self._callback(body["context"], "on_search",
                                 {"catalog": {"bpp/descriptor": {"name": self.me.subscriber_id},
                                              "bpp/providers": providers}}))
        return ACK

    # ------------------------------------------------------------------ select
    def _price(self, seller: Seller, items: list[dict]) -> tuple[int, list[dict]]:
        by_id = {i["id"]: i for i in seller.items}
        lines, total = [], 0
        for it in items:
            item = by_id[it["id"]]
            qty = int(it.get("quantity", {}).get("count", 1))
            total += _paise(item["price"]) * qty
            lines.append({"id": item["id"], "name": item["name"], "qty": qty, "unit_price": item["price"]})
        return total, lines

    async def select(self, request: Request):
        try:
            body = await self._verify(request)
        except Rejected as r:
            return r.response
        order = body["message"]["order"]
        seller = self.sellers.get(order["provider"]["id"])
        if seller is None:
            return nack("UNKNOWN_PROVIDER", "no such seller here", 404, "DOMAIN-ERROR")
        try:
            total, lines = self._price(seller, order["items"])
        except KeyError:
            return nack("UNKNOWN_ITEM", "item not in catalogue", 404, "DOMAIN-ERROR")
        ctx = body["context"]
        quote = new_receipt("QUOTE", self.me.subscriber_id, ctx["bap_id"], ctx["transaction_id"], "-", seller.id,
                            order.get("sakshi_buyer_ref", ""), {
                                "items": lines, "price": {"currency": "INR", "value": _money(total)},
                                "promised_delivery_s": seller.promise_s,
                                "valid_until": int(time.time()) + 120})
        spawn(self._callback(ctx, "on_select", {"order": {
            "provider": {"id": seller.id}, "items": order["items"],
            "quote": {"price": {"currency": "INR", "value": _money(total)}, "breakup": lines},
            "sakshi_receipt": self._sign(quote)}}))
        return ACK

    async def init(self, request: Request):
        try:
            body = await self._verify(request)
        except Rejected as r:
            return r.response
        order = body["message"]["order"]
        spawn(self._callback(body["context"], "on_init", {"order": {
            **order, "payment": {"type": "ON-FULFILLMENT", "collected_by": "BPP", "status": "NOT-PAID"}}}))
        return ACK

    # ----------------------------------------------------------------- confirm
    async def confirm(self, request: Request):
        try:
            body = await self._verify(request)
        except Rejected as r:
            return r.response
        ctx, order = body["context"], body["message"]["order"]
        seller = self.sellers.get(order["provider"]["id"])
        if seller is None:
            return nack("UNKNOWN_PROVIDER", "no such seller here", 404, "DOMAIN-ERROR")
        total, lines = self._price(seller, order["items"])
        if seller.profile == "bait":
            total = total * 125 // 100          # quietly raises the price at confirmation
        now = int(time.time())
        order_id = f"{seller.id}-{uuid.uuid4().hex[:8]}"
        buyer = order.get("sakshi_buyer_ref", "")
        contract = new_receipt("ORDER_CONTRACT", self.me.subscriber_id, ctx["bap_id"], ctx["transaction_id"],
                               order_id, seller.id, buyer, {
                                   "items": lines, "price": {"currency": "INR", "value": _money(total)},
                                   "promised_delivery_by": now + seller.promise_s,
                                   "cancellation_policy": "free before dispatch",
                               }, evidence={"quote_receipt_id": order.get("sakshi_quote_id", "")}, issued_at=now)
        self.orders[order_id] = {"ctx": ctx, "seller": seller.id, "buyer": buyer, "status": "Accepted",
                                 "fake": bool(order.get("sakshi_sim_fake")), "promised_by": now + seller.promise_s}
        seller.stats["orders"] += 1
        spawn(self._callback(ctx, "on_confirm", {"order": {
            "id": order_id, "state": "Accepted", "provider": {"id": seller.id}, "items": order["items"],
            "quote": {"price": {"currency": "INR", "value": _money(total)}},
            "sakshi_receipt": self._sign(contract)}}))
        if seller.profile != "bait":
            spawn(self._fulfil(order_id))
        return ACK

    async def _fulfil(self, order_id: str) -> None:
        o = self.orders[order_id]
        seller = self.sellers[o["seller"]]
        p, r = seller.promise_s, self.rng.random
        if seller.profile == "ghost":
            return                                         # takes the order, never shows up
        if seller.profile == "flaky" and r() < 0.45:
            await asyncio.sleep(p * (0.1 + 0.2 * r()) * self.time_scale)
            await self._cancel(order_id)
            return
        if seller.profile == "booster" and o["fake"]:
            delay = p * 0.02 * (0.5 + r())                 # nothing to ship: instant "delivery"
        elif seller.profile == "slow" and r() < 0.55:
            delay = p * (1.15 + 0.6 * r())
        else:
            delay = p * (0.3 + 0.45 * r())
        await asyncio.sleep(delay * self.time_scale)
        o["status"] = "Completed"
        seller.stats["delivered"] += 1
        receipt = new_receipt("FULFILMENT", self.me.subscriber_id, o["ctx"]["bap_id"], o["ctx"]["transaction_id"],
                              order_id, seller.id, o["buyer"], {"delivered_at": int(time.time()), "state": "Completed"})
        await self._callback(o["ctx"], "on_status", {"order": {"id": order_id, "state": "Completed",
                                                               "sakshi_receipt": self._sign(receipt)}})

    async def _cancel(self, order_id: str) -> None:
        o = self.orders[order_id]
        o["status"] = "Cancelled"
        self.sellers[o["seller"]].stats["cancelled"] += 1
        receipt = new_receipt("CANCELLATION", self.me.subscriber_id, o["ctx"]["bap_id"], o["ctx"]["transaction_id"],
                              order_id, o["seller"], o["buyer"], {"cancelled_by": "seller", "reason": "out of stock"})
        await self._callback(o["ctx"], "on_cancel", {"order": {"id": order_id, "state": "Cancelled",
                                                               "sakshi_receipt": self._sign(receipt)}})

    async def status(self, request: Request):
        try:
            body = await self._verify(request)
        except Rejected as r:
            return r.response
        o = self.orders.get(body["message"].get("order_id", ""))
        if o is None:
            return nack("UNKNOWN_ORDER", "no such order", 404, "DOMAIN-ERROR")
        spawn(self._callback(body["context"], "on_status",
                             {"order": {"id": body["message"]["order_id"], "state": o["status"]}}))
        return ACK
