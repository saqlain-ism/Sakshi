"""Buyer app (BAP): runs the order flow for its users and holds sellers to their word.

For every order it:
  1. searches through the gateway and gathers offers from all seller apps,
  2. checks each seller's GST credential and drops sellers whose
     credential is missing, forged or revoked,
  3. ranks the rest by verifiable reputation and steers buyers away from
     sellers flagged for collusion,
  4. keeps the seller-signed quote, and on confirmation checks the seller
     signed the *same* terms. If the price changed, it refuses to
     countersign and files a dispute using the seller's own signatures,
  5. countersigns contracts, deliveries and cancellations and logs them
     with the witness, keeping the inclusion proofs,
  6. files disputes for its buyers when a promise is broken.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
import uuid
from collections import deque
from dataclasses import dataclass, field

import httpx
from fastapi import APIRouter, Request

from sakshi.client import RegistryResolver, SignedClient
from sakshi.credentials import Credential, CredentialError, verify_credential, verify_status_list
from sakshi.receipts import Receipt, ReceiptError, verify_receipt

from .common import ACK, EventBus, Participant, Rejected, authenticate, buyer_ref, context, nack, spawn
from .registry import on_subscribe_router

CALLBACKS = ("on_search", "on_select", "on_init", "on_confirm", "on_status", "on_cancel")


@dataclass
class Order:
    order_id: str
    transaction_id: str
    buyer: str
    seller_id: str
    seller_name: str
    bpp_id: str
    bpp_uri: str
    price: str
    promised_by: int
    status: str
    created: float = field(default_factory=time.time)
    contract: dict | None = None
    quote: dict | None = None
    ledger: dict = field(default_factory=dict)        # receipt type -> {index, root}
    disputes: list[dict] = field(default_factory=list)
    delivered_at: int | None = None
    fake: bool = False

    def summary(self) -> dict:
        return {k: getattr(self, k) for k in ("order_id", "transaction_id", "buyer", "seller_id", "seller_name",
                                              "bpp_id", "price", "promised_by", "status", "created", "ledger",
                                              "disputes", "delivered_at")}


class BuyerApp:
    def __init__(self, me: Participant, http: httpx.AsyncClient, resolver: RegistryResolver, replay, bus: EventBus,
                 registry_encryption_public: str, gateway_url: str, ledger_url: str, issuer_id: str, issuer_url: str,
                 time_scale: float = 1.0, search_window_s: float = 1.0, rng: random.Random | None = None) -> None:
        self.me = me
        self.http = http
        self.resolver = resolver
        self.replay = replay
        self.bus = bus
        self.gateway_url = gateway_url
        self.ledger_url = ledger_url
        self.issuer_id = issuer_id
        self.issuer_url = issuer_url
        self.time_scale = time_scale
        self.search_window_s = search_window_s
        self.rng = rng or random.Random()
        self.orders: dict[str, Order] = {}
        self.recent: deque[str] = deque(maxlen=300)
        self._inbox: dict[tuple[str, str], asyncio.Queue] = {}
        self._revoked: tuple[float, set[str]] = (0.0, set())
        self._trust: tuple[float, dict, set[str]] = (0.0, {}, set())
        self._cred_warned: dict[str, float] = {}
        self.sellers_seen: dict[str, dict] = {}
        self.router = APIRouter()
        self.router.include_router(on_subscribe_router(lambda: self.me, registry_encryption_public, bus))
        for action in CALLBACKS:
            self.router.add_api_route(f"/{action}", self._make_callback(action), methods=["POST"])
        self.router.add_api_route("/api/orders", self.api_place_order, methods=["POST"])
        self.router.add_api_route("/api/orders", self.api_orders, methods=["GET"])
        self.router.add_api_route("/api/sellers", self.api_sellers, methods=["GET"])

    def start(self) -> None:
        spawn(self._watch_promises())

    @property
    def client(self) -> SignedClient:
        return SignedClient(self.me.subscriber_id, self.me.unique_key_id, self.me.keys.signing_private, self.http)

    # ---------------------------------------------------------------- inbound
    def _make_callback(self, action: str):
        async def handler(request: Request):
            try:
                body = json.loads(await request.body())
                claimed = body["context"]["bpp_id"]
                txn = body["context"]["transaction_id"]
            except (ValueError, KeyError, TypeError):
                return nack("CONTEXT_MISSING", "malformed callback", 400, "CONTEXT-ERROR")
            try:
                await authenticate(request, self.resolver, self.replay, self.bus, self.me.subscriber_id,
                                   expect_signer=claimed)
            except Rejected as r:
                return r.response
            if action in ("on_status", "on_cancel"):
                spawn(self._on_update(action, body))
            elif (q := self._inbox.get((txn, action))) is not None:
                q.put_nowait(body)
            return ACK
        handler.__name__ = action
        return handler

    def _expect(self, txn: str, action: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._inbox[(txn, action)] = q
        return q

    async def _wait(self, txn: str, action: str, timeout: float = 8.0) -> dict:
        try:
            return await asyncio.wait_for(self._inbox[(txn, action)].get(), timeout)
        finally:
            self._inbox.pop((txn, action), None)

    async def _send(self, url: str, action: str, payload: dict) -> None:
        r = await self.client.post(f"{url}/{action}", payload)
        if r.status_code != 200:
            raise RuntimeError(f"{action} refused: {r.text[:200]}")

    # ------------------------------------------------------------ trust inputs
    async def _revocations(self) -> set[str]:
        ts, revoked = self._revoked
        if time.time() - ts < 5:
            return revoked
        status = (await self.http.get(f"{self.issuer_url}/status")).json()
        key = await self.resolver.resolve(self.issuer_id, status["proof"]["key_id"])
        revoked = verify_status_list(status, key.signing_public_key) if key else set()
        self._revoked = (time.time(), revoked)
        return revoked

    async def _trust_view(self) -> tuple[dict, set[str]]:
        ts, reps, flagged = self._trust
        if time.time() - ts < 2:
            return reps, flagged
        try:
            reps = (await self.http.get(f"{self.ledger_url}/reputation")).json()["sellers"]
            flagged = set((await self.http.get(f"{self.ledger_url}/fraud")).json()["flagged"])
        except (httpx.HTTPError, ValueError, KeyError):
            pass
        self._trust = (time.time(), reps, flagged)
        return reps, flagged

    async def check_credential(self, bpp_id: str, provider: dict) -> str | None:
        """None if the seller's credential is valid, else the reason it isn't."""
        raw = provider.get("sakshi_credential")
        if not raw:
            return "no credential"
        try:
            await verify_credential(Credential.from_dict(raw), self.resolver, {self.issuer_id},
                                    expected_subject=f"{bpp_id}/{provider['id']}", revoked=await self._revocations())
            return None
        except CredentialError as exc:
            return exc.code
        except (KeyError, TypeError):
            return "malformed credential"

    # ------------------------------------------------------------- the flow
    async def place_order(self, buyer: str, query: str, seller_id: str | None = None, fake: bool = False) -> dict:
        txn = str(uuid.uuid4())
        ref = buyer_ref(buyer, self.me.subscriber_id, self.me.keys.signing_private)
        results = self._expect(txn, "on_search")
        await self._send(self.gateway_url, "search", {
            "context": context("search", self.me, txn),
            "message": {"intent": {"item": {"descriptor": {"name": query}},
                                   "fulfillment": {"type": "Delivery"}}}})
        await asyncio.sleep(self.search_window_s)
        self._inbox.pop((txn, "on_search"), None)
        offers = []
        while not results.empty():
            cat = results.get_nowait()
            for p in cat["message"]["catalog"]["bpp/providers"]:
                offers.append((cat["context"], p))
        if not offers:
            return {"status": "NO_OFFERS", "transaction_id": txn}

        reps, flagged = await self._trust_view()
        candidates = []
        for ctx, p in offers:
            if seller_id and p["id"] != seller_id:
                continue
            problem = await self.check_credential(ctx["bpp_id"], p)
            cred = (p.get("sakshi_credential") or {}).get("body", {})
            self.sellers_seen[p["id"]] = {"seller_id": p["id"], "name": p["descriptor"]["name"], "bpp_id": ctx["bpp_id"],
                                          "credential": problem or "verified",
                                          "gstin": cred.get("claims", {}).get("gstin")}
            if problem:
                if time.time() - self._cred_warned.get(p["id"], 0) > 60:     # one notice a minute, not per search
                    self._cred_warned[p["id"]] = time.time()
                    self.bus.emit("auth", self.me.subscriber_id,
                                  f"hiding seller {p['id']} from all buyers: GST credential failed ({problem})",
                                  "blocked", seller_id=p["id"], code=problem)
                continue
            score = (reps.get(p["id"]) or {}).get("score", 66.7)
            weight = (score / 100) ** 4 * (0.05 if p["id"] in flagged else 1.0)
            candidates.append((weight, ctx, p))
        if not candidates:
            return {"status": "NO_TRUSTED_SELLER", "transaction_id": txn}
        if seller_id:
            _, ctx, provider = candidates[0]
        else:
            _, ctx, provider = self.rng.choices(candidates, weights=[c[0] for c in candidates])[0]
        return await self._buy(txn, buyer, ref, ctx, provider, fake)

    async def _buy(self, txn: str, buyer: str, ref: str, search_ctx: dict, provider: dict, fake: bool) -> dict:
        bpp = {"bpp_id": search_ctx["bpp_id"], "bpp_uri": search_ctx["bpp_uri"]}
        item = provider["items"][0]
        items = [{"id": item["id"], "quantity": {"count": 1 + self.rng.randrange(3)}}]
        base = {"provider": {"id": provider["id"]}, "items": items, "sakshi_buyer_ref": ref}

        # select -> signed quote
        self._expect(txn, "on_select")
        await self._send(bpp["bpp_uri"], "select", {"context": context("select", self.me, txn, bpp),
                                                    "message": {"order": base}})
        on_select = await self._wait(txn, "on_select")
        quote = Receipt.from_dict(on_select["message"]["order"]["sakshi_receipt"])
        await verify_receipt(quote, self.resolver, require_countersignature=False)
        if quote.issuer != bpp["bpp_id"] or quote.body["seller_id"] != provider["id"]:
            raise ReceiptError("QUOTE_MISMATCH", "quote not issued by the seller we asked")

        # init
        self._expect(txn, "on_init")
        await self._send(bpp["bpp_uri"], "init", {"context": context("init", self.me, txn, bpp), "message": {
            "order": {**base, "billing": {"name": buyer}, "fulfillment": {"type": "Delivery"}}}})
        await self._wait(txn, "on_init")

        # confirm -> signed contract
        self._expect(txn, "on_confirm")
        await self._send(bpp["bpp_uri"], "confirm", {"context": context("confirm", self.me, txn, bpp), "message": {
            "order": {**base, "sakshi_quote_id": quote.receipt_id, "sakshi_sim_fake": fake}}})
        on_confirm = await self._wait(txn, "on_confirm")
        contract = Receipt.from_dict(on_confirm["message"]["order"]["sakshi_receipt"])
        await verify_receipt(contract, self.resolver, require_countersignature=False)

        cb, qb = contract.body, quote.body
        order = Order(cb["order_id"], txn, buyer, provider["id"], provider["descriptor"]["name"], bpp["bpp_id"],
                      bpp["bpp_uri"], cb["terms"]["price"]["value"], cb["terms"]["promised_delivery_by"], "CONFIRMING",
                      contract=contract.to_dict(), quote=quote.to_dict(), fake=fake)
        self.orders[order.order_id] = order
        self.recent.append(order.order_id)

        if cb["terms"]["price"] != qb["terms"]["price"] or cb["terms"]["items"] != qb["terms"]["items"] \
                or cb["issuer"] != qb["issuer"]:
            order.status = "REFUSED_PRICE_CHANGED"
            self.bus.emit("order", self.me.subscriber_id,
                          f"{provider['id']} quoted Rs {qb['terms']['price']['value']} but confirmed "
                          f"Rs {cb['terms']['price']['value']}: refusing to countersign", "blocked",
                          order_id=order.order_id, seller_id=provider["id"])
            await self.raise_dispute(order, "PRICE_MISMATCH", evidence=[quote.to_dict(), contract.to_dict()])
            return order.summary()

        contract.countersign(self.me.unique_key_id, self.me.keys.signing_private)
        order.contract = contract.to_dict()
        await self._log(order, contract)
        order.status = "CONFIRMED"
        self.bus.emit("order", self.me.subscriber_id,
                      f"{buyer} ordered from {provider['descriptor']['name']} for Rs {order.price}; "
                      f"contract countersigned and logged", "success", order_id=order.order_id)
        return order.summary()

    async def _log(self, order: Order, receipt: Receipt) -> dict:
        r = await self.client.post(f"{self.ledger_url}/entries", {"receipt": receipt.to_dict()})
        data = r.json()
        if r.status_code != 200:
            raise RuntimeError(f"ledger refused {receipt.body['type']}: {data.get('error')}")
        order.ledger[receipt.body["type"]] = {"index": data["index"], "root": data["sth"]["root_hash"],
                                              "tree_size": data["sth"]["tree_size"]}
        return data

    async def _on_update(self, action: str, body: dict) -> None:
        o = body["message"]["order"]
        order = self.orders.get(o.get("id", ""))
        raw = o.get("sakshi_receipt")
        if order is None or raw is None or order.status not in ("CONFIRMED", "OVERDUE"):
            return
        receipt = Receipt.from_dict(raw)
        try:
            await verify_receipt(receipt, self.resolver, require_countersignature=False)
            if receipt.issuer != order.bpp_id or receipt.body["order_id"] != order.order_id:
                raise ReceiptError("RECEIPT_MISMATCH", "receipt is for a different order or seller")
        except ReceiptError as exc:
            self.bus.emit("order", self.me.subscriber_id, f"ignored bad {action} receipt: {exc}", "blocked")
            return
        # In the simulation the buyer confirms what actually happened; in a real app this
        # is the buyer tapping "received" (or an OTP handed to the delivery agent).
        receipt.countersign(self.me.unique_key_id, self.me.keys.signing_private)
        try:
            await self._log(order, receipt)
        except RuntimeError as exc:
            self.bus.emit("ledger", self.me.subscriber_id, str(exc), "warning")
            return
        if receipt.body["type"] == "FULFILMENT":
            order.delivered_at = receipt.body["terms"]["delivered_at"]
            order.status = "DELIVERED" if order.delivered_at <= order.promised_by else "DELIVERED_LATE"
            late = order.status == "DELIVERED_LATE"
            self.bus.emit("order", self.me.subscriber_id,
                          f"{order.seller_name} delivered {order.order_id}{' LATE' if late else ' on time'}",
                          "warning" if late else "success", order_id=order.order_id)
            if late and not order.fake and self.rng.random() < 0.6:
                await self.raise_dispute(order, "LATE_DELIVERY")
        else:
            order.status = "CANCELLED_BY_SELLER"
            self.bus.emit("order", self.me.subscriber_id, f"{order.seller_name} cancelled {order.order_id}", "warning")

    # -------------------------------------------------------------- disputes
    async def raise_dispute(self, order: Order, claim: str, evidence: list[dict] | None = None) -> dict:
        r = await self.client.post(f"{self.ledger_url}/disputes",
                                   {"order_id": order.order_id, "claim": claim, "evidence": evidence or []})
        result = r.json()
        verdict = result.get("verdict") or {"outcome": "ERROR", "reason": json.dumps(result.get("error"))}
        order.disputes.append({"claim": claim, "outcome": verdict["outcome"], "reason": verdict["reason"],
                               "ledger_index": result.get("logged", {}).get("index")})
        return result

    async def _watch_promises(self) -> None:
        """Buyers complain when a promise is broken: overdue orders become disputes."""
        while True:
            await asyncio.sleep(2)
            now = time.time()
            for order in list(self.orders.values()):
                # complain once the order is a full promise-window overdue (late deliveries still count)
                window = order.promised_by - order.contract["body"]["issued_at"]
                if order.status == "CONFIRMED" and now > order.promised_by + max(5, window) and not order.disputes:
                    order.status = "OVERDUE"
                    try:
                        await self.raise_dispute(order, "NOT_DELIVERED")
                    except (httpx.HTTPError, ValueError) as exc:
                        self.bus.emit("dispute", self.me.subscriber_id, f"could not file dispute: {exc}", "warning")

    # ---------------------------------------------------------------- API
    async def api_place_order(self, payload: dict):
        try:
            # `sim_fake` exists only for the simulation: it tells the colluding seller that this
            # buyer is one of its own sock puppets (in reality the seller simply knows).
            return await self.place_order(payload.get("buyer", "demo-user"), payload.get("query", ""),
                                          payload.get("seller_id"), bool(payload.get("sim_fake")))
        except (TimeoutError, ReceiptError, RuntimeError, httpx.HTTPError) as exc:
            return nack("ORDER_FAILED", f"{type(exc).__name__}: {exc}", 502)

    async def api_orders(self, limit: int = 50):
        ids = list(self.recent)[-limit:]
        return [self.orders[i].summary() for i in reversed(ids)]

    async def api_sellers(self):
        return sorted(self.sellers_seen.values(), key=lambda s: s["seller_id"])
