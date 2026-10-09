"""The Sakshi witness: an append-only transparency log of signed commitments.

Participants submit receipts that *both* sides have signed. The witness
checks the signatures and basic consistency (no delivery without a
contract, no double delivery), appends the receipt to the Merkle log, and
hands back an inclusion proof plus a Signed Tree Head.

On top of the log it serves:
  * reputation  - recomputable from the log (sakshi.reputation)
  * disputes    - evidence-based verdicts, themselves logged (sakshi.disputes)
  * fraud       - collusion analysis over the trade graph (sakshi.fraud)

The witness is *not* trusted blindly. Independent auditors (see Auditor
below) keep the tree heads they've seen and demand consistency proofs, so a
witness that edits or deletes history gets caught.
"""

from __future__ import annotations

import asyncio
import json
import random
import sqlite3
import time
from dataclasses import dataclass

import httpx
from fastapi import APIRouter, Query, Request

from sakshi.canonical import canonical_json
from sakshi.client import RegistryResolver
from sakshi.crypto import b64d, b64e
from sakshi.disputes import CLAIMS, decide
from sakshi.fraud import detect_collusion
from sakshi.merkle import MerkleTree, SignedTreeHead, leaf_hash, verify_consistency, verify_inclusion
from sakshi.orders import LedgerEntry, build_orders
from sakshi.receipts import Receipt, ReceiptError, new_receipt, verify_receipt
from sakshi.reputation import compute_reputation

from .common import EventBus, Participant, Rejected, authenticate, nack
from .registry import on_subscribe_router

MAX_RECEIPT_AGE_S = 300
LOGGABLE = {"ORDER_CONTRACT", "FULFILMENT", "CANCELLATION"}


@dataclass
class Stored:
    index: int
    logged_at: int
    data: bytes                     # canonical receipt bytes (exactly what was hashed)

    @property
    def receipt(self) -> dict:
        return json.loads(self.data)


class LogStore:
    """Entries + Merkle tree, optionally persisted to SQLite."""

    def __init__(self, path: str | None = None) -> None:
        self.entries: list[Stored] = []
        self.tree = MerkleTree()
        self.by_receipt: dict[str, int] = {}
        self.db = sqlite3.connect(path, check_same_thread=False) if path else None
        if self.db:
            self.db.execute("CREATE TABLE IF NOT EXISTS entries (idx INTEGER PRIMARY KEY, logged_at INTEGER, data BLOB)")
            for idx, ts, data in self.db.execute("SELECT idx, logged_at, data FROM entries ORDER BY idx"):
                self._load(Stored(idx, ts, bytes(data)))

    def _load(self, s: Stored) -> None:
        self.entries.append(s)
        self.tree.append(s.data)
        self.by_receipt[Receipt.from_dict(s.receipt).receipt_id] = s.index

    def append(self, receipt: Receipt) -> Stored:
        s = Stored(len(self.entries), int(time.time()), receipt.to_bytes())
        self._load(s)
        if self.db:
            self.db.execute("INSERT INTO entries VALUES (?, ?, ?)", (s.index, s.logged_at, s.data))
            self.db.commit()
        return s

    def ledger_entries(self, size: int | None = None) -> list[LedgerEntry]:
        rows = self.entries if size is None else self.entries[:size]
        return [LedgerEntry(s.index, s.logged_at, s.receipt) for s in rows]

    def __len__(self) -> int:
        return len(self.entries)


class Witness:
    def __init__(self, me: Participant, http: httpx.AsyncClient, resolver: RegistryResolver, replay,
                 bus: EventBus, registry_encryption_public: str, db_path: str | None = None) -> None:
        self.me = me
        self.http = http
        self.resolver = resolver
        self.replay = replay
        self.bus = bus
        self.store = LogStore(db_path)
        self._sth: SignedTreeHead | None = None
        self._cache: dict[str, tuple[int, object]] = {}
        self._lock = asyncio.Lock()
        self._pristine: dict[int, bytes] = {}          # only used by the attack lab, to undo a tamper demo
        self.router = APIRouter()
        self.router.include_router(on_subscribe_router(lambda: self.me, registry_encryption_public, bus))
        r = self.router
        r.add_api_route("/entries", self.submit, methods=["POST"])
        r.add_api_route("/entries", self.get_entries, methods=["GET"])
        r.add_api_route("/sth", self.get_sth, methods=["GET"])
        r.add_api_route("/proof/inclusion", self.inclusion, methods=["GET"])
        r.add_api_route("/proof/consistency", self.consistency, methods=["GET"])
        r.add_api_route("/receipts/{receipt_id}", self.find_receipt, methods=["GET"])
        r.add_api_route("/orders/{order_id}", self.order_history, methods=["GET"])
        r.add_api_route("/reputation", self.reputation_all, methods=["GET"])
        r.add_api_route("/reputation/{seller_id}", self.reputation_one, methods=["GET"])
        r.add_api_route("/fraud", self.fraud, methods=["GET"])
        r.add_api_route("/disputes", self.dispute, methods=["POST"])

    # ------------------------------------------------------------------- heads
    def sth(self) -> SignedTreeHead:
        size = len(self.store)
        if self._sth is None or self._sth.tree_size != size:
            self._sth = SignedTreeHead.create(self.me.subscriber_id, size, self.store.tree.root(size),
                                              self.me.unique_key_id, self.me.keys.signing_private)
        return self._sth

    def _append(self, receipt: Receipt) -> dict:
        s = self.store.append(receipt)
        head = self.sth()
        proof = self.store.tree.inclusion_proof(s.index, head.tree_size)
        return {"index": s.index, "receipt_id": receipt.receipt_id, "leaf_hash": b64e(leaf_hash(s.data)),
                "sth": head.to_dict(), "inclusion_proof": [b64e(p) for p in proof]}

    # ------------------------------------------------------------------ submit
    def _semantic_check(self, r: Receipt) -> str | None:
        b = r.body
        orders, _ = build_orders(self.store.ledger_entries())
        o = orders.get(b["order_id"])
        if b["type"] == "ORDER_CONTRACT":
            return "an order contract for this order_id is already logged" if o else None
        if o is None:
            return f"no logged contract for order {b['order_id']}"
        if (o.bpp_id, o.seller_id, o.bap_id) != (b["issuer"], b["seller_id"], b["counterparty"]):
            return "receipt parties don't match the order contract"
        if o.delivered_at is not None or o.cancelled_by is not None:
            return f"order {b['order_id']} is already closed"
        return None

    async def submit(self, request: Request):
        try:
            payload = json.loads(await request.body())
            receipt = Receipt.from_dict(payload["receipt"])
            parties = (receipt.issuer, receipt.counterparty)
        except (ValueError, KeyError, TypeError):
            return nack("LEDGER_MALFORMED", "expected {'receipt': {...}}", 400, "JSON-SCHEMA-ERROR")
        try:
            sender, _ = await authenticate(request, self.resolver, self.replay, self.bus, self.me.subscriber_id)
        except Rejected as rj:
            return rj.response
        if sender.subscriber_id not in parties:
            return nack("LEDGER_NOT_A_PARTY", "only a party to the receipt may log it", 403)
        if receipt.body.get("type") not in LOGGABLE:
            return nack("LEDGER_TYPE", f"{receipt.body.get('type')} receipts are not logged directly", 400)

        async with self._lock:
            existing = self.store.by_receipt.get(receipt.receipt_id)
            if existing is not None:          # idempotent: same receipt, same answer
                head = self.sth()
                return {"index": existing, "receipt_id": receipt.receipt_id, "duplicate": True, "sth": head.to_dict(),
                        "inclusion_proof": [b64e(p) for p in self.store.tree.inclusion_proof(existing, head.tree_size)]}
            if abs(time.time() - receipt.body.get("issued_at", 0)) > MAX_RECEIPT_AGE_S:
                return nack("LEDGER_STALE", "receipt timestamp too far from now: backdating is not accepted", 400)
            try:
                await verify_receipt(receipt, self.resolver, require_countersignature=True)
            except ReceiptError as exc:
                self.bus.emit("ledger", self.me.subscriber_id, f"rejected receipt: {exc}", "blocked", code=exc.code)
                return nack(exc.code, str(exc), 400)
            if problem := self._semantic_check(receipt):
                self.bus.emit("ledger", self.me.subscriber_id, f"rejected receipt: {problem}", "blocked")
                return nack("LEDGER_INCONSISTENT", problem, 409)
            result = self._append(receipt)
        b = receipt.body
        self.bus.emit("ledger", self.me.subscriber_id,
                      f"#{result['index']} {b['type']} {b['order_id']} ({b['seller_id']}) "
                      f"signed by {b['issuer']} + {b['counterparty']}", "success",
                      index=result["index"], type=b["type"], root=result["sth"]["root_hash"])
        return result

    # ------------------------------------------------------------------- reads
    async def get_entries(self, start: int = Query(0, ge=0), end: int | None = Query(None)):
        end = min(len(self.store), start + 1000 if end is None else end)
        return [{"index": s.index, "logged_at": s.logged_at, "receipt": s.receipt}
                for s in self.store.entries[start:end]]

    async def get_sth(self):
        return self.sth().to_dict()

    async def inclusion(self, index: int = Query(..., ge=0), tree_size: int | None = Query(None)):
        size = tree_size or len(self.store)
        try:
            proof = self.store.tree.inclusion_proof(index, size)
        except ValueError:
            return nack("PROOF_RANGE", "index/tree_size out of range", 400)
        return {"index": index, "tree_size": size, "proof": [b64e(p) for p in proof]}

    async def consistency(self, first: int = Query(..., ge=1), second: int | None = Query(None)):
        second = second or len(self.store)
        try:
            proof = self.store.tree.consistency_proof(first, second)
        except ValueError:
            return nack("PROOF_RANGE", "sizes out of range", 400)
        return {"first": first, "second": second, "proof": [b64e(p) for p in proof]}

    async def find_receipt(self, receipt_id: str):
        idx = self.store.by_receipt.get(receipt_id)
        if idx is None:
            return nack("NOT_FOUND", "receipt not in log", 404)
        return {"index": idx, "receipt": self.store.entries[idx].receipt}

    async def order_history(self, order_id: str):
        rows = [{"index": s.index, "type": s.receipt["body"]["type"], "receipt": s.receipt}
                for s in self.store.entries if s.receipt["body"]["order_id"] == order_id]
        return rows or nack("NOT_FOUND", "order not in log", 404)

    def _cached(self, name: str, compute):
        size = len(self.store)
        hit = self._cache.get(name)
        if hit and hit[0] == size:
            return hit[1]
        value = compute()
        self._cache[name] = (size, value)
        return value

    def reputation_snapshot(self) -> dict:
        head = self.sth()
        # as_of is part of the signed head, so anyone can recompute exactly this result
        reps = compute_reputation(self.store.ledger_entries(head.tree_size), as_of=head.timestamp)
        return {"computed_over": {"tree_size": head.tree_size, "root_hash": head.root_hash, "as_of": head.timestamp},
                "sellers": {k: v.to_dict() for k, v in reps.items()}}

    async def reputation_all(self):
        return self.reputation_snapshot()

    async def reputation_one(self, seller_id: str):
        snap = self.reputation_snapshot()
        rep = snap["sellers"].get(seller_id)
        return {"computed_over": snap["computed_over"], "reputation": rep} if rep else nack("NOT_FOUND", "no history", 404)

    def fraud_report(self) -> dict:
        def compute():
            risks = detect_collusion(self.store.ledger_entries())
            return {"tree_size": len(self.store), "sellers": [r.to_dict() for r in risks],
                    "flagged": [r.seller_id for r in risks if r.flagged]}
        return self._cached("fraud", compute)

    async def fraud(self):
        return self.fraud_report()

    # ---------------------------------------------------------------- disputes
    async def dispute(self, request: Request):
        try:
            payload = json.loads(await request.body())
            order_id, claim = payload["order_id"], payload["claim"]
            evidence = [Receipt.from_dict(e) for e in payload.get("evidence", [])]
        except (ValueError, KeyError, TypeError):
            return nack("DISPUTE_MALFORMED", "expected order_id, claim, evidence[]", 400, "JSON-SCHEMA-ERROR")
        try:
            sender, _ = await authenticate(request, self.resolver, self.replay, self.bus, self.me.subscriber_id)
        except Rejected as rj:
            return rj.response
        if claim not in CLAIMS:
            return nack("DISPUTE_CLAIM", f"claim must be one of {sorted(CLAIMS)}", 400)
        for e in evidence:                      # evidence binds its issuer, so the issuer's signature is enough
            try:
                await verify_receipt(e, self.resolver, require_countersignature=False)
            except ReceiptError as exc:
                return nack("DISPUTE_BAD_EVIDENCE", f"evidence rejected: {exc}", 400)

        async with self._lock:
            orders, verdicts = build_orders(self.store.ledger_entries())
            order = orders.get(order_id)
            if order is not None:
                bap, seller, bpp, txn, buyer = order.bap_id, order.seller_id, order.bpp_id, "-", order.buyer_ref
            elif evidence:
                eb = evidence[0].body
                bap, seller, bpp, txn, buyer = eb["counterparty"], eb["seller_id"], eb["issuer"], eb["transaction_id"], eb["buyer_ref"]
            else:
                return nack("DISPUTE_UNKNOWN_ORDER", "order not in ledger and no evidence supplied", 404)
            if sender.subscriber_id != bap:
                return nack("DISPUTE_NOT_A_PARTY", "only the buyer's app can raise a dispute for this order", 403)
            if any(v.body["order_id"] == order_id and v.body["terms"]["claim"] == claim for v in verdicts):
                return nack("DISPUTE_DUPLICATE", "this claim was already decided", 409)

            verdict = decide(claim, order, as_of=int(time.time()), evidence=evidence)
            result = {"verdict": verdict.to_terms()}
            if verdict.outcome != "REJECTED":
                vr = new_receipt("DISPUTE_VERDICT", self.me.subscriber_id, bap, txn, order_id, seller, buyer,
                                 verdict.to_terms(), evidence={"seller_app": bpp})
                vr.sign_as_issuer(self.me.unique_key_id, self.me.keys.signing_private)
                result["logged"] = self._append(vr)
        sev = {"BUYER_WINS": "warning", "SELLER_WINS": "info", "NEEDS_HUMAN_REVIEW": "info"}.get(verdict.outcome, "info")
        self.bus.emit("dispute", self.me.subscriber_id,
                      f"{claim} on {order_id}: {verdict.outcome.replace('_', ' ').lower()} ({verdict.reason})", sev,
                      order_id=order_id, seller_id=seller, outcome=verdict.outcome)
        return result

    # ---------------------------------------------------- attack-lab helpers
    def tamper_entry(self, index: int, rebuild_tree: bool) -> dict:
        """Simulates a dishonest operator editing history. Only used by the attack lab."""
        s = self.store.entries[index]
        self._pristine.setdefault(index, s.data)
        rec = s.receipt
        terms = rec["body"]["terms"]
        if "price" in terms:
            terms["price"] = {"currency": "INR", "value": "1.00"}      # "the buyer only agreed to pay Rs 1"
        elif "delivered_at" in terms:
            terms["delivered_at"] -= 3600                              # "it was delivered an hour earlier"
        else:
            terms["edited"] = True
        s.data = canonical_json(rec)
        if rebuild_tree:              # a careful attacker recomputes the tree so it is self-consistent
            self.store.tree = MerkleTree([leaf_hash(e.data) for e in self.store.entries])
            self._sth = None
        return {"index": index, "rebuilt_tree": rebuild_tree}

    def restore(self) -> int:
        for index, data in self._pristine.items():
            self.store.entries[index].data = data
        n = len(self._pristine)
        self._pristine.clear()
        self.store.tree = MerkleTree([leaf_hash(e.data) for e in self.store.entries])
        self._sth = None
        return n


class Auditor:
    """Independent monitor of the witness, which nobody has to trust.

    Every few seconds it fetches the latest signed tree head and checks:
      1. the head is signed by the witness's registered key,
      2. it is consistent with the last head it accepted (append-only),
      3. a sample of entries really is in the tree (inclusion proofs).
    It never needs the full log to do this.
    """

    def __init__(self, name: str, ledger_url: str, ledger_key: str, http: httpx.AsyncClient, bus: EventBus,
                 sample: int = 3) -> None:
        self.name = name
        self.url = ledger_url.rstrip("/")
        self.ledger_key = ledger_key
        self.http = http
        self.bus = bus
        self.sample = sample
        self.trusted: SignedTreeHead | None = None
        self.checks = 0
        self.violations = 0
        self.last_error: str | None = None

    def _alarm(self, msg: str) -> bool:
        self.violations += 1
        self.last_error = msg
        self.bus.emit("audit", self.name, f"LOG INTEGRITY VIOLATION: {msg}", "critical")
        return False

    async def check(self) -> bool:
        self.checks += 1
        head = SignedTreeHead.from_dict((await self.http.get(f"{self.url}/sth")).json())
        if not head.verify(self.ledger_key):
            return self._alarm("tree head signature invalid")
        old = self.trusted
        if old is not None and head.tree_size < old.tree_size:
            return self._alarm(f"log shrank from {old.tree_size} to {head.tree_size}")
        if old is not None and old.tree_size > 0:
            r = (await self.http.get(f"{self.url}/proof/consistency",
                                     params={"first": old.tree_size, "second": head.tree_size})).json()
            if not verify_consistency(old.tree_size, head.tree_size, old.root, head.root, [b64d(p) for p in r["proof"]]):
                return self._alarm(f"history rewritten: tree {head.tree_size} does not extend the tree "
                                   f"{old.tree_size} published earlier")
        for idx in random.sample(range(head.tree_size), min(self.sample, head.tree_size)):
            if not await self.check_entry(idx, head):
                return False
        self.trusted = head
        self.last_error = None
        return True

    async def check_entry(self, index: int, head: SignedTreeHead) -> bool:
        entry = (await self.http.get(f"{self.url}/entries", params={"start": index, "end": index + 1})).json()[0]
        proof = (await self.http.get(f"{self.url}/proof/inclusion",
                                     params={"index": index, "tree_size": head.tree_size})).json()["proof"]
        leaf = leaf_hash(canonical_json(entry["receipt"]))
        if not verify_inclusion(leaf, index, head.tree_size, [b64d(p) for p in proof], head.root):
            return self._alarm(f"entry #{index} does not match the signed tree (edited after logging)")
        return True

    async def run(self, interval_s: float = 3.0) -> None:
        while True:
            try:
                await self.check()
            except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
                self.last_error = f"audit error: {exc}"
            await asyncio.sleep(interval_s)
