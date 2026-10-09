"""Operations console: the live dashboard, attack lab and "verify it yourself".

Everything the console shows is fetched over the same public APIs any
participant could use, so the dashboard has no backdoor into the services
(apart from the attack lab's explicitly labelled admin actions).
"""

from __future__ import annotations

import asyncio
import time
from importlib import resources

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from sakshi.auth import KeyRecord
from sakshi.canonical import canonical_json
from sakshi.client import RegistryResolver
from sakshi.crypto import b64d
from sakshi.merkle import SignedTreeHead, leaf_hash, verify_inclusion
from sakshi.receipts import Receipt, ReceiptError, verify_receipt

from .attacks import CATALOG, AttackLab
from .common import EventBus, spawn
from .ledger import Auditor
from .simulator import Simulator
from .world import Topology


class Console:
    def __init__(self, topo: Topology, http: httpx.AsyncClient, bus: EventBus, sim: Simulator | None,
                 event_sources: list[str] | None = None) -> None:
        self.t = topo
        self.http = http
        self.bus = bus
        self.sim = sim
        self.sources = event_sources or []
        self._cursors = {s: 0 for s in self.sources}
        self.auditor = Auditor("auditor.independent", topo.url("ledger"), topo.ledger.keys.signing_public, http, bus)
        self.lab = AttackLab(topo, http, bus, self.auditor, sim)
        reg = topo.registry
        self.resolver = RegistryResolver(topo.url("registry"), KeyRecord(
            reg.subscriber_id, reg.unique_key_id, reg.keys.signing_public, 0, 4102444800, "SUBSCRIBED", "REGISTRY"), http)
        self._state: tuple[float, dict] = (0.0, {})
        self.started = time.time()
        self.router = self._routes()

    def start(self) -> None:
        spawn(self.auditor.run())
        if self.sim is not None:
            spawn(self.sim.run())
        if self.sources:
            spawn(self._pull_events())

    async def _pull_events(self) -> None:
        """Docker mode: merge each service's event stream into the console's."""
        while True:
            for src in self.sources:
                try:
                    rows = (await self.http.get(f"{src}/_events", params={"after": self._cursors[src]})).json()
                except (httpx.HTTPError, ValueError):
                    continue
                for e in rows:
                    self._cursors[src] = max(self._cursors[src], e["id"])
                    self.bus.emit(e["kind"], e["actor"], e["summary"], e["severity"], **e.get("detail", {}))
            await asyncio.sleep(1)

    async def _get(self, url: str, **params):
        try:
            r = await self.http.get(url, params=params or None, timeout=10)
            return r.json()
        except (httpx.HTTPError, ValueError):
            return None

    async def state(self) -> dict:
        ts, cached = self._state
        if time.time() - ts < 1.0:
            return cached
        ledger, bap = self.t.url("ledger"), self.t.url("bap")
        participants, sth, rep, fraud, orders, sellers = await asyncio.gather(
            self._get(f"{self.t.url('registry')}/participants"), self._get(f"{ledger}/sth"),
            self._get(f"{ledger}/reputation"), self._get(f"{ledger}/fraud"), self._get(f"{bap}/api/orders", limit=30),
            self._get(f"{bap}/api/sellers"))
        a = self.auditor
        state = {
            "now": time.time(), "uptime_s": round(time.time() - self.started),
            "participants": participants or [], "sth": sth, "reputation": rep, "fraud": fraud, "orders": orders or [],
            "sellers": sellers or [],
            "auditor": {"checks": a.checks, "violations": a.violations, "last_error": a.last_error,
                        "trusted_size": a.trusted.tree_size if a.trusted else 0},
            "sim": {"running": self.sim.running if self.sim else False, "active": self.sim.active if self.sim else False,
                    "placed": self.sim.placed if self.sim else 0},
            "counters": dict(self.bus.counters),
        }
        self._state = (time.time(), state)
        return state

    async def verify_order(self, order_id: str) -> dict:
        """Independently verify everything about one order, the way any outsider could."""
        ledger = self.t.url("ledger")
        steps: list[dict] = []
        head = SignedTreeHead.from_dict((await self.http.get(f"{ledger}/sth")).json())
        steps.append({"check": f"tree head #{head.tree_size} signed by the witness's key",
                      "ok": head.verify(self.t.ledger.keys.signing_public), "detail": head.root_hash})
        rows = await self._get(f"{ledger}/orders/{order_id}")
        if not isinstance(rows, list):
            return {"order_id": order_id, "steps": steps + [{"check": "order found in ledger", "ok": False}], "ok": False}
        for row in rows:
            receipt = Receipt.from_dict(row["receipt"])
            single = receipt.body["type"] == "DISPUTE_VERDICT"
            try:
                await verify_receipt(receipt, self.resolver, require_countersignature=not single)
                sig_ok, why = True, ("signed by " + " + ".join(s["signer"] for s in receipt.signatures))
            except ReceiptError as exc:
                sig_ok, why = False, str(exc)
            steps.append({"check": f"#{row['index']} {row['type']} signatures", "ok": sig_ok, "detail": why})
            proof = (await self.http.get(f"{ledger}/proof/inclusion",
                                         params={"index": row["index"], "tree_size": head.tree_size})).json()["proof"]
            inc = verify_inclusion(leaf_hash(canonical_json(row["receipt"])), row["index"], head.tree_size,
                                   [b64d(p) for p in proof], head.root)
            steps.append({"check": f"#{row['index']} included in signed tree", "ok": inc,
                          "detail": f"{len(proof)}-hash Merkle proof"})
        return {"order_id": order_id, "steps": steps, "ok": all(s["ok"] for s in steps),
                "receipts": [r["receipt"] for r in rows]}

    def _routes(self) -> APIRouter:
        r = APIRouter()

        @r.get("/", response_class=HTMLResponse)
        async def index():
            return resources.files("sakshi_network").joinpath("static/index.html").read_text(encoding="utf-8")

        @r.get("/api/state")
        async def state():
            if self.sim is not None:
                self.sim.last_viewer = time.time()
            return await self.state()

        @r.get("/api/events")
        async def events(after: int = 0):
            return self.bus.since(after, limit=150)

        @r.get("/api/attacks")
        async def attacks():
            return [a.__dict__ for a in CATALOG]

        @r.post("/api/attacks/{name}")
        async def attack(name: str):
            if name not in self.lab.handlers:
                return {"outcome": "ERROR", "summary": f"unknown attack {name}"}
            return await self.lab.run(name)

        @r.post("/api/sim")
        async def sim(request: Request):
            if self.sim is None:
                return {"running": False}
            self.sim.running = bool((await request.json()).get("running"))
            return {"running": self.sim.running}

        @r.post("/api/order")
        async def order(request: Request):
            q = await request.json()
            resp = await self.http.post(f"{self.t.url('bap')}/api/orders", timeout=30,
                                        json={"buyer": "you (dashboard)", "query": q.get("query", "rice"),
                                              "seller_id": q.get("seller_id")})
            return resp.json()

        @r.get("/api/verify/{order_id}")
        async def verify(order_id: str):
            return await self.verify_order(order_id)

        return r
