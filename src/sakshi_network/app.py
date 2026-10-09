"""Process wiring: one image, many roles.

    SAKSHI_ROLE=all        everything in one process (local demo, free hosting)
    SAKSHI_ROLE=registry | gateway | ledger | issuer | bap | bpp | console
                           one service per container (docker compose)

In `all` mode the participants still talk over HTTP: the HTTP client is wired
to the app in-process (httpx.ASGITransport). Every request is still
serialised, signed, routed and verified, just without a network hop.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import random
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import RedirectResponse

from sakshi.auth import KeyRecord
from sakshi.client import RegistryResolver
from sakshi.credentials import Credential, issue_credential
from sakshi.replay import MemoryReplayStore, RedisReplayStore

from .bap import BuyerApp
from .bpp import SellerApp
from .common import EventBus, Participant, nack, spawn
from .console import Console
from .gateway import Gateway
from .issuer import Issuer
from .ledger import Witness
from .registry import Registry, on_subscribe_router, subscribe
from .simulator import Simulator
from .world import SELLER_APPS, Topology, build_sellers, env

log = logging.getLogger("sakshi")
ROLES = ("registry", "gateway", "ledger", "issuer", "bap", "bpp", "console")


async def join(me: Participant, registry_url: str, http: httpx.AsyncClient, bus: EventBus,
               current: Participant | None = None, attempts: int = 60) -> None:
    """Subscribe to the registry, retrying while it starts up."""
    for i in range(attempts):
        try:
            r = await subscribe(me, registry_url, http, current)
            if r.status_code == 200:
                return
            log.warning("subscribe %s refused: %s", me.subscriber_id, r.text[:200])
        except httpx.HTTPError as exc:
            log.info("registry not reachable yet (%s), retry %d", exc, i + 1)
        await asyncio.sleep(1)
    raise RuntimeError(f"{me.subscriber_id} could not join the network")


def create_app(role: str | None = None) -> FastAPI:
    logging.basicConfig(level=env("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    role = role or env("SAKSHI_ROLE", "all")
    roles = set(ROLES) if role == "all" else {role}
    t = Topology.from_env()
    bus = EventBus()
    startup: list = []           # coroutine factories, run in order
    background: list = []        # callables started after startup

    async def bootstrap() -> None:
        for step in startup:
            await step()
        for start in background:
            start()
        bus.emit("system", "network", f"Sakshi network ready ({role} mode)", "success")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if role == "all":
            await bootstrap()          # in-process transport: the app can already serve its own requests
        else:
            # A separate service only accepts connections once startup returns, but joining the
            # registry needs the registry to call us back (the encrypted challenge). So join in
            # the background, once the server is listening.
            spawn(bootstrap())
        yield
        await http.aclose()

    app = FastAPI(title="Sakshi trust network", version="1.0.0", lifespan=lifespan,
                  description="A trust layer for open commerce networks (ONDC-style), running as a live demo.")

    if role == "all":
        http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), timeout=20)
    else:
        http = httpx.AsyncClient(timeout=20)
    if os.environ.get("REDIS_URL"):
        import redis.asyncio as aioredis
        replay = RedisReplayStore(aioredis.from_url(os.environ["REDIS_URL"]))
    else:
        replay = MemoryReplayStore()

    reg = t.registry
    pinned = KeyRecord(reg.subscriber_id, reg.unique_key_id, reg.keys.signing_public, 0, 4102444800,
                       "SUBSCRIBED", "REGISTRY")
    resolver = RegistryResolver(t.url("registry"), pinned, http, ttl_s=float(env("KEY_CACHE_TTL_S", "30")))
    enc = reg.keys.encryption_public
    registry_url = t.url("registry")
    time_scale = float(env("TIME_SCALE", "1.0"))

    def admin_ok(token: str) -> bool:
        return hmac.compare_digest(token, t.admin_token)

    if "registry" in roles:
        registry = Registry(reg, http, bus, approved=t.approved(), admin_token=t.admin_token)
        app.include_router(registry.router, prefix="/registry", tags=["registry"])

    if "gateway" in roles:
        gateway = Gateway(t.gateway, http, resolver, replay, bus, enc)
        app.include_router(gateway.router, prefix="/gateway", tags=["gateway"])
        startup.append(lambda: join(t.gateway, registry_url, http, bus))

    if "ledger" in roles:
        witness = Witness(t.ledger, http, resolver, replay, bus, enc, db_path=os.environ.get("LEDGER_DB"))
        app.include_router(witness.router, prefix="/ledger", tags=["ledger"])
        startup.append(lambda: join(t.ledger, registry_url, http, bus))

        @app.post("/ledger/admin/tamper", tags=["attack-lab"])
        async def tamper(request: Request, x_admin_token: str = Header(default="")):
            if not admin_ok(x_admin_token):
                return nack("ADMIN_UNAUTHORISED", "operator token required", 403)
            q = await request.json()
            return witness.tamper_entry(int(q["index"]), bool(q.get("rebuild")))

        @app.post("/ledger/admin/restore", tags=["attack-lab"])
        async def restore(x_admin_token: str = Header(default="")):
            if not admin_ok(x_admin_token):
                return nack("ADMIN_UNAUTHORISED", "operator token required", 403)
            return {"restored": witness.restore()}

    if "issuer" in roles:
        issuer = Issuer(t.issuer, bus, enc, t.admin_token)
        app.include_router(issuer.router, prefix="/issuer", tags=["issuer"])
        startup.append(lambda: join(t.issuer, registry_url, http, bus))

    if "bap" in roles:
        bap = BuyerApp(t.bap, http, resolver, replay, bus, enc, t.url("gateway"), t.url("ledger"),
                       t.issuer.subscriber_id, t.url("issuer"), time_scale=time_scale,
                       search_window_s=float(env("SEARCH_WINDOW_S", "0.8")))
        app.include_router(bap.router, prefix="/bap", tags=["buyer app"])
        startup.append(lambda: join(t.bap, registry_url, http, bus))
        background.append(bap.start)

    if "bpp" in roles:
        names = list(SELLER_APPS) if role == "all" else [env("BPP_NAME", "kirana")]
        for name in names:
            me = t.bpp(name)
            sellers = build_sellers(name, t.seed)
            seller_app = SellerApp(me, sellers, http, resolver, replay, bus, enc, time_scale=time_scale,
                                   rng=random.Random(f"{t.seed}|{name}"))
            app.include_router(seller_app.router, prefix=f"/bpp/{name}", tags=[f"seller app: {name}"])

            async def setup(me=me, sellers=sellers):
                await join(me, registry_url, http, bus)
                for s in sellers:
                    subject = f"{me.subscriber_id}/{s.id}"
                    if s.profile == "forged":
                        # Signs its own "GST verified" badge and names the real authority as issuer.
                        fake = issue_credential(t.issuer.subscriber_id, t.issuer.unique_key_id,
                                                me.keys.signing_private, subject,
                                                {"gstin": s.gstin, "legal_name": s.name, "gst_status": "Active"})
                        s.credential = fake.to_dict()
                        continue
                    for _ in range(30):
                        try:
                            r = await http.post(f"{t.url('issuer')}/credentials/issue",
                                                headers={"X-Admin-Token": t.admin_token},
                                                json={"subject": subject, "gstin": s.gstin, "legal_name": s.name})
                            if r.status_code == 200:
                                s.credential = Credential.from_dict(r.json()).to_dict()
                                break
                        except httpx.HTTPError:
                            pass
                        await asyncio.sleep(1)
            startup.append(setup)

    if "console" in roles:
        # Participants owned by the attack lab: a rival buyer app and one with a leaked key.
        rival, leaky1, leaky2 = t.rival_bap, t.leaky_bap("k1"), t.leaky_bap("k2")
        current = {"quickbuy": rival, "leakyshop": leaky1}
        for name in ("quickbuy", "leakyshop"):
            app.include_router(on_subscribe_router(lambda n=name: current[n], enc, bus), prefix=f"/attackers/{name}")

        async def attackers():
            await join(rival, registry_url, http, bus)
            await join(leaky1, registry_url, http, bus)
            current["leakyshop"] = leaky2
            await join(leaky2, registry_url, http, bus, current=leaky1)      # rotation, authorised by k1
            await http.post(f"{registry_url}/admin/revoke", headers={"X-Admin-Token": t.admin_token},
                            json={"subscriber_id": leaky1.subscriber_id, "ukId": "k1"})   # k1 leaked: revoke it
        startup.append(attackers)

        sim = None
        if env("SIMULATION", "on") == "on":
            sim = Simulator(t.url("bap"), http, bus, orders_per_s=float(env("SIM_ORDERS_PER_S", "0.8")),
                            idle_pause_s=float(env("SIM_IDLE_PAUSE_S", "600")))
        sources = [s for s in env("EVENT_SOURCES", "").split(",") if s] if role != "all" else []
        console = Console(t, http, bus, sim, sources)
        app.include_router(console.router, prefix="/console", tags=["console"])
        background.append(console.start)

        @app.get("/", include_in_schema=False)
        async def root():
            return RedirectResponse("/console/")

    @app.get("/_events", include_in_schema=False)
    async def events(after: int = 0):
        return bus.since(after, limit=500)

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return {"ok": True, "role": role}

    return app

