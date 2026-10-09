"""Plumbing shared by every network participant."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import itertools
import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from sakshi.auth import AuthError, KeyResolver, ReplayStore, VerifiedSender, verify_authorization
from sakshi.crypto import KeyPair

log = logging.getLogger("sakshi")

DOMAIN = "ONDC:RET10"          # grocery
CORE_VERSION = "1.2.0"


@dataclass
class Participant:
    subscriber_id: str
    type: str                  # REGISTRY / BG / BAP / BPP / LEDGER / ISSUER
    base_url: str              # where its API lives
    keys: KeyPair
    unique_key_id: str = "k1"
    domain: str = DOMAIN

    @classmethod
    def derive(cls, subscriber_id: str, type_: str, base_url: str, seed: str, ukid: str = "k1") -> Participant:
        """Deterministic demo keys, so separate containers agree without a key exchange step.

        Production participants would generate keys inside a KMS/HSM instead.
        """
        material = hashlib.sha256(f"{seed}|{subscriber_id}|{ukid}".encode()).digest()
        return cls(subscriber_id, type_, base_url.rstrip("/"), KeyPair.from_seed(material), ukid)

    def rotate(self, seed: str) -> Participant:
        n = int(self.unique_key_id.lstrip("k") or 1) + 1
        return Participant.derive(self.subscriber_id, self.type, self.base_url, seed, f"k{n}")


# ----------------------------------------------------------------------- events
@dataclass
class Event:
    id: int
    ts: float
    kind: str                  # auth / order / ledger / dispute / attack / registry / fraud / system
    actor: str
    summary: str
    severity: str = "info"     # info / success / warning / blocked / critical
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class EventBus:
    """Ring buffer of human-readable events, read by the dashboard."""

    def __init__(self, size: int = 2000) -> None:
        self.events: deque[Event] = deque(maxlen=size)
        self._ids = itertools.count(1)
        self.counters: dict[str, int] = {}

    def emit(self, kind: str, actor: str, summary: str, severity: str = "info", **detail: Any) -> Event:
        e = Event(next(self._ids), time.time(), kind, actor, summary, severity, detail)
        self.events.append(e)
        key = f"{kind}:{severity}"
        self.counters[key] = self.counters.get(key, 0) + 1
        level = logging.WARNING if severity in ("blocked", "critical", "warning") else logging.INFO
        log.log(level, "[%s] %s: %s", kind, actor, summary)
        return e

    def since(self, after_id: int = 0, limit: int = 200) -> list[dict]:
        out = [e.to_dict() for e in self.events if e.id > after_id]
        return out[-limit:]


# ------------------------------------------------------------------- background
_tasks: set[asyncio.Task] = set()


def spawn(coro) -> asyncio.Task:
    """Fire-and-forget that keeps a reference (asyncio only keeps weak ones)."""
    task = asyncio.create_task(coro)
    _tasks.add(task)
    task.add_done_callback(_done)
    return task


def _done(task: asyncio.Task) -> None:
    _tasks.discard(task)
    if not task.cancelled() and task.exception() is not None:
        log.error("background task failed", exc_info=task.exception())


# ---------------------------------------------------------------- beckn helpers
def iso_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def context(action: str, bap: Participant, transaction_id: str, bpp: dict | None = None,
            message_id: str | None = None) -> dict:
    ctx = {
        "domain": DOMAIN, "action": action, "core_version": CORE_VERSION,
        "country": "IND", "city": "std:080",
        "bap_id": bap.subscriber_id, "bap_uri": bap.base_url,
        "transaction_id": transaction_id, "message_id": message_id or str(uuid.uuid4()),
        "timestamp": iso_now(), "ttl": "PT30S",
    }
    if bpp:
        ctx["bpp_id"], ctx["bpp_uri"] = bpp["bpp_id"], bpp["bpp_uri"]
    return ctx


def callback_context(ctx: dict, action: str, bpp: Participant) -> dict:
    return {**ctx, "action": action, "bpp_id": bpp.subscriber_id, "bpp_uri": bpp.base_url, "timestamp": iso_now()}


ACK = {"message": {"ack": {"status": "ACK"}}}


def nack(code: str, message: str, status: int = 400, error_type: str = "POLICY-ERROR") -> JSONResponse:
    headers = {"WWW-Authenticate": 'Signature realm="sakshi",headers="(created) (expires) digest"'} if status == 401 else None
    return JSONResponse({"message": {"ack": {"status": "NACK"}},
                         "error": {"type": error_type, "code": code, "message": message}},
                        status_code=status, headers=headers)


class _Scoped:
    """Replay memory per receiver: the same signed search legitimately reaches
    the gateway *and* every seller app; it's only a replay if one receiver
    sees it twice."""

    def __init__(self, store: ReplayStore, scope: str) -> None:
        self.store, self.scope = store, scope

    async def first_seen(self, key: str, ttl_s: int) -> bool:
        return await self.store.first_seen(f"{self.scope}|{key}", ttl_s)


class Rejected(Exception):
    def __init__(self, response: JSONResponse) -> None:
        self.response = response


async def authenticate(request: Request, resolver: KeyResolver, replay: ReplayStore | None, bus: EventBus,
                       me: str, header: str = "Authorization", expect_signer: str | None = None,
                       expect_type: str | None = None, type_of=None) -> tuple[VerifiedSender, bytes]:
    """Verify the signed request or raise Rejected with a ready NACK.

    `expect_signer` is the anti-spoofing check: a valid signature from
    participant A on a message that claims to come from participant B is
    still a forgery.
    """
    body = await request.body()
    try:
        sender = await verify_authorization(request.headers.get(header), body, resolver,
                                            # `is not None`, not truthiness: an empty store has len 0 and is falsy!
                                            _Scoped(replay, f"{me}|{header}") if replay is not None else None)
    except AuthError as exc:
        bus.emit("auth", me, f"blocked {request.url.path}: {exc.message}", "blocked",
                 code=exc.code, path=request.url.path, header=header)
        raise Rejected(nack(exc.code, exc.message, 401)) from exc
    if expect_signer is not None and sender.subscriber_id != expect_signer:
        msg = f"signed by {sender.subscriber_id} but claims to come from {expect_signer}"
        bus.emit("auth", me, f"blocked {request.url.path}: {msg}", "blocked", code="AUTH_SPOOFED_SENDER")
        raise Rejected(nack("AUTH_SPOOFED_SENDER", msg, 401))
    if expect_type is not None and type_of is not None:
        actual = await type_of(sender.subscriber_id, sender.unique_key_id)
        if actual != expect_type:
            msg = f"{sender.subscriber_id} is a {actual or 'unknown'}, expected a {expect_type}"
            bus.emit("auth", me, f"blocked {request.url.path}: {msg}", "blocked", code="AUTH_WRONG_ROLE")
            raise Rejected(nack("AUTH_WRONG_ROLE", msg, 401))
    return sender, body


def buyer_ref(buyer: str, bap_id: str, secret: str) -> str:
    """Pseudonymous buyer id for the public ledger.

    A keyed HMAC, not a plain hash: phone numbers and emails are guessable,
    so a plain hash could be reversed by trying them all. Only the buyer
    app (which holds `secret`) can link a ref back to a person, yet the same
    buyer always maps to the same ref, so fraud analysis still works.
    """
    return hmac.new(secret.encode(), f"{bap_id}|{buyer}".encode(), hashlib.sha256).hexdigest()[:16]
