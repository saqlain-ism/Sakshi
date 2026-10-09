"""Registry: the network's phone book of participants and their public keys.

Onboarding (`/subscribe`) proves three things before a key is trusted:

1. **Admission:** the network operator approved this participant *at this
   exact URL* (in real ONDC, after KYC, agreements and domain checks).
   Strangers can't self-register.
2. **Possession of the signing key:** the subscribe request is signed with
   the very key being registered.
3. **Control of the endpoint and encryption key:** the registry encrypts a
   random challenge to the participant's X25519 key (ECDH, then HKDF, then
   AES-256-GCM) and sends it to the participant's own URL. Only the real
   owner can decrypt it and answer.

ONDC's reference flow uses AES-ECB for the challenge. ECB leaks patterns and
has no integrity check, so Sakshi uses AES-GCM (authenticated encryption).

Key **rotation** is a fresh subscribe under a new key id, and it must also be
signed by a key that is *currently* valid (`X-Rotation-Authorization`).
Otherwise anyone who briefly controlled the endpoint could swap in their
own key. The old key is kept for a short overlap so requests already in
flight still verify.
**Revocation** takes effect for everyone within one resolver-cache TTL.
"""

from __future__ import annotations

import hmac
import json
import os
import time

import httpx
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, Response

from sakshi.auth import AuthError, KeyRecord, create_authorization_header, verify_authorization
from sakshi.client import REGISTRY_SIG_HEADER, StaticResolver
from sakshi.crypto import decrypt, encrypt, shared_key

from .common import ACK, EventBus, Participant, nack

ROTATION_OVERLAP_S = 60
DEFAULT_VALIDITY_S = 365 * 86400


class Registry:
    def __init__(self, me: Participant, http: httpx.AsyncClient, bus: EventBus,
                 approved: dict[str, str] | None = None, admin_token: str = "") -> None:
        self.me = me
        self.http = http
        self.bus = bus
        self.approved = approved
        self.admin_token = admin_token
        self.entries: dict[tuple[str, str], dict] = {}
        now = time.time()
        self._put({
            "subscriber_id": me.subscriber_id, "ukId": me.unique_key_id, "subscriber_url": me.base_url,
            "type": "REGISTRY", "domain": "*", "signing_public_key": me.keys.signing_public,
            "encr_public_key": me.keys.encryption_public, "valid_from": now - 60,
            "valid_until": now + DEFAULT_VALIDITY_S, "status": "SUBSCRIBED",
        })
        self.router = self._routes()

    def _put(self, entry: dict) -> None:
        entry.setdefault("created", time.time())
        entry["updated"] = time.time()
        self.entries[(entry["subscriber_id"], entry["ukId"])] = entry

    def _signed(self, payload) -> Response:
        body = json.dumps(payload, separators=(",", ":")).encode()
        sig = create_authorization_header(body, self.me.subscriber_id, self.me.unique_key_id,
                                          self.me.keys.signing_private, ttl_s=60)
        return Response(body, media_type="application/json", headers={REGISTRY_SIG_HEADER: sig})

    def lookup(self, q: dict) -> list[dict]:
        out = []
        for e in self.entries.values():
            if e["status"] in ("INITIATED", "CHALLENGE_FAILED"):
                continue
            if any(q.get(k) and e.get(f) != q[k] for k, f in
                   (("subscriber_id", "subscriber_id"), ("ukId", "ukId"), ("type", "type"))):
                continue
            if q.get("domain") and e["domain"] not in (q["domain"], "*"):
                continue
            out.append(e)
        return out

    def revoke(self, subscriber_id: str, ukid: str | None = None) -> int:
        n = 0
        for (sub, uk), e in self.entries.items():
            if sub == subscriber_id and (ukid is None or uk == ukid) and e["status"] != "REVOKED":
                e["status"], e["updated"] = "REVOKED", time.time()
                n += 1
        if n:
            self.bus.emit("registry", self.me.subscriber_id, f"revoked {n} key(s) of {subscriber_id}", "warning",
                          subscriber_id=subscriber_id, ukId=ukid)
        return n

    async def _challenge(self, entry: dict) -> bool:
        challenge = os.urandom(32).hex()
        key = shared_key(self.me.keys.encryption_private, entry["encr_public_key"])
        token = encrypt(key, challenge.encode(), aad=entry["subscriber_id"].encode())
        try:
            r = await self.http.post(f"{entry['subscriber_url']}/on_subscribe",
                                     json={"subscriber_id": entry["subscriber_id"], "challenge": token}, timeout=10)
            answer = r.json().get("answer", "") if r.status_code == 200 else ""
        except (httpx.HTTPError, ValueError):
            answer = ""
        return hmac.compare_digest(answer.encode(), challenge.encode())

    def _routes(self) -> APIRouter:
        r = APIRouter()

        @r.post("/subscribe")
        async def subscribe(request: Request):
            body = await request.body()
            try:
                e = json.loads(body)
                sub, ukid, sign_pub = e["subscriber_id"], e["ukId"], e["signing_public_key"]
                for f in ("subscriber_url", "type", "encr_public_key"):
                    e[f]  # noqa: B018 - presence check
            except (ValueError, KeyError) as exc:
                return nack("SUBSCRIBE_MALFORMED", f"bad subscribe payload: {exc}", 400, "JSON-SCHEMA-ERROR")

            if self.approved is not None and sub not in self.approved:
                self.bus.emit("registry", self.me.subscriber_id, f"refused {sub}: not approved by the network operator",
                              "blocked", subscriber_id=sub)
                return nack("SUBSCRIBE_NOT_APPROVED", f"{sub} has not been approved to join this network", 403)
            if self.approved is not None and e["subscriber_url"].rstrip("/") != self.approved[sub].rstrip("/"):
                self.bus.emit("registry", self.me.subscriber_id,
                              f"refused {sub}: URL {e['subscriber_url']} is not the approved endpoint", "blocked")
                return nack("SUBSCRIBE_URL_MISMATCH", "subscriber_url differs from the operator-approved URL", 403)

            now = time.time()
            proof_key = KeyRecord(sub, ukid, sign_pub, now - 60, now + 60, "SUBSCRIBED")
            try:   # proof of possession: signed with the key being registered
                await verify_authorization(request.headers.get("Authorization"), body, StaticResolver([proof_key]))
            except AuthError as exc:
                return nack("SUBSCRIBE_NO_POSSESSION", f"request must be signed by the key being registered ({exc.code})", 401)

            current = [KeyRecord(x["subscriber_id"], x["ukId"], x["signing_public_key"], x["valid_from"],
                                 x["valid_until"], x["status"]) for (s_, _), x in self.entries.items()
                       if s_ == sub and x["status"] == "SUBSCRIBED" and x["valid_until"] > now]
            if current and ukid not in {k.unique_key_id for k in current}:
                try:   # continuity: a new key must be vouched for by a key that is valid right now
                    await verify_authorization(request.headers.get("X-Rotation-Authorization"), body,
                                               StaticResolver(current))
                except AuthError as exc:
                    self.bus.emit("registry", self.me.subscriber_id,
                                  f"refused new key for {sub}: not authorised by its current key ({exc.code})", "blocked")
                    return nack("SUBSCRIBE_ROTATION_UNAUTHORISED",
                                "a new key must be co-signed by a currently valid key of this participant", 401)

            existing = self.entries.get((sub, ukid))
            if existing and existing["signing_public_key"] != sign_pub:
                return nack("SUBSCRIBE_KEY_ID_TAKEN", f"key id {ukid} already used by {sub} for a different key", 409)
            if existing and existing["status"] == "REVOKED":
                return nack("SUBSCRIBE_KEY_REVOKED", "a revoked key can never be re-registered", 409)

            entry = {k: e[k] for k in ("subscriber_id", "ukId", "subscriber_url", "type", "signing_public_key",
                                       "encr_public_key")}
            entry.update(domain=e.get("domain", "*"), valid_from=float(e.get("valid_from", now - 5)),
                         valid_until=float(e.get("valid_until", now + DEFAULT_VALIDITY_S)), status="INITIATED")
            self._put(entry)

            if not await self._challenge(entry):
                entry["status"] = "CHALLENGE_FAILED"
                self.bus.emit("registry", self.me.subscriber_id, f"{sub} failed the encrypted challenge", "blocked")
                return nack("SUBSCRIBE_CHALLENGE_FAILED", "could not prove control of the endpoint/encryption key", 401)

            rotated = []
            for (s, uk), old in self.entries.items():
                if s == sub and uk != ukid and old["status"] == "SUBSCRIBED" and old["valid_until"] > now + ROTATION_OVERLAP_S:
                    old["valid_until"], old["updated"] = now + ROTATION_OVERLAP_S, now
                    rotated.append(uk)
            entry["status"] = "SUBSCRIBED"
            entry["updated"] = time.time()
            msg = f"{sub} subscribed key {ukid} as {entry['type']}"
            if rotated:
                msg += f" (rotated from {', '.join(rotated)}, {ROTATION_OVERLAP_S}s overlap)"
            self.bus.emit("registry", self.me.subscriber_id, msg, "success", subscriber_id=sub, ukId=ukid)
            return {**ACK, "status": "SUBSCRIBED"}

        @r.post("/lookup")
        async def lookup(request: Request):
            try:
                q = json.loads(await request.body() or b"{}")
            except ValueError:
                return nack("LOOKUP_MALFORMED", "body must be JSON", 400)
            return self._signed(self.lookup(q))

        @r.post("/admin/revoke")
        async def revoke(request: Request, x_admin_token: str = Header(default="")):
            if not self.admin_token or not hmac.compare_digest(x_admin_token, self.admin_token):
                return nack("ADMIN_UNAUTHORISED", "operator token required", 403)
            q = await request.json()
            return {"revoked": self.revoke(q["subscriber_id"], q.get("ukId"))}

        @r.get("/participants")
        async def participants():
            rows = sorted(self.entries.values(), key=lambda e: (e["type"], e["subscriber_id"], e["ukId"]))
            return JSONResponse([{k: v for k, v in e.items() if k != "encr_public_key"} for e in rows])

        return r


# ------------------------------------------------------------- participant side
def on_subscribe_router(me_ref, registry_encryption_public: str, bus: EventBus) -> APIRouter:
    """Lets a participant answer the registry's encrypted challenge.

    `me_ref` is a zero-argument callable returning the participant's
    *current* identity (it changes on key rotation).
    """
    r = APIRouter()

    @r.post("/on_subscribe")
    async def on_subscribe(payload: dict):
        me: Participant = me_ref()
        key = shared_key(me.keys.encryption_private, registry_encryption_public)
        try:
            answer = decrypt(key, payload["challenge"], aad=me.subscriber_id.encode()).decode()
        except (ValueError, KeyError):
            return nack("CHALLENGE_UNREADABLE", "could not decrypt challenge", 400)
        return {"answer": answer}

    return r


async def subscribe(me: Participant, registry_url: str, http: httpx.AsyncClient,
                    current: Participant | None = None) -> httpx.Response:
    """Register (or rotate to) `me`'s key. For a rotation pass the `current` identity."""
    body = json.dumps({
        "subscriber_id": me.subscriber_id, "ukId": me.unique_key_id, "subscriber_url": me.base_url,
        "type": me.type, "domain": me.domain, "signing_public_key": me.keys.signing_public,
        "encr_public_key": me.keys.encryption_public,
    }).encode()
    headers = {"Content-Type": "application/json",
               "Authorization": create_authorization_header(body, me.subscriber_id, me.unique_key_id,
                                                            me.keys.signing_private)}
    if current is not None:
        headers["X-Rotation-Authorization"] = create_authorization_header(
            body, current.subscriber_id, current.unique_key_id, current.keys.signing_private)
    return await http.post(f"{registry_url}/subscribe", content=body, headers=headers, timeout=15)
