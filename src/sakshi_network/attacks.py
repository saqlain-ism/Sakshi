"""Attack lab: real attacks against the running network, one button each.

Every attack sends genuine HTTP requests (or tampers with genuine state)
and reports what the network did. Nothing is mocked: a "blocked" result
means the defending code actually rejected the request.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx

from sakshi.auth import AuthError, KeyRecord, create_authorization_header, verify_authorization
from sakshi.canonical import canonical_json
from sakshi.client import REGISTRY_SIG_HEADER, _PinnedRegistry
from sakshi.crypto import b64d
from sakshi.merkle import SignedTreeHead, leaf_hash, verify_inclusion
from sakshi.receipts import Receipt, new_receipt, verify_receipt

from .common import EventBus, Participant, context
from .ledger import Auditor
from .registry import subscribe
from .simulator import BOOSTER, Simulator
from .world import Topology


@dataclass
class AttackInfo:
    name: str
    title: str
    category: str
    threat: str          # what the attacker wants


CATALOG = [
    AttackInfo("forged_signature", "Forged signature", "Transport",
               "Send an order request as PayBuddy without PayBuddy's private key"),
    AttackInfo("tampered_body", "Tampered request", "Transport",
               "Intercept a genuine signed request and change the quantity from 1 to 50"),
    AttackInfo("replay", "Replay attack", "Transport",
               "Capture a valid signed request and send it again"),
    AttackInfo("expired", "Expired signature", "Transport",
               "Reuse a signed request captured 10 minutes ago"),
    AttackInfo("spoofed_sender", "Sender spoofing", "Transport",
               "A registered buyer app signs with its own valid key but claims to be PayBuddy"),
    AttackInfo("fake_gateway", "Gateway bypass", "Transport",
               "Skip the gateway and pretend to be one, to reach sellers directly"),
    AttackInfo("leaked_key", "Leaked key", "Identity",
               "Use a buyer app's old private key that leaked and was revoked"),
    AttackInfo("rogue_registry", "Fake registry answer", "Identity",
               "Answer a key lookup with the attacker's key, posing as the registry"),
    AttackInfo("hijack_registration", "Registration hijack", "Identity",
               "Register a new key for PayBuddy so the attacker can sign as it"),
    AttackInfo("unapproved_join", "Unapproved participant", "Identity",
               "Join the network without operator approval"),
    AttackInfo("forged_credential", "Forged GST credential", "Identity",
               "A seller shows a GST-verified badge it signed itself"),
    AttackInfo("bait_and_switch", "Bait and switch", "Commitments",
               "Quote a low price, then confirm a higher one"),
    AttackInfo("deny_promise", "Seller denies a promise", "Commitments",
               "A seller claims it never promised a delivery time"),
    AttackInfo("backdated_receipt", "Backdated receipt", "Commitments",
               "Two colluding parties log a fully signed receipt dated 3 days ago"),
    AttackInfo("silent_edit", "Silent ledger edit", "Ledger",
               "The ledger operator edits an old entry (price -> Rs 1)"),
    AttackInfo("history_rewrite", "History rewrite", "Ledger",
               "The operator edits an entry AND recomputes the whole Merkle tree to hide it"),
    AttackInfo("sybil_boost", "Fake-review boosting", "Reputation",
               "A seller places orders through its own sock-puppet buyers to inflate its score"),
]


def result(outcome: str, summary: str, why: str, code: str | None = None, steps: list[str] | None = None,
           **detail) -> dict:
    return {"outcome": outcome, "summary": summary, "why_it_matters": why, "code": code, "steps": steps or [],
            "detail": detail}


class AttackLab:
    def __init__(self, topo: Topology, http: httpx.AsyncClient, bus: EventBus, auditor: Auditor,
                 sim: Simulator | None) -> None:
        self.t = topo
        self.http = http
        self.bus = bus
        self.auditor = auditor
        self.sim = sim
        self.handlers: dict[str, Callable[[], Awaitable[dict]]] = {a.name: getattr(self, a.name) for a in CATALOG}
        self._lock = asyncio.Lock()

    async def run(self, name: str) -> dict:
        info = next(a for a in CATALOG if a.name == name)
        async with self._lock:
            try:
                res = await self.handlers[name]()
            except Exception as exc:  # report, don't crash the console
                res = result("ERROR", f"attack could not run: {type(exc).__name__}: {exc}", "")
        res.update(name=name, title=info.title, category=info.category, threat=info.threat)
        sev = {"BLOCKED": "blocked", "DETECTED": "blocked", "NOT_BLOCKED": "critical"}.get(res["outcome"], "warning")
        self.bus.emit("attack", "attack-lab", f"{info.title}: {res['outcome'].lower().replace('_', ' ')} - "
                      f"{res['summary']}", sev, attack=name, code=res.get("code"))
        return res

    # ---------------------------------------------------------------- helpers
    def _search(self, bap: Participant, claimed_bap: Participant | None = None, query: str = "rice") -> bytes:
        ctx = context("search", claimed_bap or bap, str(uuid.uuid4()))
        return json.dumps({"context": ctx, "message": {"intent": {"item": {"descriptor": {"name": query}}}}},
                          separators=(",", ":")).encode()

    async def _post(self, url: str, body: bytes, headers: dict) -> httpx.Response:
        return await self.http.post(url, content=body, headers={"Content-Type": "application/json", **headers})

    @staticmethod
    def _code(r: httpx.Response) -> str | None:
        try:
            return r.json().get("error", {}).get("code")
        except ValueError:
            return None

    def _verdict(self, r: httpx.Response, expected: str, summary: str, why: str, steps: list[str]) -> dict:
        code = self._code(r)
        if r.status_code >= 400 and code:
            return result("BLOCKED", f"{summary} Rejected with {code}.", why, code, steps, http_status=r.status_code,
                          expected_code=expected)
        return result("NOT_BLOCKED", f"request was accepted (HTTP {r.status_code})", why, None, steps)

    def _auth(self, body: bytes, p: Participant, **kw) -> str:
        return create_authorization_header(body, p.subscriber_id, p.unique_key_id, p.keys.signing_private, **kw)

    # -------------------------------------------------------------- transport
    async def forged_signature(self) -> dict:
        bap, mallory = self.t.bap, self.t.mallory
        body = self._search(bap)
        header = create_authorization_header(body, bap.subscriber_id, bap.unique_key_id, mallory.keys.signing_private)
        r = await self._post(f"{self.t.url('gateway')}/search", body, {"Authorization": header})
        return self._verdict(r, "AUTH_BAD_SIGNATURE", "The gateway fetched PayBuddy's real public key from the "
                             "registry; the signature doesn't verify under it.",
                             "Without the private key nobody can produce a valid signature, so identity can't be faked.",
                             ["Mallory builds a search claiming keyId paybuddy.app|k1",
                              "signs it with her own key", "POST gateway /search"])

    async def tampered_body(self) -> dict:
        bap, bpp = self.t.bap, self.t.bpp("kirana")
        order = {"provider": {"id": "fresh-basket"}, "items": [{"id": "fresh-basket:rice-5kg", "quantity": {"count": 1}}]}
        ctx = context("select", bap, str(uuid.uuid4()), {"bpp_id": bpp.subscriber_id, "bpp_uri": bpp.base_url})
        body = json.dumps({"context": ctx, "message": {"order": order}}, separators=(",", ":")).encode()
        header = self._auth(body, bap)                         # genuine signature by PayBuddy
        tampered = body.replace(b'"count":1', b'"count":50')
        r = await self._post(f"{bpp.base_url}/select", tampered, {"Authorization": header})
        return self._verdict(r, "AUTH_BAD_SIGNATURE", "The BLAKE2b-512 digest of the received body no longer "
                             "matches the digest PayBuddy signed.",
                             "Any change in transit, even one character, is detected. Integrity is end-to-end.",
                             ["PayBuddy signs select with quantity 1", "attacker changes quantity to 50 in transit",
                              "seller app recomputes the digest"])

    async def replay(self) -> dict:
        bap = self.t.bap
        body = self._search(bap)
        header = self._auth(body, bap)
        first = await self._post(f"{self.t.url('gateway')}/search", body, {"Authorization": header})
        second = await self._post(f"{self.t.url('gateway')}/search", body, {"Authorization": header})
        res = self._verdict(second, "AUTH_REPLAY", f"First copy accepted (HTTP {first.status_code}); the identical "
                            "second copy was refused.",
                            "Valid signatures stay valid until they expire. Remembering accepted signatures until "
                            "then stops 'buy it again' replays (shared via Redis across replicas).",
                            ["capture one genuine signed search", "send it", "send the exact same bytes again"])
        return res

    async def expired(self) -> dict:
        bap = self.t.bap
        body = self._search(bap)
        header = self._auth(body, bap, created=int(time.time()) - 600, ttl_s=30)
        r = await self._post(f"{self.t.url('gateway')}/search", body, {"Authorization": header})
        return self._verdict(r, "AUTH_EXPIRED", "The signature expired 9.5 minutes ago.",
                             "Every signature carries its own short lifetime, so old captures are worthless.",
                             ["take a request signed 10 minutes ago (30 s lifetime)", "send it now"])

    async def spoofed_sender(self) -> dict:
        rival, bap = self.t.rival_bap, self.t.bap
        body = self._search(rival, claimed_bap=bap)            # context says paybuddy.app
        r = await self._post(f"{self.t.url('gateway')}/search", body, {"Authorization": self._auth(body, rival)})
        return self._verdict(r, "AUTH_SPOOFED_SENDER", "The signature is valid, but it belongs to quickbuy.app "
                             "while the message claims to be from paybuddy.app.",
                             "A valid signature isn't enough. The signer must be the party the message claims to "
                             "come from; otherwise any member could act in another's name.",
                             ["quickbuy.app (a real, registered buyer app) signs with its own key",
                              "sets context.bap_id = paybuddy.app", "POST gateway /search"])

    async def fake_gateway(self) -> dict:
        rival, bpp = self.t.rival_bap, self.t.bpp("kirana")
        body = self._search(rival)
        r = await self._post(f"{bpp.base_url}/search", body, {"Authorization": self._auth(body, rival),
                                                              "X-Gateway-Authorization": self._auth(body, rival)})
        return self._verdict(r, "AUTH_WRONG_ROLE", "The seller app checked the gateway signature's owner in the "
                             "registry: it's a buyer app, not a gateway.",
                             "Roles are enforced, not just identities, so participants can't bypass the gateway's "
                             "fair-broadcast rules.",
                             ["quickbuy.app sends search straight to a seller app",
                              "adds an X-Gateway-Authorization header signed by itself"])

    # --------------------------------------------------------------- identity
    async def leaked_key(self) -> dict:
        old = self.t.leaky_bap("k1")
        body = self._search(old)
        r = await self._post(f"{self.t.url('gateway')}/search", body, {"Authorization": self._auth(body, old)})
        return self._verdict(r, "AUTH_KEY_REVOKED", "leakyshop.app rotated to key k2 and the operator revoked k1; "
                             "every participant's lookup now sees k1 as REVOKED.",
                             "A leaked key can be killed network-wide within one cache TTL (30 s), without "
                             "breaking the participant's new key.",
                             ["leakyshop.app rotated k1 -> k2 (signed by k1)", "k1 later leaked and was revoked",
                              "attacker signs with k1"])

    async def rogue_registry(self) -> dict:
        mallory, reg = self.t.mallory, self.t.registry
        fake = json.dumps([{"subscriber_id": "paybuddy.app", "ukId": "k1",
                            "signing_public_key": mallory.keys.signing_public, "valid_from": 0,
                            "valid_until": 4102444800, "status": "SUBSCRIBED", "type": "BAP"}]).encode()
        header = create_authorization_header(fake, reg.subscriber_id, reg.unique_key_id, mallory.keys.signing_private)
        pinned = _PinnedRegistry(KeyRecord(reg.subscriber_id, reg.unique_key_id, reg.keys.signing_public, 0,
                                           4102444800, "SUBSCRIBED", "REGISTRY"))
        try:
            await verify_authorization(header, fake, pinned)
            return result("NOT_BLOCKED", "forged lookup accepted", "")
        except AuthError as exc:
            return result("BLOCKED", f"Lookup response rejected ({exc.code}): it isn't signed by the registry key "
                          "pinned in every participant's configuration.",
                          "If key lookups could be spoofed (DNS hijack, compromised proxy), every signature check "
                          "would become meaningless. Pinning the registry key closes that hole.", exc.code,
                          ["attacker intercepts a /lookup", "answers 'paybuddy.app's key is <mallory's key>'",
                           f"signs it, header {REGISTRY_SIG_HEADER}"])

    async def hijack_registration(self) -> dict:
        bap, mallory = self.t.bap, self.t.mallory
        imposter = Participant("paybuddy.app", "BAP", bap.base_url, mallory.keys, "k9")
        r = await subscribe(imposter, self.t.url("registry"), self.http)
        return self._verdict(r, "SUBSCRIBE_ROTATION_UNAUTHORISED", "PayBuddy already has an active key, so a new "
                             "key must be co-signed by it. Mallory can't produce that signature.",
                             "Even someone who can reach the registry and knows the approved URL can't swap in "
                             "their own key for an existing participant.",
                             ["Mallory asks the registry to add key k9 for paybuddy.app",
                              "proves possession of k9 (her own key)", "has no signature from PayBuddy's current key"])

    async def unapproved_join(self) -> dict:
        r = await subscribe(self.t.mallory, self.t.url("registry"), self.http)
        return self._verdict(r, "SUBSCRIBE_NOT_APPROVED", "mallory.evil isn't on the operator's approved list.",
                             "Membership is governed: only vetted (KYC'd) organisations get keys into the registry.",
                             ["mallory.evil generates keys", "calls /subscribe"])

    async def forged_credential(self) -> dict:
        r = await self.http.post(f"{self.t.url('bap')}/api/orders", timeout=30,
                                 json={"buyer": "attack-lab", "query": "", "seller_id": "cheap-n-best"})
        data = r.json()
        if data.get("status") == "NO_TRUSTED_SELLER":
            return result("BLOCKED", "PayBuddy verified the credential's signature against the GST authority's "
                          "registered key. It fails (CRED_BAD_SIGNATURE), so the seller is hidden from buyers.",
                          "Badges can't be self-awarded. Only the trusted issuer's signature counts, and it can be "
                          "checked offline by any buyer app.", "CRED_BAD_SIGNATURE",
                          ["Cheap n Best signs a GST credential with its seller app's key",
                           "claims the issuer is gst-authority.sakshi.network", "buyer tries to order from it"])
        return result("NOT_BLOCKED", f"order went through: {data.get('status')}", "")

    # ------------------------------------------------------------ commitments
    async def bait_and_switch(self) -> dict:
        r = await self.http.post(f"{self.t.url('bap')}/api/orders", timeout=30,
                                 json={"buyer": "attack-lab", "query": "", "seller_id": "deal-dhamaka"})
        data = r.json()
        if data.get("status") == "REFUSED_PRICE_CHANGED":
            v = (data.get("disputes") or [{}])[0]
            return result("BLOCKED", f"PayBuddy refused to countersign; dispute verdict: {v.get('outcome')} "
                          f"({v.get('reason')}). Logged at #{v.get('ledger_index')}.",
                          "The seller's own signatures on the quote and the confirmation are the evidence: a "
                          "statement signed by X is proof against X, so no he-said-she-said.", "PRICE_MISMATCH",
                          ["Deal Dhamaka signs a quote", "then signs a confirmation 25% higher",
                           "buyer app compares the two signed documents"], order=data)
        return result("NOT_BLOCKED", f"order status {data.get('status')}", "")

    async def deny_promise(self) -> dict:
        ledger = self.t.url("ledger")
        head = SignedTreeHead.from_dict((await self.http.get(f"{ledger}/sth")).json())
        entries = (await self.http.get(f"{ledger}/entries", params={"start": max(0, head.tree_size - 200),
                                                                     "end": head.tree_size})).json()
        contract = next((e for e in reversed(entries) if e["receipt"]["body"]["type"] == "ORDER_CONTRACT"), None)
        if contract is None:
            return result("ERROR", "no contracts logged yet: let the simulation run a few seconds", "")
        receipt = Receipt.from_dict(contract["receipt"])
        resolver = _LookupResolver(self.http, self.t)
        await verify_receipt(receipt, resolver)
        proof = (await self.http.get(f"{ledger}/proof/inclusion",
                                     params={"index": contract["index"], "tree_size": head.tree_size})).json()["proof"]
        included = verify_inclusion(leaf_hash(canonical_json(contract["receipt"])), contract["index"],
                                    head.tree_size, [b64d(p) for p in proof], head.root)
        ledger_key = self.t.ledger.keys.signing_public
        b = receipt.body
        promised = time.strftime("%H:%M:%S", time.localtime(b["terms"]["promised_delivery_by"]))
        if included and head.verify(ledger_key):
            return result("DISPROVEN", f"{b['seller_id']} ({b['issuer']}) signed: deliver order {b['order_id']} "
                          f"for Rs {b['terms']['price']['value']} by {promised}. The buyer app countersigned it, and "
                          f"it is entry #{contract['index']} of the signed log (proof: {len(proof)} hashes).",
                          "Non-repudiation: the seller's signature can only come from the seller's private key, "
                          "and the log proves when it was recorded. Denial is impossible.", "SIGNATURE_VERIFIED",
                          ["seller: 'I never promised that'", "fetch the contract from the ledger",
                           "verify both signatures + inclusion proof against the signed tree head"],
                          receipt=receipt.to_dict(), index=contract["index"])
        return result("NOT_BLOCKED", "could not verify the contract", "")

    async def backdated_receipt(self) -> dict:
        bap, bpp = self.t.bap, self.t.bpp("kirana")
        issued = int(time.time()) - 3 * 86400
        rc = new_receipt("ORDER_CONTRACT", bpp.subscriber_id, bap.subscriber_id, str(uuid.uuid4()),
                         f"fresh-basket-backdated-{uuid.uuid4().hex[:6]}", "fresh-basket", "colluder",
                         {"items": [], "price": {"currency": "INR", "value": "9999.00"},
                          "promised_delivery_by": issued + 60}, issued_at=issued)
        rc.sign_as_issuer(bpp.unique_key_id, bpp.keys.signing_private)
        rc.countersign(bap.unique_key_id, bap.keys.signing_private)
        body = json.dumps({"receipt": rc.to_dict()}).encode()
        r = await self._post(f"{self.t.url('ledger')}/entries", body, {"Authorization": self._auth(body, bap)})
        return self._verdict(r, "LEDGER_STALE", "Both signatures are genuine, but the witness only accepts "
                             "receipts stamped within 5 minutes of arrival.",
                             "Colluding parties can sign anything, but they can't insert it into the past: the "
                             "log position is the trusted timestamp.",
                             ["seller app and buyer app collude", "both sign a contract dated 3 days ago",
                              "try to log it"])

    # ---------------------------------------------------------------- ledger
    async def _tamper(self, rebuild: bool) -> int:
        ledger = self.t.url("ledger")
        size = (await self.http.get(f"{ledger}/sth")).json()["tree_size"]
        if size < 2:
            raise RuntimeError("ledger has too few entries yet")
        index = max(0, size - 5)
        r = await self.http.post(f"{ledger}/admin/tamper", json={"index": index, "rebuild": rebuild},
                                 headers={"X-Admin-Token": self.t.admin_token})
        r.raise_for_status()
        return index

    async def _restore(self) -> None:
        await self.http.post(f"{self.t.url('ledger')}/admin/restore", headers={"X-Admin-Token": self.t.admin_token})

    async def silent_edit(self) -> dict:
        await self.auditor.check()
        index = await self._tamper(rebuild=False)
        try:
            head = SignedTreeHead.from_dict((await self.http.get(f"{self.t.url('ledger')}/sth")).json())
            ok = await self.auditor.check_entry(index, head)
        finally:
            await self._restore()
        if not ok:
            return result("DETECTED", f"Entry #{index} was edited; its hash no longer matches the signed Merkle "
                          "root. The auditor raised an alarm. (Entry restored for the demo.)",
                          "Every entry is locked into the root hash the witness signed. Changing a single byte "
                          "of an old receipt is caught by anyone holding an inclusion proof.", "INCLUSION_FAILED",
                          [f"operator changes entry #{index} in the database", "auditor fetches it with its proof",
                           "recomputed root != signed root"])
        return result("NOT_BLOCKED", "edit went unnoticed", "")

    async def history_rewrite(self) -> dict:
        await self.auditor.check()
        before = self.auditor.trusted.tree_size if self.auditor.trusted else 0
        index = await self._tamper(rebuild=True)
        try:
            ok = await self.auditor.check()
        finally:
            await self._restore()
        if not ok:
            return result("DETECTED", f"The operator edited #{index} and rebuilt the tree, producing a validly "
                          f"signed but different root. The auditor still holds the head of size {before} and "
                          "the new tree is not consistent with it. (Entry restored.)",
                          "Even the log's own operator can't rewrite history: auditors that remember old tree "
                          "heads catch any fork. This is the same defence Certificate Transparency uses.",
                          "CONSISTENCY_FAILED",
                          [f"operator edits #{index}", "recomputes every hash and signs a new root",
                           "auditor asks for a consistency proof from its saved head"])
        return result("NOT_BLOCKED", "rewrite went unnoticed", "")

    # ------------------------------------------------------------- reputation
    async def sybil_boost(self) -> dict:
        if self.sim is not None:
            await self.sim.burst(6)
        await asyncio.sleep(2)
        report = (await self.http.get(f"{self.t.url('ledger')}/fraud")).json()
        row = next((s for s in report["sellers"] if s["seller_id"] == BOOSTER), None)
        if row and row["flagged"]:
            return result("DETECTED", "Star Traders flagged for review: " + "; ".join(row["reasons"][:3]) + ".",
                          "Signatures prove orders happened, not that they were genuine. Graph analysis of who "
                          "buys from whom, plus how real the trade looks, catches sock-puppet rings.",
                          "COLLUSION_FLAGGED", ["Star Traders' puppets place small orders",
                                                "the seller 'delivers' them instantly",
                                                "fraud analysis runs over the ledger"], risk=row)
        return result("PENDING", "not flagged yet: the detector needs a few bursts of evidence (about a minute of "
                      "simulation). Try again shortly.", "", None, [], risk=row)


class _LookupResolver:
    """Small resolver for the attack lab: fetches keys via the registry over HTTP (signature checked)."""

    def __init__(self, http: httpx.AsyncClient, topo: Topology) -> None:
        from sakshi.client import RegistryResolver
        reg = topo.registry
        self.inner = RegistryResolver(topo.url("registry"), KeyRecord(reg.subscriber_id, reg.unique_key_id,
                                      reg.keys.signing_public, 0, 4102444800, "SUBSCRIBED", "REGISTRY"), http)

    async def resolve(self, subscriber_id: str, unique_key_id: str):
        return await self.inner.resolve(subscriber_id, unique_key_id)
